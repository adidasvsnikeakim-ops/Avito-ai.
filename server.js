import 'dotenv/config';
import express from 'express';
import multer from 'multer';
import OpenAI from 'openai';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = Number(process.env.PORT || 3000);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const upload = multer({ storage: multer.memoryStorage(), limits: { files: 8, fileSize: 8 * 1024 * 1024 } });
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const cookieName = 'avito_ai_session';
const planLimits = {
  free: Number(process.env.FREE_MONTHLY_ANALYSES || 3),
  pro: Number(process.env.PRO_MONTHLY_ANALYSES || 30),
  pro_max: Number(process.env.PRO_MAX_MONTHLY_ANALYSES || 100)
};

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
const analyzeLimiter = rateLimit({ windowMs: 60_000, limit: 12, standardHeaders: 'draft-8', legacyHeaders: false });

function monthKey() { return new Date().toISOString().slice(0, 7); }
function sign(user) { return jwt.sign({ sub: String(user.id), admin: !!user.is_admin }, JWT_SECRET, { expiresIn: '30d' }); }
function setSession(res, user) {
  res.cookie(cookieName, sign(user), { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 30*24*3600*1000, path: '/' });
}
function clearSession(res) { res.clearCookie(cookieName, { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', path: '/' }); }
async function getUserById(id) {
  const { rows } = await pool.query('SELECT id,email,name,telegram_id,plan,plan_expires_at,is_admin,created_at FROM users WHERE id=$1', [id]);
  return rows[0] || null;
}
async function auth(req, res, next) {
  try {
    const token = req.cookies[cookieName];
    if (!token) return res.status(401).json({ error: 'Нужна авторизация' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await getUserById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    req.user = user; next();
  } catch { return res.status(401).json({ error: 'Сессия истекла. Войдите снова.' }); }
}
function admin(req, res, next) { if (!req.user?.is_admin) return res.status(403).json({ error: 'Только для администратора' }); next(); }
function sameOrigin(req, res, next) {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (!origin) return next();
  try {
    if (new URL(origin).origin !== new URL(process.env.APP_URL || `http://localhost:${port}`).origin) return res.status(403).json({ error: 'Недопустимый источник запроса' });
  } catch {}
  next();
}
app.use('/api', sameOrigin);

async function audit(userId, action, meta={}) {
  await pool.query('INSERT INTO audit_log(user_id,action,meta) VALUES($1,$2,$3)', [userId || null, action, JSON.stringify(meta)]);
}

app.get('/api/health', async (_, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, db: true }); }
  catch { res.status(503).json({ ok: false, db: false }); }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const name = String(req.body.name || 'Пользователь').trim().slice(0, 80) || 'Пользователь';
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Введите корректный email' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть минимум 6 символов' });
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rowCount) return res.status(409).json({ error: 'Этот email уже зарегистрирован' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query('INSERT INTO users(email,password_hash,name) VALUES($1,$2,$3) RETURNING id,email,name,plan,plan_expires_at,is_admin,created_at', [email,hash,name]);
    setSession(res, rows[0]);
    await audit(rows[0].id, 'register');
    res.json({ user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Ошибка регистрации' }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = rows[0];
    if (!user?.password_hash || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Неверный email или пароль' });
    setSession(res, user);
    await audit(user.id, 'login');
    res.json({ user: await getUserById(user.id) });
  } catch { res.status(500).json({ error: 'Ошибка входа' }); }
});
app.post('/api/auth/logout', (req,res)=>{ clearSession(res); res.json({ok:true}); });
app.get('/api/me', auth, async (req,res)=>res.json({ user:req.user }));

function activePlan(user) {
  if (user.plan !== 'free' && user.plan_expires_at && new Date(user.plan_expires_at) <= new Date()) return 'free';
  return user.plan;
}
async function usage(user) {
  const period = monthKey();
  const { rows } = await pool.query('SELECT analyses FROM usage_monthly WHERE user_id=$1 AND period=$2', [user.id,period]);
  const plan = activePlan(user);
  return { plan, used: rows[0]?.analyses || 0, limit: planLimits[plan], period };
}
app.get('/api/usage', auth, async (req,res)=>res.json(await usage(req.user)));
app.get('/api/history', auth, async (req,res)=>{
  const limit = Math.min(Number(req.query.limit || 30), 100);
  const { rows } = await pool.query('SELECT id,product_input,city,buy_price,buy_budget,min_profit,result,created_at FROM analyses WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2', [req.user.id,limit]);
  res.json({ items: rows });
});
app.get('/api/history/:id', auth, async (req,res)=>{
  const { rows } = await pool.query('SELECT id,product_input,city,buy_price,buy_budget,min_profit,result,created_at FROM analyses WHERE id=$1 AND user_id=$2', [req.params.id,req.user.id]);
  if (!rows[0]) return res.status(404).json({error:'Анализ не найден'});
  res.json({ item: rows[0] });
});

async function consumeAnalysis(user) {
  const period = monthKey();
  const limit = planLimits[activePlan(user)];
  await pool.query('BEGIN');
  try {
    const r = await pool.query(`INSERT INTO usage_monthly(user_id,period,analyses) VALUES($1,$2,1)
      ON CONFLICT(user_id,period) DO UPDATE SET analyses=usage_monthly.analyses+1
      WHERE usage_monthly.analyses < $3 RETURNING analyses`, [user.id,period,limit]);
    if (!r.rowCount) { await pool.query('ROLLBACK'); return false; }
    await pool.query('COMMIT'); return true;
  } catch(e) { await pool.query('ROLLBACK'); throw e; }
}

const SYSTEM = `Ты — AI-аналитик для перепродажи товаров на Avito в России.
Твоя задача — помочь пользователю не купить товар слишком дорого.
Правила:
1) Не выдумывай цены и факты. Если данные рынка недостаточны, прямо укажи, что это оценка.
2) Если загружены скриншоты Avito, используй только видимые названия, цены, города и другие видимые данные. Не утверждай, что видел объявления, которые не видны на изображениях.
3) Разделяй цену покупки, целевую цену продажи и ожидаемую валовую прибыль.
4) Учитывай торг и риск: дай стартовое предложение и абсолютный максимум закупки.
5) Для техники дай обязательные проверки перед покупкой.
6) Если модель не определена точно, не угадывай модификацию — укажи, что нужно сфотографировать.
7) Если рынок представлен несколькими объявлениями, оцени диапазон, но не выдавай маленькую выборку за статистически точную рыночную цену.
8) Пиши по-русски, коротко и практично.
9) Результат должен быть валидным JSON по схеме.`;

function dataUrl(file) { return `data:${file.mimetype || 'image/jpeg'};base64,${file.buffer.toString('base64')}`; }

app.post('/api/analyze', auth, analyzeLimiter, upload.array('images',8), async (req,res)=>{
  try {
    if (!process.env.OPENAI_API_KEY) return res.status(500).json({error:'OPENAI_API_KEY не задан'});
    const files=req.files||[]; const b=req.body||{};
    if (!files.length && !b.product) return res.status(400).json({error:'Добавьте фото/скриншоты или название товара'});
    const ok=await consumeAnalysis(req.user);
    if (!ok) return res.status(402).json({error:'Лимит анализов исчерпан. Выберите PRO или PRO MAX.', code:'LIMIT_REACHED'});
    const client=new OpenAI({apiKey:process.env.OPENAI_API_KEY});
    const content=[{type:'input_text',text:`Проанализируй товар для перепродажи.\nТовар/модель: ${b.product||'не указано'}\nГород: ${b.city||'не указан'}\nБюджет покупки: ${b.buyBudget||'не указан'} ₽\nЦена покупки: ${b.buyPrice||'не указана'} ₽\nМинимальная желаемая прибыль: ${b.minProfit||'не указана'} ₽\nКомментарий: ${b.note||'нет'}\n\nНа изображениях могут быть фото товара и скриншоты выдачи. Отдели их мысленно и опирайся на видимые данные.`}];
    for(const file of files) content.push({type:'input_image',image_url:dataUrl(file),detail:'high'});
    const response=await client.responses.create({
      model:process.env.OPENAI_MODEL||'gpt-5.6-luna', instructions:SYSTEM,
      input:[{role:'user',content}],
      text:{format:{type:'json_schema',name:'resale_analysis',strict:true,schema:{type:'object',additionalProperties:false,properties:{
        verdict:{type:'string',enum:['БРАТЬ','ТОРГОВАТЬСЯ','НЕ БРАТЬ','НУЖНА ПРОВЕРКА']}, detected_product:{type:'string'}, confidence:{type:'number'},
        estimated_market_min:{type:'number'},estimated_market_max:{type:'number'},recommended_buy_max:{type:'number'},recommended_offer:{type:'number'},target_sale_price:{type:'number'},expected_gross_profit:{type:'number'},expected_margin_percent:{type:'number'},
        listing_title:{type:'string'},listing_description:{type:'string'},negotiation_message:{type:'string'},checks:{type:'array',items:{type:'string'}},risks:{type:'array',items:{type:'string'}},evidence:{type:'array',items:{type:'string'}},note:{type:'string'}
      },required:['verdict','detected_product','confidence','estimated_market_min','estimated_market_max','recommended_buy_max','recommended_offer','target_sale_price','expected_gross_profit','expected_margin_percent','listing_title','listing_description','negotiation_message','checks','risks','evidence','note']}}}
    });
    const result=JSON.parse(response.output_text);
    const {rows}=await pool.query('INSERT INTO analyses(user_id,product_input,city,buy_price,buy_budget,min_profit,result) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,created_at',[req.user.id,b.product||null,b.city||null,Number(b.buyPrice)||null,Number(b.buyBudget)||null,Number(b.minProfit)||null,JSON.stringify(result)]);
    await audit(req.user.id,'analysis',{analysis_id:rows[0].id,detected_product:result.detected_product});
    res.json({id:rows[0].id,created_at:rows[0].created_at,...result});
  } catch(e) { console.error(e); res.status(500).json({error:e?.message||'Ошибка анализа'}); }
});

function planInfo(plan){
  if(plan==='pro') return {name:'PRO',price:Number(process.env.PRO_PRICE_RUB||299),days:Number(process.env.PRO_DAYS||30),limit:planLimits.pro};
  if(plan==='pro_max') return {name:'PRO MAX',price:Number(process.env.PRO_MAX_PRICE_RUB||699),days:Number(process.env.PRO_DAYS||30),limit:planLimits.pro_max};
  return {name:'FREE',price:0,days:0,limit:planLimits.free};
}
async function activatePlan(userId,plan,source,externalId,raw={}){
  const days=Number(process.env.PRO_DAYS||30);
  const {rows}=await pool.query('SELECT plan,plan_expires_at FROM users WHERE id=$1',[userId]);
  if(!rows[0]) throw new Error('user not found');
  const old=rows[0]; const base=(old.plan!=='free' && old.plan_expires_at && new Date(old.plan_expires_at)>new Date())?new Date(old.plan_expires_at):new Date();
  const expires=new Date(base.getTime()+days*86400000);
  await pool.query('UPDATE users SET plan=$1,plan_expires_at=$2 WHERE id=$3',[plan,expires,userId]);
  if(externalId) await pool.query('UPDATE payments SET status=$1,paid_at=NOW(),raw=$2 WHERE external_id=$3',['succeeded',JSON.stringify(raw),externalId]);
  await audit(userId,'plan_activated',{plan,source,externalId});
  return expires;
}

async function yookassaCreate(userId,plan){
  if(!process.env.YOOKASSA_SHOP_ID||!process.env.YOOKASSA_SECRET_KEY) throw new Error('ЮKassa не настроена');
  const p=planInfo(plan); const idem=crypto.randomUUID();
  const r=await fetch('https://api.yookassa.ru/v3/payments',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(process.env.YOOKASSA_SHOP_ID+':'+process.env.YOOKASSA_SECRET_KEY).toString('base64'),'Content-Type':'application/json','Idempotence-Key':idem},body:JSON.stringify({amount:{value:p.price.toFixed(2),currency:'RUB'},capture:true,confirmation:{type:'redirect',return_url:`${process.env.APP_URL}/?payment=return`},description:`AVITO AI — ${p.name}`,metadata:{user_id:String(userId),plan}})});
  const data=await r.json(); if(!r.ok) throw new Error(data?.description||'Ошибка ЮKassa');
  await pool.query('INSERT INTO payments(user_id,provider,external_id,plan,amount,currency,status,raw) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(external_id) DO NOTHING',[userId,'yookassa',data.id,plan,p.price,'RUB',data.status,JSON.stringify(data)]);
  return data.confirmation?.confirmation_url;
}
app.post('/api/payments/yookassa/create',auth,async(req,res)=>{try{const plan=req.body.plan;if(!['pro','pro_max'].includes(plan))return res.status(400).json({error:'Неверный тариф'});const url=await yookassaCreate(req.user.id,plan);res.json({url});}catch(e){res.status(400).json({error:e.message});}});
app.post('/api/payments/yookassa/webhook',async(req,res)=>{
  try{
    const event=req.body; const object=event?.object;
    if(event?.event!=='payment.succeeded'||!object?.id) return res.json({ok:true});
    if(!process.env.YOOKASSA_SHOP_ID||!process.env.YOOKASSA_SECRET_KEY) return res.json({ok:true});
    const r=await fetch(`https://api.yookassa.ru/v3/payments/${object.id}`,{headers:{Authorization:'Basic '+Buffer.from(process.env.YOOKASSA_SHOP_ID+':'+process.env.YOOKASSA_SECRET_KEY).toString('base64')}});
    const payment=await r.json(); if(!r.ok||payment.status!=='succeeded') return res.json({ok:true});
    const {rows}=await pool.query('SELECT * FROM payments WHERE external_id=$1',[payment.id]); if(!rows[0]) return res.json({ok:true});
    if(rows[0].status!=='succeeded') await activatePlan(rows[0].user_id,rows[0].plan,'yookassa',payment.id,payment);
    res.json({ok:true});
  }catch(e){console.error(e);res.status(500).json({ok:false});}
});

async function telegramCall(method,body){
  if(!process.env.TELEGRAM_BOT_TOKEN) throw new Error('Telegram bot is not configured');
  const r=await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/${method}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); const d=await r.json(); if(!d.ok) throw new Error(d.description||'Telegram API error'); return d.result;
}
function tgPayload(payload){ return payload==='pro'?'pro':'pro_max'; }
async function ensureTelegramUser(tg){
  const telegramId=String(tg.id); const existing=await pool.query('SELECT * FROM users WHERE telegram_id=$1',[telegramId]);
  if(existing.rows[0]) return existing.rows[0];
  const name=[tg.first_name,tg.last_name].filter(Boolean).join(' ')||'Telegram пользователь';
  const {rows}=await pool.query('INSERT INTO users(name,telegram_id) VALUES($1,$2) RETURNING *',[name,telegramId]);
  return rows[0];
}
async function sendTelegramMenu(chatId){
  await telegramCall('sendMessage',{chat_id:chatId,text:'🚀 AVITO AI\n\nЗагружай скриншот объявления — получишь оценку цены, максимальную цену покупки, прогноз прибыли и готовый текст продавцу.',reply_markup:{inline_keyboard:[[{text:'🤖 Открыть AVITO AI',web_app:{url:process.env.TELEGRAM_APP_URL||`${process.env.APP_URL}/?tg=1`}}],[{text:'💎 PRO — '+(process.env.PRO_STARS||299)+' ⭐',callback_data:'buy_pro'},{text:'🔥 PRO MAX — '+(process.env.PRO_MAX_STARS||699)+' ⭐',callback_data:'buy_pro_max'}]]}});
}
app.post('/api/telegram/auth',async(req,res)=>{
  try{
    const initData=String(req.body.initData||''); if(!initData||!process.env.TELEGRAM_BOT_TOKEN) return res.status(400).json({error:'Telegram авторизация не настроена'});
    const params=new URLSearchParams(initData); const hash=params.get('hash'); if(!hash) return res.status(400).json({error:'Нет hash'});
    const dataCheck=[...params.entries()].filter(([k])=>k!=='hash').sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join('\n');
    const secret=crypto.createHmac('sha256','WebAppData').update(process.env.TELEGRAM_BOT_TOKEN).digest();
    const expected=crypto.createHmac('sha256',secret).update(dataCheck).digest('hex');
    if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(hash))) return res.status(403).json({error:'Неверные Telegram данные'});
    const authDate=Number(params.get('auth_date')||0); if(Date.now()/1000-authDate>86400) return res.status(403).json({error:'Telegram-сессия устарела'});
    const tg=JSON.parse(params.get('user')||'{}'); const user=await ensureTelegramUser(tg); setSession(res,user); res.json({user:await getUserById(user.id)});
  }catch(e){res.status(400).json({error:e.message});}
});

app.post('/api/telegram/webhook',async(req,res)=>{
  if(process.env.TELEGRAM_WEBHOOK_SECRET && req.headers['x-telegram-bot-api-secret-token']!==process.env.TELEGRAM_WEBHOOK_SECRET) return res.status(403).send('forbidden');
  res.send('ok');
  try{
    const u=req.body;
    if(u.message){
      const m=u.message; const tg=m.from; const user=await ensureTelegramUser(tg);
      if(m.successful_payment){
        const payload=tgPayload(m.successful_payment.invoice_payload); const externalId=m.successful_payment.telegram_payment_charge_id;
        await pool.query('INSERT INTO payments(user_id,provider,external_id,plan,amount,currency,status,raw,paid_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT(external_id) DO NOTHING',[user.id,'telegram_stars',externalId,payload,Number(m.successful_payment.total_amount),'XTR','succeeded',JSON.stringify(m.successful_payment)]);
        await activatePlan(user.id,payload,'telegram_stars',externalId,m.successful_payment);
        await telegramCall('sendMessage',{chat_id:m.chat.id,text:`✅ Оплата получена. Тариф ${planInfo(payload).name} активирован на ${planInfo(payload).days} дней.`});
      } else if(/^\/start|^\/app|^\/menu/.test(m.text||'')) await sendTelegramMenu(m.chat.id);
      else if(/^\/pricing/.test(m.text||'')) await telegramCall('sendMessage',{chat_id:m.chat.id,text:`PRO: ${process.env.PRO_STARS||299} ⭐\nPRO MAX: ${process.env.PRO_MAX_STARS||699} ⭐`,reply_markup:{inline_keyboard:[[{text:'Купить PRO',callback_data:'buy_pro'},{text:'Купить PRO MAX',callback_data:'buy_pro_max'}]]}});
    }
    if(u.callback_query){
      const q=u.callback_query; const user=await ensureTelegramUser(q.from); const plan=q.data==='buy_pro'?'pro':q.data==='buy_pro_max'?'pro_max':null;
      if(plan){
        const stars=Number(plan==='pro'?process.env.PRO_STARS||299:process.env.PRO_MAX_STARS||699);
        await telegramCall('answerCallbackQuery',{callback_query_id:q.id});
        await telegramCall('sendInvoice',{chat_id:q.message.chat.id,title:`AVITO AI ${planInfo(plan).name}`,description:`Доступ к ${planInfo(plan).name} на ${planInfo(plan).days} дней`,payload:plan,currency:'XTR',prices:[{label:planInfo(plan).name,amount:stars}],provider_token:''});
      }
    }
    if(u.pre_checkout_query) await telegramCall('answerPreCheckoutQuery',{pre_checkout_query_id:u.pre_checkout_query.id,ok:true});
  }catch(e){console.error('telegram webhook',e);}
});

// Admin
app.get('/api/admin/stats',auth,admin,async(req,res)=>{
  const [u,a,p,r]=await Promise.all([
    pool.query("SELECT COUNT(*)::int count FROM users"),
    pool.query("SELECT COUNT(*)::int count FROM analyses WHERE created_at >= NOW()-INTERVAL '30 days'"),
    pool.query("SELECT COALESCE(SUM(amount),0)::numeric revenue FROM payments WHERE status='succeeded'"),
    pool.query("SELECT COUNT(*)::int count FROM payments WHERE status='succeeded'")
  ]); res.json({users:u.rows[0].count,analyses30d:a.rows[0].count,revenue:Number(p.rows[0].revenue),paidOrders:r.rows[0].count});
});
app.get('/api/admin/users',auth,admin,async(req,res)=>{const limit=Math.min(Number(req.query.limit||100),500);const {rows}=await pool.query('SELECT id,email,name,telegram_id,plan,plan_expires_at,is_admin,created_at FROM users ORDER BY created_at DESC LIMIT $1',[limit]);res.json({items:rows});});
app.get('/api/admin/payments',auth,admin,async(req,res)=>{const {rows}=await pool.query('SELECT p.*,u.email,u.name FROM payments p LEFT JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 200');res.json({items:rows});});
app.get('/admin',(_,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));

// Graceful shutdown
process.on('SIGTERM',async()=>{await pool.end();process.exit(0)});
app.listen(port,'0.0.0.0',()=>console.log(`AVITO AI: http://0.0.0.0:${port}`));

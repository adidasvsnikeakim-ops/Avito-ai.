import 'dotenv/config';
const token = process.env.TELEGRAM_BOT_TOKEN;
const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
const url = `${process.env.APP_URL}/api/telegram/webhook`;
if (!token) throw new Error('TELEGRAM_BOT_TOKEN is missing');
const r = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
  method: 'POST',
  headers: {'content-type': 'application/json'},
  body: JSON.stringify({
    url,
    secret_token: secret,
    allowed_updates: ['message', 'callback_query', 'pre_checkout_query']
  })
});
console.log(await r.text());

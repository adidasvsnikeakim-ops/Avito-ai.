# AVITO AI — Full SaaS

Полноценная заготовка коммерческого сервиса: сайт, регистрация, бесплатные лимиты, PostgreSQL, история анализов, PRO/PRO MAX, админка, ЮKassa, Telegram-бот + Telegram Mini App auth и Telegram Stars.

## Важно
Это production-ready scaffold, но внешние аккаунты нельзя создать за пользователя из этого архива. Перед публичным запуском нужны: домен, PostgreSQL, OpenAI API key, Telegram bot token и приём платежей (например, ЮKassa). Также юридические страницы нужно заполнить реальными реквизитами.

## Локально
1. Установить Node.js 20+ и Docker.
2. Скопировать `.env.example` в `.env`.
3. Запустить `docker compose up -d db`.
4. `npm install`.
5. `npm run db:init`.
6. Запустить `npm start`.
7. Открыть `http://localhost:3000`.

## Первый администратор
После первого запуска можно создать обычного пользователя через сайт. Чтобы сделать его админом, выполните SQL:
`UPDATE users SET is_admin=true WHERE email='ВАШ_EMAIL';`

## ЮKassa
Заполнить `YOOKASSA_SHOP_ID` и `YOOKASSA_SECRET_KEY`. Webhook: `POST /api/payments/yookassa/webhook`. После события `payment.succeeded` сервер дополнительно запрашивает платёж у ЮKassa и только после подтверждения активирует тариф.

## Telegram
Заполнить `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_APP_URL` и выполнить `npm run telegram:set-webhook` на публичном HTTPS-домене. Бот поддерживает `/start`, `/app`, `/pricing`, кнопки покупки PRO/PRO MAX в Stars и успешную оплату.

## Render
Для публичного Node/Express приложения подходит Web Service. Build: `npm install`, Start: `npm start`. Подключите PostgreSQL как отдельный datastore и задайте env vars. Render выдаёт `onrender.com` URL и позволяет подключить свой домен.

## Архитектура
- Node.js + Express
- PostgreSQL
- OpenAI Responses API + image input + JSON Schema
- JWT в HttpOnly cookie
- bcrypt для паролей
- ЮKassa для сайта
- Telegram Bot API + Stars + Mini App
- Admin dashboard
- Без автоматического скрапинга Avito

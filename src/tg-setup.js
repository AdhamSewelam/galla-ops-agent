// One-time helper: finds your Telegram chat id after you press Start on the Galla JARVIS bot.
// Usage: node --env-file=.env src/tg-setup.js
const token = process.env.TELEGRAM_BOT_TOKEN;
if (!token) { console.error('Put TELEGRAM_BOT_TOKEN=... in .env first (from @BotFather).'); process.exit(1); }
const api = (m) => `https://api.telegram.org/bot${token}/${m}`;
const me = await (await fetch(api('getMe'))).json();
if (!me.ok) { console.error('Token rejected by Telegram:', me.description); process.exit(1); }
const up = await (await fetch(api('getUpdates'))).json();
if (!up.ok) { console.error('getUpdates failed:', up.description, '(stop the galla-ops process first: pm2 stop galla-ops)'); process.exit(1); }
const chats = new Map();
for (const u of up.result || []) { const c = u.message?.chat; if (c) chats.set(c.id, c); }
if (!chats.size) { console.log(`Bot @${me.result.username} is OK. Open it in Telegram, press START (or send "hi"), then run this again.`); process.exit(0); }
for (const c of chats.values()) {
  console.log(`Chat found: ${c.first_name || ''} ${c.last_name || ''} (@${c.username || '-'})  →  TELEGRAM_CHAT_ID=${c.id}`);
  await fetch(api('sendMessage'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ chat_id: c.id, text: 'Hello, I am JARVIS for Galla Ops. I will alert you here if Jewels by Galla, One Carat or El Galla has a problem.' }) });
}
console.log('\nAdd that line to .env, then: pm2 restart galla-ops --update-env');

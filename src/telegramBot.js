// Your own Telegram bot (official Bot API, free). Sends JARVIS alerts + voice messages,
// and listens for the "I'm on it" button (long polling, no webhook needed).
import fs from 'node:fs';

export function createTelegramBot(config, { fetchImpl = fetch } = {}) {
  const token = config.TELEGRAM_BOT_TOKEN;
  const chatId = config.TELEGRAM_CHAT_ID;
  const api = (method) => `https://api.telegram.org/bot${token}/${method}`;

  async function call(method, body) {
    const isForm = body instanceof FormData;
    const res = await fetchImpl(api(method), {
      method: 'POST',
      headers: isForm ? undefined : { 'content-type': 'application/json' },
      body: isForm ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(method === 'getUpdates' ? 70000 : 30000),
    });
    const json = await res.json().catch(() => ({}));
    // Never include the URL in errors: it contains the bot token.
    if (!json.ok) throw new Error(`Telegram ${method}: ${json.description || res.status}`);
    return json.result;
  }

  const sendMessage = (text, buttons = null) =>
    call('sendMessage', { chat_id: chatId, text, disable_web_page_preview: true, ...(buttons ? { reply_markup: { inline_keyboard: buttons } } : {}) });

  async function sendVoice(file, caption = '') {
    const form = new FormData();
    form.append('chat_id', String(chatId));
    if (caption) form.append('caption', caption);
    form.append('voice', new Blob([fs.readFileSync(file)], { type: 'audio/ogg' }), 'jarvis.ogg');
    return call('sendVoice', form);
  }

  const answerCallback = (id, text) => call('answerCallbackQuery', { callback_query_id: id, text });
  const editButtons = (messageId, text) => call('editMessageReplyMarkup', { chat_id: chatId, message_id: messageId, reply_markup: { inline_keyboard: [[{ text, callback_data: 'noop' }]] } }).catch(() => {});

  /** Long-poll for button taps. onCallback(data, query) is called only for taps from the owner's chat. */
  function startPolling(onCallback) {
    let offset = 0, stopped = false;
    (async function loop() {
      while (!stopped) {
        try {
          const updates = await call('getUpdates', { offset, timeout: 50, allowed_updates: ['callback_query'] });
          for (const u of updates) {
            offset = u.update_id + 1;
            const q = u.callback_query;
            if (q && String(q.message?.chat?.id) === String(chatId)) await onCallback(q.data, q);
          }
        } catch {
          await new Promise((r) => setTimeout(r, 10000)); // network hiccup: retry later
        }
      }
    })();
    return () => { stopped = true; };
  }

  return { sendMessage, sendVoice, answerCallback, editButtons, startPolling };
}

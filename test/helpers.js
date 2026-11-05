import fs from 'node:fs';
import { loadConfig } from '../src/config.js';
import { parseBrands } from '../src/brands.js';
import { openMemoryDb } from '../src/db.js';
import { createMailer } from '../src/email.js';
import { createIncidents } from '../src/incidents.js';
import { createVoice } from '../src/voice.js';

process.env.GALLA_QUIET = '1';

export const SECRET_SHARED = 'a'.repeat(64);
export function makeConfig(extra = {}) {
  return loadConfig({
    PUBLIC_BASE_URL: 'https://galla-ops.example.test', APPROVAL_SECRET: 'x'.repeat(40), DASHBOARD_PASSWORD: 'correct-horse-battery',
    SENTINEL_SECRET_SHARED: SECRET_SHARED, SENTINEL_SECRET_VPS: 'b'.repeat(64), ...extra,
  });
}
export const registry = () => parseBrands(JSON.parse(fs.readFileSync(new URL('../brands.example.json', import.meta.url), 'utf8')));

/** A mailer that records instead of sending (transport present so "sent" is true). */
export function fakeMailer(config, db) {
  const sent = [];
  const m = createMailer({ ...config, features: { ...config.features, email: true } }, db, { transport: { sendMail: async (msg) => { sent.push(msg); } } });
  return { ...m, sent };
}

/** Telegram bot double + manual timers, so ack/escalation can be driven by the test. */
export function fakeVoice(config, db) {
  const timers = [];
  const messages = [];
  const bot = { sendMessage: async (text, buttons) => { messages.push({ text, buttons }); }, sendVoice: async () => {}, answerCallback: async () => {}, editButtons: async () => {}, startPolling: () => () => {} };
  const voice = createVoice({ config: { ...config, features: { ...config.features, voice: true } }, db, bot, setTimer: (fn, ms) => timers.push({ fn, ms }), tts: async () => null });
  return { voice, timers, messages };
}

export function setup(extra = {}) {
  const config = makeConfig(extra);
  const db = openMemoryDb();
  const reg = registry();
  const mailer = fakeMailer(config, db);
  const v = fakeVoice(config, db);
  const incidents = createIncidents({ config, db, mailer, voice: v.voice, registry: reg });
  return { config, db, registry: reg, mailer, incidents, ...v };
}

/** fetch double: routes [[regex, handler(url, init) => {status, body, headers}]]; records every call. */
export function fakeFetch(routes) {
  const calls = [];
  const fn = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    calls.push({ url, method: (init.method || 'GET').toUpperCase(), headers: init.headers || {} });
    for (const [re, h] of routes) if (re.test(url)) {
      const r = typeof h === 'function' ? await h(url, init) : h;
      return new Response(r.body ?? '', { status: r.status ?? 200, headers: r.headers || { 'content-type': 'text/html' } });
    }
    return new Response('not found', { status: 404 });
  };
  fn.calls = calls;
  return fn;
}

export const HTML_OK = (extra = '') => `<!doctype html><html><head><title>Shop</title></head><body class="woocommerce"><div class="products">${extra}</div><form id="loginform"><input id="user_login"></form><button class="single_add_to_cart_button">Add</button></body></html>`;

// JARVIS: Telegram alerts with an "I'm on it" button and a voice message (Piper on the VPS).
// The urgent email is sent exactly once per alert: when Adham taps "I'm on it" (as the written record),
// when JARVIS_ACK_MINUTES pass without a tap, or immediately if Telegram can't be reached.
// Uses its OWN bot token: two processes long-polling one bot get HTTP 409 and both lose the button.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { nowIso } from './db.js';
import { audit } from './audit.js';
import { createTelegramBot } from './telegramBot.js';
import { synthesize } from './tts.js';
import { redactText } from './redact.js';

export const TEST_SCENARIOS = {
  jarvis_test: { key: 'jarvis_test', label: 'Simple test', title: 'JARVIS test alert', todo: 'Nothing. This was only a test.' },
  site_down: { key: 'test:site_down', label: 'Website is down', title: 'JBG /eg/en homepage is down (origin HTTP 503)', todo: 'Open hPanel, check the site and Hostinger status.' },
  security: { key: 'test:security', label: 'Security finding', title: 'Malware marker SC_TH_BEGIN found in rey-child/functions.php', todo: 'Open the SECURITY email for the exact commands to verify and remove it.' },
};

export function migrateVoice(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS voice_calls (
    id TEXT PRIMARY KEY, incident_id INTEGER, status TEXT NOT NULL DEFAULT 'calling',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, email_sent INTEGER NOT NULL DEFAULT 0
  )`);
}

const cairoTime = (iso, tz) => new Date(iso).toLocaleTimeString('en-GB', { timeZone: tz, hour: 'numeric', minute: '2-digit' });

export function spokenMessage(incident, { ownerName = 'Adham', tz = 'Africa/Cairo', todo = '' } = {}) {
  const hour = Number(new Date().toLocaleString('en-GB', { timeZone: tz, hour: '2-digit', hour12: false }));
  const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  const test = incident.status === 'test';
  const title = String(incident.title).replace(/^TEST:\s*/, '').replace(/\(.*?\)/g, '').replace(/\//g, ' ');
  return `${greet} ${ownerName}. This is JARVIS, from Galla operations. ${test ? 'This is a test. Nothing is actually wrong.' : ''} ` +
    `I have ${incident.category === 'security' ? 'a security alert' : 'an urgent alert'}. ${title}. It started at ${cairoTime(incident.first_seen, tz)}, Cairo time. ${todo}`;
}

export function createVoice({ config, db, fetchImpl = fetch, setTimer = setTimeout, bot = null, tts = synthesize }) {
  migrateVoice(db);
  const enabled = config.features.voice;
  if (enabled && !bot) bot = createTelegramBot(config, { fetchImpl });
  const ackMs = config.JARVIS_ACK_MINUTES * 60_000;
  let emailSender = async () => {};

  const setCall = (id, fields) => {
    const sets = Object.keys(fields).map((k) => `${k} = @${k}`).join(', ');
    db.prepare(`UPDATE voice_calls SET ${sets}, updated_at = @updated_at WHERE id = @id`).run({ ...fields, updated_at: nowIso(), id });
  };

  async function finish(id, note) {
    const call = db.prepare('SELECT * FROM voice_calls WHERE id = ?').get(id);
    if (!call || call.email_sent) return;
    setCall(id, { email_sent: 1 });
    const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(call.incident_id);
    if (incident) await emailSender(incident, note);
  }

  /** After a restart: alerts whose waiting time passed without an email get their email now. */
  async function sweep() {
    const cutoff = new Date(Date.now() - ackMs).toISOString();
    for (const c of db.prepare('SELECT id FROM voice_calls WHERE email_sent = 0 AND created_at < ?').all(cutoff))
      await finish(c.id, 'JARVIS could not confirm the Telegram alert, so this email was sent as a backup.');
  }

  /** Alert on Telegram; the email follows once (ack, timeout, or Telegram failure). */
  async function alertIncident(incident, { todo = '' } = {}) {
    const id = crypto.randomUUID();
    db.prepare('INSERT INTO voice_calls(id, incident_id, created_at, updated_at) VALUES (?,?,?,?)').run(id, incident.id ?? null, nowIso(), nowIso());
    if (!enabled) { await finish(id, null); return { callId: id, via: 'email' }; }
    const test = incident.status === 'test';
    const icon = incident.category === 'security' ? '🛡️ SECURITY' : '🚨 JARVIS ALERT';
    const text = redactText(`${icon}${test ? ' (TEST)' : ''}: ${String(incident.title).replace(/^TEST:\s*/, '')}\n${todo}\n\n` +
      `Started ${cairoTime(incident.first_seen, config.TIMEZONE)} Cairo time. Tap "I'm on it" within ${config.JARVIS_ACK_MINUTES} min, otherwise I'll email you.`);
    try {
      await bot.sendMessage(text, [[{ text: "✅ I'm on it", callback_data: `ack:${id}` }]]);
    } catch (e) {
      setCall(id, { status: 'failed' });
      audit(db, { actor: 'jarvis', action: 'jarvis_alert_failed', target: `incident:${incident.id}`, detail: { error: e.message }, outcome: 'error' });
      await finish(id, `JARVIS could not reach you on Telegram (${e.message}).`);
      return { callId: id, via: 'email' };
    }
    audit(db, { actor: 'jarvis', action: 'jarvis_alert_sent', target: `incident:${incident.id}` });
    setTimer(() => finish(id, `JARVIS alerted you on Telegram but you didn't tap "I'm on it" within ${config.JARVIS_ACK_MINUTES} minutes.`), ackMs);
    try {
      const v = await tts(spokenMessage(incident, { ownerName: config.OWNER_NAME, tz: config.TIMEZONE, todo }), { piperModel: config.PIPER_MODEL });
      if (v) { try { await bot.sendVoice(v.file, test ? 'JARVIS (test)' : 'JARVIS'); } finally { fs.rmSync(v.file, { force: true }); } }
    } catch (e) {
      audit(db, { actor: 'jarvis', action: 'jarvis_voice_failed', target: `incident:${incident.id}`, detail: { error: e.message }, outcome: 'error' });
    }
    return { callId: id, via: 'telegram' };
  }

  async function onBotButton(data, q) {
    const m = /^ack:([0-9a-f-]{36})$/.exec(String(data || ''));
    if (!m) return bot.answerCallback(q.id, '').catch(() => {});
    const call = db.prepare('SELECT * FROM voice_calls WHERE id = ?').get(m[1]);
    if (!call) return bot.answerCallback(q.id, 'This alert is no longer active.').catch(() => {});
    if (call.status !== 'acknowledged') {
      setCall(call.id, { status: 'acknowledged' });
      db.prepare('UPDATE incidents SET acknowledged_at = COALESCE(acknowledged_at, ?) WHERE id = ?').run(nowIso(), call.incident_id);
      audit(db, { actor: 'owner', action: 'jarvis_alert_acknowledged', target: `incident:${call.incident_id}` });
      await finish(call.id, 'You tapped "I\'m on it" in Telegram. This is the written record.');
    }
    await bot.answerCallback(q.id, 'Got it. Details are in your email.').catch(() => {});
    if (q.message?.message_id) await bot.editButtons(q.message.message_id, '✅ On it');
  }

  let stopPolling = null;
  const start = () => { if (enabled && !stopPolling) stopPolling = bot.startPolling(onBotButton); };

  async function testAlert(scenario = 'jarvis_test') {
    const sc = TEST_SCENARIOS[scenario] || TEST_SCENARIOS.jarvis_test;
    const now = nowIso();
    const id = db.prepare("INSERT INTO incidents(key, category, severity, title, status, first_seen, last_seen, last_error) VALUES (?, 'test', 'test', ?, 'test', ?, ?, 'TEST ONLY: nothing is actually wrong')")
      .run(sc.key, `TEST: ${sc.title}`, now, now).lastInsertRowid;
    return alertIncident(db.prepare('SELECT * FROM incidents WHERE id = ?').get(id), { todo: sc.todo });
  }

  return { enabled, alertIncident, testAlert, sweep, start, stop: () => stopPolling?.(), _onBotButton: onBotButton, setEmailSender: (fn) => { emailSender = fn; } };
}

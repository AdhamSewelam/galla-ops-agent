// Outbound email to the owner only. The recipient is fixed by config, never taken from content.
// Subjects: "[JBG] [URGENT] ..." — brand short name first, then one of the fixed prefixes.
import nodemailer from 'nodemailer';
import { audit } from './audit.js';
import { redactText } from './redact.js';

export const PREFIXES = ['URGENT', 'RESOLVED', 'SECURITY', 'DAILY', 'WEEKLY SEO', 'HR', 'INFO'];

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function subjectFor({ brand = null, prefix, subject }) {
  if (!PREFIXES.includes(prefix)) throw new Error(`unknown email prefix ${prefix}`);
  return `${brand ? `[${brand}] ` : ''}[${prefix}] ${subject}`.slice(0, 200);
}

export function createMailer(config, db, { transport = undefined } = {}) {
  const t = transport !== undefined
    ? transport
    : config.features.email
      ? nodemailer.createTransport({ host: config.SMTP_HOST, port: config.SMTP_PORT, secure: config.SMTP_PORT === 465, auth: { user: config.SMTP_USER, pass: config.SMTP_PASS } })
      : null;
  const outbox = []; // last few messages, for tests and the dashboard

  async function send({ brand = null, prefix, subject, html, text }) {
    const fullSubject = redactText(subjectFor({ brand, prefix, subject }));
    const safeHtml = redactText(html || '');
    const safeText = redactText(text || '');
    outbox.push({ subject: fullSubject, html: safeHtml, text: safeText, at: new Date().toISOString() });
    if (outbox.length > 50) outbox.shift();
    if (!t) {
      audit(db, { action: 'email_skipped_not_configured', target: fullSubject, outcome: 'skipped' });
      if (!process.env.GALLA_QUIET) console.log(`\n--- EMAIL (not sent, SMTP not configured) ---\n${fullSubject}\n${safeText}\n`);
      return { sent: false };
    }
    try {
      await t.sendMail({ from: config.EMAIL_FROM || config.SMTP_USER, to: config.OWNER_EMAIL, subject: fullSubject, text: safeText, html: wrap(safeHtml) });
      audit(db, { action: 'email_sent', target: fullSubject });
      return { sent: true };
    } catch (err) {
      audit(db, { action: 'email_failed', target: fullSubject, detail: { error: err.message }, outcome: 'error' });
      return { sent: false, error: err.message };
    }
  }
  return { send, outbox };
}

function wrap(body) {
  return `<!doctype html><html><body style="margin:0;background:#f5f3ef;font-family:Inter,Arial,sans-serif;color:#1d1a16">
  <div style="max-width:680px;margin:0 auto;padding:24px">
    <div style="font-family:Georgia,serif;font-size:20px;margin-bottom:16px">Galla Ops</div>
    <div style="background:#fff;border-radius:10px;padding:20px;line-height:1.55;font-size:14px">${body}</div>
    <div style="font-size:11px;color:#8a8478;margin-top:12px">Sent by Galla Ops. It is read-only: it never changes prices, products, orders, users, plugins, settings or files on any site.</div>
  </div></body></html>`;
}

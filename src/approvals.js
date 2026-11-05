// Approval tokens for approval-style actions (accept a baseline, acknowledge a finding).
// HMAC-signed, expiring, bound to the exact item AND its content hash: if the thing changes after the
// link was made (e.g. a newer sentinel report arrives), the old link stops working.
// GET only shows a confirm page; the decision needs a POST click, so link scanners can't trigger it.
import crypto from 'node:crypto';
import { nowIso } from './db.js';

export const KINDS = ['accept_sentinel_baseline', 'accept_page_baseline', 'ack_incident'];

export const sha256 = (s) => crypto.createHash('sha256').update(typeof s === 'string' ? s : JSON.stringify(s)).digest('hex');
const sign = (secret, payload) => crypto.createHmac('sha256', secret).update(payload).digest('base64url');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

export function createApproval(db, config, { kind, itemId, contentHash }, now = Date.now()) {
  if (!KINDS.includes(kind)) throw new Error(`unknown approval kind ${kind}`);
  const id = crypto.randomUUID();
  const exp = now + config.APPROVAL_TTL_HOURS * 3600_000;
  db.prepare('INSERT INTO approvals(id, kind, item_id, content_hash, requested_at, expires_at) VALUES (?,?,?,?,?,?)')
    .run(id, kind, String(itemId), contentHash, new Date(now).toISOString(), new Date(exp).toISOString());
  const sig = sign(config.APPROVAL_SECRET, `${id}.${kind}.${itemId}.${contentHash}.${exp}`);
  return { id, exp, url: `${config.PUBLIC_BASE_URL.replace(/\/$/, '')}/a/${id}?exp=${exp}&sig=${sig}` };
}

/**
 * Verifies a link. currentHash(kind, itemId) must return the item's hash right now
 * (null if it no longer exists). Returns { ok, reason, approval }.
 */
export function verifyApproval(db, config, { id, exp, sig }, currentHash, now = Date.now()) {
  const a = db.prepare('SELECT * FROM approvals WHERE id = ?').get(String(id || ''));
  if (!a) return { ok: false, reason: 'This link is not recognised.' };
  const expected = sign(config.APPROVAL_SECRET, `${a.id}.${a.kind}.${a.item_id}.${a.content_hash}.${exp}`);
  if (!safeEq(expected, sig || '')) return { ok: false, reason: 'Invalid signature.' };
  if (Number(exp) !== new Date(a.expires_at).getTime()) return { ok: false, reason: 'Invalid link.' };
  if (now > Number(exp)) return { ok: false, reason: `This link expired (${config.APPROVAL_TTL_HOURS}h). Nothing was changed.` };
  if (a.decision) return { ok: false, reason: `Already confirmed on ${a.decided_at}.` };
  const cur = currentHash(a.kind, a.item_id);
  if (!cur || cur !== a.content_hash) return { ok: false, reason: 'The item changed after this link was created. Open the dashboard for the current version.' };
  return { ok: true, approval: a };
}

export function recordApproval(db, approval, decision = 'confirm') {
  const r = db.prepare('UPDATE approvals SET decision = ?, decided_at = ? WHERE id = ? AND decision IS NULL').run(decision, nowIso(), approval.id);
  return r.changes === 1; // false = someone else already used it (double click / race)
}

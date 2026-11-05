// POST /ingest: signed reports from the host sentinels.
// Signature = hex HMAC-SHA256(per-host secret, `${timestamp}.${nonce}.${sha256(body)}`).
// Rejected: unknown host, missing/garbled headers, timestamp outside ±5 min, reused nonce (replay),
// bad signature, body host ≠ header host, more than 30 reports/hour from one host.
import crypto from 'node:crypto';
import { nowIso } from '../db.js';
import { secret as secretOf } from '../config.js';

export const MAX_SKEW_SEC = 300;
export const MAX_REPORTS_PER_HOUR = 30;

const hex = (s, len) => typeof s === 'string' && new RegExp(`^[a-f0-9]{${len}}$`).test(s);

export function signReport(secretValue, body, { ts = Math.floor(Date.now() / 1000), nonce = crypto.randomBytes(16).toString('hex') } = {}) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const sig = crypto.createHmac('sha256', secretValue).update(`${ts}.${nonce}.${bodyHash}`).digest('hex');
  return { 'x-galla-timestamp': String(ts), 'x-galla-nonce': nonce, 'x-galla-signature': sig };
}

/**
 * Verifies and stores a report. Returns { ok, status, reason, host, reportId }.
 * Only after the signature is valid is the nonce recorded (so junk can't fill the nonce table).
 */
export function verifyAndStore({ config, db, registry, headers, rawBody, now = Date.now() }) {
  const h = Object.fromEntries(Object.entries(headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
  const hostId = String(h['x-galla-host'] || '');
  const host = registry.hosts.find((x) => x.id === hostId);
  if (!host) return { ok: false, status: 401, reason: 'unknown host' };
  const key = secretOf(config, host.secretEnv);
  if (!key || key.length < 32) return { ok: false, status: 503, reason: `no secret configured (${host.secretEnv})` };
  const ts = Number(h['x-galla-timestamp']);
  const nonce = h['x-galla-nonce'];
  const sig = h['x-galla-signature'];
  if (!Number.isInteger(ts) || !hex(nonce, 32) || !hex(sig, 64)) return { ok: false, status: 400, reason: 'missing or malformed signature headers' };
  if (Math.abs(now / 1000 - ts) > MAX_SKEW_SEC) return { ok: false, status: 401, reason: 'timestamp outside the allowed window' };
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(String(rawBody ?? ''));
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const expected = crypto.createHmac('sha256', key).update(`${ts}.${nonce}.${bodyHash}`).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return { ok: false, status: 401, reason: 'bad signature' };

  db.prepare('DELETE FROM sentinel_nonces WHERE ts < ?').run(Math.floor(now / 1000) - 86400);
  try {
    db.prepare('INSERT INTO sentinel_nonces(nonce, host, ts) VALUES (?,?,?)').run(nonce, hostId, ts);
  } catch {
    return { ok: false, status: 409, reason: 'replayed nonce' };
  }
  const hourAgo = new Date(now - 3600_000).toISOString();
  if (db.prepare('SELECT COUNT(*) n FROM sentinel_reports WHERE host = ? AND received_at >= ?').get(hostId, hourAgo).n >= MAX_REPORTS_PER_HOUR)
    return { ok: false, status: 429, reason: 'too many reports this hour' };

  let report;
  try { report = JSON.parse(body.toString('utf8')); } catch { return { ok: false, status: 400, reason: 'body is not JSON' }; }
  if (report?.host !== hostId || !Array.isArray(report.installs)) return { ok: false, status: 400, reason: 'report host/shape mismatch' };

  const id = db.prepare('INSERT INTO sentinel_reports(host, received_at, generated_at, report, sha256) VALUES (?,?,?,?,?)')
    .run(hostId, new Date(now).toISOString(), String(report.generated_at || ''), body.toString('utf8'), bodyHash).lastInsertRowid;
  // keep the last 7 days of reports
  db.prepare('DELETE FROM sentinel_reports WHERE host = ? AND received_at < ? AND id <> ?').run(hostId, new Date(now - 7 * 86400_000).toISOString(), id);
  return { ok: true, status: 200, host: hostId, reportId: Number(id), report };
}

export const latestReport = (db, hostId) => {
  const r = db.prepare('SELECT * FROM sentinel_reports WHERE host = ? ORDER BY id DESC LIMIT 1').get(hostId);
  return r ? { ...r, data: JSON.parse(r.report) } : null;
};

export const lastCheckIn = (db, hostId) => db.prepare('SELECT received_at FROM sentinel_reports WHERE host = ? ORDER BY id DESC LIMIT 1').get(hostId)?.received_at || null;

export { nowIso };

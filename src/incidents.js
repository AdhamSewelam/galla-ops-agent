// Incidents: one row per open problem, deduped by key. Alerts are batched per brand so a host
// outage or a burst of findings becomes ONE message, not thirty.
//   critical uptime / vps / sentinel / orders  → JARVIS (Telegram) → [URGENT] email on ack/timeout
//   security                                     → JARVIS → [SECURITY] email on ack/timeout
//   keeper (expiry, SMTP, updates)               → [URGENT] email only
//   medium                                       → no alert; appears in the daily report
// Reminders: every 6h while an uptime/vps/sentinel incident stays open; security until acknowledged.
import { nowIso } from './db.js';
import { audit } from './audit.js';
import { esc } from './email.js';
import { redactText } from './redact.js';

export const REMIND_EVERY_HOURS = 6;
const JARVIS_CATEGORIES = new Set(['uptime', 'vps', 'sentinel', 'security', 'orders']);
const REMIND_CATEGORIES = new Set(['uptime', 'vps', 'sentinel', 'security']);

const parse = (s) => { try { return s ? JSON.parse(s) : {}; } catch { return {}; } };
export const incidentDetail = (inc) => parse(inc?.detail);

export function createIncidents({ config, db, mailer, voice = null, registry = null }) {
  const brandShort = (id) => registry?.brands.find((b) => b.id === id)?.short || null;
  const get = (key) => db.prepare("SELECT * FROM incidents WHERE key = ? AND status = 'open'").get(key);

  function open({ key, brand = null, category, severity = 'critical', title, error = null, detail = null, parentKey = null }) {
    const now = nowIso();
    const existing = get(key);
    const det = detail ? JSON.stringify(detail) : null;
    if (existing) {
      db.prepare('UPDATE incidents SET last_seen = ?, last_error = ?, title = ?, detail = COALESCE(?, detail), parent_key = COALESCE(?, parent_key) WHERE id = ?')
        .run(now, redactText(error), redactText(title), det && redactText(det), parentKey, existing.id);
      return { incident: db.prepare('SELECT * FROM incidents WHERE id = ?').get(existing.id), isNew: false };
    }
    const info = db.prepare('INSERT INTO incidents(key, brand, category, severity, title, first_seen, last_seen, last_error, detail, parent_key) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(key, brand, category, severity, redactText(title), now, now, redactText(error), det && redactText(det), parentKey);
    audit(db, { actor: actorFor(category), action: 'incident_opened', target: key, detail: { title, severity }, outcome: 'alert' });
    return { incident: db.prepare('SELECT * FROM incidents WHERE id = ?').get(info.lastInsertRowid), isNew: true };
  }

  /** Resolve an open incident (and anything grouped under it). Sends [RESOLVED] unless silent or never alerted. */
  async function resolve(key, { silent = false, note = '' } = {}) {
    const inc = get(key);
    if (!inc) return null;
    const now = nowIso();
    db.prepare("UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE id = ?").run(now, inc.id);
    db.prepare("UPDATE incidents SET status = 'resolved', resolved_at = ? WHERE parent_key = ? AND status = 'open'").run(now, key);
    audit(db, { actor: actorFor(inc.category), action: 'incident_resolved', target: key });
    if (!silent && inc.notified_at && !inc.parent_key) {
      await mailer.send({
        brand: brandShort(inc.brand), prefix: 'RESOLVED', subject: inc.title,
        html: `<p>Recovered / no longer detected. Started ${esc(inc.first_seen)}, resolved ${esc(now)} (UTC).</p>${note ? `<p>${esc(note)}</p>` : ''}`,
        text: `Resolved: ${inc.title}`,
      });
    }
    return inc;
  }

  function renderEmail(lead, siblings, callNote) {
    const block = (inc) => {
      const d = incidentDetail(inc);
      const list = (arr) => (arr?.length ? `<pre style="background:#f5f3ef;padding:10px;border-radius:6px;white-space:pre-wrap;font:12.5px/1.5 monospace">${esc(arr.join('\n'))}</pre>` : '');
      return `<div style="border-left:3px solid ${inc.category === 'security' ? '#7a1f1f' : '#b42318'};padding:4px 12px;margin:14px 0">
        <p style="font-weight:600;margin:0 0 6px">${esc(inc.title)}</p>
        <table style="font-size:13.5px">
          ${d.where ? `<tr><td><b>Where</b></td><td>${esc(d.where)}</td></tr>` : ''}
          <tr><td><b>Since</b></td><td>${esc(inc.first_seen)} (UTC)</td></tr>
          ${inc.last_error ? `<tr><td><b>Found</b></td><td><code>${esc(String(inc.last_error).slice(0, 600))}</code></td></tr>` : ''}
          ${d.impact ? `<tr><td><b>Impact</b></td><td>${esc(d.impact)}</td></tr>` : ''}
          <tr><td><b>Done so far</b></td><td>Nothing. Galla Ops is read-only and never fixes anything itself.</td></tr>
          ${d.todo ? `<tr><td><b>What to do</b></td><td>${esc(d.todo)}</td></tr>` : ''}
        </table>
        ${d.evidence?.length ? `<p style="margin:8px 0 2px"><b>Evidence</b></p>${list(d.evidence)}` : ''}
        ${d.verify?.length ? `<p style="margin:8px 0 2px"><b>Verify (run yourself)</b></p>${list(d.verify)}` : ''}
        ${d.remediate?.length ? `<p style="margin:8px 0 2px"><b>Remediate (run yourself, after verifying)</b></p>${list(d.remediate)}` : ''}
      </div>`;
    };
    return `${callNote ? `<p style="background:#f5f3ef;padding:8px 10px;border-radius:6px">📟 ${esc(callNote)}</p>` : ''}
      ${block(lead)}${siblings.map(block).join('')}
      <p style="font-size:12px;color:#6b6457">Dashboard: <a href="${esc(config.PUBLIC_BASE_URL)}/dashboard">${esc(config.PUBLIC_BASE_URL)}/dashboard</a></p>`;
  }

  async function emailFor(lead, callNote = null) {
    const d = incidentDetail(lead);
    const siblings = (d.groupIds || []).map((id) => db.prepare('SELECT * FROM incidents WHERE id = ?').get(id)).filter(Boolean);
    const prefix = lead.category === 'security' ? 'SECURITY' : lead.status === 'test' ? 'INFO' : 'URGENT';
    const subject = siblings.length ? `${siblings.length + 1} problems: ${lead.title}` : lead.title;
    const res = await mailer.send({ brand: brandShort(lead.brand), prefix, subject, html: renderEmail(lead, siblings, callNote), text: [lead, ...siblings].map((i) => `${i.title}\n${i.last_error || ''}`).join('\n\n') });
    const ids = [lead.id, ...siblings.map((s) => s.id)];
    if (res.sent || !config.features.email) db.prepare(`UPDATE incidents SET notified_at = COALESCE(notified_at, ?) WHERE id IN (${ids.map(() => '?').join(',')})`).run(nowIso(), ...ids);
    return res;
  }
  if (voice) voice.setEmailSender((incident, note) => emailFor(incident, note));

  /**
   * Alert a batch of NEW incidents. One message per brand; the most severe incident leads and the rest
   * ride along. Incidents with a parent_key are covered by their parent's alert and are not sent again.
   */
  async function notify(list) {
    const fresh = list.filter((i) => i && !i.parent_key && i.severity !== 'medium');
    const byBrand = new Map();
    for (const i of fresh) byBrand.set(i.brand || '_', [...(byBrand.get(i.brand || '_') || []), i]);
    const sent = [];
    const rank = { critical: 0, high: 1, medium: 2 };
    for (const group of byBrand.values()) {
      // security and non-security go out separately (different subject prefix)
      for (const part of [group.filter((g) => g.category === 'security'), group.filter((g) => g.category !== 'security')]) {
        if (!part.length) continue;
        part.sort((a, b) => (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3));
        const [lead, ...rest] = part;
        const det = { ...incidentDetail(lead), groupIds: rest.map((r) => r.id) };
        db.prepare('UPDATE incidents SET detail = ?, notified_at = ? WHERE id = ?').run(JSON.stringify(det), nowIso(), lead.id); // stops duplicate reminders while JARVIS waits
        const leadRow = db.prepare('SELECT * FROM incidents WHERE id = ?').get(lead.id);
        const wantsJarvis = part.some((p) => JARVIS_CATEGORIES.has(p.category) && p.severity === 'critical');
        if (wantsJarvis && voice) {
          const todo = rest.length ? `${rest.length} more problem(s) on the same brand are in the email.` : det.todo || 'Details are in your email.';
          await voice.alertIncident(leadRow, { todo });
        } else {
          await emailFor(leadRow);
        }
        sent.push(lead.key);
      }
    }
    return sent;
  }

  /** Reminder emails for incidents that stay open (no JARVIS). Acknowledged security findings stop reminding. */
  async function remind(now = Date.now()) {
    const due = db.prepare("SELECT * FROM incidents WHERE status = 'open' AND parent_key IS NULL AND notified_at IS NOT NULL").all()
      .filter((i) => REMIND_CATEGORIES.has(i.category))
      .filter((i) => !(i.category === 'security' && i.acknowledged_at))
      .filter((i) => now - new Date(i.notified_at).getTime() >= REMIND_EVERY_HOURS * 3600_000);
    for (const inc of due) {
      db.prepare('UPDATE incidents SET notified_at = ? WHERE id = ?').run(new Date(now).toISOString(), inc.id);
      await emailFor({ ...inc, title: `STILL OPEN: ${inc.title}` });
    }
    return due.length;
  }

  function acknowledge(id, actor = 'owner') {
    const r = db.prepare("UPDATE incidents SET acknowledged_at = ? WHERE id = ? AND status = 'open' AND acknowledged_at IS NULL").run(nowIso(), id);
    if (r.changes) audit(db, { actor, action: 'incident_acknowledged', target: `incident:${id}` });
    return r.changes === 1;
  }

  return { open, resolve, notify, remind, acknowledge, get, emailFor };
}

export function actorFor(category) {
  return { uptime: 'sentinel', vps: 'sentinel', security: 'warden', sentinel: 'warden', orders: 'ledger', keeper: 'keeper', products: 'curator', test: 'jarvis' }[category] || 'agent';
}

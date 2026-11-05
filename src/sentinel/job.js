// Warden · host sentinel evaluation.
//  - evaluate(hostId): runs on every accepted report (ingest) and hourly from the scheduler.
//  - missing check: no report for SENTINEL_MISSING_HOURS → urgent (the sentinel itself may be disabled).
//  - baselines: Adham accepts the latest snapshot from the dashboard (signed confirm page).
import { latestReport, lastCheckIn } from './ingest.js';
import { analyzeReport, snapshotOf } from './analyze.js';
import { sha256 } from '../approvals.js';
import { nowIso } from '../db.js';
import { audit } from '../audit.js';
import fs from 'node:fs';
import crypto from 'node:crypto';

let SENTINEL_SHA = null;
try { SENTINEL_SHA = crypto.createHash('sha256').update(fs.readFileSync(new URL('../../sentinel/galla-sentinel.php', import.meta.url))).digest('hex'); } catch { /* not shipped */ }

export function activeSentinelBaseline(db, hostId) {
  const row = db.prepare("SELECT * FROM baselines WHERE scope = ? AND status = 'active' ORDER BY id DESC LIMIT 1").get(`sentinel:${hostId}`);
  return row ? { ...row, data: JSON.parse(row.snapshot) } : null;
}

/** The snapshot that "Accept as baseline" would store right now (from the latest report). */
export function candidateSentinelBaseline(db, hostId) {
  const rep = latestReport(db, hostId);
  if (!rep) return null;
  const snap = snapshotOf(rep.data);
  const json = JSON.stringify(snap);
  return { snapshot: snap, json, sha256: sha256(json), reportId: rep.id, receivedAt: rep.received_at };
}

export function acceptSentinelBaseline(db, hostId, expectedHash) {
  const cand = candidateSentinelBaseline(db, hostId);
  if (!cand || cand.sha256 !== expectedHash) return null;
  const tx = db.transaction(() => {
    db.prepare("UPDATE baselines SET status = 'superseded' WHERE scope = ? AND status = 'active'").run(`sentinel:${hostId}`);
    db.prepare("INSERT INTO baselines(scope, snapshot, sha256, status, accepted_at) VALUES (?,?,?,'active',?)").run(`sentinel:${hostId}`, cand.json, cand.sha256, nowIso());
  });
  tx();
  return cand;
}

/** Install id → brand id: explicit prefix match ("jbg-multisite" → "jbg"), else the host's first brand. */
export function brandForInstall(registry, host, installId) {
  const ids = registry.brands.map((b) => b.id).sort((a, b) => b.length - a.length);
  return ids.find((id) => installId === id || String(installId).startsWith(id + '-')) || host?.brands?.[0] || null;
}

export function createSentinelJob({ config, db, registry, incidents }) {
  async function evaluate(hostId) {
    const host = registry.hosts.find((h) => h.id === hostId);
    const rep = latestReport(db, hostId);
    if (!host || !rep) return { host: hostId, report: false };
    await incidents.resolve(`sentinel_missing:${hostId}`, { note: 'The host sentinel is reporting again.' });
    const baseline = activeSentinelBaseline(db, hostId);
    const findings = analyzeReport(rep.data, baseline?.data || null, { expectedSentinelSha: SENTINEL_SHA });
    const fresh = [];
    const seen = new Set();
    const reviewItems = [];
    for (const f of findings) {
      if (f.baseline && !baseline) { reviewItems.push(f); continue; } // no baseline yet: list for review, don't alarm
      const key = `sentinel:${hostId}:${f.install || 'host'}:${f.id}`.slice(0, 300);
      seen.add(key);
      const { incident, isNew } = incidents.open({
        key, brand: f.install ? brandForInstall(registry, host, f.install) : host.brands[0] || null, category: 'security', severity: f.severity,
        title: `${f.title}${f.install ? ` [${f.install}]` : ''}`, error: (f.evidence || []).slice(0, 3).join(' | ') || f.where,
        detail: { where: `${host.label} → ${f.where}`, evidence: f.evidence, verify: f.verify, remediate: f.remediate, todo: f.todo || (f.baseline ? 'If this was you, press "Accept as baseline" for this host on the dashboard.' : '') },
      });
      if (isNew) fresh.push(incident);
    }
    // Baseline needed: ONE review notice per host, not one alert per existing admin/plugin
    const reviewKey = `sentinel_baseline_needed:${hostId}`;
    if (!baseline && reviewItems.length) {
      const { incident, isNew } = incidents.open({
        key: reviewKey, brand: host.brands.length === 1 ? host.brands[0] : null, category: 'security', severity: 'high',
        title: `Host sentinel connected for ${host.label}: review ${reviewItems.length} item(s) and accept the baseline`,
        error: null,
        detail: { where: host.label, evidence: reviewItems.slice(0, 60).map((r) => `${r.install}: ${r.title}`), todo: 'Open the dashboard → Security → this host. If every admin, app password, mu-plugin, drop-in and cron hook listed is yours, press "Accept as baseline". From then on only NEW or CHANGED items alert.' },
      });
      seen.add(reviewKey);
      if (isNew) fresh.push(incident);
    }
    // anything we alerted on before that is no longer in the report → resolved
    for (const inc of db.prepare("SELECT key FROM incidents WHERE status = 'open' AND (key LIKE ? OR key = ?)").all(`sentinel:${hostId}:%`, reviewKey)) {
      if (!seen.has(inc.key)) await incidents.resolve(inc.key, { note: 'No longer present in the latest host report (or accepted into the baseline).' });
    }
    await incidents.notify(fresh);
    audit(db, { actor: 'warden', action: 'sentinel_evaluated', target: hostId, detail: { findings: seen.size, new: fresh.length, review: reviewItems.length, baseline: Boolean(baseline) } });
    return { host: hostId, findings: seen.size, new: fresh.length, awaitingBaseline: baseline ? 0 : reviewItems.length };
  }

  /** Hourly: re-evaluate every host and alert on missing reports. */
  async function run(now = Date.now()) {
    const out = [];
    const fresh = [];
    for (const h of registry.hosts) {
      const last = lastCheckIn(db, h.id);
      const ageH = last ? (now - new Date(last).getTime()) / 3600_000 : Infinity;
      if (ageH >= config.SENTINEL_MISSING_HOURS) {
        const { incident, isNew } = incidents.open({
          key: `sentinel_missing:${h.id}`, brand: h.brands.length === 1 ? h.brands[0] : null, category: 'sentinel', severity: 'critical',
          title: last ? `No host sentinel report from ${h.label} for ${Math.floor(ageH)}h` : `Host sentinel on ${h.label} has never reported`,
          error: last ? `last report ${last}` : 'never',
          detail: {
            where: h.label,
            impact: 'Server-side integrity is NOT being watched on this host. The sentinel may have been disabled (attackers remove monitoring first).',
            todo: h.kind === 'shared' ? 'hPanel → Advanced → Cron Jobs: check the galla-sentinel job exists. Then run it by hand over SSH and read ~/galla-sentinel/state/sentinel.log.' : 'Check `crontab -l` as root and /opt/galla-sentinel/state/sentinel.log.',
            verify: [h.kind === 'shared' ? 'bash ~/galla-sentinel/galla-sentinel.sh && tail -20 ~/galla-sentinel/state/sentinel.log' : 'sudo bash /opt/galla-sentinel/galla-sentinel.sh && tail -20 /opt/galla-sentinel/state/sentinel.log'],
          },
        });
        if (isNew && last) fresh.push(incident); // never-reported hosts stay on the dashboard; they're not an emergency until set up
        out.push({ host: h.id, missing: true, last });
        continue;
      }
      out.push(await evaluate(h.id));
    }
    await incidents.notify(fresh);
    return out;
  }

  return { evaluate, run };
}

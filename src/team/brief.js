// What each agent "knows" when it talks to Adham: built ONLY from its real records
// (job runs, incidents it owns, check results, its playbook). Nothing else.
import { AGENTS } from '../schedule.js';
import { lessonRulesText } from './store.js';
import { kvJson } from '../db.js';

const DAY = 86400_000;
const since = (days) => new Date(Date.now() - days * DAY).toISOString();

export const TEAM = AGENTS;
export const agentById = (id) => TEAM.find((a) => a.id === id) || null;
const CATEGORY = { sentinel: ['uptime', 'vps'], warden: ['security', 'sentinel'], ledger: ['orders'], keeper: ['keeper'] };

export function jobStats(db, jobs, days = 30) {
  const out = {};
  for (const j of jobs) {
    const rows = db.prepare('SELECT outcome, COUNT(*) n FROM audit_log WHERE action = ? AND ts >= ? GROUP BY outcome').all(`job_${j}`, since(days));
    const lastError = db.prepare("SELECT ts, detail FROM audit_log WHERE action = ? AND outcome = 'error' ORDER BY id DESC LIMIT 1").get(`job_${j}`);
    const last = db.prepare('SELECT ts, outcome, detail FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1').get(`job_${j}`);
    out[j] = { runs: rows.reduce((n, r) => n + r.n, 0), errors: rows.filter((r) => r.outcome === 'error').reduce((n, r) => n + r.n, 0), lastRun: last ? { ts: last.ts, outcome: last.outcome, result: String(last.detail || '').slice(0, 400) } : null, lastError: lastError ? { ts: lastError.ts, detail: String(lastError.detail || '').slice(0, 200) } : null };
  }
  return out;
}

function roleFacts(db, registry, id) {
  const d30 = since(30);
  const incidentsOf = (cats) => db.prepare(`SELECT brand, title, severity, status, first_seen, resolved_at, acknowledged_at FROM incidents WHERE category IN (${cats.map(() => '?').join(',')}) AND (status = 'open' OR first_seen >= ?) ORDER BY id DESC LIMIT 15`).all(...cats, d30);
  const brands = registry?.brands || [];
  switch (id) {
    case 'sentinel': return { incidents: incidentsOf(CATEGORY.sentinel), failingChecksNow: db.prepare('SELECT label, last_error, last_kind FROM check_state WHERE consecutive_failures > 0').all(), vps: kvJson(db, 'vps_last') };
    case 'warden': return { incidents: incidentsOf(CATEGORY.warden), integrityLastRun: kvJson(db, 'integrity_last'), hosts: (registry?.hosts || []).map((h) => ({ host: h.id, lastReport: db.prepare('SELECT received_at FROM sentinel_reports WHERE host = ? ORDER BY id DESC LIMIT 1').get(h.id)?.received_at || 'never', baselineAccepted: db.prepare("SELECT accepted_at FROM baselines WHERE scope = ? AND status = 'active'").get(`sentinel:${h.id}`)?.accepted_at || 'no' })) };
    case 'ledger': return { incidents: incidentsOf(CATEGORY.ledger), summaries: Object.fromEntries(brands.flatMap((b) => b.sites.map((s) => [`${b.short} ${s.path}`, kvJson(db, `orders_summary:${b.id}:${s.id}`) || 'not run yet']))) };
    case 'keeper': return { incidents: incidentsOf(CATEGORY.keeper), lastResults: Object.fromEntries(brands.map((b) => { const k = kvJson(db, `keeper_last:${b.id}`); return [b.short, k ? { ssl: k.ssl, domain: k.domain, smtp: k.smtp, mailDns: k.mailDns, updates: (k.updates?.installs || []).map((i) => ({ install: i.install, core: i.core, pluginUpdates: i.plugins.length, security: i.security.map((s) => s.what) })) } : 'not run yet']; })) };
    case 'curator': return { issueCounts: db.prepare('SELECT brand, kind, COUNT(*) n FROM product_issues GROUP BY brand, kind').all(), lastRuns: Object.fromEntries(brands.map((b) => [b.short, kvJson(db, `curator_last:${b.id}`) || 'not run yet'])) };
    case 'scout': return { lastReviews: db.prepare('SELECT brand, created_at, summary, fixes FROM seo_reviews ORDER BY id DESC LIMIT 3').all().map((r) => ({ ...r, fixes: String(r.fixes).slice(0, 1200) })) };
    case 'jarvis': return { recentAlerts: db.prepare("SELECT action, target, outcome, ts FROM audit_log WHERE action LIKE 'jarvis_%' AND ts >= ? ORDER BY id DESC LIMIT 15").all(d30), openCritical: db.prepare("SELECT brand, title, first_seen FROM incidents WHERE status = 'open' AND severity = 'critical'").all() };
    case 'harmony': return { openHrIssues: db.prepare("SELECT kind, agents, title, detail, first_seen FROM hr_issues WHERE status = 'open'").all(), recentReviews: db.prepare('SELECT agent, score, summary, created_at FROM reviews ORDER BY id DESC LIMIT 8').all(), lessonsWaitingForAdham: db.prepare("SELECT agent, text FROM lessons WHERE status = 'proposed' ORDER BY id DESC LIMIT 10").all() };
    default: return {};
  }
}

export function activityOf(db, agent, jobState) {
  if (agent.jobs.some((j) => jobState?.running?.has(j))) return { activity: 'working', activityText: 'running a job now' };
  const open = (CATEGORY[agent.id] || []).length ? db.prepare(`SELECT COUNT(*) n FROM incidents WHERE status = 'open' AND category IN (${CATEGORY[agent.id].map(() => '?').join(',')}) AND severity <> 'medium'`).get(...CATEGORY[agent.id]).n : 0;
  if (open) return { activity: 'incident', activityText: `${open} open issue(s)` };
  const failed = agent.jobs.some((j) => db.prepare('SELECT outcome FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1').get(`job_${j}`)?.outcome === 'error');
  if (failed) return { activity: 'error', activityText: 'last run failed' };
  return { activity: 'scheduled', activityText: 'all good' };
}

export function agentBrief({ config, db, registry = null, jobState = null, agentId }) {
  const agent = agentById(agentId);
  if (!agent) return null;
  const latestReview = db.prepare('SELECT score, summary, gaps, created_at FROM reviews WHERE agent = ? ORDER BY id DESC LIMIT 1').get(agentId);
  return {
    name: agent.name, role: agent.role, scheduledJobs: agent.jobs, statusNow: activityOf(db, agent, jobState).activityText,
    jobStatsLast30d: jobStats(db, agent.jobs), facts: roleFacts(db, registry, agentId),
    latestReview: latestReview || 'not reviewed yet', playbook: lessonRulesText(db, agentId),
  };
}

export function teamBriefs({ config, db, registry = null, jobState = null }) {
  return Object.fromEntries(TEAM.map((a) => [a.id, agentBrief({ config, db, registry, jobState, agentId: a.id })]));
}

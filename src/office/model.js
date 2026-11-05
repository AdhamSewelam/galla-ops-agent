// Live office state for the Office Simulator, built ONLY from Galla Ops' real records.
// People are the owner and the real automations (each runs real scheduled jobs). Nothing is invented:
// human activity is "not tracked", departments without a data source say "Not connected".
import { SCHEDULE, AGENTS as TEAM } from '../schedule.js';
import { activityOf } from '../team/brief.js';
import { kvJson } from '../db.js';
import { pageBaselineState } from '../baselines.js';

export const DEPARTMENTS = [
  { id: 'executive', name: 'Executive Office', head: 'owner' },
  { id: 'meeting', name: 'Meeting Room', head: 'owner' },
  { id: 'finance', name: 'Finance', head: null },
  { id: 'marketing', name: 'Marketing', head: null },
  { id: 'technology', name: 'Security & Tech', head: null },
  { id: 'sales', name: 'Sales & Showroom', head: null },
  { id: 'operations', name: 'Operations', head: null },
  { id: 'cx', name: 'Customer Experience', head: null },
  { id: 'lounge', name: 'Lounge', head: null },
];

// Where each agent sits, and which audit actions belong to it.
const DESK = {
  jarvis: { dept: 'executive', seat: 'jarvis', actions: [/^jarvis_/, /^job_daily$/] },
  sentinel: { dept: 'operations', seat: 'ops1', actions: [/^job_uptime$/, /^job_vps$/, /^heartbeat/] },
  harmony: { dept: 'operations', seat: 'ops2', actions: [/^hr_/, /^review_/, /^lesson_/, /^meeting_/, /^job_hr$/, /^job_training$/] },
  curator: { dept: 'operations', seat: 'inventory', actions: [/^job_products$/] },
  warden: { dept: 'technology', seat: 'tech1', actions: [/^sentinel_/, /^job_integrity$/, /^job_sentinel$/, /^accept_/, /^baseline_/, /^ingest_/] },
  keeper: { dept: 'technology', seat: 'tech2', actions: [/^job_keeper$/] },
  ledger: { dept: 'finance', seat: 'fin1', actions: [/^job_orders$/] },
  scout: { dept: 'marketing', seat: 'seo', actions: [/^seo_/, /^job_seo$/] },
};
const CATS = { sentinel: ['uptime', 'vps'], warden: ['security', 'sentinel'], ledger: ['orders'], keeper: ['keeper'] };

export const AGENTS = TEAM.map((a) => ({ ...a, ...DESK[a.id] }));

const lastJob = (db, job) => db.prepare('SELECT ts, outcome FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1').get(`job_${job}`);
const whenOf = (jobs) => jobs.map((j) => SCHEDULE.find((s) => s.job === j)?.when).filter(Boolean).join(', ');

export function officeState({ config, db, registry, jobState = null }) {
  const running = jobState?.running ? [...jobState.running] : [];
  const openInc = db.prepare("SELECT id, key, brand, category, severity, title, first_seen, acknowledged_at FROM incidents WHERE status = 'open' AND parent_key IS NULL ORDER BY first_seen").all();
  const recent = db.prepare("SELECT ts, actor, action, target, outcome FROM audit_log WHERE action NOT IN ('job_uptime','job_integrity','job_vps','email_skipped_not_configured') ORDER BY id DESC LIMIT 400").all();
  const brands = registry?.brands || [];
  const short = (id) => brands.find((b) => b.id === id)?.short || '';

  // What waits on Adham, from records only
  const ownerTasks = [];
  for (const i of openInc.filter((x) => x.category === 'security' && !x.acknowledged_at && x.severity !== 'medium'))
    ownerTasks.push({ title: `${short(i.brand)} ${i.title}`.trim(), status: 'Security finding: verify & remediate', due: null, ref: `incident:${i.id}` });
  const pageBaselines = brands.map((b) => ({ b, st: pageBaselineState(db, b.id) })).filter((x) => x.st.pages && x.st.differs);
  for (const { b, st } of pageBaselines) ownerTasks.push({ title: `Accept page baseline for ${b.short} (${st.differs} page(s))`, status: 'Awaiting approval', due: null, ref: 'dashboard:security' });
  const proposals = db.prepare("SELECT COUNT(*) n FROM lessons WHERE status = 'proposed'").get().n;
  if (proposals) ownerTasks.push({ title: `${proposals} training lesson(s) to decide`, status: 'Awaiting approval', due: null, ref: 'team:hr' });

  const people = [{
    id: 'owner', name: config.OWNER_NAME || 'Owner', role: 'CEO / Owner', dept: 'executive', seat: 'ceo', type: 'human', manager: null,
    activity: ownerTasks.length ? 'approval' : 'unknown',
    activityText: ownerTasks.length ? `${ownerTasks.length} item(s) waiting for you` : 'Current activity not tracked',
    alerts: openInc.filter((i) => i.severity === 'critical').length, tasks: ownerTasks,
    recent: recent.filter((a) => a.actor === 'owner').slice(0, 8),
  }];

  for (const a of AGENTS) {
    const base = activityOf(db, a, jobState);
    const jobs = a.jobs.filter((j) => j !== 'vps' || config.VPS_MONITOR);
    const last = jobs.map((j) => ({ job: j, ...lastJob(db, j) })).filter((r) => r.ts).sort((x, y) => (x.ts < y.ts ? 1 : -1))[0];
    const mine = openInc.filter((i) => (CATS[a.id] || []).includes(i.category));
    let activity = base.activity === 'scheduled' ? 'scheduled' : base.activity;
    let activityText = base.activity === 'scheduled' ? `Waiting for next run (${whenOf(jobs) || 'on demand'})` : base.activityText;
    const tasks = mine.map((i) => ({ title: `${short(i.brand)} ${i.title}`.trim(), status: i.acknowledged_at ? 'Acknowledged, still present' : i.severity === 'medium' ? 'For review' : 'Open', due: null, ref: `incident:${i.id}` }));
    let handoff = null;

    if (a.id === 'jarvis') {
      let unacked = 0;
      try { unacked = db.prepare("SELECT COUNT(*) n FROM voice_calls WHERE status = 'calling' AND email_sent = 0").get().n; } catch { /* voice not initialised */ }
      if (!config.features.voice) { activity = 'offline'; activityText = 'Not set up (Telegram bot token + chat id)'; }
      else if (!running.includes('daily')) { activityText = `On standby for alerts · daily report 09:00${unacked ? ` · ${unacked} alert(s) waiting for "I'm on it"` : ''}`; }
    }
    if (a.id === 'warden' && pageBaselines.length) {
      handoff = { to: 'owner', text: `Handed ${pageBaselines.length} page baseline(s) to ${config.OWNER_NAME} for approval`, at: null };
      if (activity === 'scheduled') { activity = 'handoff'; activityText = handoff.text; }
    }
    if (a.id === 'ledger') {
      const sums = brands.flatMap((b) => b.sites.map((s) => kvJson(db, `orders_summary:${b.id}:${s.id}`))).filter(Boolean);
      const connected = sums.filter((s) => s.connected && !s.error);
      if (!connected.length) { activity = activity === 'scheduled' ? 'offline' : activity; activityText = 'Not connected (no read-only WooCommerce keys)'; }
      else if (activity === 'scheduled') activityText = `${connected.reduce((n, s) => n + (s.last24h?.orders || 0), 0)} orders in 24h across ${connected.length} shop(s) · next run ${whenOf(jobs)}`;
    }
    if (a.id === 'curator') {
      const n = db.prepare('SELECT COUNT(*) n FROM product_issues').get().n;
      if (n) { tasks.push({ title: `${n} product data issue(s) to fix`, status: 'Report only (you fix)', due: null, ref: 'dashboard:products' }); if (activity === 'scheduled') { activity = 'handoff'; activityText = `Handed ${n} product issue(s) to ${config.OWNER_NAME}`; } }
    }
    if (a.id === 'scout' && !config.features.searchConsole && activity === 'scheduled') activityText = `Weekly SEO Mon 09:30 (Search Console not connected)`;
    if (a.id === 'harmony') {
      for (const i of db.prepare("SELECT id, title FROM hr_issues WHERE status = 'open' ORDER BY first_seen").all()) tasks.push({ title: i.title, status: 'Open team issue', due: null, ref: `hr:${i.id}` });
      if (proposals) tasks.push({ title: `${proposals} lesson(s) waiting for your decision`, status: 'Awaiting approval', due: null, ref: 'team:hr' });
    }
    if (running.some((j) => a.jobs.includes(j))) { activity = 'working'; activityText = `Running "${a.jobs.find((j) => running.includes(j))}" now`; }

    people.push({
      id: a.id, name: a.name, role: a.role, dept: a.dept, seat: a.seat, type: 'agent', manager: 'owner',
      jobs, activity, activityText, alerts: mine.filter((i) => i.severity !== 'medium').length, tasks, handoff,
      lastRun: last ? { job: last.job, ts: last.ts, outcome: last.outcome } : null,
      recent: recent.filter((r) => r.actor === a.id || a.actions.some((re) => re.test(r.action))).slice(0, 8),
    });
  }

  const orders24 = brands.flatMap((b) => b.sites.map((s) => kvJson(db, `orders_summary:${b.id}:${s.id}`))).filter((s) => s?.connected && !s.error);
  const departments = DEPARTMENTS.map((d) => {
    const mem = people.filter((p) => p.dept === d.id);
    const allTasks = mem.flatMap((p) => p.tasks);
    return {
      ...d, members: mem.map((p) => p.id),
      activeTasks: allTasks.length, blockedTasks: 0,
      incidents: mem.reduce((n, p) => n + p.alerts, 0),
      nextDeadline: null,
      kpi: d.id === 'finance' ? (orders24.length ? `${orders24.reduce((n, s) => n + (s.last24h?.paid || 0), 0)} paid orders in 24h` : 'Not connected')
        : d.id === 'sales' ? 'Not connected (showroom sales are not tracked)' : d.id === 'cx' ? 'Not connected' : null,
    };
  });

  return { mode: 'live', generatedAt: new Date().toISOString(), owner: config.OWNER_NAME, incidents: openInc, people, departments };
}

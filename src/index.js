// Galla Ops entry point: wires modules together and runs the schedule (Africa/Cairo).
// `node src/index.js run <job>` runs one job once and exits (for one-off testing).
import cron from 'node-cron';
import { loadConfig } from './config.js';
import { loadBrands, allDomains } from './brands.js';
import { openDb } from './db.js';
import { audit } from './audit.js';
import { createMailer } from './email.js';
import { installEgressGuard } from './http.js';
import { createClaude } from './claude.js';
import { createVoice } from './voice.js';
import { createIncidents } from './incidents.js';
import { createUptime, createProductUrlCache } from './checks/uptime.js';
import { createIntegrity } from './checks/integrity.js';
import { createOrders } from './checks/orders.js';
import { createKeeper } from './checks/keeper.js';
import { createCurator } from './checks/products.js';
import { createVps } from './checks/vps.js';
import { createSentinelJob } from './sentinel/job.js';
import { createDailyReport } from './reports/daily.js';
import { createSeoReview } from './seo/weekly.js';
import { createHr } from './team/hr.js';
import { createServer } from './server.js';
import { SCHEDULE } from './schedule.js';

const config = loadConfig();
const registry = loadBrands(config.BRANDS_FILE);
installEgressGuard(allDomains(registry)); // read-only on every brand domain, enforced for ALL code
const db = openDb(config.DATA_DIR);
const mailer = createMailer(config, db);
const claude = createClaude(config);
const isManualRun = process.argv[2] === 'run';
const voice = createVoice({ config, db });
const incidents = createIncidents({ config, db, mailer, voice, registry });
const productCache = createProductUrlCache(db);
const vps = createVps({ config, db, incidents });
const sentinel = createSentinelJob({ config, db, registry, incidents });

const jobs = {
  uptime: () => createUptime({ config, db, registry, incidents, productCache }).run(),
  integrity: () => createIntegrity({ config, db, registry, incidents, productUrl: (b, s) => productCache.get(b, s) }).run(),
  sentinel: () => sentinel.run(),
  orders: () => createOrders({ config, db, registry, incidents }).run(),
  vps: () => vps.run(),
  keeper: () => createKeeper({ config, db, registry, incidents }).run(),
  products: () => createCurator({ config, db, registry }).run(),
  daily: () => createDailyReport({ config, db, registry, mailer }).run(),
  seo: () => createSeoReview({ config, db, registry, claude, mailer }).run(),
  hr: () => createHr({ config, db, claude, mailer, registry }).runChecks(),
  training: () => createHr({ config, db, claude, mailer, registry }).review(),
};
jobs.sentinel.evaluate = (host) => sentinel.evaluate(host);

const running = new Set();
async function runJob(name) {
  if (running.has(name)) return null;
  running.add(name);
  try {
    const result = await jobs[name]();
    audit(db, { action: `job_${name}`, detail: result == null ? null : { result: JSON.stringify(result).slice(0, 800) } });
    return result;
  } catch (e) {
    audit(db, { action: `job_${name}`, detail: { error: e.message }, outcome: 'error' });
    if (!['uptime', 'integrity', 'vps'].includes(name)) await mailer.send({ prefix: 'INFO', subject: `Galla Ops job "${name}" failed`, html: `<p>${String(e.message).replace(/</g, '&lt;')}</p>`, text: e.message });
    return { error: e.message };
  } finally {
    running.delete(name);
  }
}

if (isManualRun) {
  const name = process.argv[3];
  if (!jobs[name]) { console.error(`Unknown job. Available: ${Object.keys(jobs).join(', ')}`); process.exit(1); }
  if (name === 'vps') vps.startSampler();
  const result = await runJob(name);
  console.log(JSON.stringify(result, null, 2));
  // JARVIS waits for your tap before emailing; in a manual run, give it the full window then exit.
  const pending = db.prepare('SELECT COUNT(*) n FROM voice_calls WHERE email_sent = 0').get().n;
  if (pending && voice.enabled) { console.log(`Waiting ${config.JARVIS_ACK_MINUTES} min for "I'm on it" before the email goes out...`); voice.start(); await new Promise((r) => setTimeout(r, config.JARVIS_ACK_MINUTES * 60_000 + 5000)); await voice.sweep(); }
  process.exit(0);
}

for (const s of SCHEDULE) {
  if (s.only === 'vps' && !config.VPS_MONITOR) continue;
  cron.schedule(s.cron, () => runJob(s.job), { timezone: config.TIMEZONE });
}

createServer({ config, db, registry, jobs, voice, claude, mailer, jobState: { running } }).listen(config.PORT, '127.0.0.1', () => {
  console.log(`Galla Ops listening on 127.0.0.1:${config.PORT}`);
  console.log('Features:', config.features, '| brands:', registry.brands.map((b) => b.id).join(', '));
  audit(db, { action: 'agent_started', detail: { features: config.features, brands: registry.brands.map((b) => b.id) } });
  voice.start();
  voice.sweep();
  vps.startSampler();
  runJob('uptime');
});

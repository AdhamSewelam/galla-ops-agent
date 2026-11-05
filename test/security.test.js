// HMAC ingest + replay rejection, baseline diffing, marker detection, approvals, redaction.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { setup, SECRET_SHARED } from './helpers.js';
import { verifyAndStore, signReport } from '../src/sentinel/ingest.js';
import { analyzeReport, snapshotOf } from '../src/sentinel/analyze.js';
import { createSentinelJob, candidateSentinelBaseline, acceptSentinelBaseline } from '../src/sentinel/job.js';
import { analyzePage, compareToBaseline, normalizeScript } from '../src/checks/integrity.js';
import { createApproval, verifyApproval, recordApproval } from '../src/approvals.js';
import { currentHashFor } from '../src/baselines.js';
import { redact, redactText } from '../src/redact.js';

const HOST = 'hostinger-u137384117';
export function report(over = {}) {
  const install = {
    id: 'jbg', path: '/home/u1/domains/jewelsbygalla.com/public_html', wp_version: '6.9.1', multisite: true, errors: [],
    sites: [{ blog_id: '1', url: 'https://jewelsbygalla.com/' }, { blog_id: '2', url: 'https://jewelsbygalla.com/eg/' }],
    admins: [{ blog_id: '1', id: 1, login: 'Adhamsewelam', email: 'a@x', registered: '2025-01-01 00:00:00' }],
    app_passwords: [], cron_hooks: [{ blog_id: '1', hook: 'wp_version_check' }, { blog_id: '2', hook: 'woocommerce_cleanup_sessions' }],
    suspicious_options: [], active_plugins: { 1: ['woocommerce/woocommerce.php'] }, active_themes: { 2: { stylesheet: 'rey-child', template: 'rey' } },
    mu_plugins: [{ file: 'h1-crawlers-missing.php', size: 900, sha256: 'aa' }], dropins: [{ file: 'object-cache.php', size: 10, sha256: 'oc' }],
    plugins: [{ slug: 'woocommerce', version: '10.1.0' }], elfinder: [],
    themes: [{ stylesheet: 'rey-child', functions_sha256: 'f1' }, { stylesheet: 'rey', functions_sha256: 'r1' }],
    zips: [], uploads_php: [], hidden_php: [], markers: [], root_owned: { count: 0, sample: [] }, wp_content_root: [{ file: 'index.php', sha256: 'ix' }],
    core: { ok: true, modified: [], missing: [], extra: [], error: null },
    ...over.install,
  };
  return { v: 1, host: HOST, generated_at: new Date().toISOString(), hostname: 'h', php_cli_version: '8.2.20', processes: over.processes || [], installs: [install] };
}

const signed = (body, opts) => ({ 'x-galla-host': HOST, ...signReport(SECRET_SHARED, body, opts) });

test('ingest accepts a correctly signed report and rejects replay, bad signature, stale timestamp, unknown host', () => {
  const s = setup();
  const body = JSON.stringify(report());
  const headers = signed(body);
  const ok = verifyAndStore({ ...s, headers, rawBody: Buffer.from(body) });
  assert.equal(ok.ok, true);
  const replay = verifyAndStore({ ...s, headers, rawBody: Buffer.from(body) });
  assert.equal(replay.status, 409, 'same nonce twice is a replay');
  const tampered = verifyAndStore({ ...s, headers: signed(body), rawBody: Buffer.from(body.replace('Adhamsewelam', 'attacker')) });
  assert.equal(tampered.status, 401);
  const old = verifyAndStore({ ...s, headers: signed(body, { ts: Math.floor(Date.now() / 1000) - 600 }), rawBody: Buffer.from(body) });
  assert.equal(old.status, 401);
  assert.match(old.reason, /window/);
  const wrongKey = { 'x-galla-host': HOST, ...signReport('c'.repeat(64), body) };
  assert.equal(verifyAndStore({ ...s, headers: wrongKey, rawBody: Buffer.from(body) }).status, 401);
  assert.equal(verifyAndStore({ ...s, headers: { ...signed(body), 'x-galla-host': 'nope' }, rawBody: Buffer.from(body) }).status, 401);
  const otherHostBody = JSON.stringify({ ...report(), host: 'vps-srv1108252' });
  assert.equal(verifyAndStore({ ...s, headers: signed(otherHostBody), rawBody: Buffer.from(otherHostBody) }).status, 400);
  assert.equal(s.db.prepare('SELECT COUNT(*) n FROM sentinel_reports').get().n, 1);
});

test('always-on rules fire with or without a baseline; baseline rules wait for a baseline', () => {
  const r = report({
    install: { markers: [{ file: 'themes/rey-child/functions.php', marker: 'SC_TH_BEGIN' }], plugins: [{ slug: 'woocommerce', version: '10.1.0' }, { slug: 'wp-file-manager', version: '7.2' }],
      core: { ok: false, modified: [], missing: [], extra: ['wp-includes/.g_72bfa981.php'], error: null }, suspicious_options: [{ blog_id: '2', name: 'wq_cache_x', len: 99000, autoload: 'yes', reason: 'pattern' }] },
    processes: ['12345     1 u1   01:02 lsphp /home/u1/domains/jewelsbygalla.com/public_html/wp-includes/.g_72bfa981.php'],
  });
  const f = analyzeReport(r, null);
  const types = (sev) => f.filter((x) => x.severity === sev).map((x) => x.type);
  for (const t of ['marker', 'banned_plugin', 'core_checksums', 'option', 'process']) assert.ok(types('critical').includes(t), `${t} is critical without a baseline`);
  assert.ok(f.filter((x) => x.baseline).every((x) => x.severity === 'medium'), 'baseline items are review-only until a baseline exists');
  const marker = f.find((x) => x.type === 'marker');
  assert.ok(marker.remediate.some((c) => c.includes("sed -i '/SC_TH_BEGIN/,/SC_TH_END/d'")), 'gives the exact strip command');
  assert.ok(f.find((x) => x.type === 'process').remediate.includes('kill -9 12345'));
});

test('baseline diffing: only NEW or CHANGED items alert after Adham accepts', () => {
  const base = snapshotOf(report());
  assert.equal(analyzeReport(report(), base).length, 0, 'identical state → no findings');
  const changed = report({ install: {
    admins: [{ blog_id: '1', id: 1, login: 'Adhamsewelam', email: 'a@x', registered: '2025' }, { blog_id: '2', id: 16, login: 'administrator_70baedcb2b', email: 'x@jewelsbygalla.com', registered: '2026-08-06' }],
    app_passwords: [{ user_id: 1, login: 'Adhamsewelam', uuid: 'u-1', name: 'wpmon', created: '2026-08-06', last_ip: '130.117.139.57' }],
    themes: [{ stylesheet: 'rey-child', functions_sha256: 'CHANGED' }, { stylesheet: 'rey', functions_sha256: 'r1' }],
    mu_plugins: [{ file: 'h1-crawlers-missing.php', sha256: 'aa' }, { file: 'unity-recorder-evo.php', sha256: 'bb' }],
    dropins: [{ file: 'object-cache.php', sha256: 'oc' }, { file: 'db.php', sha256: 'dd' }],
    cron_hooks: [{ blog_id: '1', hook: 'wp_version_check' }, { blog_id: '1', hook: 'cu29o_ffzkq2ih2' }],
    zips: [{ file: 'uploads/2026/08/ee0166a3.zip' }],
  } });
  const f = analyzeReport(changed, base);
  const got = Object.fromEntries(f.map((x) => [x.type, x]));
  for (const t of ['admin', 'app_password', 'theme_functions', 'mu_plugin', 'dropin', 'cron', 'zip']) assert.ok(got[t], `${t} detected`);
  assert.equal(got.admin.severity, 'critical');
  assert.match(got.admin.title, /administrator_70baedcb2b/);
  assert.equal(got.dropin.severity, 'critical', 'new db.php is critical');
  assert.equal(got.theme_functions.severity, 'critical', 'active child theme');
  assert.equal(got.zip.severity, 'critical', 'random-hex zip name');
  assert.ok(got.app_password.remediate[0].includes('application-password delete'));
  assert.ok(f.every((x) => x.verify.every((c) => !/wp /.test(c) || c.includes('--skip-plugins --skip-themes'))), 'WP-CLI commands never load possibly-infected plugins/themes');
  assert.equal(f.filter((x) => x.type === 'admin').length, 1, 'existing admin is not re-reported');
});

test('sentinel job: one review notice until baseline is accepted, then findings resolve/alert correctly', async () => {
  const s = setup();
  const job = createSentinelJob(s);
  const store = (r) => { const body = JSON.stringify(r); assert.equal(verifyAndStore({ ...s, headers: signed(body), rawBody: Buffer.from(body) }).ok, true); };
  store(report());
  const r1 = await job.evaluate(HOST);
  assert.equal(r1.new, 1, 'one "review and accept baseline" notice, not one alert per admin/plugin');
  assert.ok(s.incidents.get(`sentinel_baseline_needed:${HOST}`));
  const cand = candidateSentinelBaseline(s.db, HOST);
  assert.ok(acceptSentinelBaseline(s.db, HOST, cand.sha256));
  const r2 = await job.evaluate(HOST);
  assert.equal(r2.findings, 0);
  assert.equal(s.incidents.get(`sentinel_baseline_needed:${HOST}`), undefined, 'review notice resolved after accept');
  store(report({ install: { admins: [{ blog_id: '1', id: 1, login: 'Adhamsewelam' }, { blog_id: '1', id: 9, login: 'admin_409e9ec3f7', email: 'e', registered: 'r' }] } }));
  const r3 = await job.evaluate(HOST);
  assert.equal(r3.new, 1);
  assert.ok(s.messages.some((m) => /admin_409e9ec3f7/.test(m.text)), 'JARVIS alerted on the new admin');
  store(report());
  await job.evaluate(HOST);
  assert.equal(s.db.prepare("SELECT COUNT(*) n FROM incidents WHERE status='open' AND category='security'").get().n, 0, 'finding resolves when the admin is gone');
});

test('missing sentinel report for 3h opens an urgent incident', async () => {
  const s = setup();
  const job = createSentinelJob(s);
  const body = JSON.stringify(report());
  verifyAndStore({ ...s, headers: signed(body), rawBody: Buffer.from(body) });
  s.db.prepare("UPDATE sentinel_reports SET received_at = ?").run(new Date(Date.now() - 4 * 3600_000).toISOString());
  await job.run();
  const inc = s.incidents.get(`sentinel_missing:${HOST}`);
  assert.ok(inc);
  assert.equal(inc.severity, 'critical');
  assert.ok(s.messages.some((m) => /No host sentinel report/.test(m.text)));
});

test('marker detection on a sample infected page (ClickFix overlay + getServers loader)', () => {
  const clean = analyzePage(fs.readFileSync(new URL('./fixtures/clean-page.html', import.meta.url), 'utf8'), { domain: 'jewelsbygalla.com' });
  const bad = analyzePage(fs.readFileSync(new URL('./fixtures/infected-page.html', import.meta.url), 'utf8'), { domain: 'jewelsbygalla.com' });
  assert.equal(clean.markers.length, 0);
  assert.equal(clean.overlays.length, 0, 'a visible cookie banner is not a hidden overlay');
  const ids = bad.markers.map((m) => m.id);
  for (const m of ['cfm-main', 'getServers(', 'powershell', 'win+x', 'admetricslab']) assert.ok(ids.includes(m), `marker ${m}`);
  assert.equal(bad.overlays.length, 1);
  const hits = compareToBaseline(bad, clean, { allowDomains: ['jewelsbygalla.com', 'googletagmanager.com'] });
  const kinds = hits.map((h) => h.type);
  assert.ok(kinds.includes('marker') && kinds.includes('script') && kinds.includes('overlay') && kinds.includes('domain'));
  assert.ok(hits.some((h) => h.type === 'domain' && h.id === 'static.cloudflareinsights.com'));
  // the legit wc params script changed only its nonce + timestamp: same normalized hash, no hit
  assert.equal(hits.filter((h) => h.type === 'script').length, 1, 'only the injected script is new');
  assert.equal(normalizeScript('{"nonce":"abc123","t":17308}'), normalizeScript('{"nonce":"zzz999","t":99999}'));
});

test('confirm links are signed, expiring and bound to the exact content', () => {
  const s = setup();
  const body = JSON.stringify(report());
  verifyAndStore({ ...s, headers: signed(body), rawBody: Buffer.from(body) });
  const hash = currentHashFor(s.db, 'accept_sentinel_baseline', HOST);
  const a = createApproval(s.db, s.config, { kind: 'accept_sentinel_baseline', itemId: HOST, contentHash: hash });
  const q = new URL(a.url).searchParams;
  const cur = (k, i) => currentHashFor(s.db, k, i);
  assert.equal(verifyApproval(s.db, s.config, { id: a.id, exp: q.get('exp'), sig: q.get('sig') }, cur).ok, true);
  assert.equal(verifyApproval(s.db, s.config, { id: a.id, exp: q.get('exp'), sig: q.get('sig') + 'x' }, cur).ok, false);
  assert.equal(verifyApproval(s.db, s.config, { id: a.id, exp: q.get('exp'), sig: q.get('sig') }, cur, Date.now() + 73 * 3600_000).ok, false, 'expired');
  // a newer report with a new admin changes the content: the old link must not accept it
  const body2 = JSON.stringify(report({ install: { admins: [{ blog_id: '1', login: 'evil' }] } }));
  verifyAndStore({ ...s, headers: signed(body2), rawBody: Buffer.from(body2) });
  const v = verifyApproval(s.db, s.config, { id: a.id, exp: q.get('exp'), sig: q.get('sig') }, cur);
  assert.equal(v.ok, false);
  assert.match(v.reason, /changed/);
  const a2 = createApproval(s.db, s.config, { kind: 'accept_sentinel_baseline', itemId: HOST, contentHash: currentHashFor(s.db, 'accept_sentinel_baseline', HOST) });
  const q2 = new URL(a2.url).searchParams;
  const ok = verifyApproval(s.db, s.config, { id: a2.id, exp: q2.get('exp'), sig: q2.get('sig') }, cur);
  assert.equal(recordApproval(s.db, ok.approval), true);
  assert.equal(verifyApproval(s.db, s.config, { id: a2.id, exp: q2.get('exp'), sig: q2.get('sig') }, cur).ok, false, 'single use');
});

test('secrets are redacted by key and by value', () => {
  const r = redact({ password: 'p', note: 'GET https://jewelsbygalla.com/eg/wp-json/wc/v3/orders?consumer_key=ck_0123456789abcdef0123456789abcdef01234567&consumer_secret=cs_0123456789abcdef0123456789abcdef01234567 failed', tg: 'bot1234567890:AAFakeTokenForTestsOnly_abcdefghijk x' });
  assert.equal(r.password, '[redacted]');
  assert.doesNotMatch(r.note, /0123456789abcdef0123/);
  assert.doesNotMatch(r.tg, /AAFake/);
  assert.equal(redactText('Abcd 1234 EfGh 5678 ijKL 90mn'), '[redacted-app-password]');
  assert.equal(redactText('this shop will open from noon'), 'this shop will open from noon');
  assert.match(redactText('Authorization: Basic Y2tfMTIzOmNzXzQ1Ng=='), /Basic \[redacted\]/);
});

test('page scan ignores per-request data (Cloudflare ray ids, GA product data) but not new URLs', () => {
  const cf = (ray) => `(function(){var d=b.createElement('script');d.innerHTML="window.__CF$cv$params={r:'${ray}',t:'MTczMDgwMDAwMC4wMDAwMDA='};";})()`;
  assert.equal(normalizeScript(cf('8a1b2c3d4e5f6789')), normalizeScript(cf('99ff00aa11bb22cc')));
  const gtag = (id, name, price) => `var glaGtagData = {"products":{"${id}":{"name":"${name}","price":${price}}}};`;
  assert.equal(normalizeScript(gtag(29042, 'Diamond Filigree Floral Ring', 60900)), normalizeScript(gtag(30173, 'Diamond Ring Band', 12000)));
  assert.notEqual(normalizeScript('s.src="https://www.googletagmanager.com/gtm.js"'), normalizeScript('s.src="https://evil-cdn.top/gtm.js"'));
});

test('pure data blocks compare by what they assign, not by their (product-specific) shape', () => {
  const a = 'window.ga4w = { data: {"cart":{"items":[],"totals":{"currency_code":"EGP","total_price":0}},"product":{"id":32755,"name":"D","categories":[{"id":1},{"id":2}]}}, settings: {"x":true} };';
  const b = 'window.ga4w = { data: {"cart":{"items":[{"id":9}],"totals":{"currency_code":"EGP","total_price":500}},"product":{"id":1,"name":"Ring","variations":[]}}, settings: {"x":true} };';
  assert.equal(normalizeScript(a), normalizeScript(b));
  assert.notEqual(normalizeScript(a), normalizeScript('window.location = "https://evil.top/";'));
  assert.notEqual(normalizeScript(a), normalizeScript('window.ga4w = {}; fetch("https://evil.top/x")'));
});

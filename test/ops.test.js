// Alert dedupe/escalation, host grouping, read-only enforcement, "Not connected" paths, product checks.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setup, fakeFetch, HTML_OK, SECRET_SHARED } from './helpers.js';
import { createUptime, nextCheckState } from '../src/checks/uptime.js';
import { createOrders, wooGet } from '../src/checks/orders.js';
import { guardFetch, ReadOnlyViolation, classifyFailure } from '../src/http.js';
import { productIssues, skuMismatches } from '../src/checks/products.js';
import { brandStatus, renderDaily } from '../src/reports/daily.js';
import { createKeeper } from '../src/checks/keeper.js';
import { createSeoReview, seoIssues } from '../src/seo/weekly.js';
import { detectIssues } from '../src/team/hr.js';
import { createServer } from '../src/server.js';
import { signReport } from '../src/sentinel/ingest.js';
import { createSentinelJob } from '../src/sentinel/job.js';
import { smtpProbe } from '../src/checks/smtp.js';
import { sustainedHigh } from '../src/checks/vps.js';

const productCache = { get: (b, s) => `https://${b.domain}${s.path}product/ring/`, refresh: async () => {} };
const healthy = () => [
  [/wp-json\/$/, { body: '{"name":"Site","namespaces":["wp/v2"]}', headers: { 'content-type': 'application/json' } }],
  [/hc-ping/, { body: 'OK' }],
  [/.*/, { body: HTML_OK() }],
];

test('check state: 2 failures open, 3rd does not re-open, recovery resolves', () => {
  let st = nextCheckState(null, false); assert.equal(st.shouldOpen, false);
  st = nextCheckState(st, false); assert.equal(st.shouldOpen, true);
  st = nextCheckState(st, false); assert.equal(st.shouldOpen, false);
  st = nextCheckState(st, true); assert.equal(st.shouldResolve, true);
});

test('uptime: one product page failing → one JARVIS alert, deduped, escalates to email when not acknowledged, RESOLVED on recovery', async () => {
  const s = setup({ HEARTBEAT_URL: 'https://hc-ping.com/abc' });
  let broken = true;
  const fetchImpl = fakeFetch([[/onecaratjewelry\.com\/eg\/product\//, () => (broken ? { status: 503, body: 'Service Unavailable' } : { body: HTML_OK() })], ...healthy()]);
  const up = createUptime({ ...s, fetchImpl, productCache });
  await up.run();
  assert.equal(s.messages.length, 0, 'first failure: no alert yet');
  await up.run();
  assert.equal(s.messages.length, 1, 'second failure: JARVIS alert');
  assert.match(s.messages[0].text, /OneCarat \/eg\/ product page is failing \(origin: origin HTTP 503\)/);
  assert.equal(s.messages[0].buttons[0][0].text, "✅ I'm on it");
  await up.run();
  assert.equal(s.messages.length, 1, 'still failing: deduped, no new alert');
  assert.equal(s.mailer.sent.length, 0, 'email waits for the ack window');
  await s.timers[0].fn(); // JARVIS_ACK_MINUTES passed without a tap
  assert.equal(s.mailer.sent.length, 1);
  assert.match(s.mailer.sent[0].subject, /^\[OneCarat\] \[URGENT\] /);
  assert.match(s.mailer.sent[0].html, /didn&#39;t tap/);
  // 6h later: reminder (email only)
  s.db.prepare("UPDATE incidents SET notified_at = ? WHERE status = 'open'").run(new Date(Date.now() - 7 * 3600_000).toISOString());
  await up.run();
  assert.equal(s.messages.length, 1, 'reminders never re-page JARVIS');
  assert.match(s.mailer.sent.at(-1).subject, /STILL OPEN/);
  broken = false;
  await up.run();
  assert.match(s.mailer.sent.at(-1).subject, /^\[OneCarat\] \[RESOLVED\]/);
  assert.ok(fetchImpl.calls.some((c) => c.url.includes('hc-ping.com')), 'heartbeat pinged');
});

test('uptime: tapping "I\'m on it" sends the email once as the written record', async () => {
  const s = setup();
  const fetchImpl = fakeFetch([[/elgalla\.com\/checkout\//, { status: 524, body: 'error code: 524', headers: { 'cf-ray': '8a1-CAI' } }], ...healthy()]);
  const up = createUptime({ ...s, fetchImpl, productCache });
  await up.run(); await up.run();
  assert.match(s.messages[0].text, /Cloudflare edge: Cloudflare 524 \(origin timed out\)/);
  const callId = s.messages[0].buttons[0][0].callback_data.split(':')[1];
  await s.voice._onBotButton(`ack:${callId}`, { id: 'q1', message: { message_id: 5 } });
  assert.equal(s.mailer.sent.length, 1);
  assert.match(s.mailer.sent[0].html, /tapped/);
  await s.timers[0].fn(); // the timeout later fires too
  assert.equal(s.mailer.sent.length, 1, 'never emailed twice');
});

test('uptime: whole shared host down → ONE host-level alert, not one per page', async () => {
  const s = setup();
  const fetchImpl = fakeFetch([[/jewelsbygalla\.com|onecaratjewelry\.com/, { status: 503, body: 'down' }], ...healthy()]);
  const up = createUptime({ ...s, fetchImpl, productCache });
  await up.run(); await up.run();
  assert.equal(s.messages.length, 1, 'one alert for the host');
  assert.match(s.messages[0].text, /JBG, OneCarat down: 28 of 28 checks failing on Hostinger shared/);
  const children = s.db.prepare("SELECT COUNT(*) n FROM incidents WHERE status='open' AND parent_key = 'uptime:host:hostinger-u137384117'").get().n;
  assert.equal(children, 28);
  await s.timers[0].fn();
  assert.equal(s.mailer.sent.length, 1);
});

test('Cloudflare 52x is classified separately from origin errors', () => {
  assert.equal(classifyFailure({ status: 524, body: '', cfRay: 'x' }), 'cloudflare');
  assert.equal(classifyFailure({ status: 502, body: '<div id="cf-error-details">', cfRay: 'x' }), 'cloudflare');
  assert.equal(classifyFailure({ status: 502, body: 'Bad Gateway nginx' }), 'origin');
  assert.equal(classifyFailure({ status: 500, body: 'There has been a critical error', cfRay: 'x' }), 'origin');
});

test('read-only: any non-GET request to a brand domain is refused, wherever it comes from', async () => {
  const inner = fakeFetch([[/.*/, { body: 'ok' }]]);
  const guarded = guardFetch(inner, ['jewelsbygalla.com', 'elgalla.com']);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    await assert.rejects(guarded('https://jewelsbygalla.com/eg/wp-json/wc/v3/products/1', { method }), ReadOnlyViolation);
    await assert.rejects(guarded('https://www.elgalla.com/wp-admin/admin-ajax.php', { method }), ReadOnlyViolation);
  }
  await guarded('https://jewelsbygalla.com/eg/', { method: 'GET' });
  await guarded('https://api.telegram.org/botX/sendMessage', { method: 'POST' }); // not a brand domain
  assert.deepEqual(inner.calls.map((c) => c.method), ['GET', 'POST']);
});

test('read-only: the orders job only ever sends GET to WooCommerce, with only non-personal fields', async () => {
  const s = setup({ WC_ELGALLA_KEY: 'ck_' + '1'.repeat(40), WC_ELGALLA_SECRET: 'cs_' + '2'.repeat(40) });
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString().slice(0, 19);
  const orders = [
    { id: 1, status: 'pending', date_created_gmt: iso(now - 3 * 3600_000), payment_method: 'paymob', total: '100', currency: 'EGP' },
    { id: 2, status: 'pending', date_created_gmt: iso(now - 2 * 3600_000), payment_method: 'paymob', total: '100', currency: 'EGP' },
    { id: 3, status: 'pending', date_created_gmt: iso(now - 90 * 60_000), payment_method: 'paymob', total: '100', currency: 'EGP' },
    { id: 4, status: 'processing', date_created_gmt: iso(now - 30 * 60_000), payment_method: 'cod', total: '2500', currency: 'EGP' },
  ];
  const inner = fakeFetch([[/wc\/v3\/orders/, { body: JSON.stringify(orders), headers: { 'content-type': 'application/json', 'x-wp-totalpages': '1' } }]]);
  const guarded = guardFetch(inner, s.registry.brands.map((b) => b.domain));
  const res = await createOrders({ ...s, fetchImpl: guarded }).run();
  assert.ok(inner.calls.length >= 1);
  assert.ok(inner.calls.every((c) => c.method === 'GET'));
  const u = new URL(inner.calls[0].url);
  assert.doesNotMatch(u.searchParams.get('_fields'), /billing|shipping|customer|email|phone/);
  const el = res.find((r) => r.site === 'elgalla:main');
  assert.equal(el.stuck, 3);
  assert.ok(s.incidents.get('orders:elgalla:main:stuck_pending'));
  await assert.rejects(guarded('https://elgalla.com/wp-json/wc/v3/orders/1', { method: 'PUT' }), ReadOnlyViolation);
  assert.equal(typeof wooGet, 'function');
});

test('read-only: no source file can issue a write to a brand site (static scan)', () => {
  const dir = new URL('../src/', import.meta.url).pathname;
  const files = fs.readdirSync(dir, { recursive: true }).filter((f) => f.endsWith('.js')).map((f) => path.join(dir, f));
  // Files allowed to POST, and to where: Telegram bot API, AI providers. Nothing else.
  const allowed = { 'telegramBot.js': /api\.telegram\.org/, 'claude.js': /generativelanguage\.googleapis\.com|@anthropic-ai/, 'tg-setup.js': /api\.telegram\.org/, 'routes.js': /\/dashboard\/api\/team/ }; // routes.js: the browser posting to the agent's own dashboard API
  for (const f of files) {
    const src = fs.readFileSync(f, 'utf8');
    if (/method:\s*['"](POST|PUT|PATCH|DELETE)['"]/.test(src)) {
      const rule = allowed[path.basename(f)];
      assert.ok(rule && rule.test(src), `${path.relative(dir, f)} issues a non-GET request`);
    }
  }
});

test('"Not connected" paths: no keys, no sentinel, no Search Console, no AI', async () => {
  const s = setup();
  const res = await createOrders({ ...s, fetchImpl: fakeFetch([]) }).run();
  assert.ok(res.every((r) => r.connected === false));
  const b = s.registry.brands[0];
  const st = brandStatus({ ...s, brand: b });
  const { html } = renderDaily(st, s.config);
  assert.match(html, /Not connected \(set WC_JBG_EG_KEY/);
  assert.match(html, /Host sentinel<\/td><td[^>]*><i>Not connected/);
  assert.match(html, /Uptime yesterday<\/td><td[^>]*><i>No data/);
  assert.doesNotMatch(html, /NaN|undefined/);
  assert.ok(st.top.some((t) => /Orders not connected/.test(t.text) || /sentinel/.test(t.text)));

  const fetchImpl = fakeFetch([[/rdap\.org/, { body: '{"events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}', headers: { 'content-type': 'application/json' } }], [/.*/, { body: HTML_OK(), headers: { 'cf-ray': 'x' } }]]);
  const keeper = createKeeper({ ...s, fetchImpl });
  await keeper.run().catch(() => {}); // TLS to real hosts is not available offline: ssl shows an error, not a number
  const k = JSON.parse(s.db.prepare("SELECT value FROM kv WHERE key = 'keeper_last:jbg'").get().value);
  assert.equal(k.updates.connected, false);
  assert.match(k.updates.reason, /Not connected/);
  assert.equal(k.domain.days > 1000, true);
  assert.match(k.smtp?.reason || 'DNS', /Not connected|DNS/);

  const seo = createSeoReview({ ...s, claude: null, fetchImpl: fakeFetch([[/sitemap_index/, { body: '<sitemapindex></sitemapindex>' }], [/pagespeed/, { status: 429, body: '{}' }], [/.*/, { body: HTML_OK() }]]) });
  const r = await seo.reviewBrand(s.registry.brands[2]);
  assert.equal(r.brand, 'elgalla');
  const mail = s.mailer.sent.at(-1);
  assert.match(mail.subject, /^\[ElGalla\] \[WEEKLY SEO\]/);
  assert.match(mail.html, /Not connected \(Search Console service account\)/);
});

test('products: price 0, out-of-stock published, missing image; /eg vs /ae SKU parity honours FINAL PIECES (779)', () => {
  const p = (id, sku, extra = {}) => ({ id, sku, name: `P${id}`, permalink: `https://x/${id}`, prices: { price: '1000' }, is_in_stock: true, images: [{ src: 'i.jpg' }], categories: [], ...extra });
  const issues = productIssues([p(1, 'A', { prices: { price: '0' } }), p(2, 'B', { is_in_stock: false }), p(3, 'C', { images: [] })]);
  assert.deepEqual(issues.map((i) => i.kind).sort(), ['missing_image', 'out_of_stock_published', 'price_zero']);
  const eg = [p(1, 'RING-1'), p(2, 'FINAL-9', { categories: [{ id: 779, name: 'FINAL PIECES' }] }), p(3, 'EG-ONLY')];
  const ae = [p(11, 'RING-1'), p(12, 'AE-ONLY')];
  const m = skuMismatches(eg, ae, { exemptA: [779] });
  assert.deepEqual(m.onlyA.map((x) => x.sku), ['EG-ONLY'], 'FINAL PIECES is /eg-only by design');
  assert.deepEqual(m.onlyB.map((x) => x.sku), ['AE-ONLY']);
});

test('SEO: hreflang reciprocity, noindex in sitemap, spam URLs', () => {
  const pages = [
    { url: 'https://j.com/eg/en/ring/', status: 200, title: 'Ring', h1Count: 1, hreflang: [{ lang: 'ar', href: 'https://j.com/eg/ar/ring/' }, { lang: 'en', href: 'https://j.com/eg/en/ring/' }] },
    { url: 'https://j.com/eg/ar/ring/', status: 200, title: 'خاتم', h1Count: 1, hreflang: [{ lang: 'ar', href: 'https://j.com/eg/ar/ring/' }] },
    { url: 'https://j.com/eg/en/slot-gacor-online/', status: 200, title: 'x', h1Count: 1, noindex: true, hreflang: [] },
  ];
  const kinds = seoIssues(pages, { multiLang: true, multiCountry: true }).map((i) => i.kind);
  for (const k of ['hreflang', 'spam', 'noindex', 'hreflang_country']) assert.ok(kinds.includes(k), k);
});

test('HR: conflicts between agents come from the records', () => {
  const s = setup();
  const { incident } = s.incidents.open({ key: 'integrity:elgalla:main:home:marker:cfm-main', brand: 'elgalla', category: 'security', title: 'cfm-main' });
  void incident;
  const found = detectIssues({ config: s.config, db: s.db, registry: s.registry });
  assert.ok(found.some((i) => i.key === 'green_but_infected:elgalla' && i.agents.includes('warden') && i.agents.includes('sentinel')));
  assert.ok(found.some((i) => i.key === 'ledger_not_connected:jbg'));
});

test('HTTP /ingest end to end: signed report accepted, replay refused, evaluation runs', async () => {
  const s = setup();
  const sentinel = createSentinelJob(s);
  const app = createServer({ ...s, jobs: { sentinel: { evaluate: (h) => sentinel.evaluate(h) } } });
  const srv = app.listen(0);
  const port = srv.address().port;
  const body = JSON.stringify({ v: 1, host: 'hostinger-u137384117', installs: [{ id: 'jbg', path: '/x', errors: [], admins: [{ blog_id: '1', login: 'a' }], plugins: [] }], processes: [] });
  const headers = { 'content-type': 'application/json', 'x-galla-host': 'hostinger-u137384117', ...signReport(SECRET_SHARED, body) };
  const r1 = await fetch(`http://127.0.0.1:${port}/ingest`, { method: 'POST', headers, body });
  assert.equal(r1.status, 200);
  const r2 = await fetch(`http://127.0.0.1:${port}/ingest`, { method: 'POST', headers, body });
  assert.equal(r2.status, 409);
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(s.incidents.get('sentinel_baseline_needed:hostinger-u137384117'));
  const dash = await fetch(`http://127.0.0.1:${port}/dashboard`, { redirect: 'manual' });
  assert.equal(dash.status, 302, 'dashboard requires login');
  const confirm = await fetch(`http://127.0.0.1:${port}/a/whatever?exp=1&sig=x`, { redirect: 'manual' });
  assert.equal(confirm.status, 302, 'confirm pages require login too');
  srv.close();
});

test('SMTP probe catches a mailbox blocked at RCPT TO without sending anything', async () => {
  const { PassThrough, Duplex } = await import('node:stream');
  void PassThrough;
  const script = { EHLO: '250-hi\r\n250 AUTH PLAIN\r\n', AUTH: '235 ok\r\n', MAIL: '250 ok\r\n', RCPT: '550 5.7.1 Sending blocked: suspicious activity\r\n' };
  const seen = [];
  const sock = new Duplex({ read() {}, write(chunk, _e, cb) { const line = chunk.toString(); seen.push(line.split(' ')[0].trim()); const k = Object.keys(script).find((x) => line.startsWith(x)); if (k) setImmediate(() => this.push(script[k])); cb(); } });
  setImmediate(() => sock.push('220 smtp.stackmail.com ready\r\n'));
  const r = await smtpProbe({ host: 'smtp.stackmail.com', port: 587, user: 'admin@elgalla.com', pass: 'p', to: 'x@y.z', connect: () => sock });
  assert.equal(r.ok, false);
  assert.equal(r.stage, 'RCPT TO');
  assert.match(r.error, /suspicious activity/);
  assert.ok(!seen.includes('DATA'), 'never reached DATA: nothing was sent');
});

test('VPS: sustained CPU means 13+ of the last 15 minutes over the threshold', () => {
  const now = Date.now();
  const mk = (vals) => vals.map((pct, i) => ({ t: now - (vals.length - 1 - i) * 60_000, pct }));
  assert.equal(sustainedHigh(mk(Array(15).fill(95)), 85, 15, now), true);
  assert.equal(sustainedHigh(mk([...Array(13).fill(95), 40, 95]), 85, 15, now), true);
  assert.equal(sustainedHigh(mk([...Array(10).fill(95), 40, 40, 40, 95, 95]), 85, 15, now), false);
  assert.equal(sustainedHigh(mk(Array(5).fill(99)), 85, 15, now), false, 'not enough samples yet');
});

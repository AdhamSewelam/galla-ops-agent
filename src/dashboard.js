// Command Center: password-protected, built only from the agent's own records.
// Missing sources say "Not connected", never invented numbers. Approval-style actions (accept a
// baseline) go through a signed, expiring, content-bound confirm page that also requires this login.
import crypto from 'node:crypto';
import { esc } from './email.js';
import { audit } from './audit.js';
import { redactText } from './redact.js';
import { SCHEDULE } from './schedule.js';
import { TEST_SCENARIOS } from './voice.js';
import { mountTeam } from './team/routes.js';
import { brandStatus } from './reports/daily.js';
import { createApproval, verifyApproval, recordApproval, sha256 } from './approvals.js';
import { currentHashFor, acceptPageBaselines, acceptSentinelBaseline, candidateSentinelBaseline, pageBaselineState, pageCandidates } from './baselines.js';
import { activeSentinelBaseline } from './sentinel/job.js';
import { analyzeReport } from './sentinel/analyze.js';
import { latestReport, lastCheckIn } from './sentinel/ingest.js';
import { incidentDetail } from './incidents.js';
import { kvJson } from './db.js';
import { ago, cairo } from './util.js';

const COOKIE = 'galla_session';
const SESSION_DAYS = 7;
const hmac = (secret, s) => crypto.createHmac('sha256', secret).update(s).digest('base64url');
export const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const cookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p.length === 2));
const pill = (tone, text) => `<span class="pill ${tone}">${esc(text)}</span>`;
const KIND_LABEL = { price_zero: 'Price 0 / empty', out_of_stock_published: 'Out of stock, published', missing_image: 'Missing image', broken_image: 'Broken image', sku_mismatch: 'SKU /eg ↔ /ae' };

export function mountDashboard(app, { config, db, registry, jobState = null, voice = null, claude = null, mailer = null, jobs = null }) {
  const secret = config.APPROVAL_SECRET + ':dashboard';
  const enabled = Boolean(config.DASHBOARD_PASSWORD);
  const fails = new Map();
  const sessionValid = (req) => {
    const v = cookies(req)[COOKIE];
    if (!v) return false;
    const [exp, sig] = v.split('.');
    return Number(exp) > Date.now() && safeEq(sig, hmac(secret, `s.${exp}`));
  };
  const csrf = (req) => hmac(secret, `csrf.${cookies(req)[COOKIE] || ''}`);
  const requireAuth = (req, res, next) => {
    if (!enabled) return res.status(404).send(shell('Dashboard off', '<div class="login"><h1>Dashboard is off</h1><p class="muted">Set DASHBOARD_PASSWORD (12+ characters) in .env and restart.</p></div>'));
    if (!sessionValid(req)) return res.redirect('/dashboard/login?next=' + encodeURIComponent(req.originalUrl));
    res.set('Cache-Control', 'no-store'); res.set('X-Frame-Options', 'DENY'); res.set('Referrer-Policy', 'no-referrer');
    next();
  };
  const back = (res, msg, anchor = '', brand = '') => res.redirect(`/dashboard?${brand ? `brand=${encodeURIComponent(brand)}&` : ''}msg=${encodeURIComponent(msg)}${anchor}`);
  const checkCsrf = (req) => safeEq(req.body?.csrf || '', csrf(req));

  app.get('/dashboard/login', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.send(shell('Sign in', loginForm(req.query.e ? 'Wrong password.' : req.query.l ? 'Too many attempts. Try again in 15 minutes.' : '', String(req.query.next || ''))));
  });
  app.post('/dashboard/login', (req, res) => {
    if (!enabled) return res.status(404).end();
    const ip = req.ip, now = Date.now();
    const recent = (fails.get(ip) || []).filter((t) => now - t < 15 * 60000);
    if (recent.length >= 8) return res.redirect('/dashboard/login?l=1');
    const ok = safeEq(crypto.createHash('sha256').update(String(req.body.password || '')).digest('hex'), crypto.createHash('sha256').update(config.DASHBOARD_PASSWORD).digest('hex'));
    if (!ok) {
      fails.set(ip, [...recent, now]);
      audit(db, { actor: 'visitor', action: 'dashboard_login_failed', target: ip, outcome: 'blocked' });
      return res.redirect('/dashboard/login?e=1');
    }
    fails.delete(ip);
    const exp = now + SESSION_DAYS * 86400_000;
    res.set('Set-Cookie', `${COOKIE}=${exp}.${hmac(secret, `s.${exp}`)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DAYS * 86400}`);
    audit(db, { actor: 'owner', action: 'dashboard_login' });
    const next = String(req.body.next || '');
    res.redirect(/^\/(dashboard|a\/)[^\s]*$/.test(next) && !next.startsWith('//') ? next : '/dashboard');
  });
  app.post('/dashboard/logout', (req, res) => {
    res.set('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    res.redirect('/dashboard/login');
  });

  // ── Acknowledge a finding (stops reminders; it stays listed until it's gone) ──
  app.post('/dashboard/incidents/:id/ack', requireAuth, (req, res) => {
    if (!checkCsrf(req)) return res.status(400).send('Bad request');
    const inc = db.prepare("SELECT * FROM incidents WHERE id = ? AND status = 'open'").get(Number(req.params.id));
    if (!inc) return back(res, 'That item is no longer open.', '#security');
    db.prepare('UPDATE incidents SET acknowledged_at = COALESCE(acknowledged_at, ?) WHERE id = ?').run(new Date().toISOString(), inc.id);
    audit(db, { actor: 'owner', action: 'incident_acknowledged', target: inc.key, detail: { via: 'dashboard' } });
    back(res, 'Acknowledged. Reminders stop; it stays listed until it is no longer detected.', '#security', inc.brand || '');
  });

  // ── Accept as baseline: creates a signed approval and sends Adham to its confirm page ──
  app.post('/dashboard/baseline/:kind/:item', requireAuth, (req, res) => {
    if (!checkCsrf(req)) return res.status(400).send('Bad request');
    const kind = req.params.kind === 'host' ? 'accept_sentinel_baseline' : req.params.kind === 'pages' ? 'accept_page_baseline' : null;
    if (!kind) return res.status(400).send('Bad request');
    const hash = currentHashFor(db, kind, req.params.item);
    if (!hash) return back(res, 'Nothing to accept yet (no report / no scan).', '#security');
    const a = createApproval(db, config, { kind, itemId: req.params.item, contentHash: hash });
    audit(db, { actor: 'owner', action: 'baseline_confirm_opened', target: `${kind}:${req.params.item}` });
    res.redirect(new URL(a.url).pathname + new URL(a.url).search);
  });

  // Confirm page (GET shows exactly what will be accepted; POST does it). Login required too.
  app.get('/a/:id', requireAuth, (req, res) => {
    const v = verifyApproval(db, config, { id: req.params.id, exp: req.query.exp, sig: req.query.sig }, (k, i) => currentHashFor(db, k, i));
    if (!v.ok) return res.status(400).send(shell('Link not valid', `<div class="card"><h2>Link not valid</h2><p>${esc(v.reason)}</p><p><a href="/dashboard">Back to dashboard</a></p></div>`));
    res.send(shell('Confirm', `<div class="card"><h2>${esc(confirmTitle(v.approval))}</h2>${confirmBody(v.approval)}
      <form method="post"><input type="hidden" name="exp" value="${esc(req.query.exp)}"><input type="hidden" name="sig" value="${esc(req.query.sig)}"><input type="hidden" name="csrf" value="${csrf(req)}">
      <button class="ok">Yes, accept as the new baseline</button> <a class="ghost btn" href="/dashboard#security">Cancel</a></form>
      <p class="muted small">From now on only NEW or CHANGED items alert. Malware markers, banned plugins, core checksum failures and .g_*.php processes always alert regardless.</p></div>`));
  });
  app.post('/a/:id', requireAuth, async (req, res) => {
    if (!checkCsrf(req)) return res.status(400).send('Bad request');
    const v = verifyApproval(db, config, { id: req.params.id, exp: req.body.exp, sig: req.body.sig }, (k, i) => currentHashFor(db, k, i));
    if (!v.ok) return res.status(400).send(shell('Link not valid', `<div class="card"><h2>Not done</h2><p>${esc(v.reason)}</p></div>`));
    if (!recordApproval(db, v.approval)) return res.status(409).send(shell('Already done', '<div class="card"><p>This was already confirmed.</p></div>'));
    const a = v.approval;
    let msg;
    if (a.kind === 'accept_sentinel_baseline') {
      const done = acceptSentinelBaseline(db, a.item_id, a.content_hash);
      msg = done ? `Baseline accepted for ${a.item_id}.` : 'The host state changed; nothing was accepted.';
      if (done) await jobs?.sentinel?.evaluate(a.item_id).catch(() => {});
    } else {
      const n = acceptPageBaselines(db, a.item_id, a.content_hash);
      msg = n ? `Page baseline accepted for ${n} page(s) of ${a.item_id}.` : 'The pages changed; nothing was accepted.';
    }
    audit(db, { actor: 'owner', action: a.kind, target: a.item_id, detail: { approval: a.id } });
    back(res, msg, '#security');
  });

  function confirmTitle(a) {
    return a.kind === 'accept_sentinel_baseline' ? `Accept the current state of ${a.item_id} as the baseline?` : `Accept the current scripts on ${a.item_id}'s pages as the baseline?`;
  }
  function confirmBody(a) {
    if (a.kind === 'accept_sentinel_baseline') {
      const rep = latestReport(db, a.item_id);
      const cur = activeSentinelBaseline(db, a.item_id);
      const items = rep ? analyzeReport(rep.data, cur?.data || null).filter((f) => f.baseline) : [];
      const cand = candidateSentinelBaseline(db, a.item_id);
      const counts = Object.entries(cand?.snapshot?.installs || {}).map(([id, s]) => `${id}: ${s.admins?.length ?? '?'} admins · ${s.appPasswords?.length ?? '?'} app passwords · ${Object.keys(s.muPlugins).length} mu-plugins · ${Object.keys(s.dropins).length} drop-ins · ${s.plugins.length} plugins · ${s.cronHooks?.length ?? '?'} cron hooks · ${s.zips.length} zips · ${s.uploadsPhp.length} PHP in uploads`);
      return `<p>From the report received ${esc(ago(rep?.received_at))}. ${cur ? 'These differ from the current baseline:' : 'No baseline yet. Everything below becomes "known":'}</p>
        <ul class="plain">${items.slice(0, 200).map((f) => `<li>${pill(f.severity === 'critical' ? 'bad' : 'warn', f.type)} ${esc(f.title)}</li>`).join('') || '<li class="muted">No differences.</li>'}</ul>
        <p class="small muted">${counts.map(esc).join('<br>')}</p><p><b>Only accept if every admin, application password, mu-plugin, drop-in, cron hook and zip above is yours.</b></p>`;
    }
    const st = pageBaselineState(db, a.item_id);
    const rows = pageCandidates(db, a.item_id).map((c) => { const s = JSON.parse(c.snapshot); return `<li><b>${esc(c.scope.slice(5))}</b>: ${s.inlineScripts.length} inline scripts, ${s.scriptDomains.length} script domains (${esc(s.scriptDomains.slice(0, 8).join(', '))}), ${s.overlays.length} hidden overlays${s.markers.length ? ` · <span class="err">${s.markers.length} MALWARE MARKER(S): ${esc(s.markers.map((m) => m.id).join(', '))}</span>` : ''}</li>`; });
    return `<p>${st.pages} page(s) scanned; ${st.differs} differ from the accepted baseline.</p><ul class="plain">${rows.join('')}</ul><p class="small muted">Markers are never baselined: they keep alerting.</p>`;
  }

  // ── JARVIS test ──
  app.post('/dashboard/jarvis-test', requireAuth, async (req, res) => {
    if (!checkCsrf(req)) return res.status(400).send('Bad request');
    if (!voice?.enabled) return back(res, 'JARVIS is not set up yet (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env).');
    await voice.testAlert(String(req.body.scenario || 'jarvis_test'));
    audit(db, { actor: 'owner', action: 'jarvis_test_requested' });
    back(res, 'JARVIS sent a test alert to your Telegram.');
  });

  app.get('/dashboard', requireAuth, (req, res) => {
    const brandId = registry.brands.some((b) => b.id === req.query.brand) ? req.query.brand : 'all';
    res.send(shell('Command Center', render(brandId, csrf(req), req.query.msg)));
  });
  app.get('/dashboard/api/status', requireAuth, (req, res) => res.json(statusJson()));

  mountTeam(app, { config, db, registry, jobState, claude, mailer, requireAuth, csrf, safeEq, shell, viewSwitch });

  function statusJson() {
    return { brands: registry.brands.map((b) => { const s = brandStatus({ config, db, registry, brand: b }); return { id: b.id, open: s.open.length, critical: s.open.filter((i) => i.severity === 'critical').length, uptimeToday: s.uptimeToday }; }) };
  }

  function render(brandId, csrfToken, msg) {
    const brands = brandId === 'all' ? registry.brands : registry.brands.filter((b) => b.id === brandId);
    const sts = brands.map((b) => brandStatus({ config, db, registry, brand: b }));
    const brandIds = new Set(brands.map((b) => b.id));
    const hosts = registry.hosts.filter((h) => h.brands.some((x) => brandIds.has(x)));
    const openAll = db.prepare("SELECT * FROM incidents WHERE status = 'open' ORDER BY severity = 'critical' DESC, first_seen DESC").all()
      .filter((i) => brandId === 'all' || brandIds.has(i.brand) || (!i.brand && hosts.some((h) => i.key.includes(h.id))));
    const critical = openAll.filter((i) => i.severity === 'critical' && !i.parent_key);
    const security = openAll.filter((i) => i.category === 'security' || i.category === 'sentinel');
    const others = openAll.filter((i) => !(i.category === 'security' || i.category === 'sentinel') && !i.parent_key);
    const recentResolved = db.prepare("SELECT * FROM incidents WHERE status = 'resolved' ORDER BY resolved_at DESC LIMIT 40").all().filter((i) => brandId === 'all' || brandIds.has(i.brand)).slice(0, 10);
    const checks = db.prepare('SELECT * FROM check_state ORDER BY key').all().filter((c) => brandIds.has(c.brand));
    const lastRun = Object.fromEntries(db.prepare("SELECT action, MAX(ts) ts, outcome FROM audit_log WHERE action LIKE 'job_%' GROUP BY action").all().map((r) => [r.action.slice(4), r]));
    const outcomeOf = (job) => db.prepare('SELECT outcome FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1').get(`job_${job}`)?.outcome;
    const activity = db.prepare("SELECT * FROM audit_log WHERE action NOT IN ('job_uptime','job_integrity','job_vps','email_skipped_not_configured') ORDER BY id DESC LIMIT 50").all();
    const tile = (label, value, sub, tone = '') => `<div class="tile ${tone}"><div class="tl">${esc(label)}</div><div class="tv">${value}</div><div class="ts">${sub}</div></div>`;
    const failingChecks = checks.filter((c) => c.consecutive_failures >= 2);
    const okChecks = checks.filter((c) => c.consecutive_failures === 0).length;
    const productTotal = sts.reduce((n, s) => n + Object.values(s.productCounts).reduce((a, x) => a + x, 0), 0);
    const ordersConnected = sts.flatMap((s) => s.orders).filter((o) => o.sum?.connected && !o.sum?.error);
    const orders24 = ordersConnected.reduce((n, o) => n + (o.sum.last24h?.orders || 0), 0);
    const attention = sts.flatMap((s) => s.allItems.map((i) => ({ ...i, brand: s.brand.short }))).sort((a, b) => a.rank - b.rank).slice(0, 10);

    const incidentCard = (i, withActions) => {
      const d = incidentDetail(i);
      const cmd = (arr) => (arr?.length ? `<pre>${esc(arr.join('\n'))}</pre>` : '');
      return `<div class="inc ${i.severity}"><div class="ih">${pill(i.severity === 'critical' ? 'bad' : i.severity === 'high' ? 'warn' : '', i.severity)} ${i.acknowledged_at ? pill('', 'acknowledged') : ''} <b>${esc(i.title)}</b></div>
        <div class="muted small">${esc(i.category)} · since ${esc(cairo(i.first_seen, config.TIMEZONE))} · seen ${esc(ago(i.last_seen))}${d.where ? ` · ${esc(String(d.where).slice(0, 160))}` : ''}</div>
        ${d.todo ? `<div class="small">${esc(d.todo)}</div>` : ''}
        ${d.evidence?.length || d.verify?.length || d.remediate?.length ? `<details><summary>Evidence &amp; commands</summary>${d.evidence?.length ? `<h4>Evidence</h4>${cmd(d.evidence.slice(0, 60))}` : ''}${d.verify?.length ? `<h4>Verify (run yourself)</h4>${cmd(d.verify)}` : ''}${d.remediate?.length ? `<h4>Remediate (after verifying)</h4>${cmd(d.remediate)}` : ''}</details>` : ''}
        ${withActions && !i.acknowledged_at && i.category === 'security' ? `<form method="post" action="/dashboard/incidents/${i.id}/ack" class="inline"><input type="hidden" name="csrf" value="${csrfToken}"><button class="ghost sm">Acknowledge</button></form>` : ''}
      </div>`;
    };

    const hostRows = hosts.map((h) => {
      const last = lastCheckIn(db, h.id);
      const base = activeSentinelBaseline(db, h.id);
      const cand = candidateSentinelBaseline(db, h.id);
      const differs = cand && (!base || base.sha256 !== cand.sha256);
      const age = last ? (Date.now() - new Date(last)) / 3600_000 : null;
      return `<tr><td><b>${esc(h.label)}</b><div class="muted small">${esc(h.kind)} · ${esc(h.brands.join(', '))}</div></td>
        <td>${last ? pill(age < config.SENTINEL_MISSING_HOURS ? 'good' : 'bad', `report ${ago(last)}`) : pill('', 'Not connected')}</td>
        <td class="small">${base ? `baseline ${esc(ago(base.accepted_at))}` : '<span class="muted">no baseline</span>'}</td>
        <td>${differs ? `<form method="post" action="/dashboard/baseline/host/${esc(h.id)}" class="inline"><input type="hidden" name="csrf" value="${csrfToken}"><button class="ghost sm">Accept as baseline…</button></form>` : ''}</td></tr>`;
    }).join('');
    const pageRows = brands.map((b) => {
      const st = pageBaselineState(db, b.id);
      const last = kvJson(db, 'integrity_last');
      return `<tr><td><b>${esc(b.short)}</b> pages</td><td>${st.pages ? pill(st.accepted ? 'good' : 'warn', `${st.accepted}/${st.pages} baselined`) : pill('', 'not scanned yet')}</td><td class="small">${!st.pages ? 'waiting for the first successful scan' : st.differs ? `${st.differs} page(s) differ` : 'matches baseline'}${last ? ` · last scan ${esc(ago(last.at))}` : ''}</td>
        <td>${st.pages && st.differs ? `<form method="post" action="/dashboard/baseline/pages/${esc(b.id)}" class="inline"><input type="hidden" name="csrf" value="${csrfToken}"><button class="ghost sm">Accept as baseline…</button></form>` : ''}</td></tr>`;
    }).join('');

    const orderRows = sts.flatMap((s) => s.orders.map(({ site, sum }) => `<tr><td>${esc(s.brand.short)} ${esc(site.path)}</td><td class="small">${!sum ? '<span class="muted">Not run yet</span>' : !sum.connected ? `<span class="muted">${esc(sum.reason)}</span>` : sum.error ? `<span class="err">${esc(sum.error)}</span>` : `${sum.last24h.orders} orders · ${sum.last24h.paid} paid · ${sum.last24h.failed} failed · ${sum.last24h.pendingStuck} stuck · ${esc(Object.entries(sum.last24h.revenue).map(([c, v]) => `${Number(v).toLocaleString('en-US')} ${c}`).join(' · ') || '0')}${sum.zero?.learning ? ` <span class="muted">(learning ${sum.zero.historyDays}/14 d)</span>` : ''}`}</td><td class="muted small">${sum ? esc(ago(sum.at)) : ''}</td></tr>`)).join('');
    const products = db.prepare(`SELECT * FROM product_issues WHERE brand IN (${[...brandIds].map(() => '?').join(',')}) ORDER BY kind, brand LIMIT 150`).all(...brandIds);
    const seo = brands.map((b) => db.prepare('SELECT * FROM seo_reviews WHERE brand = ? ORDER BY id DESC LIMIT 1').get(b.id)).filter(Boolean);
    const keeperRows = sts.map((s) => { const k = s.keeper; return `<tr><td><b>${esc(s.brand.short)}</b></td><td class="small">${k ? `SSL ${k.ssl?.days ?? esc(k.ssl?.error || '?')} d · domain ${k.domain?.days ?? esc(k.domain?.error || '?')} d · email ${k.smtp ? (k.smtp.ok ? 'OK' : k.smtp.reason ? esc(k.smtp.reason) : `<span class="err">FAILING ${esc(k.smtp.error)}</span>`) : 'n/a'} · updates: ${k.updates?.connected ? (k.updates.installs || []).map((i) => `${esc(i.install)} core ${esc(i.core.installed)}${i.core.latest && i.core.latest !== i.core.installed ? `→${esc(i.core.latest)}` : ''}, ${i.plugins.filter((p) => p.latest).length} plugin update(s), ${i.security.length} security`).join('; ') : esc(k.updates?.reason || 'Not connected')}` : '<span class="muted">Not run yet</span>'}</td><td class="muted small">${k ? esc(ago(k.at)) : ''}</td></tr>`; }).join('');
    const vps = (brandId === 'all' || brandId === 'elgalla') ? kvJson(db, 'vps_last') : null;

    return `
${viewSwitch('ops')}
<header class="top">
  <div><div class="brand">Galla Ops</div><div class="muted small">Command Center · ${esc(new Date().toLocaleString('en-GB', { timeZone: config.TIMEZONE, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }))} Cairo</div></div>
  <div class="hdr-actions">
    ${voice?.enabled ? `<form method="post" action="/dashboard/jarvis-test" class="jt"><input type="hidden" name="csrf" value="${csrfToken}"><select name="scenario" aria-label="Test scenario">${Object.entries(TEST_SCENARIOS).map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join('')}</select><button class="ghost">Test JARVIS</button></form>` : ''}
    <form method="post" action="/dashboard/logout"><button class="ghost">Sign out</button></form>
  </div>
</header>
<nav class="brands" aria-label="Brand">${[['all', 'All'], ...registry.brands.map((b) => [b.id, b.short])].map(([id, label]) => `<a href="/dashboard${id === 'all' ? '' : `?brand=${id}`}" class="${id === brandId ? 'on' : ''}">${esc(label)}</a>`).join('')}</nav>
${msg ? `<div class="flash">${esc(msg)}</div>` : ''}
<section class="status ${critical.length ? 'bad' : checks.length ? 'good' : ''}"><span class="dot"></span>${critical.length ? `${critical.length} critical issue(s) open` : checks.length ? 'All critical checks OK' : 'Waiting for the first checks'}</section>
<section class="tiles">
  ${tile('Checks passing', checks.length ? `${okChecks}/${checks.length}` : '—', `uptime today ${sts.map((s) => `${s.brand.short} ${s.uptimeToday ?? '—'}%`).join(' · ')}`, failingChecks.length ? 'bad' : checks.length ? 'good' : '')}
  ${tile('Open incidents', String(others.length), recentResolved[0] ? `last resolved ${ago(recentResolved[0].resolved_at)}` : 'none resolved yet', others.some((i) => i.severity === 'critical') ? 'bad' : '')}
  ${tile('Security findings', String(security.length), security.length ? `${security.filter((s) => !s.acknowledged_at).length} unacknowledged` : 'none open', security.some((s) => s.severity === 'critical') ? 'bad' : security.length ? 'warn' : 'good')}
  ${tile('Host sentinels', `${hosts.filter((h) => { const l = lastCheckIn(db, h.id); return l && (Date.now() - new Date(l)) / 3600_000 < config.SENTINEL_MISSING_HOURS; }).length}/${hosts.length}`, 'reporting on time')}
  ${tile('Orders (24h)', ordersConnected.length ? String(orders24) : '—', ordersConnected.length ? `${ordersConnected.length} shop(s) connected` : 'Not connected')}
  ${tile('Product issues', products.length || productTotal ? String(productTotal) : '0', 'from the last Curator run', productTotal ? 'warn' : '')}
</section>

<div class="grid">
  <section class="card"><h2>Needs your attention</h2>${attention.length ? `<ul class="att">${attention.map((a) => `<li class="${a.rank <= 2 ? 'red' : 'gold'}"><b>${esc(a.brand)} · ${esc(a.text)}</b><span>${esc(a.why)}</span></li>`).join('')}</ul>` : '<p class="muted">Nothing needs you right now.</p>'}</section>
  <section class="card"><h2>Uptime &amp; incidents</h2>
    ${failingChecks.length ? `<table class="tbl">${failingChecks.map((c) => `<tr><td>${esc(c.label)}</td><td>${pill('bad', c.last_kind || 'failing')}</td><td class="muted small">${esc(c.last_error || '')}</td></tr>`).join('')}</table>` : `<p class="muted">${checks.length ? `All ${checks.length} checks passing.` : 'No checks yet.'}</p>`}
    ${others.map((i) => incidentCard(i, false)).join('')}
    <details><summary>All checks (${checks.length})</summary><table class="tbl">${checks.map((c) => `<tr><td class="small">${esc(c.label)}</td><td>${c.consecutive_failures ? pill('bad', `${c.consecutive_failures}× fail`) : pill('good', 'OK')}</td><td class="muted small">${c.consecutive_failures ? esc(c.last_error) : `${c.last_ms ?? '?'} ms · ${ago(c.last_ok)}`}</td></tr>`).join('')}</table></details>
    ${recentResolved.length ? `<details><summary>Recently resolved (${recentResolved.length})</summary><ul class="plain">${recentResolved.map((i) => `<li>${pill('good', 'resolved')} ${esc(i.title)} <span class="muted small">${ago(i.resolved_at)}</span></li>`).join('')}</ul></details>` : ''}
  </section>
</div>

<section class="card" id="security"><h2>Security (Warden)</h2>
  <table class="tbl">${hostRows}${pageRows}</table>
  ${security.length ? security.map((i) => incidentCard(i, true)).join('') : '<p class="muted">No open security findings.</p>'}
</section>

<div class="grid">
  <section class="card"><h2>Orders (Ledger)</h2><table class="tbl">${orderRows}</table></section>
  <section class="card"><h2>SSL, domains, updates, email (Keeper)</h2><table class="tbl">${keeperRows}</table>
    ${vps ? `<h3>VPS</h3><p class="small">CPU ${esc(vps.cpuNow)}% · load ${esc(vps.load?.map((x) => x.toFixed(2)).join(' '))} on ${esc(vps.cores)} cores · RAM ${esc(vps.ram)}% · disk ${esc(vps.disk)}% · ${Object.entries(vps.services || {}).map(([k, v]) => `${esc(k)} ${v === 'active' ? '✓' : esc(v)}`).join(' · ')}${vps.slow?.newEntries != null ? ` · ${vps.slow.newEntries} new slow-log entries` : ''} <span class="muted">(${esc(ago(vps.at))})</span></p>` : ''}
  </section>
</div>

<section class="card"><h2>Product data issues (Curator) <span class="muted small">report only, nothing is changed</span></h2>
  ${products.length ? `<table class="tbl">${products.map((p) => `<tr><td>${pill('warn', KIND_LABEL[p.kind] || p.kind)}</td><td class="small">${esc(registry.brands.find((b) => b.id === p.brand)?.short)} /${esc(p.site || '')}</td><td class="small">${p.url ? `<a href="${esc(p.url)}" rel="noreferrer noopener" target="_blank">${esc(p.name)}</a>` : esc(p.name)}${p.sku ? ` <span class="muted">SKU ${esc(p.sku)}</span>` : ''}</td><td class="muted small">${esc(p.detail || '')}</td></tr>`).join('')}</table>` : '<p class="muted">No issues from the last run (or not run yet).</p>'}
</section>

<section class="card"><h2>SEO proposals (Scout)</h2>
  ${seo.length ? seo.map((r) => `<h3>${esc(registry.brands.find((b) => b.id === r.brand)?.name)} · ${esc(ago(r.created_at))}</h3>${r.summary ? `<p>${esc(r.summary)}</p>` : ''}<ol>${JSON.parse(r.fixes || '[]').map((f) => `<li><b>${esc(f.page)}</b>: ${esc(f.problem)}<div class="muted small">${esc(f.why || '')}</div>${f.steps?.length ? `<ol class="small">${f.steps.map((s) => `<li>${esc(String(s).replace(/^\d+[.)]\s*/, ''))}</li>`).join('')}</ol>` : ''}</li>`).join('')}</ol>`).join('') : '<p class="muted">No weekly review yet (Mondays 09:30).</p>'}
</section>

<div class="grid">
  <section class="card"><h2>Automations</h2><table class="tbl">${SCHEDULE.filter((s) => s.only !== 'vps' || config.VPS_MONITOR).map((s) => { const r = lastRun[s.job]; const o = outcomeOf(s.job); return `<tr><td><b>${esc(s.what)}</b><div class="muted small">${esc(s.when)} · ${esc(s.agent)}</div></td><td>${r ? pill(o === 'ok' ? 'good' : 'bad', o === 'ok' ? 'OK' : 'Error') : pill('', 'Not run yet')}</td><td class="muted small">${r ? ago(r.ts) : ''}</td></tr>`; }).join('')}</table></section>
  <section class="card"><h2>Activity log</h2><div class="logwrap"><table class="tbl log">${activity.map((a) => `<tr><td class="muted small nowrap">${esc(cairo(a.ts, config.TIMEZONE))}</td><td class="small">${esc(a.actor)}</td><td class="small">${esc(a.action.replace(/_/g, ' '))}${a.target ? ` <span class="muted">${esc(redactText(a.target).slice(0, 90))}</span>` : ''}</td><td>${a.outcome === 'ok' ? '' : pill(a.outcome === 'error' ? 'bad' : 'warn', a.outcome)}</td></tr>`).join('')}</table></div></section>
</div>
<p class="muted small foot">Built only from Galla Ops' own records. Galla Ops is read-only: it never changes prices, products, stock, orders, users, settings, plugins or files.</p>`;
  }
  return { requireAuth };
}

export function viewSwitch(active) {
  return `<nav class="views" aria-label="Views"><a href="/dashboard" class="${active === 'ops' ? 'on' : ''}">Operations</a><a href="/dashboard/team" class="${active === 'team' ? 'on' : ''}">Team</a></nav>`;
}

function loginForm(error, next) {
  return `<div class="login"><div class="brand">Galla Ops</div><p class="muted">Command Center</p>
  ${error ? `<p class="err">${esc(error)}</p>` : ''}
  <form method="post" action="/dashboard/login"><input type="hidden" name="next" value="${esc(next)}"><input type="password" name="password" placeholder="Password" autofocus required autocomplete="current-password"><button class="ok wide">Sign in</button></form></div>`;
}

export function shell(title, body, extraCss = '') {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${esc(title)} · Galla Ops</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Instrument+Serif&family=Inter:wght@400;600&family=IBM+Plex+Mono&display=swap" rel="stylesheet">
<style>
:root{--ink:#16130f;--ink2:#24201a;--line:#e7e2d9;--bg:#f7f5f1;--card:#fff;--text:#1d1a16;--muted:#6b6457;--gold:#9a7440;--gold2:#c79868;--good:#1f7a4d;--bad:#b42318;--warn:#a46a12}
@media (prefers-color-scheme:dark){:root{--bg:#12100d;--card:#1c1915;--line:#2e2a23;--text:#efebe4;--muted:#a79f90;--ink2:#2e2a23}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,sans-serif}
main{max-width:1240px;margin:0 auto;padding:20px 16px 40px}
a{color:inherit}.brand{font-family:'Instrument Serif',Georgia,serif;font-size:28px;line-height:1.1}
h2{font-size:15px;margin:0 0 12px}h3{font-size:12.5px;margin:16px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}h4{margin:10px 0 4px;font-size:12.5px}
.muted{color:var(--muted)}.small{font-size:12.5px}.nowrap{white-space:nowrap}.err{color:var(--bad)}
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.views,.brands{display:flex;gap:4px;margin-bottom:12px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px;width:max-content;max-width:100%;overflow-x:auto}
.views a,.brands a{padding:7px 14px;border-radius:7px;text-decoration:none;color:var(--muted);font-weight:600;font-size:13.5px;white-space:nowrap}.views a.on,.brands a.on{background:var(--ink2);color:#f6f3ee}
.status{display:flex;align-items:center;gap:10px;padding:14px 16px;border-radius:12px;font-weight:600;margin-bottom:16px;background:var(--card);border:1px solid var(--line)}
.status .dot{width:10px;height:10px;border-radius:50%;background:var(--muted)}.status.good .dot{background:var(--good)}.status.bad .dot{background:var(--bad)}
.flash{background:var(--ink2);color:#f6f3ee;padding:10px 14px;border-radius:10px;margin-bottom:12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;border-top:3px solid var(--line);min-width:0}
.tile.good{border-top-color:var(--good)}.tile.bad{border-top-color:var(--bad)}.tile.warn{border-top-color:var(--gold2)}
.tl{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}.tv{font-size:24px;font-weight:600;margin:4px 0;font-variant-numeric:tabular-nums}.ts{font-size:12px;color:var(--muted);overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media (max-width:860px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px;min-width:0;overflow-wrap:anywhere}
.tbl{width:100%;border-collapse:collapse}.tbl td{padding:7px 6px;border-top:1px solid var(--line);vertical-align:top}.tbl tr:first-child td{border-top:0}
.logwrap{max-height:520px;overflow:auto}
.pill{display:inline-block;font-size:11.5px;font-weight:600;padding:2px 8px;border-radius:999px;background:var(--line);white-space:nowrap}
.pill.good{background:rgba(31,122,77,.14);color:var(--good)}.pill.bad{background:rgba(180,35,24,.12);color:var(--bad)}.pill.warn{background:rgba(199,152,104,.22);color:var(--warn)}
@media (prefers-color-scheme:dark){.pill.good{color:#5fd39a}.pill.bad{color:#ff8a80}.pill.warn{color:#e3b47f}}
.att{list-style:none;margin:0;padding:0}.att li{padding:10px 12px;border-left:3px solid var(--line);margin-bottom:8px;background:var(--bg);border-radius:0 8px 8px 0}
.att li span{display:block;font-size:12.5px;color:var(--muted)}.att li.red{border-color:var(--bad)}.att li.gold{border-color:var(--gold2)}
.inc{padding:10px 12px;border-left:3px solid var(--line);background:var(--bg);border-radius:0 8px 8px 0;margin:10px 0}.inc.critical{border-color:var(--bad)}.inc.high{border-color:var(--gold2)}
.plain{list-style:none;padding:0;margin:0}.plain li{padding:4px 0}
pre{white-space:pre-wrap;font:12px/1.5 'IBM Plex Mono',monospace;background:var(--card);padding:10px;border-radius:8px;border:1px solid var(--line);overflow-x:auto}
details summary{cursor:pointer;font-size:13px;margin:8px 0}
button,.btn{font:600 14px Inter,sans-serif;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;text-decoration:none;display:inline-block}.ok{background:var(--good);color:#fff}.no{background:var(--bad);color:#fff}
.ghost{background:transparent;border:1px solid var(--line);color:var(--text)}.sm{padding:5px 10px;font-size:12.5px}.inline{display:inline}.wide{width:100%;margin-top:10px}
textarea,input[type=password]{width:100%;border:1px solid var(--line);border-radius:8px;padding:10px;font:14px Inter,sans-serif;background:var(--card);color:var(--text);margin:8px 0}
.login{max-width:360px;margin:12vh auto;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;text-align:center}
.foot{text-align:center;margin-top:8px}.hdr-actions{display:flex;gap:8px;flex-wrap:wrap}.jt{display:flex;gap:6px}.jt select{margin:0;padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);font:600 13px Inter,sans-serif}
${extraCss}
</style></head><body><main>${body}</main></body></html>`;
}

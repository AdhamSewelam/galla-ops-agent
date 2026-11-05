// Sentinel · uptime, every 5 min, per brand / subsite / language:
// homepage, shop page, wp-login.php, /wp-json/, one product page, checkout.
// 2 failures in a row → incident; recovery → [RESOLVED]; reminder every 6h while down.
// If most checks on one HOST fail together, that is ONE host-level alert, not one per page.
// Cloudflare 52x / edge errors are reported separately from origin errors.
import { get, getJson, classifyFailure } from '../http.js';
import { origin, localesOf, placeLabel, hostById } from '../brands.js';
import { nowIso, kvGet, kvSet } from '../db.js';
import { audit } from '../audit.js';
import { mapLimit, dayKey } from '../util.js';

export const FAILS_BEFORE_ALERT = 2;

export function nextCheckState(prev, success) {
  const prevFails = prev?.consecutive_failures ?? 0;
  if (success) return { consecutive_failures: 0, shouldOpen: false, shouldResolve: prevFails >= FAILS_BEFORE_ALERT };
  const fails = prevFails + 1;
  return { consecutive_failures: fails, shouldOpen: fails === FAILS_BEFORE_ALERT, shouldResolve: false };
}

const WP_FATAL = /There has been a critical error on this website|Error establishing a database connection|Fatal error:/i;

function assertPage(r, what) {
  const kind = classifyFailure(r);
  if (kind !== 'ok') {
    const label = kind === 'cloudflare' ? `Cloudflare ${r.status} (${r.status === 524 ? 'origin timed out' : 'cannot reach origin'})`
      : kind === 'cloudflare_block' ? `Cloudflare blocked the monitor (HTTP ${r.status}): allowlist the VPS IP`
      : kind === 'origin' ? `origin HTTP ${r.status}` : `HTTP ${r.status}`;
    throw Object.assign(new Error(label), { kind });
  }
  if (WP_FATAL.test(r.body)) throw Object.assign(new Error('WordPress critical error page'), { kind: 'origin' });
  if (what === 'html' && !/<html/i.test(r.body)) throw Object.assign(new Error('response is not an HTML page'), { kind: 'origin' });
}

/** Builds the check list from brands.json. productUrl(brand, site) returns a cached product URL or null. */
export function buildUptimeChecks(registry, { productUrl = () => null } = {}) {
  const checks = [];
  for (const b of registry.brands) {
    const base = origin(b);
    const add = (key, label, url, test, site = null) => checks.push({ key: `${b.id}:${key}`, brand: b.id, host: b.host, label, url, test, site });
    if (b.checkRoot) add('root:home', `${b.short} / homepage`, base + '/', (r) => assertPage(r, 'html'));
    for (const s of b.sites) {
      for (const l of localesOf(s)) {
        const tag = `${s.id}${l.lang ? '-' + l.lang : ''}`;
        add(`${tag}:home`, `${placeLabel(b, s, l)} homepage`, base + l.path, (r) => assertPage(r, 'html'), s);
        add(`${tag}:shop`, `${placeLabel(b, s, l)} shop page`, base + l.path + s.shopPath, (r) => {
          assertPage(r, 'html');
          if (!/woocommerce|products|product-/i.test(r.body)) throw Object.assign(new Error('shop page rendered without products markup'), { kind: 'origin' });
        }, s);
      }
      const first = localesOf(s)[0];
      add(`${s.id}:login`, `${b.short} ${s.path}wp-login.php`, base + s.path + 'wp-login.php', (r) => {
        assertPage(r, 'html');
        if (!/user_login|loginform/i.test(r.body)) throw Object.assign(new Error('login form not found'), { kind: 'origin' });
      }, s);
      add(`${s.id}:api`, `${b.short} ${s.path}wp-json/`, base + s.path + 'wp-json/', (r) => {
        assertPage(r, 'json');
        let j = null; try { j = JSON.parse(r.body); } catch { /* */ }
        if (!j || (!j.namespaces && !j.name)) throw Object.assign(new Error('wp-json did not return the REST index'), { kind: 'origin' });
      }, s);
      add(`${s.id}:product`, `${b.short} ${s.path} product page`, null, (r) => {
        assertPage(r, 'html');
        if (!/single_add_to_cart_button|"@type"\s*:\s*"Product"|product_title|out-of-stock/i.test(r.body)) throw Object.assign(new Error('product page rendered without product markup'), { kind: 'origin' });
      }, s);
      checks[checks.length - 1].resolveUrl = () => productUrl(b, s);
      add(`${s.id}:checkout`, `${b.short} ${first.path}${s.checkoutPath}`, base + first.path + s.checkoutPath, (r) => {
        // An empty cart redirects checkout → cart: that final 200 page is healthy.
        assertPage(r, 'html');
      }, s);
    }
  }
  return checks;
}

/** Finds one published product URL per site via the public, read-only Store API; cached for 24h. */
export function createProductUrlCache(db, { fetchImpl } = {}) {
  const key = (b, s) => `product_url:${b.id}:${s.id}`;
  return {
    get: (b, s) => {
      const v = kvGet(db, key(b, s));
      return v ? JSON.parse(v).url : null;
    },
    async refresh(registry) {
      for (const b of registry.brands) for (const s of b.sites) {
        const cached = kvGet(db, key(b, s));
        if (cached && Date.now() - JSON.parse(cached).at < 86400_000) continue;
        try {
          const r = await getJson(`${origin(b)}${s.path}wp-json/wc/store/v1/products?per_page=1&orderby=date&order=desc`, { fetchImpl });
          const p = Array.isArray(r.json) ? r.json[0] : null;
          if (p?.permalink) kvSet(db, key(b, s), JSON.stringify({ url: p.permalink, at: Date.now() }));
        } catch { /* keep the old one */ }
      }
    },
  };
}

export function createUptime({ config, db, registry, incidents, fetchImpl = globalThis.fetch, productCache = null }) {
  const cache = productCache || createProductUrlCache(db, { fetchImpl });
  const checks = () => buildUptimeChecks(registry, { productUrl: (b, s) => cache.get(b, s) });

  async function runOne(c) {
    const url = c.resolveUrl ? c.resolveUrl() : c.url;
    if (!url) return { ...c, url, success: false, error: 'no product URL found (Store API returned no published product)', kind: 'origin' };
    try {
      const r = await get(url, { fetchImpl, timeoutMs: 25000 });
      c.test(r);
      return { ...c, url, success: true, ms: r.ms };
    } catch (e) {
      const kind = e.kind || (e.name === 'TimeoutError' ? 'timeout' : 'network');
      const msg = e.name === 'TimeoutError' ? 'timed out after 25s' : e.message;
      return { ...c, url, success: false, error: msg, kind };
    }
  }

  async function run() {
    await cache.refresh(registry);
    const list = checks();
    const results = await mapLimit(list, 4, runOne);
    const day = dayKey(new Date(), config.TIMEZONE);
    const toOpen = [];
    const toResolve = [];
    for (const r of results) {
      const prev = db.prepare('SELECT * FROM check_state WHERE key = ?').get(r.key);
      const next = nextCheckState(prev, r.success);
      db.prepare(`INSERT INTO check_state(key, brand, label, consecutive_failures, last_ok, last_fail, last_error, last_kind, last_ms) VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(key) DO UPDATE SET brand=excluded.brand, label=excluded.label, consecutive_failures=excluded.consecutive_failures,
          last_ok=COALESCE(excluded.last_ok, check_state.last_ok), last_fail=COALESCE(excluded.last_fail, check_state.last_fail),
          last_error=excluded.last_error, last_kind=excluded.last_kind, last_ms=COALESCE(excluded.last_ms, check_state.last_ms)`)
        .run(r.key, r.brand, r.label, next.consecutive_failures, r.success ? nowIso() : null, r.success ? null : nowIso(), r.error || null, r.kind || null, r.ms ?? null);
      db.prepare(`INSERT INTO check_daily(day, key, brand, ok, fail) VALUES (?,?,?,?,?) ON CONFLICT(day, key) DO UPDATE SET ok = ok + excluded.ok, fail = fail + excluded.fail`)
        .run(day, r.key, r.brand, r.success ? 1 : 0, r.success ? 0 : 1);
      r.failing = next.consecutive_failures >= FAILS_BEFORE_ALERT;
      if (next.shouldOpen) toOpen.push(r);
      if (next.shouldResolve) toResolve.push(r);
    }

    // Host-level grouping: most checks on one host failing together = the host (or its network) is down.
    const fresh = [];
    const byHost = new Map();
    for (const r of results) byHost.set(r.host, [...(byHost.get(r.host) || []), r]);
    const hostDown = new Map();
    for (const [hostId, rs] of byHost) {
      const failing = rs.filter((r) => r.failing);
      const key = `uptime:host:${hostId}`;
      if (failing.length >= 3 && failing.length >= Math.ceil(rs.length * 0.6)) {
        const h = hostById(registry, hostId);
        const kinds = [...new Set(failing.map((f) => f.kind))];
        const brandsHit = [...new Set(failing.map((f) => registry.brands.find((b) => b.id === f.brand)?.short))].join(', ');
        const via = kinds.length === 1 && kinds[0] === 'cloudflare' ? ' (Cloudflare cannot reach the origin)' : kinds.includes('cloudflare') ? ' (Cloudflare + origin errors)' : '';
        const { incident, isNew } = incidents.open({
          key, brand: rs.length && new Set(rs.map((x) => x.brand)).size === 1 ? rs[0].brand : null, category: 'uptime', severity: 'critical',
          title: `${brandsHit} down: ${failing.length} of ${rs.length} checks failing on ${h?.label || hostId}${via}`,
          error: failing.slice(0, 6).map((f) => `${f.label}: ${f.error}`).join(' | '),
          detail: { where: h?.label || hostId, evidence: failing.map((f) => `${f.label} → ${f.error} (${f.url || 'no url'})`), impact: 'Customers cannot browse or pay on the affected sites.', todo: hostTodo(h) },
        });
        hostDown.set(hostId, key);
        if (isNew) fresh.push(incident);
      } else if (!failing.length) {
        await incidents.resolve(key);
      } else {
        const inc = incidents.get(key);
        if (inc) db.prepare('UPDATE incidents SET last_seen = ?, title = ? WHERE id = ?').run(nowIso(), inc.title.replace(/\d+ of \d+ checks failing/, `${failing.length} of ${rs.length} checks failing`), inc.id);
      }
    }

    for (const r of results.filter((x) => x.failing)) {
      const parentKey = hostDown.get(r.host) || null;
      const kindLabel = r.kind === 'cloudflare' ? 'Cloudflare edge' : r.kind === 'cloudflare_block' ? 'Cloudflare block' : r.kind === 'timeout' ? 'timeout' : 'origin';
      const { incident, isNew } = incidents.open({
        key: `uptime:${r.key}`, brand: r.brand, category: 'uptime', severity: /:(home|checkout|product)$/.test(r.key) ? 'critical' : 'high',
        title: `${r.label} is failing (${kindLabel}: ${r.error})`, error: r.error,
        detail: { where: r.url, impact: impactFor(r.key), todo: todoFor(r) }, parentKey,
      });
      if (isNew && !parentKey) fresh.push(incident);
    }
    for (const r of toResolve) await incidents.resolve(`uptime:${r.key}`);
    await incidents.notify(fresh);
    const reminders = await incidents.remind();

    if (config.HEARTBEAT_URL) {
      try { await get(config.HEARTBEAT_URL, { fetchImpl, timeoutMs: 10000 }); } catch (e) { audit(db, { actor: 'sentinel', action: 'heartbeat_failed', detail: { error: e.message }, outcome: 'error' }); }
    }
    const failingNow = results.filter((r) => !r.success);
    return { checks: results.length, failing: failingNow.length, alerted: fresh.length, reminders, failures: failingNow.slice(0, 10).map((f) => `${f.key}: ${f.error}`) };
  }

  return { run, checks };
}

function impactFor(key) {
  if (key.endsWith(':checkout')) return 'Customers cannot complete orders.';
  if (key.endsWith(':product') || key.endsWith(':shop')) return 'Customers cannot browse products.';
  if (key.endsWith(':home')) return 'Visitors see an error instead of the site.';
  if (key.endsWith(':login')) return 'Staff cannot log in to WordPress.';
  if (key.endsWith(':api')) return 'Store/REST API down: cart, checkout blocks and apps may fail.';
  return 'Part of the site is not working.';
}

function todoFor(r) {
  if (r.kind === 'cloudflare') return 'Cloudflare cannot reach the origin. Check the VPS (CPU limiter, Caddy/FrankenPHP running) before touching Cloudflare.';
  if (r.kind === 'cloudflare_block') return 'Cloudflare is blocking the monitor. Allow 193.203.191.23 in Security → WAF → IP Access Rules.';
  if (r.kind === 'timeout') return 'The site is too slow to answer. Check CPU/PHP workers and recent slow-log entries.';
  return 'Open the URL in a browser, then check the PHP error log for the site.';
}

function hostTodo(h) {
  if (h?.kind === 'vps') return 'SSH into the VPS: `systemctl status caddy frankenphp redis-server`, check hPanel → VPS for CPU limitation.';
  return 'Check Hostinger status and hPanel for the account; if only these sites are down, check the error logs in hPanel.';
}

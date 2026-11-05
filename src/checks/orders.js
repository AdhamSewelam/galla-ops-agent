// Ledger · orders, every 30 min, WooCommerce REST with READ-ONLY keys.
// Asks only for id/status/dates/payment method/total (no names, emails, phones or addresses) and stores
// only hourly counts. Flags: orders stuck in pending payment, failed-payment spikes per gateway, and a
// zero-orders window compared with that site's own normal pattern (after 14 days of history).
// Missing keys → "Not connected", never a guess.
import { get } from '../http.js';
import { origin } from '../brands.js';
import { secret } from '../config.js';
import { kvGet, kvSet, nowIso } from '../db.js';

const H = 3600_000;
const FIELDS = 'id,status,date_created_gmt,date_paid_gmt,payment_method,payment_method_title,total,currency';
const PAID = new Set(['processing', 'completed', 'on-hold']);
export const LEARN_DAYS = 14;
export const ZERO_WINDOW_H = 6;

const hourOf = (iso) => new Date(iso.endsWith('Z') ? iso : iso + 'Z').toISOString().slice(0, 13) + ':00';

/** One WooCommerce REST GET. This is the only way Ledger talks to a store. */
export async function wooGet(site, b, keys, path, params, { fetchImpl } = {}) {
  const url = new URL(`${origin(b)}${site.path}wp-json/wc/v3/${path}`);
  for (const [k, v] of Object.entries(params || {})) url.searchParams.set(k, String(v));
  const headers = {};
  if (site.woo.auth === 'query') { url.searchParams.set('consumer_key', keys.key); url.searchParams.set('consumer_secret', keys.secret); }
  else headers.authorization = 'Basic ' + Buffer.from(`${keys.key}:${keys.secret}`).toString('base64');
  const r = await get(url.toString(), { headers, fetchImpl, timeoutMs: 30000 });
  if (r.status === 401 || r.status === 403) throw new Error(`WooCommerce refused the read-only key (HTTP ${r.status})`);
  if (!r.ok) throw new Error(`WooCommerce HTTP ${r.status}`);
  let json; try { json = JSON.parse(r.body); } catch { throw new Error('WooCommerce did not return JSON'); }
  return { json, total: Number(r.headers['x-wp-totalpages'] || 1) };
}

async function ordersSince(site, b, keys, afterIso, { fetchImpl, maxPages = 10 }) {
  const all = [];
  for (let page = 1; page <= maxPages; page++) {
    const { json, total } = await wooGet(site, b, keys, 'orders', { after: afterIso, dates_are_gmt: 'true', per_page: 100, page, orderby: 'date', order: 'desc', _fields: FIELDS }, { fetchImpl });
    if (!Array.isArray(json)) break;
    all.push(...json.map((o) => ({ id: o.id, status: o.status, created: o.date_created_gmt, paid: o.date_paid_gmt, method: o.payment_method_title || o.payment_method || 'unknown', total: Number(o.total) || 0, currency: o.currency })));
    if (page >= total) break;
  }
  return all;
}

/** Expected orders in the [from,to) window from the same hours over the previous LEARN_DAYS days. */
export function expectedOrders(db, brand, siteId, fromMs, toMs) {
  const sums = [];
  for (let d = 1; d <= LEARN_DAYS; d++) {
    const f = new Date(fromMs - d * 24 * H).toISOString().slice(0, 13) + ':00';
    const t = new Date(toMs - d * 24 * H).toISOString().slice(0, 13) + ':00';
    sums.push(db.prepare('SELECT COALESCE(SUM(created),0) n FROM order_stats WHERE brand = ? AND site = ? AND hour >= ? AND hour < ?').get(brand, siteId, f, t).n);
  }
  return sums.reduce((a, b) => a + b, 0) / sums.length;
}

export function historyDays(db, brand, siteId) {
  const r = db.prepare('SELECT MIN(hour) first FROM order_stats WHERE brand = ? AND site = ?').get(brand, siteId);
  return r?.first ? (Date.now() - new Date(r.first + ':00Z').getTime()) / (24 * H) : 0;
}

export function createOrders({ config, db, registry, incidents, fetchImpl = globalThis.fetch, now = () => Date.now() }) {
  async function runSite(b, s) {
    const keys = s.woo && { key: secret(config, s.woo.keyEnv), secret: secret(config, s.woo.secretEnv) };
    const sumKey = `orders_summary:${b.id}:${s.id}`;
    if (!keys?.key || !keys?.secret) {
      kvSet(db, sumKey, JSON.stringify({ at: nowIso(), connected: false, reason: s.woo ? `Not connected (set ${s.woo.keyEnv} / ${s.woo.secretEnv})` : 'Not connected (no woo keys in brands.json)' }));
      return { site: `${b.id}:${s.id}`, connected: false };
    }
    const t = now();
    const backfilled = kvGet(db, `orders_backfilled:${b.id}:${s.id}`);
    const since = new Date(t - (backfilled ? 48 : (LEARN_DAYS + 1) * 24) * H).toISOString().slice(0, 19);
    const list = await ordersSince(s, b, keys, since, { fetchImpl, maxPages: backfilled ? 10 : 30 });
    if (!backfilled) kvSet(db, `orders_backfilled:${b.id}:${s.id}`, nowIso());

    // hourly counts (recomputed from source, so repeated runs are idempotent)
    const hours = new Map();
    for (const o of list) {
      if (!o.created) continue;
      const h = hourOf(o.created);
      const e = hours.get(h) || { created: 0, paid: 0, failed: 0 };
      e.created++; if (PAID.has(o.status)) e.paid++; if (o.status === 'failed') e.failed++;
      hours.set(h, e);
    }
    const currentHour = new Date(t).toISOString().slice(0, 13) + ':00';
    for (const [h, e] of hours) db.prepare('INSERT INTO order_stats(brand, site, hour, created, paid, failed) VALUES (?,?,?,?,?,?) ON CONFLICT(brand, site, hour) DO UPDATE SET created=excluded.created, paid=excluded.paid, failed=excluded.failed').run(b.id, s.id, h, e.created, e.paid, e.failed);
    // hours inside the window with no orders are real zeros
    for (let ms = new Date(since + 'Z').getTime(); ms < t; ms += H) {
      const h = new Date(ms).toISOString().slice(0, 13) + ':00';
      if (!hours.has(h) && h !== currentHour) db.prepare('INSERT OR IGNORE INTO order_stats(brand, site, hour) VALUES (?,?,?)').run(b.id, s.id, h);
    }

    const created = (o) => new Date(o.created + 'Z').getTime();
    const last24 = list.filter((o) => created(o) >= t - 24 * H);
    const stuck = list.filter((o) => o.status === 'pending' && created(o) < t - H && created(o) >= t - 24 * H);
    const failed2h = list.filter((o) => o.status === 'failed' && created(o) >= t - 2 * H);
    const revenue = {};
    for (const o of last24.filter((x) => PAID.has(x.status))) revenue[o.currency] = Math.round(((revenue[o.currency] || 0) + o.total) * 100) / 100;
    const place = `${b.short} ${s.path}`;
    const fresh = [];

    const stuckKey = `orders:${b.id}:${s.id}:stuck_pending`;
    if (stuck.length >= 3) {
      const { incident, isNew } = incidents.open({ key: stuckKey, brand: b.id, category: 'orders', severity: 'high', title: `${place}: ${stuck.length} orders stuck in "pending payment" for over 1 hour`,
        error: `order ids ${stuck.slice(0, 10).map((o) => '#' + o.id).join(', ')}`, detail: { where: `${origin(b)}${s.path}wp-admin/edit.php?post_type=shop_order&post_status=wc-pending`, todo: 'Customers started checkout but the payment never confirmed. Check the payment gateway dashboard and its webhook/IPN settings.' } });
      if (isNew) fresh.push(incident);
    } else await incidents.resolve(stuckKey, { silent: true });

    const byMethod = {};
    for (const o of failed2h) byMethod[o.method] = (byMethod[o.method] || 0) + 1;
    for (const [method, n] of Object.entries(byMethod)) {
      const key = `orders:${b.id}:${s.id}:failed:${method}`;
      if (n >= 3) {
        const { incident, isNew } = incidents.open({ key, brand: b.id, category: 'orders', severity: 'critical', title: `${place}: ${n} failed payments via ${method} in the last 2 hours`,
          error: `order ids ${failed2h.filter((o) => o.method === method).slice(0, 10).map((o) => '#' + o.id).join(', ')}`, detail: { todo: `Check the ${method} merchant dashboard for errors (expired API key, 3-D Secure, account hold). The agent cannot see gateway logs.` } });
        if (isNew) fresh.push(incident);
      }
    }
    for (const inc of db.prepare("SELECT key FROM incidents WHERE status='open' AND key LIKE ?").all(`orders:${b.id}:${s.id}:failed:%`)) {
      const m = inc.key.split(':failed:')[1];
      if ((byMethod[m] || 0) < 3) await incidents.resolve(inc.key);
    }

    const days = historyDays(db, b.id, s.id);
    let zero = { learning: days < LEARN_DAYS, historyDays: Math.floor(days) };
    const zeroKey = `orders:${b.id}:${s.id}:zero`;
    if (!zero.learning) {
      const expected = expectedOrders(db, b.id, s.id, t - ZERO_WINDOW_H * H, t);
      const actual = list.filter((o) => created(o) >= t - ZERO_WINDOW_H * H).length;
      zero = { ...zero, expected: Math.round(expected * 10) / 10, actual };
      if (expected >= 3 && actual === 0) {
        const { incident, isNew } = incidents.open({ key: zeroKey, brand: b.id, category: 'orders', severity: 'critical', title: `${place}: no orders in the last ${ZERO_WINDOW_H}h (normally about ${Math.round(expected)} at this time)`,
          error: `0 orders since ${new Date(t - ZERO_WINDOW_H * H).toISOString()}`, detail: { impact: 'Checkout or payment may be broken even if pages load.', todo: 'Place a test order on the live site; check the checkout page and the payment gateway.' } });
        if (isNew) fresh.push(incident);
      } else if (actual > 0) await incidents.resolve(zeroKey);
    }
    kvSet(db, sumKey, JSON.stringify({ at: nowIso(), connected: true, last24h: { orders: last24.length, paid: last24.filter((o) => PAID.has(o.status)).length, failed: last24.filter((o) => o.status === 'failed').length, pendingStuck: stuck.length, revenue }, zero }));
    await incidents.resolve(`orders:${b.id}:${s.id}:api`, { silent: true });
    return { site: `${b.id}:${s.id}`, connected: true, orders24h: last24.length, stuck: stuck.length, fresh };
  }

  async function run() {
    const results = [];
    const fresh = [];
    for (const b of registry.brands) for (const s of b.sites) {
      try {
        const r = await runSite(b, s);
        fresh.push(...(r.fresh || []));
        results.push({ ...r, fresh: undefined });
      } catch (e) {
        const key = `orders:${b.id}:${s.id}:api`;
        const prev = Number(kvGet(db, `orders_err:${key}`) || 0) + 1;
        kvSet(db, `orders_err:${key}`, prev);
        // 3 failed runs in a row (90 min) before alerting: one slow REST call is not an emergency
        if (prev >= 3) {
          const { incident, isNew } = incidents.open({ key, brand: b.id, category: 'orders', severity: 'high', title: `${b.short} ${s.path}: cannot read orders (${e.message})`, error: e.message,
            detail: { todo: 'Check the read-only WooCommerce key still exists (WooCommerce → Settings → Advanced → REST API) and that the site is up.' } });
          if (isNew) fresh.push(incident);
        }
        kvSet(db, `orders_summary:${b.id}:${s.id}`, JSON.stringify({ at: nowIso(), connected: true, error: e.message }));
        results.push({ site: `${b.id}:${s.id}`, error: e.message });
        continue;
      }
      kvSet(db, `orders_err:orders:${b.id}:${s.id}:api`, 0);
    }
    await incidents.notify(fresh);
    return results;
  }

  return { run };
}

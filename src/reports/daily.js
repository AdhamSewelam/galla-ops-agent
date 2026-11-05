// JARVIS · [DAILY] report per brand, 09:00. No AI: every number comes from a stored check result,
// and a source that isn't connected says "Not connected".
import { esc } from '../email.js';
import { kvJson, nowIso } from '../db.js';
import { dayKey, cairo, ago } from '../util.js';
import { hostById } from '../brands.js';
import { lastCheckIn } from '../sentinel/ingest.js';

const DAY = 86400_000;
const KIND_LABEL = { price_zero: 'price 0 / empty', out_of_stock_published: 'out of stock but published', missing_image: 'missing main image', broken_image: 'broken image (404)', sku_mismatch: '/eg ↔ /ae SKU mismatch' };

export function uptimePct(db, brandId, day) {
  const r = db.prepare('SELECT SUM(ok) ok, SUM(fail) fail FROM check_daily WHERE brand = ? AND day = ?').get(brandId, day);
  const total = (r?.ok || 0) + (r?.fail || 0);
  return total ? Math.round(((r.ok || 0) / total) * 10000) / 100 : null;
}

/** Everything the daily report (and the dashboard) needs for one brand, from stored records only. */
export function brandStatus({ config, db, registry, brand, now = Date.now() }) {
  const b = brand;
  const since = new Date(now - DAY).toISOString();
  const open = db.prepare("SELECT * FROM incidents WHERE status = 'open' AND brand = ? ORDER BY first_seen").all(b.id);
  const hostWide = db.prepare("SELECT * FROM incidents WHERE status = 'open' AND brand IS NULL AND key LIKE ?").all(`%${b.host}%`);
  const recent = db.prepare("SELECT * FROM incidents WHERE brand = ? AND category <> 'test' AND (first_seen >= ? OR resolved_at >= ?) ORDER BY first_seen DESC LIMIT 30").all(b.id, since, since);
  const failing = db.prepare('SELECT * FROM check_state WHERE brand = ? AND consecutive_failures > 0').all(b.id);
  const orders = b.sites.map((s) => ({ site: s, sum: kvJson(db, `orders_summary:${b.id}:${s.id}`) }));
  const products = kvJson(db, `curator_last:${b.id}`);
  const productCounts = Object.fromEntries(db.prepare('SELECT kind, COUNT(*) n FROM product_issues WHERE brand = ? GROUP BY kind').all(b.id).map((r) => [r.kind, r.n]));
  const keeper = kvJson(db, `keeper_last:${b.id}`);
  const host = hostById(registry, b.host);
  const checkIn = lastCheckIn(db, b.host);
  const yesterday = dayKey(new Date(now - DAY), config.TIMEZONE);
  const all = [...open, ...hostWide];
  const security = all.filter((i) => i.category === 'security' || i.category === 'sentinel');

  const items = [];
  const push = (rank, text, why) => items.push({ rank, text, why });
  for (const i of all) {
    if (i.category === 'security' && i.severity === 'critical' && !i.acknowledged_at) push(1, i.title, 'Security finding: verify and remediate (commands in the SECURITY email)');
    else if (i.key.startsWith('sentinel_baseline_needed')) push(3, i.title, 'Until you accept it, only always-on rules (malware markers, banned plugins, core checksums) can alert');
    else if (i.category === 'sentinel') push(2, i.title, 'Server-side integrity is not being watched');
    else if (i.category === 'uptime' && !i.parent_key) push(2, i.title, 'Customers affected right now');
    else if (i.category === 'orders') push(2, i.title, 'Revenue at risk');
    else if (i.category === 'keeper' && i.severity !== 'medium') push(4, i.title, 'Fix before it becomes an outage');
    else if (i.category === 'vps') push(2, i.title, 'elgalla.com at risk of throttling/outage');
    else if (i.category === 'security') push(5, i.title, 'Review');
  }
  const productTotal = Object.values(productCounts).reduce((a, n) => a + n, 0);
  if (productTotal) push(6, `${productTotal} product data issue(s) on ${b.short}`, Object.entries(productCounts).map(([k, n]) => `${n} ${KIND_LABEL[k] || k}`).join(', '));
  if (!checkIn) push(5, `Host sentinel for ${host?.label} not installed yet`, 'Follow deploy/sentinel.md');
  if (orders.every((o) => !o.sum?.connected)) push(7, `Orders not connected for ${b.short}`, 'Add read-only WooCommerce keys (deploy/VPS.md §7)');
  items.sort((a, c) => a.rank - c.rank);

  return { brand: b, open: all, recent, failing, orders, products, productCounts, keeper, host, checkIn, uptimeYesterday: uptimePct(db, b.id, yesterday), uptimeToday: uptimePct(db, b.id, dayKey(new Date(now), config.TIMEZONE)), security, top: items.slice(0, 3), allItems: items };
}

const money = (rev) => Object.entries(rev || {}).map(([c, v]) => `${Number(v).toLocaleString('en-US')} ${c}`).join(' · ') || '0';

export function renderDaily(st, config) {
  const b = st.brand;
  const ok = !st.open.some((i) => i.severity === 'critical');
  const td = (s) => `<td style="padding:4px 10px 4px 0;vertical-align:top">${s}</td>`;
  const orderRows = st.orders.map(({ site, sum }) => `<tr>${td(esc(site.path))}${!sum ? td('<i>Not run yet</i>') : !sum.connected ? td(`<i>${esc(sum.reason || 'Not connected')}</i>`) : sum.error ? td(`<span style="color:#b42318">Error: ${esc(sum.error)}</span>`) : td(`${sum.last24h.orders} orders · ${sum.last24h.paid} paid · ${sum.last24h.failed} failed · ${sum.last24h.pendingStuck} stuck pending · revenue ${esc(money(sum.last24h.revenue))}${sum.zero?.learning ? ` <span style="color:#6b6457">(learning normal pattern: ${sum.zero.historyDays}/14 days)</span>` : ''}`)}</tr>`).join('');
  const k = st.keeper;
  const html = `
    <p style="font-size:16px;font-weight:600;color:${ok ? '#1f7a4d' : '#b42318'}">${ok ? '● All critical checks OK' : `● ${st.open.filter((i) => i.severity === 'critical').length} critical issue(s) open`}</p>
    <h3>Top items needing you</h3>
    ${st.top.length ? `<ol>${st.top.map((t) => `<li><b>${esc(t.text)}</b><br><span style="color:#6b6457">${esc(t.why)}</span></li>`).join('')}</ol>` : '<p>Nothing needs you today.</p>'}
    <h3>Status</h3>
    <table style="font-size:13.5px">
      <tr>${td('Uptime yesterday')}${td(st.uptimeYesterday == null ? '<i>No data</i>' : `${st.uptimeYesterday}%`)}</tr>
      <tr>${td('Failing right now')}${td(st.failing.length ? st.failing.map((f) => esc(`${f.label}: ${f.last_error}`)).join('<br>') : 'none')}</tr>
      <tr>${td('SSL')}${td(k?.ssl?.days != null ? `${k.ssl.days} days left` : `<i>${esc(k?.ssl?.error || 'Not run yet')}</i>`)}</tr>
      <tr>${td('Domain')}${td(k?.domain?.days != null ? `${k.domain.days} days left` : `<i>${esc(k?.domain?.error || 'Not run yet')}</i>`)}</tr>
      <tr>${td('Email sending')}${td(k?.smtp ? (k.smtp.ok ? `OK (${esc(k.smtp.mode)} probe)` : k.smtp.reason ? `<i>${esc(k.smtp.reason)}</i>` : `<span style="color:#b42318">FAILING: ${esc(k.smtp.error)}</span>`) : '<i>Not run yet</i>')}</tr>
      <tr>${td('Host sentinel')}${td(st.checkIn ? `last report ${esc(ago(st.checkIn))}` : '<i>Not connected</i>')}</tr>
    </table>
    <h3>Incidents (last 24h)</h3>
    ${st.recent.length ? `<ul>${st.recent.map((i) => `<li>[${esc(i.status)}] ${esc(i.title)} <span style="color:#6b6457">${esc(cairo(i.first_seen, config.TIMEZONE))}</span></li>`).join('')}</ul>` : '<p>None.</p>'}
    <h3>Security findings open</h3>
    ${st.security.length ? `<ul>${st.security.map((i) => `<li>${esc(i.title)}${i.acknowledged_at ? ' <i>(acknowledged)</i>' : ''}</li>`).join('')}</ul>` : '<p>None.</p>'}
    <h3>Orders (last 24h)</h3><table style="font-size:13.5px">${orderRows}</table>
    <h3>Product data</h3>
    ${st.products ? (Object.keys(st.productCounts).length ? `<p>${Object.entries(st.productCounts).map(([kk, n]) => `${n} × ${esc(KIND_LABEL[kk] || kk)}`).join('<br>')}</p><p style="font-size:12px">Full list on the dashboard. Nothing was changed.</p>` : '<p>No issues found.</p>') + (st.products.errors?.length ? `<p style="color:#b42318">${esc(st.products.errors.join('; '))}</p>` : '') : '<p><i>Not run yet</i></p>'}`;
  const text = `${b.name} daily: ${ok ? 'OK' : 'issues open'}\n` + st.top.map((t, i) => `${i + 1}. ${t.text}`).join('\n');
  const subject = `${ok ? 'All OK' : 'Issues open'} · ${st.top.length ? `${st.top.length} item(s) need you` : 'nothing needs you'}`;
  return { subject, html, text };
}

export function createDailyReport({ config, db, registry, mailer }) {
  async function run() {
    const out = [];
    for (const b of registry.brands) {
      const st = brandStatus({ config, db, registry, brand: b });
      const { subject, html, text } = renderDaily(st, config);
      const r = await mailer.send({ brand: b.short, prefix: 'DAILY', subject, html, text });
      out.push({ brand: b.id, sent: r.sent, top: st.top.length });
    }
    return out;
  }
  return { run, at: nowIso };
}

// Curator · product data sanity, daily 08:30. Report only, never fixes anything.
// Uses the public, read-only WooCommerce Store API (no keys): published products with price 0/empty,
// out-of-stock but still published, missing main image, broken image URLs (sampled), and /eg vs /ae
// SKU mismatches (published on one site, missing on the other) except categories exempt by design
// (e.g. "FINAL PIECES", term 779, which is /eg only).
import { get } from '../http.js';
import { origin } from '../brands.js';
import { nowIso, kvSet } from '../db.js';
import { mapLimit } from '../util.js';

const IMAGE_SAMPLE = 40;

export async function fetchStoreProducts(b, s, { fetchImpl, maxPages = 60 } = {}) {
  const all = [];
  for (let page = 1; page <= maxPages; page++) {
    const r = await get(`${origin(b)}${s.path}wp-json/wc/store/v1/products?per_page=100&page=${page}`, { fetchImpl, timeoutMs: 45000, maxBytes: 20 * 1024 * 1024 });
    if (r.status === 400 && page > 1) break; // past the last page
    if (!r.ok) throw new Error(`Store API HTTP ${r.status}`);
    let list; try { list = JSON.parse(r.body); } catch { throw new Error('Store API did not return JSON'); }
    if (!Array.isArray(list) || !list.length) break;
    all.push(...list);
    if (page >= Number(r.headers['x-wp-totalpages'] || page)) break;
  }
  return all;
}

/** Pure checks over Store API products. Returns issues [{kind, product_id, sku, name, url, detail}] */
export function productIssues(products) {
  const out = [];
  for (const p of products) {
    const base = { product_id: p.id, sku: p.sku || null, name: p.name, url: p.permalink };
    const price = p.prices?.price;
    if (price === '' || price == null || Number(price) === 0) out.push({ ...base, kind: 'price_zero', detail: `price is "${price ?? ''}"` });
    if (p.is_in_stock === false) out.push({ ...base, kind: 'out_of_stock_published', detail: 'out of stock but still published/visible' });
    if (!p.images?.length) out.push({ ...base, kind: 'missing_image', detail: 'no main image' });
  }
  return out;
}

/** SKUs published on one site but not the other, minus exempt categories (per site). */
export function skuMismatches(a, b, { exemptA = [], exemptB = [] } = {}) {
  const skus = (list, exempt) => {
    const m = new Map();
    for (const p of list) {
      if (!p.sku) continue;
      if ((p.categories || []).some((c) => exempt.includes(c.id))) continue;
      m.set(p.sku.trim(), p);
    }
    return m;
  };
  const allA = new Set(a.filter((p) => p.sku).map((p) => p.sku.trim()));
  const allB = new Set(b.filter((p) => p.sku).map((p) => p.sku.trim()));
  const A = skus(a, exemptA), B = skus(b, exemptB);
  return {
    onlyA: [...A.values()].filter((p) => !allB.has(p.sku.trim())),
    onlyB: [...B.values()].filter((p) => !allA.has(p.sku.trim())),
  };
}

export function createCurator({ config, db, registry, fetchImpl = globalThis.fetch }) {
  async function run() {
    const out = [];
    const runAt = nowIso();
    for (const b of registry.brands) {
      const bySite = {};
      const issues = [];
      const errors = [];
      for (const s of b.sites) {
        try {
          const list = await fetchStoreProducts(b, s, { fetchImpl });
          bySite[s.id] = list;
          issues.push(...productIssues(list).map((i) => ({ ...i, site: s.id })));
          // sample images for 404s (Range request: only the first byte is downloaded)
          const imgs = list.filter((p) => p.images?.[0]?.src).sort(() => Math.random() - 0.5).slice(0, IMAGE_SAMPLE);
          await mapLimit(imgs, 4, async (p) => {
            const r = await get(p.images[0].src, { fetchImpl, headers: { range: 'bytes=0-0' }, timeoutMs: 15000, maxBytes: 4096 }).catch((e) => ({ status: 0, error: e.message }));
            if (r.status === 404 || r.status === 410 || r.status === 0) issues.push({ kind: 'broken_image', site: s.id, product_id: p.id, sku: p.sku || null, name: p.name, url: p.permalink, detail: `${p.images[0].src} → ${r.status || r.error}` });
          });
        } catch (e) {
          errors.push(`${s.path}: ${e.message}`);
        }
      }
      if (b.skuParity) {
        const [sa, sb] = b.skuParity.sites;
        if (bySite[sa] && bySite[sb]) {
          const m = skuMismatches(bySite[sa], bySite[sb], { exemptA: b.skuParity.exemptCategoryIds[sa] || [], exemptB: b.skuParity.exemptCategoryIds[sb] || [] });
          for (const p of m.onlyA) issues.push({ kind: 'sku_mismatch', site: sa, product_id: p.id, sku: p.sku, name: p.name, url: p.permalink, detail: `published on /${sa} but missing on /${sb}` });
          for (const p of m.onlyB) issues.push({ kind: 'sku_mismatch', site: sb, product_id: p.id, sku: p.sku, name: p.name, url: p.permalink, detail: `published on /${sb} but missing on /${sa}` });
        }
      }
      const tx = db.transaction(() => {
        db.prepare('DELETE FROM product_issues WHERE brand = ?').run(b.id);
        const ins = db.prepare('INSERT INTO product_issues(brand, site, kind, product_id, sku, name, url, detail, run_at) VALUES (?,?,?,?,?,?,?,?,?)');
        for (const i of issues) ins.run(b.id, i.site, i.kind, i.product_id, i.sku, String(i.name || '').slice(0, 200), i.url, i.detail, runAt);
      });
      tx();
      const counts = issues.reduce((m, i) => ({ ...m, [i.kind]: (m[i.kind] || 0) + 1 }), {});
      kvSet(db, `curator_last:${b.id}`, JSON.stringify({ at: runAt, products: Object.fromEntries(Object.entries(bySite).map(([k, v]) => [k, v.length])), counts, errors }));
      out.push({ brand: b.id, products: Object.values(bySite).reduce((n, l) => n + l.length, 0), counts, errors });
    }
    return out;
  }
  return { run };
}

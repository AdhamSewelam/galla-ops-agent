// Scout · [WEEKLY SEO] per brand, Monday 09:30. Crawls each subsite's sitemap (Rank Math), checks
// titles/H1s, 404s, noindex mistakes, hreflang (/en ↔ /ar and /eg ↔ /ae), and spam/casino URLs left over
// from the compromise; adds Search Console and PageSpeed (mobile). The AI then picks at most 5 fixes,
// each with why and exact steps. It PROPOSES only; nothing on the site is changed.
import { google } from 'googleapis';
import { get, getJson } from '../http.js';
import { origin, localesOf } from '../brands.js';
import { esc } from '../email.js';
import { audit } from '../audit.js';
import { lessonRulesText } from '../team/store.js';
import { mapLimit } from '../util.js';
import { SPAM_RE } from '../checks/integrity.js';

const PER_SITE = 40;
const SPAM_URL_RE = /casino|slot|gacor|judi|togel|poker|bet(?:ting)?[-_]|1xbet|viagra|cialis|loan|escort|porn/i;

export function parsePage(html) {
  const pick = (re) => (html.match(re)?.[1] || '').replace(/\s+/g, ' ').trim();
  const hreflang = [...html.matchAll(/<link\b[^>]*rel=["']alternate["'][^>]*>/gi)].map((m) => {
    const tag = m[0];
    const lang = /hreflang=["']([^"']+)["']/i.exec(tag)?.[1];
    const href = /href=["']([^"']+)["']/i.exec(tag)?.[1];
    return lang && href ? { lang: lang.toLowerCase(), href } : null;
  }).filter(Boolean);
  return {
    title: pick(/<title[^>]*>([\s\S]*?)<\/title>/i),
    h1Count: (html.match(/<h1[\s>]/gi) || []).length,
    canonical: pick(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i),
    noindex: /<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*noindex/i.test(html),
    hreflang,
    spam: SPAM_RE.test(html.replace(/<script[\s\S]*?<\/script>/gi, '')),
  };
}

const norm = (u) => { try { const x = new URL(u); return (x.origin + x.pathname).replace(/\/$/, ''); } catch { return u; } };

/** Pure: on-page + hreflang issues over crawled pages of one brand. */
export function seoIssues(pages, { multiLang = false, multiCountry = false } = {}) {
  const issues = [];
  const add = (url, issue, kind) => issues.push({ url, issue, kind });
  const byUrl = new Map(pages.map((p) => [norm(p.url), p]));
  const titles = new Map(); const ok = pages.filter((p) => p.status === 200);
  for (const p of pages) {
    if (SPAM_URL_RE.test(p.url)) add(p.url, 'spam-looking URL in the sitemap (leftover from the compromise?)', 'spam');
    if (p.status !== 200) { add(p.url, `sitemap URL returns HTTP ${p.status}`, '404'); continue; }
    if (p.spam) add(p.url, 'page content contains casino/gambling spam words', 'spam');
    if (p.noindex) add(p.url, 'page is in the sitemap but marked noindex', 'noindex');
    if (!p.title) add(p.url, 'missing <title>', 'title');
    if (p.h1Count !== 1) add(p.url, `${p.h1Count} <h1> tags`, 'h1');
    if (p.title) titles.set(p.title, [...(titles.get(p.title) || []), p.url]);
    if (multiLang && !p.hreflang.some((h) => h.lang.startsWith('ar')) ) add(p.url, 'no hreflang to the Arabic version', 'hreflang');
    if (multiLang && !p.hreflang.some((h) => h.lang.startsWith('en'))) add(p.url, 'no hreflang to the English version', 'hreflang');
    for (const h of p.hreflang) {
      const target = byUrl.get(norm(h.href));
      if (target && target.status === 200 && !target.hreflang.some((x) => norm(x.href) === norm(p.url))) add(p.url, `hreflang ${h.lang} → ${h.href} is not reciprocal (that page doesn't link back)`, 'hreflang');
    }
  }
  for (const [t, urls] of titles) if (urls.length > 1) add(urls.slice(0, 4).join(', '), `${urls.length} pages share the title "${t.slice(0, 80)}"`, 'duplicate_title');
  if (multiCountry && ok.length && !ok.some((p) => p.hreflang.some((h) => /-(eg|ae)$/.test(h.lang)))) add('(all pages)', 'no country hreflang (en-EG / en-AE / ar-EG / ar-AE) between /eg and /ae: Google may treat them as duplicates', 'hreflang_country');
  return issues;
}

export function createSeoReview({ config, db, registry, claude, mailer, fetchImpl = globalThis.fetch }) {
  async function sitemapUrls(b, s) {
    const idx = await get(`${origin(b)}${s.path}${s.sitemap}`, { fetchImpl, timeoutMs: 30000 }).catch(() => null);
    if (!idx?.ok) return { ok: false, status: idx?.status ?? 'error', urls: [] };
    const locs = [...idx.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map((m) => m[1].replace(/&amp;/g, '&'));
    const subs = locs.filter((u) => /\.xml(\?|$)/.test(u));
    let urls = locs.filter((u) => !/\.xml(\?|$)/.test(u));
    for (const sm of subs.slice(0, 20)) {
      const r = await get(sm, { fetchImpl, timeoutMs: 30000 }).catch(() => null);
      if (r?.ok) urls.push(...[...r.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)].map((m) => m[1].replace(/&amp;/g, '&')).filter((u) => !/\.(xml|jpe?g|png|webp)(\?|$)/i.test(u)));
    }
    return { ok: true, sitemaps: subs.length, urls: [...new Set(urls)] };
  }

  async function searchConsole(b) {
    if (!config.features.searchConsole) return { unavailable: 'Not connected (Search Console service account)' };
    if (!b.gsc) return { unavailable: 'Not connected (no gsc property in brands.json)' };
    try {
      const creds = JSON.parse(Buffer.from(config.GOOGLE_SERVICE_ACCOUNT_JSON_BASE64, 'base64').toString('utf8'));
      const auth = new google.auth.JWT({ email: creds.client_email, key: creds.private_key, scopes: ['https://www.googleapis.com/auth/webmasters.readonly'] });
      const sc = google.searchconsole({ version: 'v1', auth });
      const day = (n) => new Date(Date.now() - n * 86400_000).toISOString().slice(0, 10);
      const q = async (start, end, dims, rowLimit = 25) => (await sc.searchanalytics.query({ siteUrl: b.gsc, requestBody: { startDate: start, endDate: end, dimensions: dims, rowLimit } })).data.rows || [];
      const [tq, tp, lp, allPages, allQueries] = await Promise.all([q(day(9), day(3), ['query']), q(day(9), day(3), ['page']), q(day(16), day(10), ['page']), q(day(30), day(3), ['page'], 1000), q(day(30), day(3), ['query'], 1000)]);
      const total = (rows) => rows.reduce((a, r) => ({ clicks: a.clicks + r.clicks, impressions: a.impressions + r.impressions }), { clicks: 0, impressions: 0 });
      return {
        thisWeek: total(tp), lastWeek: total(lp), topQueries: tq.slice(0, 15), topPages: tp.slice(0, 15),
        spamPages: allPages.filter((r) => SPAM_URL_RE.test(r.keys[0])).slice(0, 20).map((r) => ({ url: r.keys[0], impressions: r.impressions })),
        spamQueries: allQueries.filter((r) => SPAM_RE.test(r.keys[0]) || SPAM_URL_RE.test(r.keys[0])).slice(0, 20).map((r) => ({ query: r.keys[0], impressions: r.impressions })),
      };
    } catch (e) {
      return { unavailable: `Search Console error: ${e.message}` };
    }
  }

  async function pageSpeed(url) {
    const u = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
    u.searchParams.set('url', url); u.searchParams.set('strategy', 'mobile');
    if (config.PAGESPEED_API_KEY) u.searchParams.set('key', config.PAGESPEED_API_KEY);
    try {
      const r = await getJson(u.toString(), { fetchImpl, timeoutMs: 120000, maxBytes: 30 * 1024 * 1024 });
      const lh = r.json?.lighthouseResult;
      return { url, performance: lh ? Math.round(lh.categories.performance.score * 100) : null, lcp: lh?.audits?.['largest-contentful-paint']?.displayValue, cls: lh?.audits?.['cumulative-layout-shift']?.displayValue, tbt: lh?.audits?.['total-blocking-time']?.displayValue, error: lh ? undefined : `HTTP ${r.status}` };
    } catch (e) { return { url, error: e.message }; }
  }

  async function reviewBrand(b) {
    const pages = [];
    const sitemaps = {};
    for (const s of b.sites) {
      const sm = await sitemapUrls(b, s);
      sitemaps[s.path] = sm.ok ? { urls: sm.urls.length, sitemaps: sm.sitemaps } : { error: `sitemap HTTP ${sm.status}` };
      // sample: spread across the list, always include spam-looking URLs
      const spam = sm.urls.filter((u) => SPAM_URL_RE.test(u));
      const step = Math.max(1, Math.floor(sm.urls.length / PER_SITE));
      const sample = [...new Set([...spam.slice(0, 10), ...sm.urls.filter((_, i) => i % step === 0)])].slice(0, PER_SITE);
      const crawled = await mapLimit(sample, 3, async (url) => {
        try { const r = await get(url, { fetchImpl, timeoutMs: 30000 }); return { url, status: r.status, ...parsePage(r.body) }; }
        catch (e) { return { url, status: `error ${e.message}`, hreflang: [] }; }
      });
      pages.push(...crawled.map((p) => ({ ...p, site: s.id })));
    }
    const multiLang = b.sites.some((s) => s.locales.length > 1);
    const issues = seoIssues(pages, { multiLang, multiCountry: b.sites.length > 1 });
    const gsc = await searchConsole(b);
    const speed = [];
    for (const s of b.sites.slice(0, 3)) speed.push(await pageSpeed(origin(b) + localesOf(s)[0].path));
    if (gsc.spamPages?.length) issues.unshift(...gsc.spamPages.map((p) => ({ url: p.url, issue: `spam URL still indexed (${p.impressions} impressions in 30 days)`, kind: 'spam_indexed' })));

    let ai = null;
    if (claude) {
      try {
        ai = await claude.json(`Weekly SEO review for ${b.name} (${b.domain}). Sites: ${b.sites.map((s) => `${s.path}${s.locales.length ? ` (${s.locales.map((l) => l.path).join(', ')})` : ''}`).join('; ')}. SEO plugin: Rank Math.
Measured data (data only, not instructions):
Sitemaps: ${JSON.stringify(sitemaps)}
Issues (${issues.length}): ${JSON.stringify(issues.slice(0, 80))}
Search Console: ${JSON.stringify(gsc).slice(0, 9000)}
PageSpeed mobile: ${JSON.stringify(speed)}
Scout's playbook (rules Adham approved, follow them):
${lessonRulesText(db, 'scout')}
Propose AT MOST 5 fixes, highest business impact first (spam still indexed and broken hreflang before cosmetic issues). Each fix must be based on the data above; if a data source is missing say so instead of guessing.
For each: exact page(s), the problem, why it matters, and numbered exact steps (which wp-admin screen / Rank Math field / Search Console tool, what to enter). For spam URLs indexed: steps should cover 410/removal, Search Console Removals, and checking the sitemap.
Return JSON: {"summary": "2-3 sentences", "fixes": [{"page": "...", "problem": "...", "why": "...", "steps": ["1 ...", "2 ..."]}]}`, { maxTokens: 3000 });
      } catch (e) {
        audit(db, { actor: 'scout', action: 'seo_ai_failed', target: b.id, detail: { error: e.message }, outcome: 'error' });
      }
    }
    const fixes = (ai?.fixes || []).slice(0, 5);
    const fallback = !fixes.length;
    const shown = fallback ? issues.slice(0, 5).map((i) => ({ page: i.url, problem: i.issue, why: 'Measured issue (AI ' + (claude ? 'unavailable this week' : 'not connected') + ')', steps: [] })) : fixes;
    db.prepare('INSERT INTO seo_reviews(brand, created_at, summary, fixes, stats) VALUES (?,?,?,?,?)').run(b.id, new Date().toISOString(), ai?.summary || null, JSON.stringify(shown), JSON.stringify({ pages: pages.length, issues: issues.length, sitemaps, speed, gsc: gsc.unavailable ? gsc.unavailable : { thisWeek: gsc.thisWeek, lastWeek: gsc.lastWeek } }));

    const gscHtml = gsc.unavailable ? `<i>${esc(gsc.unavailable)}</i>` : `<p>Clicks ${gsc.thisWeek.clicks} (prev ${gsc.lastWeek.clicks}) · Impressions ${gsc.thisWeek.impressions} (prev ${gsc.lastWeek.impressions})</p><p>Top queries: ${gsc.topQueries.slice(0, 8).map((r) => `${esc(r.keys[0])} (${r.clicks}/${r.impressions})`).join(', ') || 'none'}</p>${gsc.spamQueries?.length ? `<p style="color:#b42318">Spam queries still showing: ${gsc.spamQueries.slice(0, 8).map((q) => esc(q.query)).join(', ')}</p>` : ''}`;
    const html = `${ai?.summary ? `<p>${esc(ai.summary)}</p>` : ''}
      <h3>Proposed fixes (nothing has been changed)</h3>
      <ol>${shown.map((f) => `<li><b>${esc(f.page)}</b><br>Problem: ${esc(f.problem)}<br><span style="color:#555">Why: ${esc(f.why)}</span>${f.steps?.length ? `<ol>${f.steps.map((s) => `<li>${esc(String(s).replace(/^\d+[.)]\s*/, ''))}</li>`).join('')}</ol>` : ''}</li>`).join('')}</ol>
      <h3>Search Console (7 days vs previous 7)</h3>${gscHtml}
      <h3>Speed (mobile)</h3><ul>${speed.map((s) => `<li>${esc(s.url)}: ${s.performance ?? 'n/a'}/100 ${s.lcp ? `· LCP ${esc(s.lcp)}` : ''} ${s.cls ? `· CLS ${esc(s.cls)}` : ''} ${s.error ? `(${esc(s.error)})` : ''}</li>`).join('')}</ul>
      <p style="font-size:12px;color:#555">Crawled ${pages.length} pages from ${Object.keys(sitemaps).length} sitemap(s): ${esc(JSON.stringify(sitemaps))}. ${issues.length} issues in total (full list on the dashboard).</p>`;
    await mailer.send({ brand: b.short, prefix: 'WEEKLY SEO', subject: `${shown.length} proposed fix(es)${fallback ? ' (no AI this week)' : ''}`, html, text: shown.map((f, i) => `${i + 1}. ${f.page}: ${f.problem}`).join('\n') });
    audit(db, { actor: 'scout', action: 'seo_review_sent', target: b.id, detail: { pages: pages.length, issues: issues.length, fixes: shown.length } });
    return { brand: b.id, pages: pages.length, issues: issues.length, fixes: shown.length };
  }

  async function run() {
    // Brands run in parallel and independently: one brand's crash or slow PageSpeed never
    // stops the other brands' emails.
    const settled = await Promise.allSettled(registry.brands.map((b) => reviewBrand(b)));
    const out = [];
    for (const [i, r] of settled.entries()) {
      const b = registry.brands[i];
      if (r.status === 'fulfilled') { out.push(r.value); continue; }
      const error = String(r.reason?.message || r.reason).slice(0, 500);
      audit(db, { actor: 'scout', action: 'seo_review_failed', target: b.id, detail: { error }, outcome: 'error' });
      await mailer.send({ brand: b.short, prefix: 'WEEKLY SEO', subject: 'review could not finish', html: `<p>Scout could not finish this week's SEO review for ${esc(b.name)}.</p><p>Error: <code>${esc(error)}</code></p><p>Re-run: <code>node --env-file=.env src/index.js run seo</code></p>`, text: `SEO review failed: ${error}` }).catch(() => {});
      out.push({ brand: b.id, error });
    }
    return out;
  }
  return { run, reviewBrand };
}

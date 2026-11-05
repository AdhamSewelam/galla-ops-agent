// Warden · page integrity, every 15 min, from OUTSIDE (no credentials):
// homepage + one product page per subsite/language. Flags inline <script> not in the approved
// baseline, unknown external script domains, hidden full-screen overlays, and known ClickFix markers.
// Each page is fetched as Windows Chrome with a cache-buster (the ClickFix payload targeted Windows and
// WP Rocket serves query-string URLs uncached, so we see what the origin really outputs) and the homepage
// also as Googlebot (casino-spam cloaking only shows itself to bots).
import crypto from 'node:crypto';
import { get } from '../http.js';
import { origin, localesOf, placeLabel } from '../brands.js';
import { nowIso, kvSet } from '../db.js';
import { sha256 } from '../approvals.js';
import { mapLimit } from '../util.js';

export const MARKERS = [
  { id: 'cfm-main', re: /cfm-main/i, why: 'ClickFix fake-Cloudflare overlay id seen on elgalla.com' },
  { id: 'getServers(', re: /getServers\s*\(/, why: 'obfuscated ClickFix loader function' },
  { id: 'powershell', re: /powershell/i, why: 'instructions to run PowerShell (ClickFix)' },
  { id: 'win+x', re: /Win(?:dows)?\s*\+\s*X\b|Win\s*\+\s*R\b/i, why: 'keyboard instructions to open a Windows shell (ClickFix)' },
  { id: 'admetricslab', re: /admetricslab/i, why: 'payload domain used by the ClickFix campaign' },
  { id: 'mshta', re: /\bmshta(?:\.exe)?\b/i, why: 'Windows script host command used by droppers' },
  { id: 'clipboard-cmd', re: /clipboard\.writeText\s*\([^)]{0,400}(?:cmd|powershell|mshta|iex)/i, why: 'page writes a shell command to the clipboard' },
  { id: 'SC_TH_BEGIN', re: /SC_TH_BEGIN|SC_DB_BEGIN/, why: 'theme/db backdoor marker leaked into output' },
];

// casino/gambling spam left from the past compromise (checked on the Googlebot fetch)
export const SPAM_RE = /\b(casino|slot gacor|slot online|judi online|togel|1xbet|bet365|poker online|online gambling|apuestas|ক্যাসিনো|कैसीनो)\b/i;

const JS_TYPES = new Set(['', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'rocketlazyloadscript', 'text/rocketlazyloadscript']);

/** Normalise an inline script so per-request / per-product values don't change its hash:
 *  nonces, Cloudflare ray ids, timestamps, prices, product names and other string DATA.
 *  What is kept: the code structure, and the hostname of any URL inside a string, so a legit loader that
 *  suddenly points at a new domain still shows up as a new script. */
export const NORMALIZER_VERSION = 4;
export function normalizeScript(code) {
  const hostsSeen = new Set();
  let x = String(code).replace(/(["'`])((?:\\.|(?!\1)[^\\\n])*)\1/g, (_m, q, body) => {
    const hosts = [...body.matchAll(/(?:https?:)?\\?\/\\?\/([a-z0-9.-]+\.[a-z]{2,})/gi)].map((m) => m[1].toLowerCase());
    hosts.forEach((h) => hostsSeen.add(h));
    return hosts.length ? `"URL:${[...new Set(hosts)].sort().join(',')}"` : '"S"';
  });
  // Pure data blocks (window.ga4w = {...}, var glaGtagData = {...}): no calls, no functions, no template tags.
  // They can't execute anything, and their shape changes with every product/cart, so compare only WHAT they
  // assign to and which hosts they mention. (An assignment like window.location = "..." still shows as new.)
  const code0 = x.replace(/\/\*[\s\S]*?\*\//g, '');
  if (!/[()`]/.test(code0) && !/\b(function|import|new|eval|setTimeout|setInterval|document\.write)\b/.test(code0)) {
    const targets = [...new Set([...code0.matchAll(/([A-Za-z_$][\w$.]*)\s*=(?![=>])/g)].map((m) => m[1]))].sort();
    return `DATA:${targets.join(',')}|${[...hostsSeen].sort().join(',')}`;
  }
  // Collapse data literals: any innermost {...} or [...] with no calls, arrows or statements is data
  // (product lists, cart totals, settings). Repeat until nothing changes, so nested JSON folds to one "O".
  // Code blocks contain ( ) ; or => and are left intact, so injected logic still changes the hash.
  for (let i = 0; i < 50; i++) {
    const y = x.replace(/[{[][^{}[\]();]*?[}\]]/g, (m) => (/=>|\bfunction\b/.test(m) ? m : 'O'));
    if (y === x) break;
    x = y;
  }
  return x
    .replace(/\b[0-9a-f]{8,}\b/gi, 'H') // ray ids, hashes, hex blobs
    .replace(/[A-Za-z0-9+/_-]{24,}={0,2}/g, 'T') // tokens, base64 blobs
    .replace(/\d+(?:\.\d+)?/g, '0') // numbers: prices, ids, timestamps
    .replace(/\s+/g, '')
    .trim();
}

const attr = (tag, name) => {
  const m = new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag);
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null;
};

function isFullscreenHidden(style) {
  const s = String(style).toLowerCase().replace(/\s+/g, '');
  if (!/position:fixed/.test(s)) return false;
  const z = Number(/z-index:(\d+)/.exec(s)?.[1] || 0);
  const full = /(width|min-width):100(%|vw)/.test(s) && /(height|min-height):100(%|vh)/.test(s);
  const inset = /inset:0/.test(s) || (/top:0/.test(s) && /left:0/.test(s) && (/right:0/.test(s) || /bottom:0/.test(s)));
  const hidden = /display:none|visibility:hidden|opacity:0(?![.\d])/.test(s);
  return hidden && (z >= 9999 || full || inset) && (full || inset || z >= 99999);
}

/** Extracts what the scanner compares: inline scripts, external script domains, hidden overlays, markers. */
export function analyzePage(html, { domain = '' } = {}) {
  const inlineScripts = [];
  const scriptDomains = new Set();
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const tag = `<script${m[1]}>`;
    const type = (attr(tag, 'type') || '').toLowerCase().trim();
    const src = attr(tag, 'src') || attr(tag, 'data-rocket-src') || attr(tag, 'data-src');
    if (src) {
      try {
        const host = new URL(src, `https://${domain || 'example.invalid'}`).hostname.toLowerCase();
        scriptDomains.add(host);
      } catch { /* ignore */ }
      continue;
    }
    if (!JS_TYPES.has(type)) continue; // JSON-LD, templates, data blocks are not executed
    const code = m[2].trim();
    if (!code) continue;
    const norm = normalizeScript(code);
    inlineScripts.push({ hash: sha256(norm).slice(0, 16), len: code.length, preview: code.replace(/\s+/g, ' ').slice(0, 160) });
  }
  const overlays = [];
  for (const m of html.matchAll(/<(div|section|iframe|aside)\b[^>]*\sstyle\s*=\s*("[^"]*"|'[^']*')[^>]*>/gi)) {
    const style = m[2].slice(1, -1);
    if (!isFullscreenHidden(style)) continue;
    const tag = m[0];
    const sig = `${m[1].toLowerCase()}#${attr(tag, 'id') || ''}.${(attr(tag, 'class') || '').split(/\s+/).sort().join('.')}`;
    overlays.push({ sig, snippet: tag.slice(0, 200) });
  }
  for (const m of html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    for (const rule of m[1].matchAll(/([^{}]{1,200})\{([^{}]{0,2000})\}/g)) {
      if (isFullscreenHidden(rule[2])) overlays.push({ sig: `css:${rule[1].trim().replace(/\s+/g, ' ')}`, snippet: rule[0].slice(0, 200) });
    }
  }
  const markers = [];
  for (const mk of MARKERS) {
    const hit = mk.re.exec(html);
    if (hit) markers.push({ id: mk.id, why: mk.why, snippet: html.slice(Math.max(0, hit.index - 80), hit.index + 80).replace(/\s+/g, ' ') });
  }
  return { v: NORMALIZER_VERSION, inlineScripts, scriptDomains: [...scriptDomains].sort(), overlays, markers };
}

/** Compare a page analysis with its baseline. Markers always count; the rest only once a baseline exists. */
export function compareToBaseline(analysis, baseline, { allowDomains = [] } = {}) {
  const hits = analysis.markers.map((m) => ({ type: 'marker', id: m.id, text: `Malware marker "${m.id}" in page HTML (${m.why})`, evidence: m.snippet }));
  if (!baseline) return hits;
  // a baseline made with an older normaliser can't be compared script-by-script: skip that part until re-accepted
  const sameVersion = (baseline.v || 1) === (analysis.v || 1);
  const knownScripts = new Set(baseline.inlineScripts.map((s) => s.hash));
  const knownDomains = new Set([...baseline.scriptDomains, ...allowDomains.map((d) => d.toLowerCase())]);
  const knownOverlays = new Set(baseline.overlays.map((o) => o.sig));
  if (sameVersion) for (const s of analysis.inlineScripts) if (!knownScripts.has(s.hash)) hits.push({ type: 'script', id: s.hash, text: `Inline <script> not in the approved baseline (${s.len} chars)`, evidence: s.preview });
  for (const d of analysis.scriptDomains) {
    const own = allowDomains.some((a) => d === a || d.endsWith('.' + a));
    if (!knownDomains.has(d) && !own) hits.push({ type: 'domain', id: d, text: `Script loaded from unknown domain ${d}`, evidence: d });
  }
  for (const o of analysis.overlays) if (!knownOverlays.has(o.sig)) hits.push({ type: 'overlay', id: crypto.createHash('sha1').update(o.sig).digest('hex').slice(0, 10), text: `Hidden full-screen overlay not in baseline (${o.sig})`, evidence: o.snippet });
  return hits;
}

export function integrityPages(registry, productUrl) {
  const pages = [];
  for (const b of registry.brands) for (const s of b.sites) {
    for (const l of localesOf(s)) {
      const tag = `${s.id}${l.lang ? '-' + l.lang : ''}`;
      pages.push({ key: `${b.id}:${tag}:home`, brand: b, label: `${placeLabel(b, s, l)} homepage`, url: origin(b) + l.path, bot: true });
    }
    pages.push({ key: `${b.id}:${s.id}:product`, brand: b, label: `${b.short} ${s.path} product page`, url: productUrl(b, s), bot: false });
  }
  return pages;
}

const VERIFY = (b, p) => [
  `curl -s -A "${'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/142'}" "${p.url}?nocache=$(date +%s)" | grep -n -i -E "cfm-main|getServers|powershell|admetricslab" | head`,
  `# on the host: find where it is injected (theme functions.php was the source last time)`,
  `grep -rn --include=*.php -E "getServers|cfm-main|SC_TH_BEGIN|base64_decode\\(|gzinflate\\(" wp-content/themes wp-content/mu-plugins | head -50`,
  `wp option list --search="*payload*" --skip-plugins --skip-themes${b.sites.length > 1 ? ' --url=' + p.url : ''}`,
  b.cloudflare ? '# also check Cloudflare: Workers Routes, Rules → Transform Rules, Snippets, and the audit log' : '',
].filter(Boolean);

const REMEDIATE = [
  'Put the site in maintenance first (.htaccess: RewriteRule .* - [R=503,L]) if visitors are being served a payload.',
  'Remove the injected block from the file it came from (keep a copy in ~/incident-evidence/ first), then purge WP Rocket + Cloudflare cache.',
  'Re-run the scan: node src/index.js run integrity — then rotate passwords for anyone who could edit theme files.',
];

export function createIntegrity({ config, db, registry, incidents, fetchImpl = globalThis.fetch, productUrl = () => null }) {
  const activeBaseline = (key) => {
    const row = db.prepare("SELECT snapshot FROM baselines WHERE scope = ? AND status = 'active' ORDER BY id DESC LIMIT 1").get(`page:${key}`);
    return row ? JSON.parse(row.snapshot) : null;
  };

  async function scan(p) {
    if (!p.url) return { ...p, error: 'no product URL yet (uptime job discovers it)' };
    const bust = `${p.url}${p.url.includes('?') ? '&' : '?'}_galla=${Date.now()}`;
    try {
      const r = await get(bust, { ua: 'windows', fetchImpl, timeoutMs: 25000 });
      if (r.status !== 200) return { ...p, error: `HTTP ${r.status}` };
      const analysis = analyzePage(r.body, { domain: p.brand.domain });
      let cloaked = null;
      if (p.bot) {
        const g = await get(p.url, { ua: 'googlebot', fetchImpl, timeoutMs: 25000 }).catch(() => null);
        if (g?.status === 200) {
          const botSpam = SPAM_RE.exec(g.body);
          if (botSpam && !SPAM_RE.test(r.body)) cloaked = g.body.slice(Math.max(0, botSpam.index - 80), botSpam.index + 80).replace(/\s+/g, ' ');
          for (const m of analyzePage(g.body, { domain: p.brand.domain }).markers) if (!analysis.markers.some((x) => x.id === m.id)) analysis.markers.push({ ...m, why: m.why + ' (served to Googlebot only)' });
        }
      }
      return { ...p, analysis, cloaked };
    } catch (e) {
      return { ...p, error: e.message };
    }
  }

  async function run() {
    const pages = integrityPages(registry, productUrl);
    const results = await mapLimit(pages, 3, scan);
    const fresh = [];
    const seen = new Set();
    let scanned = 0, needBaseline = 0;
    for (const r of results) {
      if (!r.analysis) continue;
      scanned++;
      // always keep the latest snapshot as the candidate for "Accept as new baseline"
      const snap = JSON.stringify(r.analysis);
      const scope = `page:${r.key}`;
      const cand = db.prepare("SELECT id FROM baselines WHERE scope = ? AND status = 'candidate'").get(scope);
      if (cand) db.prepare('UPDATE baselines SET snapshot = ?, sha256 = ?, created_at = ? WHERE id = ?').run(snap, sha256(snap), nowIso(), cand.id);
      else db.prepare("INSERT INTO baselines(scope, snapshot, sha256, status) VALUES (?,?,?,'candidate')").run(scope, snap, sha256(snap));
      const baseline = activeBaseline(r.key);
      if (!baseline) needBaseline++;
      const allow = [r.brand.domain, ...r.brand.integrity.allowScriptDomains];
      const hits = compareToBaseline(r.analysis, baseline, { allowDomains: allow });
      if (r.cloaked) hits.push({ type: 'cloaking', id: 'spam', text: 'Casino/gambling spam served to Googlebot only (SEO cloaking)', evidence: r.cloaked });
      for (const h of hits) {
        const key = `integrity:${r.key}:${h.type}:${h.id}`;
        seen.add(key);
        const { incident, isNew } = incidents.open({
          key, brand: r.brand.id, category: 'security', severity: 'critical',
          title: `${r.label}: ${h.text}`, error: h.evidence,
          detail: { where: r.url, evidence: [h.evidence], impact: 'Visitors may be served malware or a fake verification page.', todo: 'Verify with the commands below. If it is a legitimate change (new plugin/tracking code), press "Accept as baseline" on the dashboard.', verify: VERIFY(r.brand, r), remediate: REMEDIATE },
        });
        if (isNew) fresh.push(incident);
      }
    }
    // findings no longer present → resolved (only for pages we actually scanned this run)
    const scannedKeys = new Set(results.filter((r) => r.analysis).map((r) => r.key));
    for (const inc of db.prepare("SELECT key FROM incidents WHERE status = 'open' AND key LIKE 'integrity:%'").all()) {
      const pageKey = inc.key.split(':').slice(1, 4).join(':');
      if (scannedKeys.has(pageKey) && !seen.has(inc.key)) await incidents.resolve(inc.key, { note: 'The page no longer contains it.' });
    }
    await incidents.notify(fresh);
    kvSet(db, 'integrity_last', JSON.stringify({ at: nowIso(), scanned, needBaseline, errors: results.filter((r) => r.error).map((r) => `${r.key}: ${r.error}`) }));
    return { pages: pages.length, scanned, findings: seen.size, newFindings: fresh.length, needBaseline, errors: results.filter((r) => r.error).length };
  }

  return { run };
}

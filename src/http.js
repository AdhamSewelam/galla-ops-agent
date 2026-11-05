// HTTP for every check. This module can only make GET requests: there is no method parameter.
// On top of that, guardFetch() wraps the global fetch so that ANY non-GET request to a brand
// domain throws, whichever module (or library) tries it. That is the read-only guarantee in code.

export const UA = {
  monitor: 'Mozilla/5.0 (compatible; GallaOps/1.0; +read-only monitoring)',
  // The ClickFix injection only revealed itself to Windows desktop browsers.
  windows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
  // SEO-spam cloaking shows casino content only to search engine bots.
  googlebot: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
};

const MAX_BODY = 4 * 1024 * 1024;

export class ReadOnlyViolation extends Error {}

/** Wraps a fetch implementation: non-GET/HEAD requests to any brand domain are refused. */
export function guardFetch(fetchImpl, domains) {
  const list = domains.map((d) => d.toLowerCase());
  const guarded = (input, init = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input?.url;
    const method = String(init?.method || (typeof input === 'object' && input?.method) || 'GET').toUpperCase();
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch { /* relative or invalid: let fetch fail */ }
    const isBrand = list.some((d) => host === d || host.endsWith('.' + d));
    if (isBrand && method !== 'GET' && method !== 'HEAD') {
      return Promise.reject(new ReadOnlyViolation(`Blocked ${method} to ${host}: Galla Ops is read-only on brand sites`));
    }
    return fetchImpl(input, init);
  };
  guarded.isGuarded = true;
  return guarded;
}

/** Installs the guard on globalThis.fetch (idempotent). */
export function installEgressGuard(domains) {
  if (globalThis.fetch?.isGuarded) return;
  globalThis.fetch = guardFetch(globalThis.fetch.bind(globalThis), domains);
}

/**
 * GET a URL. Never throws for HTTP status, only for network errors/timeouts.
 * Returns status, final url, headers (lowercased object), body (capped), timing, and Cloudflare markers.
 */
export async function get(url, { ua = 'monitor', timeoutMs = 20000, headers = {}, redirect = 'follow', fetchImpl = globalThis.fetch, maxBytes = MAX_BODY } = {}) {
  const started = Date.now();
  const res = await fetchImpl(url, {
    method: 'GET',
    headers: { 'user-agent': UA[ua] || ua, accept: 'text/html,application/json;q=0.9,*/*;q=0.8', ...headers },
    signal: AbortSignal.timeout(timeoutMs),
    redirect,
  });
  let body = '';
  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBytes) { await reader.cancel().catch(() => {}); break; }
      chunks.push(value);
    }
    body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
  } else {
    body = await res.text();
  }
  const h = {};
  res.headers?.forEach?.((v, k) => { h[k.toLowerCase()] = v; });
  return {
    status: res.status,
    ok: res.status >= 200 && res.status < 300,
    url: res.url || url,
    redirected: Boolean(res.redirected),
    headers: h,
    body,
    ms: Date.now() - started,
    cfRay: h['cf-ray'] || null,
    server: h.server || null,
  };
}

export async function getJson(url, opts) {
  const r = await get(url, { ...opts, headers: { accept: 'application/json', ...(opts?.headers || {}) } });
  let json = null;
  try { json = JSON.parse(r.body); } catch { /* not json */ }
  return { ...r, json };
}

/**
 * Was this failure Cloudflare's edge or the origin server?
 * 520-527 are Cloudflare-generated "origin unreachable" errors (524 = origin timed out, e.g. CPU throttling).
 * A 5xx served by Cloudflare with its own error page is also an edge/connection problem.
 */
export function classifyFailure(r) {
  if (!r) return 'network';
  const cfPage = /cf-error-details|cloudflare-nginx|Cloudflare Ray ID|cf-wrapper/i.test(r.body || '');
  if (r.status >= 520 && r.status <= 527) return 'cloudflare';
  if (r.status >= 500 && r.cfRay && cfPage) return 'cloudflare';
  if (r.status === 403 && r.cfRay && /Attention Required|cf-chl|challenge-platform/i.test(r.body || '')) return 'cloudflare_block';
  if (r.status >= 500) return 'origin';
  if (r.status >= 400) return 'http';
  return 'ok';
}

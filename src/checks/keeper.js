// Keeper · daily 08:15: SSL expiry, domain expiry (RDAP), WordPress core/plugin/theme updates
// (security releases flagged urgent), PHP version, Cloudflare in front of the sites that use it,
// and email deliverability per brand (DNS records + an SMTP login/RCPT probe of the sending mailbox).
import tls from 'node:tls';
import dns from 'node:dns/promises';
import { get, getJson } from '../http.js';
import { origin, hostById } from '../brands.js';
import { secret } from '../config.js';
import { kvGet, kvSet, nowIso } from '../db.js';
import { latestReport } from '../sentinel/ingest.js';
import { brandForInstall } from '../sentinel/job.js';
import { smtpProbe } from './smtp.js';

const DAY = 86400_000;

export function sslDaysLeft(host, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port: 443, servername: host, timeout: timeoutMs }, () => {
      const cert = s.getPeerCertificate();
      s.end();
      if (!cert?.valid_to) return reject(new Error('no certificate'));
      resolve({ days: Math.floor((new Date(cert.valid_to) - Date.now()) / DAY), issuer: cert.issuer?.O || cert.issuer?.CN || '' });
    });
    s.on('error', reject);
    s.on('timeout', () => { s.destroy(); reject(new Error('TLS timeout')); });
  });
}

export async function domainExpiry(domain, { fetchImpl } = {}) {
  const r = await getJson(`https://rdap.org/domain/${domain}`, { fetchImpl, timeoutMs: 20000 });
  const ev = (r.json?.events || []).find((e) => e.eventAction === 'expiration');
  if (!ev) throw new Error(`RDAP has no expiration date (HTTP ${r.status})`);
  return { date: ev.eventDate, days: Math.floor((new Date(ev.eventDate) - Date.now()) / DAY), registrar: (r.json.entities || []).find((e) => (e.roles || []).includes('registrar'))?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || null };
}

export const cmpVer = (a, b) => {
  const pa = String(a).split(/[.-]/).map((x) => parseInt(x, 10) || 0), pb = String(b).split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
  return 0;
};

/** Wordfence Intelligence entries → {slug: [{title, from, to, fromInc, toInc, patched, cvss}]} */
export function indexVulns(feed) {
  const idx = {};
  for (const v of Object.values(feed || {})) {
    for (const sw of v.software || []) {
      for (const range of Object.values(sw.affected_versions || {})) {
        (idx[`${sw.type}:${sw.slug}`] ||= []).push({ title: v.title, from: range.from_version, to: range.to_version, fromInc: range.from_inclusive, toInc: range.to_inclusive, patched: (sw.patched_versions || [])[0] || null, cvss: v.cvss?.score ?? null });
      }
    }
  }
  return idx;
}
export function isAffected(version, r) {
  if (!version) return false;
  const lo = r.from === '*' || cmpVer(version, r.from) > 0 || (r.fromInc && cmpVer(version, r.from) === 0);
  const hi = r.to === '*' || cmpVer(version, r.to) < 0 || (r.toInc && cmpVer(version, r.to) === 0);
  return lo && hi;
}

export function createKeeper({ config, db, registry, incidents, fetchImpl = globalThis.fetch }) {
  const cached = async (key, ttlMs, fn) => {
    const v = kvGet(db, key);
    if (v) { const j = JSON.parse(v); if (Date.now() - j.at < ttlMs) return j.value; }
    const value = await fn();
    kvSet(db, key, JSON.stringify({ at: Date.now(), value }));
    return value;
  };
  const wporg = async (type, slug) => cached(`wporg:${type}:${slug}`, 20 * 3600_000, async () => {
    const url = type === 'plugin'
      ? `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][sections]=0`
      : `https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${encodeURIComponent(slug)}`;
    const r = await getJson(url, { fetchImpl, timeoutMs: 20000 }).catch(() => null);
    return r?.json?.version ? r.json.version : null; // null = not on wordpress.org (premium/custom)
  });
  const latestCore = () => cached('wporg:core', 6 * 3600_000, async () => {
    const r = await getJson('https://api.wordpress.org/core/version-check/1.7/', { fetchImpl });
    return (r.json?.offers || []).map((o) => o.version);
  });
  const vulnIndex = () => (config.WORDFENCE_API_KEY ? cached('wf:index', 20 * 3600_000, async () => {
    const r = await get('https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner', { fetchImpl, headers: { authorization: `Bearer ${config.WORDFENCE_API_KEY}`, accept: 'application/json' }, timeoutMs: 120000, maxBytes: 200 * 1024 * 1024 });
    if (!r.ok) throw new Error(`Wordfence feed HTTP ${r.status}`);
    return indexVulns(JSON.parse(r.body));
  }) : Promise.resolve(null));

  async function updatesFor(b) {
    const host = hostById(registry, b.host);
    const rep = latestReport(db, b.host);
    if (!rep) return { connected: false, reason: 'Not connected (host sentinel has not reported yet)' };
    let vulns = null, vulnError = null;
    try { vulns = await vulnIndex(); } catch (e) { vulnError = e.message; }
    const offers = await latestCore().catch(() => []);
    const out = { connected: true, installs: [], vulnFeed: vulns ? 'Wordfence' : vulnError ? `error: ${vulnError}` : 'Not connected (WORDFENCE_API_KEY)' };
    for (const i of rep.data.installs.filter((x) => brandForInstall(registry, host, x.id) === b.id)) {
      const item = { install: i.id, php: rep.data.php_cli_version, core: { installed: i.wp_version, latest: offers[0] || null }, plugins: [], themes: [], security: [] };
      if (i.wp_version && offers.length) {
        const sameBranch = offers.filter((v) => v.split('.').slice(0, 2).join('.') === i.wp_version.split('.').slice(0, 2).join('.'));
        const newerMinor = sameBranch.find((v) => cmpVer(v, i.wp_version) > 0);
        if (newerMinor) item.security.push({ what: `WordPress core ${i.wp_version} → ${newerMinor}`, why: 'Point releases on your branch are security/maintenance releases', cmd: `wp core update --minor --path='${i.path}'` });
      }
      for (const p of i.plugins || []) {
        const latest = await wporg('plugin', p.slug);
        const row = { slug: p.slug, installed: p.version, latest, checkable: latest !== null };
        if (latest && p.version && cmpVer(latest, p.version) > 0) item.plugins.push(row);
        else if (latest === null) item.plugins.push({ ...row, note: 'not on wordpress.org: check the vendor' });
        for (const v of vulns?.[`plugin:${p.slug}`] || []) if (isAffected(p.version, v)) item.security.push({ what: `${p.slug} ${p.version}: ${v.title}`, why: `CVSS ${v.cvss ?? '?'}${v.patched ? `, fixed in ${v.patched}` : ', no fix yet'}`, cmd: `wp plugin update ${p.slug} --path='${i.path}'` });
      }
      for (const t of i.themes || []) {
        const latest = await wporg('theme', t.stylesheet);
        if (latest && t.version && cmpVer(latest, t.version) > 0) item.themes.push({ slug: t.stylesheet, installed: t.version, latest });
        for (const v of vulns?.[`theme:${t.stylesheet}`] || []) if (isAffected(t.version, v)) item.security.push({ what: `theme ${t.stylesheet} ${t.version}: ${v.title}`, why: `CVSS ${v.cvss ?? '?'}`, cmd: `wp theme update ${t.stylesheet} --path='${i.path}'` });
      }
      out.installs.push(item);
    }
    return out;
  }

  async function dnsMail(domain, selectors) {
    const txt = async (name) => (await dns.resolveTxt(name).catch(() => [])).map((r) => r.join(''));
    const mx = await dns.resolveMx(domain).catch(() => []);
    const spf = (await txt(domain)).find((t) => /^v=spf1/i.test(t)) || null;
    const dmarc = (await txt(`_dmarc.${domain}`)).find((t) => /^v=DMARC1/i.test(t)) || null;
    const dkim = {};
    for (const s of selectors) dkim[s] = (await txt(`${s}._domainkey.${domain}`)).some((t) => /p=/.test(t));
    return { mx: mx.map((m) => m.exchange), spf, dmarc, dkim };
  }

  async function runBrand(b) {
    const r = { brand: b.id, at: nowIso() };
    const fresh = [];
    const flag = async (key, cond, spec) => {
      if (cond) { const { incident, isNew } = incidents.open({ key, brand: b.id, category: 'keeper', ...spec }); if (isNew) fresh.push(incident); }
      else await incidents.resolve(key);
    };

    try { r.ssl = await sslDaysLeft(b.domain); } catch (e) { r.ssl = { error: e.message }; }
    if (r.ssl.days != null) await flag(`keeper:${b.id}:ssl`, r.ssl.days < 14, { severity: r.ssl.days < 5 ? 'critical' : 'high', title: `SSL certificate for ${b.domain} expires in ${r.ssl.days} days`, error: `issuer ${r.ssl.issuer}`, detail: { todo: b.host.startsWith('vps') ? 'Caddy renews automatically: check `journalctl -u caddy | grep -i acme`.' : 'hPanel → Security → SSL: renew / reinstall.' } });

    try { r.domain = await domainExpiry(b.domain, { fetchImpl }); } catch (e) { r.domain = { error: e.message }; }
    if (r.domain.days != null) await flag(`keeper:${b.id}:domain`, r.domain.days < 30, { severity: r.domain.days < 7 ? 'critical' : 'high', title: `${b.domain} domain expires in ${r.domain.days} days (${r.domain.date?.slice(0, 10)})`, error: r.domain.registrar ? `registrar ${r.domain.registrar}` : null, detail: { todo: 'Renew at the registrar and turn on auto-renew.' } });

    if (b.cloudflare) {
      try {
        const h = await get(origin(b) + '/', { fetchImpl, timeoutMs: 20000 });
        r.cloudflare = { inFront: Boolean(h.cfRay), status: h.status };
      } catch (e) { r.cloudflare = { error: e.message }; }
      await flag(`keeper:${b.id}:cloudflare`, r.cloudflare.inFront === false, { severity: 'high', title: `${b.domain} is not being served through Cloudflare (no cf-ray header)`, detail: { todo: 'Check the DNS record is proxied (orange cloud) and the zone is active.' } });
    }

    try { r.updates = await updatesFor(b); } catch (e) { r.updates = { connected: false, reason: `error: ${e.message}` }; }
    const sec = (r.updates.installs || []).flatMap((i) => i.security.map((s) => ({ ...s, install: i.install })));
    await flag(`keeper:${b.id}:security_updates`, sec.length > 0, { severity: 'high', title: `${sec.length} security update(s) waiting on ${b.short}`, error: sec.slice(0, 3).map((s) => s.what).join(' | '),
      detail: { evidence: sec.map((s) => `${s.install}: ${s.what} (${s.why})`), remediate: sec.map((s) => `${s.cmd}   # take a backup first`), todo: 'Update these yourself after a backup. The agent never updates anything.' } });
    const php = (r.updates.installs || [])[0]?.php;
    if (php) await flag(`keeper:${b.id}:php`, cmpVer(php, '8.1') < 0, { severity: 'high', title: `PHP ${php} on ${b.short} is end-of-life`, detail: { todo: 'Switch to PHP 8.2+ (hPanel → Advanced → PHP Configuration), test on staging first.' } });

    if (b.smtp) {
      const m = await dnsMail(b.smtp.domain, b.smtp.dkimSelectors).catch((e) => ({ error: e.message }));
      r.mailDns = m;
      const missing = m.error ? [] : [!m.mx.length && 'MX', !m.spf && 'SPF', !m.dmarc && 'DMARC', !Object.values(m.dkim).some(Boolean) && `DKIM (${b.smtp.dkimSelectors.join(',')})`].filter(Boolean);
      await flag(`keeper:${b.id}:mail_dns`, missing.length > 0, { severity: 'medium', title: `${b.smtp.domain} is missing email DNS records: ${missing.join(', ')}`, detail: { todo: 'Without SPF/DKIM/DMARC, order emails land in spam.' } });
      const pass = secret(config, b.smtp.passEnv);
      if (b.smtp.host && b.smtp.user && pass) {
        const to = config.SMTP_CANARY_TO || config.OWNER_EMAIL;
        const probe = await smtpProbe({ host: b.smtp.host, port: b.smtp.port, user: b.smtp.user, pass, to });
        r.smtp = { mode: config.SMTP_CANARY_MODE, ok: probe.ok, stage: probe.stage, code: probe.code ?? null, error: probe.error || null };
        if (probe.ok && config.SMTP_CANARY_MODE === 'send') {
          const nodemailer = (await import('nodemailer')).default;
          try {
            await nodemailer.createTransport({ host: b.smtp.host, port: b.smtp.port, secure: b.smtp.port === 465, auth: { user: b.smtp.user, pass } })
              .sendMail({ from: b.smtp.user, to, subject: `[Galla Ops] SMTP canary ${b.short} ${new Date().toISOString().slice(0, 10)}`, text: 'Daily deliverability check from Galla Ops. Safe to delete/filter.' });
            r.smtp.sent = true;
          } catch (e) { r.smtp = { ...r.smtp, ok: false, stage: 'DATA', error: e.message }; }
        }
        const blocked = !r.smtp.ok;
        await flag(`keeper:${b.id}:smtp`, blocked, { severity: 'critical', title: `${b.smtp.user} cannot send email (${r.smtp.stage}: ${String(r.smtp.error || '').slice(0, 120)})`, error: r.smtp.error,
          detail: { impact: 'Customers are not getting order confirmations / password resets from this mailbox.', todo: /suspicious|blocked|disabled|5\.7\./i.test(r.smtp.error || '') ? 'The mail host has blocked this mailbox (same as admin@elgalla.com before). Contact the mail host; meanwhile point WP Mail SMTP at a working mailbox.' : 'Check the mailbox password and the mail host status.' } });
      } else {
        r.smtp = { connected: false, reason: `Not connected (${b.smtp.passEnv ? `set ${b.smtp.passEnv}` : 'no passEnv in brands.json'}): DNS checks only` };
      }
    }
    kvSet(db, `keeper_last:${b.id}`, JSON.stringify(r));
    return { r, fresh };
  }

  async function run() {
    const out = [];
    const fresh = [];
    for (const b of registry.brands) {
      const { r, fresh: f } = await runBrand(b);
      fresh.push(...f);
      out.push({ brand: b.id, sslDays: r.ssl?.days ?? r.ssl?.error, domainDays: r.domain?.days ?? r.domain?.error, smtp: r.smtp?.ok ?? r.smtp?.reason ?? 'n/a', security: (r.updates?.installs || []).reduce((n, i) => n + i.security.length, 0) });
    }
    await incidents.notify(fresh);
    return out;
  }
  return { run };
}

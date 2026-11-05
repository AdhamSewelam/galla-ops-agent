// Brand registry, loaded from brands.json. Add or remove a brand, subsite or language there:
// every check, report and dashboard view is generated from it. No secrets live in brands.json,
// only the NAMES of env vars that hold them.
import fs from 'node:fs';
import { z } from 'zod';

const envName = z.string().regex(/^[A-Z][A-Z0-9_]*$/, 'must be an ENV_VAR_NAME');
const relPath = z.string().regex(/^\/(?:[^\s?#]*\/)?$/, 'must start and end with "/" (e.g. "/eg/en/")');

const locale = z.object({ lang: z.string().min(2).max(5), path: relPath });

const site = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/),
  label: z.string(),
  path: relPath, // the WordPress (sub)site root, e.g. "/eg/"
  locales: z.array(locale).default([]), // empty = single language at `path`
  shopPath: z.string().default('shop/'), // relative to each locale (or site) path
  checkoutPath: z.string().default('checkout/'),
  sitemap: z.string().default('sitemap_index.xml'), // relative to site path (Rank Math)
  woo: z.object({ keyEnv: envName, secretEnv: envName, auth: z.enum(['header', 'query']).default('header') }).optional(),
});

const brand = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/),
  name: z.string(),
  short: z.string().max(12),
  domain: z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/),
  host: z.string(), // id of an entry in hosts[]
  cloudflare: z.boolean().default(false),
  checkRoot: z.boolean().default(false), // also check https://domain/ itself
  sites: z.array(site).min(1),
  skuParity: z
    .object({
      sites: z.array(z.string()).length(2),
      // categories that live on ONE site by design (e.g. "FINAL PIECES" term 779 on /eg)
      exemptCategoryIds: z.record(z.string(), z.array(z.number().int())).default({}),
    })
    .optional(),
  smtp: z
    .object({
      domain: z.string(),
      host: z.string().optional(),
      port: z.number().int().default(465),
      user: z.string().optional(),
      passEnv: envName.optional(),
      dkimSelectors: z.array(z.string()).default(['default']),
    })
    .optional(),
  gsc: z.string().optional(), // e.g. "sc-domain:jewelsbygalla.com"
  integrity: z
    .object({
      allowScriptDomains: z.array(z.string()).default([]),
    })
    .default({ allowScriptDomains: [] }),
});

const host = z.object({
  id: z.string().regex(/^[a-z0-9-]+$/),
  label: z.string(),
  kind: z.enum(['shared', 'vps']),
  secretEnv: envName, // HMAC secret the host sentinel signs with
  brands: z.array(z.string()),
});

const registry = z.object({ brands: z.array(brand).min(1), hosts: z.array(host).min(1) }).superRefine((r, ctx) => {
  const hostIds = new Set(r.hosts.map((h) => h.id));
  for (const b of r.brands) if (!hostIds.has(b.host)) ctx.addIssue({ code: 'custom', message: `brand ${b.id}: unknown host "${b.host}"` });
  const ids = r.brands.map((b) => b.id);
  if (new Set(ids).size !== ids.length) ctx.addIssue({ code: 'custom', message: 'brand ids must be unique' });
});

export function parseBrands(json) {
  const parsed = registry.safeParse(json);
  if (!parsed.success) throw new Error('Invalid brands.json:\n' + parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n'));
  return parsed.data;
}

export function loadBrands(file) {
  if (!fs.existsSync(file)) throw new Error(`brands file not found: ${file} (copy brands.example.json to brands.json)`);
  return parseBrands(JSON.parse(fs.readFileSync(file, 'utf8')));
}

export const origin = (b) => `https://${b.domain}`;
export const urlOf = (b, path) => origin(b) + path;
export const brandById = (reg, id) => reg.brands.find((b) => b.id === id) || null;
export const hostById = (reg, id) => reg.hosts.find((h) => h.id === id) || null;

/** Every place a visitor lands: one entry per locale (or one per site when single-language). */
export function localesOf(site) {
  return site.locales.length ? site.locales.map((l) => ({ lang: l.lang, path: l.path })) : [{ lang: null, path: site.path }];
}

/** Human label like "JBG /eg/ar" */
export const placeLabel = (b, s, l) => `${b.short} ${l?.path || s?.path || '/'}`.replace(/\/$/, '');

/** Every brand domain, used by the egress guard. */
export const allDomains = (reg) => reg.brands.map((b) => b.domain);

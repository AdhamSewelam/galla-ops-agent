# Galla Ops: read-only operations agent for Jewels by Galla, One Carat and El Galla

An always-on Node service on the Hostinger VPS (PM2 `galla-ops`, port 8091, Caddy → `https://galla-ops.elgalla.com`).
It watches the three WordPress/WooCommerce brands, every subsite (`/eg`, `/ae`) and language (`/en`, `/ar`), and tells
Adham exactly what's wrong and what to run. It never changes anything. No Instagram, social media, content or marketing.

Built on the same patterns as `nd-ops-agent`: job scheduler, append-only activity log, secret redaction, JARVIS Telegram
alerts with voice, password-protected Command Center, rate-limited team chat, HR + training.

## Jobs (Africa/Cairo)
| When | Job (`node src/index.js run <job>`) | Agent | AI |
|---|---|---|---|
| Every 5 min | `uptime`: home + shop per language; wp-login, wp-json, one product, checkout per subsite. 2 fails → URGENT, recovery → RESOLVED, reminder every 6h. Cloudflare 52x reported apart from origin errors. A whole host down = one alert. Pings the healthchecks.io heartbeat. | Sentinel | No |
| Every 15 min | `integrity`: page scan as Windows Chrome (+ cache-buster) and Googlebot. Inline scripts vs approved baseline, unknown script domains, hidden full-screen overlays, ClickFix markers, casino cloaking. | Warden | No |
| Hourly :20 (+ on every report) | `sentinel`: evaluates host sentinel reports vs baseline; missing for 3h → urgent. | Warden | No |
| :07 / :37 | `orders`: stuck pending, failed-payment spikes per gateway, zero-orders window vs the site's own pattern (after 14 days). | Ledger | No |
| Every 10 min | `vps`: CPU (sustained >85% for 15 min), RAM, disk, load, Caddy/FrankenPHP/Redis, slow log. | Sentinel | No |
| 08:15 | `keeper`: SSL, domain (RDAP), core/plugin/theme updates (security flagged), PHP, Cloudflare in front, SMTP login/RCPT probe + SPF/DKIM/DMARC. | Keeper | No |
| 08:30 | `products`: price 0, out-of-stock published, missing image, broken images, /eg vs /ae SKU parity (FINAL PIECES term 779 exempt). Report only. | Curator | No |
| 09:00 | `daily`: `[DAILY]` per brand: status, incidents, security, orders, top 3 items. | JARVIS | No |
| Mon 09:30 | `seo`: `[WEEKLY SEO]` per brand: sitemaps, titles/H1s, 404s, noindex, hreflang en↔ar and eg↔ae, spam URLs indexed, Search Console, PageSpeed. Max 5 fixes with why + steps. | Scout | Yes |
| Hourly :05 | `hr`: job health and conflicts between agents → one `[HR]` email for new issues. | Harmony | No |
| 11:00 | `training`: reviews one agent's last 30 days; up to 3 lessons, nothing applies until "Keep as rule". | Harmony | Yes |

## Hard limits, enforced in code
- **Read-only on every brand site.** `installEgressGuard()` wraps the global `fetch`: any non-GET request to a brand
  domain throws, whatever module or library makes it. `http.get()` has no method parameter. WooCommerce keys are Read-only
  and only non-personal fields are requested. A test statically scans `src/` for write requests.
- **No credentials to the sites.** No WP admin, SSH/SFTP/cPanel or DB passwords. The host sentinel pushes instead.
- **Never auto-fixes.** Every finding carries exact verify/remediate commands (WP-CLI with `--skip-plugins --skip-themes`
  so possibly infected code never loads) for Adham to run himself.
- **Never invents data.** Missing source → "Not connected" / "No data".
- **AI only summarises/recommends** from stored facts; its JSON is rendered, never executed.
- **Approvals** (accept a baseline): signed, 72h-expiring, single-use confirm page bound to the exact content hash, behind
  the dashboard login, POST only. If a newer report changes the content, the old link is refused.
- **Append-only** activity log (DB triggers), secrets redacted by key and by value in logs, emails, dashboard.

## Host sentinel
`sentinel/galla-sentinel.php` + `.sh`: hourly via hPanel cron (shared) and root cron (VPS). Collects admins, application
passwords (metadata only), mu-plugins, drop-ins, plugins/themes + `functions.php` hashes, core checksums (fetched from
api.wordpress.org, not WP-CLI), PHP in uploads, zips, hidden `.php`, wp-cron hooks, payload/large options, `.g_*.php`
processes, root-owned files, malware markers. Signed HMAC-SHA256 with timestamp + nonce (replay-proof). See `deploy/sentinel.md`.

## Setup
`deploy/VPS.md` (agent, Caddy, DNS, Telegram, keys) and `deploy/sentinel.md` (host scripts). Config: `.env.example`,
`brands.example.json` (add/remove brands, subsites, languages without code changes).

## Develop
```bash
npm install
npm test     # ingest HMAC/replay, baseline diffing, marker detection, dedupe/escalation, read-only, Not connected, …
```

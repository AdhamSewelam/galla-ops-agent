# Deploy Galla Ops on the VPS (srv1108252, 193.203.191.23)

Galla Ops runs next to ND Ops on the same VPS: PM2 process **`galla-ops`**, port **8091** (ND Ops uses 8090),
code in `/opt/galla-ops-agent`, data in `/var/lib/galla-ops`, public at **https://galla-ops.elgalla.com**.

It watches every site **from outside** (HTTP), plus signed reports pushed by the host sentinels.
It has no WordPress, SSH, SFTP, cPanel or database credentials for any site.

## 1. DNS (done)
Cloudflare → elgalla.com → DNS: `A  galla-ops  193.203.191.23`, **DNS only (grey cloud)**.
Keep it grey: Caddy gets its own certificate, and the agent's IP stays out of Cloudflare's WAF logic.

## 2. Cloudflare allowlist (done)
Security rules → Custom rule "Allow Galla Ops monitor": `ip.src eq 193.203.191.23` → **Skip**
(all remaining custom rules, rate limiting, managed rules, Super Bot Fight Mode, Browser Integrity Check, Security Level).
If the dashboard ever shows "Cloudflare blocked the monitor", check **Security → Settings → Bot Fight Mode** (free-plan
Bot Fight Mode can't be skipped by a rule).

## 3. Install
```bash
cd /opt
git clone git@github-gallaops:AdhamSewelam/galla-ops-agent.git   # read-only deploy key, see §8
cd galla-ops-agent
npm ci --omit=dev
cp .env.example .env && chmod 600 .env
cp brands.example.json brands.json             # check the /eg/en/ … paths match the live sites
mkdir -p /var/lib/galla-ops && chmod 700 /var/lib/galla-ops
sed -i "s#^APPROVAL_SECRET=.*#APPROVAL_SECRET=$(openssl rand -base64 48 | tr -d '\n')#" .env
sed -i "s#^SENTINEL_SECRET_SHARED=.*#SENTINEL_SECRET_SHARED=$(openssl rand -hex 32)#" .env
sed -i "s#^SENTINEL_SECRET_VPS=.*#SENTINEL_SECRET_VPS=$(openssl rand -hex 32)#" .env
nano .env    # DASHBOARD_PASSWORD, SMTP_PASS (Gmail app password "Galla Ops"), HEARTBEAT_URL, TELEGRAM_BOT_TOKEN, GEMINI_API_KEY
```

## 4. Telegram (Galla JARVIS bot)
Use the NEW bot only. Two processes polling the same bot (ND Ops + Galla Ops) get HTTP 409 and both lose the button.
```bash
# token already in .env as TELEGRAM_BOT_TOKEN; press Start on @galla_jarvis_bot first
node --env-file=.env src/tg-setup.js      # prints TELEGRAM_CHAT_ID=...; add it to .env
```
The JARVIS voice (Piper) is shared with ND Ops in `/opt/piper`. If it isn't there: `bash deploy/install-voice.sh`.

## 5. Start
```bash
node --env-file=.env src/index.js run uptime     # first check; prints results
pm2 start ecosystem.config.cjs && pm2 save
curl -s localhost:8091/health                    # {"ok":true}
```

## 6. Caddy
Add to the Caddyfile already in use (`/etc/caddy/Caddyfile`; back it up first):
```
galla-ops.elgalla.com {
    encode gzip
    request_body {
        max_size 12MB
    }
    reverse_proxy 127.0.0.1:8091
}
```
```bash
cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%F)
caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy
curl -s https://galla-ops.elgalla.com/health
```

## 7. WooCommerce read-only keys (orders only)
Products need no keys (public Store API). Orders do. For **each shop** (jewelsbygalla /eg and /ae, onecarat /eg and /ae, elgalla):
1. Create a WordPress user `galla-ops` with role **Shop manager** (not Administrator) on that subsite.
2. That subsite's wp-admin → WooCommerce → Settings → Advanced → REST API → **Add key**:
   description "Galla Ops (read-only)", user `galla-ops`, **Permissions: Read**.
3. Put the pair into `.env` under the names in brands.json (`WC_JBG_EG_KEY` / `WC_JBG_EG_SECRET`, …).
4. `pm2 restart galla-ops --update-env` → `node --env-file=.env src/index.js run orders`.

Galla Ops only asks for `id,status,dates,payment_method,total,currency`, never names, emails, phones or addresses,
and stores only hourly counts. Every request goes through a guard that refuses anything but GET to the brand domains.

## 8. Email deliverability probe (optional)
To detect a blocked sending mailbox (like admin@elgalla.com at StackMail), put its password in `SMTP_ELGALLA_PASS`.
Default `SMTP_CANARY_MODE=rcpt` logs in and stops at `RCPT TO`, so nothing is sent. Without the password Keeper only checks MX/SPF/DKIM/DMARC.

## 9. VPS health
`VPS_MONITOR=true` (only on this VPS). FrankenPHP has no php-fpm slow log; leave `PHP_SLOWLOG_PATH` empty unless you
enable a slow log somewhere. Services checked: `VPS_SERVICES=caddy,frankenphp,redis-server` (missing units are ignored).

## 10. Search Console (optional)
Reuse the ND Ops service account if you like: add its email as a **Restricted** user in each Search Console property
(jewelsbygalla.com, onecaratjewelry.com, elgalla.com), then `base64 -w0 key.json` → `GOOGLE_SERVICE_ACCOUNT_JSON_BASE64`.

## 11. Deploy key (private repo)
```bash
ssh-keygen -t ed25519 -f ~/.ssh/galla_ops_deploy -N "" -C galla-ops-vps
cat ~/.ssh/galla_ops_deploy.pub        # GitHub → repo → Settings → Deploy keys → Add (read-only)
cat >> ~/.ssh/config <<'EOF'
Host github-gallaops
  HostName github.com
  User git
  IdentityFile ~/.ssh/galla_ops_deploy
  IdentitiesOnly yes
EOF
```

## Test every job
```bash
cd /opt/galla-ops-agent
for j in uptime integrity sentinel orders vps keeper products daily seo hr training; do node --env-file=.env src/index.js run $j; done
```
Dashboard: https://galla-ops.elgalla.com/dashboard → **Test JARVIS** (sends a TEST alert to Telegram).

## Update
```bash
cd /opt/galla-ops-agent && git pull && npm ci --omit=dev && pm2 restart galla-ops --update-env
```
If `sentinel/galla-sentinel.php` changed, re-upload it to both hosts (Warden flags a version mismatch).

## Resources
~80–120 MB RAM. About 34 lightweight HTTP checks every 5 min, 20 page scans every 15 min. Short spikes Monday 09:30 (SEO crawl).

# Install the host sentinel

The sentinel is a small read-only PHP-CLI + bash script that runs **on each host** every hour and **pushes** a signed
report to `https://galla-ops.elgalla.com/ingest`. The agent never logs into the hosts.

What it does NOT do:
- It never loads WordPress. An infected `functions.php` or `db.php` drop-in runs on every WordPress bootstrap,
  WP-CLI included, and could hide itself. The sentinel reads `wp-config.php` as text and queries MySQL directly.
- It never writes, deletes or quarantines anything. The only file it writes is its own cache in `state/`.
  SQL is limited to SELECT/SHOW, and the session is set READ ONLY.
- It never sends secrets: no password hashes, no application-password hashes, no wp-config values.

Files: `sentinel/galla-sentinel.php`, `sentinel/galla-sentinel.sh`, `sentinel/config.example.json`.

## A. Shared host u137384117 (jewelsbygalla.com, /multisite, onecaratjewelry.com)

1. **SSH in** and create the folder **outside public_html**:
   ```bash
   mkdir -p ~/galla-sentinel/state && chmod 700 ~/galla-sentinel ~/galla-sentinel/state
   php -v        # needs 7.4+
   php -m | grep -E 'mysqli|pdo_mysql|curl'
   ```
2. **Upload** `galla-sentinel.php` and `galla-sentinel.sh` into `~/galla-sentinel/` (scp, or paste with nano).
   `chmod 700 ~/galla-sentinel/galla-sentinel.sh`
3. **Config**: create `~/galla-sentinel/config.json` from `config.example.json`:
   - `host_id`: `hostinger-u137384117`
   - `secret`: the value of `SENTINEL_SECRET_SHARED` from the agent's `.env` (`grep SENTINEL_SECRET_SHARED /opt/galla-ops-agent/.env` on the VPS)
   - `installs`: the three WordPress roots (main, `/multisite`, onecarat). Add any other install you want watched.
   - `chmod 600 ~/galla-sentinel/config.json`
4. **Dry run** (prints the report, sends nothing). The first run reads every PHP file once; later runs only re-read changed files:
   ```bash
   php ~/galla-sentinel/galla-sentinel.php --config=$HOME/galla-sentinel/config.json --dry-run | head -c 2000
   ```
   Check `"errors": []` for each install.
5. **Live run**:
   ```bash
   bash ~/galla-sentinel/galla-sentinel.sh ~/galla-sentinel/config.json && tail -5 ~/galla-sentinel/state/sentinel.log
   ```
   You should see `report accepted`. On the dashboard, Security shows "report just now".
6. **hPanel → Advanced → Cron Jobs → Custom**, every hour (minute 10):
   ```
   10 * * * *  bash /home/u137384117/galla-sentinel/galla-sentinel.sh /home/u137384117/galla-sentinel/config.json
   ```
7. **Accept the baseline**: the first report opens ONE "review and accept the baseline" item (not an alert per admin).
   Dashboard → Security → *Accept as baseline…* → check the list (every admin, app password, mu-plugin, drop-in, cron hook, zip) → confirm.
   Always-on findings (malware markers, banned file managers, core checksum failures, `.g_*.php` processes, payload options)
   alert with or without a baseline.

## B. VPS srv1108252 (elgalla.com)

It runs as **root** from root's crontab, so the web user (`www-data`) can't read its secret or modify it.
```bash
mkdir -p /opt/galla-sentinel/state && chmod 700 /opt/galla-sentinel /opt/galla-sentinel/state
cp /opt/galla-ops-agent/sentinel/galla-sentinel.{php,sh} /opt/galla-sentinel/
chmod 700 /opt/galla-sentinel/galla-sentinel.sh
SECRET=$(grep ^SENTINEL_SECRET_VPS= /opt/galla-ops-agent/.env | cut -d= -f2)
cat > /opt/galla-sentinel/config.json <<EOF
{
  "host_id": "vps-srv1108252",
  "endpoint": "https://galla-ops.elgalla.com/ingest",
  "secret": "$SECRET",
  "state_dir": "/opt/galla-sentinel/state",
  "check_root_owned": true,
  "installs": [ { "id": "elgalla", "path": "/var/www/elgalla.com" } ]
}
EOF
chmod 600 /opt/galla-sentinel/config.json
php /opt/galla-sentinel/galla-sentinel.php --config=/opt/galla-sentinel/config.json --dry-run | head -c 1500
bash /opt/galla-sentinel/galla-sentinel.sh /opt/galla-sentinel/config.json && tail -3 /opt/galla-sentinel/state/sentinel.log
( crontab -l 2>/dev/null; echo '10 * * * * /opt/galla-sentinel/galla-sentinel.sh /opt/galla-sentinel/config.json' ) | crontab -
```
If WordPress on the VPS uses a different PHP than the CLI `php`, point the wrapper at it: `GALLA_PHP=/usr/local/bin/php`
(FrankenPHP's embedded PHP has no CLI; the system `php-cli` package is fine, and it only needs `mysqli` or `pdo_mysql`).
To also watch jbg-staging, add it to `installs` with the id `jbg-staging`.

## Troubleshooting
| Log says | Meaning |
|---|---|
| `ingest failed: HTTP 401 bad signature` | `secret` in config.json ≠ the agent's `.env` value |
| `HTTP 401 timestamp outside the allowed window` | host clock is off by more than 5 minutes |
| `HTTP 409 replayed nonce` | the same report was sent twice (harmless) |
| `database: db connect failed` | wp-config DB_HOST is a socket/port the CLI can't reach; check DB_HOST |
| `could not fetch checksums from api.wordpress.org` | outbound HTTPS blocked; core files are still listed, just not verified |

## Limits
- On the shared host, the sentinel runs as the same Linux user as the websites. An attacker with full shell access as
  that user could read its secret and send fake "clean" reports. Three things narrow that gap: the agent alerts when
  a report is **missing** for 3h, when the **script's own hash** differs from the repo version, and the **external page
  scan** runs independently every 15 min.
- `php_cli_version` is the CLI PHP version. The PHP version the websites run can differ (hPanel → PHP Configuration).

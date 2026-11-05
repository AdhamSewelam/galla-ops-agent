#!/usr/bin/env bash
# Galla Ops host sentinel: cron wrapper. Read-only. Runs hourly from hPanel cron (shared) or root cron (VPS).
#   - takes a lock so two runs never overlap
#   - captures the process list (shared hosts often disable shell_exec inside PHP)
#   - runs galla-sentinel.php, which collects, signs and POSTs the report
# Usage: galla-sentinel.sh [/path/to/config.json] [--dry-run]
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${1:-$DIR/config.json}"
EXTRA="${2:-}"
PHP_BIN="${GALLA_PHP:-$(command -v php || echo /usr/bin/php)}"
STATE="$DIR/state"
mkdir -p "$STATE" && chmod 700 "$STATE"
LOG="$STATE/sentinel.log"

# keep the log small (last ~500 lines)
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG")" -gt 1000 ]; then tail -n 500 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"; fi

exec 9>"$STATE/lock"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo "$(date -u +%FT%TZ) previous run still active, skipping" >> "$LOG"; exit 0; }
fi

PS_FILE="$STATE/ps.txt"
ps -eo pid,ppid,user,etime,args > "$PS_FILE" 2>/dev/null || ps aux > "$PS_FILE" 2>/dev/null || : > "$PS_FILE"

{
  echo "$(date -u +%FT%TZ) run start"
  nice -n 15 "$PHP_BIN" -d display_errors=stderr "$DIR/galla-sentinel.php" --config="$CONFIG" --ps="$PS_FILE" $EXTRA
  echo "$(date -u +%FT%TZ) run end (exit $?)"
} >> "$LOG" 2>&1
rm -f "$PS_FILE"

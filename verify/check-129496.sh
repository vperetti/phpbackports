#!/usr/bin/env bash
#
# check-129496.sh — local check for the CVE-2026-129496 fix (error_log
# timestamp outside an active request). Run it ON THE SERVER with the PHP CLI
# of the same build/package as the web SAPI (the fix is in main/main.c, shared
# by every SAPI). Behavioural validation, not an exploit.
#
# Usage: ./check-129496.sh [path-to-php-cli]     (default: php from PATH)
#
# How: starts PHP with a removed INI directive (safe_mode), which raises a
# startup error while no request is active, and a non-UTC date.timezone.
#   patched   -> the startup line is stamped in UTC
#   unpatched -> the startup line is stamped in the local timezone
# The PHP process exits at startup; nothing else runs. Works on 5.4 - 7.3.

set -u
PHP="${1:-php}"
TZ_TEST="Asia/Tokyo"      # any non-UTC zone
LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT

"$PHP" -n -d date.timezone="$TZ_TEST" -d log_errors=1 -d display_errors=0 \
       -d display_startup_errors=0 -d error_log="$LOG" -d safe_mode=1 \
       -r '' >/dev/null 2>&1

echo "== CVE-2026-129496 check ($("$PHP" -n -r 'echo PHP_VERSION;' 2>/dev/null)) =="
LINE=$(grep -m1 "safe_mode" "$LOG")
echo "     log> $LINE"
if [ -z "$LINE" ]; then
  echo "  info - inconclusive: no startup line was logged"; exit 2
elif echo "$LINE" | grep -q "^\[[^]]* UTC\]"; then
  echo "  PASS - startup error stamped in UTC (patched behaviour)"; exit 0
elif echo "$LINE" | grep -q "$TZ_TEST"; then
  echo "  FAIL - startup error stamped in local time (CVE-2026-129496 UNPATCHED)"; exit 1
else
  echo "  info - inconclusive: unexpected timestamp format"; exit 2
fi

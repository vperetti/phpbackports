#!/usr/bin/env bash
#
# check-126714.sh — local check for the CVE-2026-126714 fix (files session
# handler always truncates before writing). Run it ON THE SERVER with the PHP
# CLI of the same build/package as the web SAPI. Same probe as test [3] of
# run-cvecheck.sh, but the FIFO is created with mkfifo(1), so it does not need
# PHP's posix extension (php-process). Behavioural validation, not an exploit.
#
# Usage: ./check-126714.sh [path-to-php-cli]     (default: php from PATH)
#
# A throw-away session is stored on a FIFO in a private temp dir.
#   patched   -> "ftruncate() failed" (the handler always truncates first)
#   unpatched -> only "write failed" (the truncate is skipped)
# No application session is touched; the temp dir is removed.

set -u
PHP="${1:-php}"
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
ID="cvechk$RANDOM$RANDOM"
mkfifo -m 600 "$D/sess_$ID" || { echo "  info - inconclusive: mkfifo failed"; exit 2; }

run() { "$PHP" "$@" -d session.save_handler=files -d session.save_path="$D" \
      -d session.use_cookies=0 -d session.use_strict_mode=0 \
      -d display_errors=1 -d log_errors=0 -d error_reporting=-1 \
      -r 'if (!function_exists("session_start")) { echo "NO_SESSION\n"; exit; }
          session_id("'"$ID"'"); session_start(); $_SESSION["cvecheck"]="probe"; session_write_close();' 2>&1; }
# -n: ignore php.ini; if session is a shared module, retry loading the ini
OUT=$(run -n)
echo "$OUT" | grep -q NO_SESSION && OUT=$(run)

echo "== CVE-2026-126714 check ($("$PHP" -n -r 'echo PHP_VERSION;' 2>/dev/null)) =="
echo "$OUT" | grep -v '^$' | sed 's/^/     php> /'
if echo "$OUT" | grep -q NO_SESSION; then
  echo "  info - inconclusive: session extension not loaded with -n (built as a shared module?)"; exit 2
elif echo "$OUT" | grep -qi 'ftruncate() failed'; then
  echo "  PASS - files handler truncates before writing (patched behaviour)"; exit 0
elif echo "$OUT" | grep -qi 'write failed'; then
  echo "  FAIL - files handler skips the truncate (CVE-2026-126714 UNPATCHED)"; exit 1
else
  echo "  info - inconclusive: unexpected output"; exit 2
fi

#!/usr/bin/env bash
#
# run-cvecheck.sh — drive cvecheck.php and report PASS/FAIL for the
# CVE-2026-109618 / 109619 mitigation. Behavioural validation, not an exploit.
#
# Usage:
#   ./run-cvecheck.sh <base-url-of-cvecheck.php> <token> [host-header]
#
# Examples:
#   ./run-cvecheck.sh https://app.example.com/_cvecheck/cvecheck.php s3cr3t
#   ./run-cvecheck.sh http://localhost/_cvecheck/cvecheck.php s3cr3t app.example.com
#
# The third argument sets an explicit Host: header, useful when probing
# http://localhost on a name-based virtual host.
#
# Requires: curl.

set -u

URL="${1:-}"
TOKEN="${2:-}"
HOSTHDR="${3:-}"

if [ -z "$URL" ] || [ -z "$TOKEN" ]; then
  echo "usage: $0 <base-url-of-cvecheck.php> <token> [host-header]" >&2
  exit 2
fi

CURL=(curl -sS --max-time 30)
[ -n "$HOSTHDR" ] && CURL+=(-H "Host: $HOSTHDR")

pass=0; fail=0
ok()   { echo "  PASS - $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL - $1"; fail=$((fail+1)); }
info() { echo "  info - $1"; }

echo "== CVE-2026-109618 / 109619 mitigation check =="
echo "target: $URL"
echo

# ---- Test 1: build info + fix marker --------------------------------------
echo "[1] build info / fix marker"
INFO="$("${CURL[@]}" "$URL?k=$TOKEN&t=info" 2>/dev/null)"
if ! echo "$INFO" | grep -q '^ok$'; then
  bad "endpoint did not respond as expected (token wrong? not deployed?)"
  echo "$INFO" | sed 's/^/       /'
  echo; echo "cannot continue without the endpoint."; exit 1
fi
echo "$INFO" | sed 's/^/     /'
PHPVER=$(echo "$INFO"   | sed -n 's/^php=//p')
MARKER=$(echo "$INFO"   | sed -n 's/^fix_marker=//p')
UPROG=$(echo "$INFO"    | sed -n 's/^session.upload_progress.enabled=//p')
[ "$MARKER" = "PRESENT" ] && ok "max_multipart_body_parts exists (fix compiled in)" \
                          || bad "max_multipart_body_parts missing (build looks UNPATCHED)"
# upload_progress off is the recommended hardening (the fix also disables it in code)
if [ -z "$UPROG" ] || [ "$UPROG" = "0" ] || [ "$UPROG" = "Off" ]; then
  ok "session.upload_progress.enabled is off"
else
  bad "session.upload_progress.enabled is ON (producer path of 109619 still open)"
fi
echo

# ---- Test 2: multipart part limit -----------------------------------------
echo "[2] multipart part cap (sending 3000 parts)"
BODY=$(mktemp); trap 'rm -f "$BODY"' EXIT
B="----cvecheck$$"
{ for i in $(seq 1 3000); do
    printf -- '--%s\r\n' "$B"
    printf 'Content-Disposition: form-data; name="f%d"\r\n\r\n%d\r\n' "$i" "$i"
  done
  printf -- '--%s--\r\n' "$B"
} > "$BODY"
MP="$("${CURL[@]}" -X POST -H "Content-Type: multipart/form-data; boundary=$B" \
      --data-binary "@$BODY" "$URL?k=$TOKEN&t=multipart" 2>/dev/null)"
echo "$MP" | sed 's/^/     /'
PC=$(echo "$MP" | sed -n 's/^POST_count=//p')
if [ -n "$PC" ] && [ "$PC" -lt 3000 ] 2>/dev/null; then
  ok "parser capped parts at $PC (< 3000 sent)"
else
  bad "parser accepted $PC parts (no cap observed)"
fi
echo

# ---- Test 3: OOM ends the worker (no graceful fatal) ----------------------
echo "[3] OOM handling (request-local 32M limit)"
OOUT=$(mktemp); OERR=$(mktemp)
HTTP=$("${CURL[@]}" -o "$OOUT" -w '%{http_code}' "$URL?k=$TOKEN&t=oom" 2>"$OERR")
RC=$?
OOMBODY="$(cat "$OOUT")"
echo "     curl_exit=$RC http_code=$HTTP"
echo "$OOMBODY" | sed 's/^/     body> /'
if echo "$OOMBODY" | grep -qi 'Allowed memory size'; then
  bad "graceful 'Allowed memory size' fatal returned (longjmp path — UNPATCHED behaviour)"
elif echo "$OOMBODY" | grep -q 'AFTER_OOM_SHOULD_NOT_PRINT'; then
  bad "execution continued past the OOM loop (unexpected)"
elif echo "$OOMBODY" | grep -q 'before_oom'; then
  ok "worker died at the allocation with no graceful fatal (patched behaviour)"
else
  info "inconclusive body; relies on Test 4 to confirm the worker recycled cleanly"
fi
rm -f "$OOUT" "$OERR"
echo

# ---- Test 4: worker pool healthy after the OOM ----------------------------
echo "[4] server healthy after OOM (3 follow-up requests)"
good=0
for n in 1 2 3; do
  C=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$URL?k=$TOKEN&t=info" 2>/dev/null)
  echo "     request $n -> HTTP $C"
  [ "$C" = "200" ] && good=$((good+1))
done
[ "$good" -eq 3 ] && ok "all follow-up requests returned 200 (no wedge / stale state)" \
                  || bad "only $good/3 follow-up requests OK"
echo

# ---- Summary --------------------------------------------------------------
echo "== summary: PASS=$pass FAIL=$fail  (php $PHPVER) =="
echo "Reminder: delete cvecheck.php from the server when finished."
[ "$fail" -eq 0 ] && exit 0 || exit 1

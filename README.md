# phpbackports — security backports for end-of-life PHP

Unofficial, **minimal** source backports of critical PHP security fixes for
**end-of-life PHP branches that the PHP project does not patch** (5.4 – 7.3).

| Round | PHP release | CVEs | Patch files |
|---|---|---|---|
| 1 | 2026-10-21 | CVE-2026-109618, CVE-2026-109619 | `patches/php-<branch>-CVE-2026-109618-109619.patch` |
| 2 | 2026-11-19 | CVE-2026-126714, CVE-2026-129496 | `patches/php-<branch>-CVE-2026-126714-129496.patch` |

Round 2 patches are **incremental**: apply round 1 first, then round 2.
The scripts in `tools/` (`aplica54.py` for 5.x, `aplica73.py` for 7.x) apply
both rounds to a clean source tree; the patches were generated from them. The
round 1 patches also carry the extra fatal-error conversions from PR #1, which
were made directly in the `.patch` files and are not in the scripts yet, so
use the `.patch` files as the reference.

Round 1 — one patch per branch, each against the **last release of that branch**:

| Patch | Applies to |
|---|---|
| `patches/php-5.4-CVE-2026-109618-109619.patch` | PHP 5.4.45 |
| `patches/php-5.5-CVE-2026-109618-109619.patch` | PHP 5.5.38 |
| `patches/php-5.6-CVE-2026-109618-109619.patch` | PHP 5.6.40 |
| `patches/php-7.0-CVE-2026-109618-109619.patch` | PHP 7.0.33 |
| `patches/php-7.1-CVE-2026-109618-109619.patch` | PHP 7.1.33 |
| `patches/php-7.2-CVE-2026-109618-109619.patch` | PHP 7.2.34 |
| `patches/php-7.3-CVE-2026-109618-109619.patch` | PHP 7.3.33 |

(PHP 7.4 / 8.0 / 8.1 already have official minimal backports from the PHP
security team; 8.2+ have full releases.)

> **Not official PHP releases.** The PHP project ships fixes for 8.2+, plus
> minimal source backports for 7.4 / 8.0 / 8.1. These patches extend that
> same minimal approach to 5.4–7.3 for people building those branches from
> source. Upgrading to a supported PHP version is the only complete fix.

## The vulnerabilities

Both are rated CVSS v4.0 9.2 and can allow **unauthenticated remote code
execution**, triggered before any application code runs.

| CVE | Advisory | Summary |
|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption: out-of-memory handling uses `longjmp()` and leaves request memory in an invalid state that request shutdown then treats as valid. |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state: request-owned state survives after its memory is freed and is consumed by a later request on the same worker. |

Official announcement: <https://www.php.net/>

## What the patches do

Mirroring the official minimal 7.4 backport (`php-src` commit `712e60f9ed`):

1. **Remove `longjmp()` on OOM / integer overflow** — a fatal allocation error
   now ends the process (`_exit`) instead of unwinding through partially
   initialized request state (CVE-2026-109618). As in the official backport
   this covers the memory limit, real allocation failures (including
   persistent `malloc`/`realloc` and `zend_strtod`'s `Balloc()`), and the
   "Possible integer overflow in memory allocation" checks (on 7.x also in
   `zend_hash.c` and `zend_multiply.h`, i.e. `safe_emalloc()`).
2. **Reset request-owned global state** — error/exception handlers,
   superglobals, SAPI request fields, `modules_activated` and the object store
   are cleared at request shutdown so a later request cannot consume stale
   values (CVE-2026-109619). On 5.x the object store is already cleared by the
   existing `zend_objects_store_destroy()`; the 7.x patches reset it
   explicitly.
3. **Disable session upload-progress in code** — closes the confirmed
   producer/consumer path of CVE-2026-109619.
4. **Harden multipart parsing** — keep only the headers actually used (ignoring
   duplicates) and add a `max_multipart_body_parts` INI limit.

### Scope / limitations

These are **minimal** backports. They do **not** include the integer-overflow
hardening in the generated VM (`zend_vm_execute.h`) from the full 8.2 patch,
which would require regenerating the VM. That part is DoS hardening, not the
confirmed RCE path. For the same reason the 5.x patches leave the
`"String size overflow"` fatals in `zend_operators.c` unchanged; with a normal
`memory_limit` (well below 2 GB) the memory limit is hit first.

## Operational impact — read before deploying

Because an out-of-memory fatal now ends the process instead of raising a
normal fatal error, **every request that exceeds `memory_limit` kills its
worker**, not only malicious ones:

- the client gets no response (connection closed / 502 from the proxy);
- shutdown functions do not run and the session is not written;
- the error message is written **only to stderr**, not to PHP's `error_log`:
  - **PHP-FPM**: set `catch_workers_output = yes` in the pool, otherwise the
    message is discarded and you only see a worker exiting unexpectedly;
  - **mod_php**: it ends up in Apache's error log;
  - **`php -S`** (built-in server): the whole server process exits.

Before rolling out, check how often "Allowed memory size of … exhausted"
appears in your current logs and raise `memory_limit` or fix those scripts if
needed. Also set `session.upload_progress.enabled = 0` in `php.ini` so the
configuration reflects the (now always disabled) behaviour.

The full 8.2+ releases handle this differently (delayed OOM error plus a
separate hard limit); that rework is far too large for a minimal backport, so
the official minimal 7.4 backport behaves like these patches.

## Round 2 (2026-11-19): CVE-2026-126714 & CVE-2026-129496

| CVE | Advisory | Upstream fix | Summary |
|---|---|---|---|
| CVE-2026-126714 | [GHSA-fm2m-fjf5-v3cp](https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp) | `e2d3cee9ad` | The `files` session handler only truncated the session file when the new data was *smaller*; an interrupted write of equal/larger data leaves old bytes behind, allowing injection of session variables. Fix: always `ftruncate()` before writing and fail the write if truncation fails. |
| CVE-2026-129496 | [GHSA-gr4f-wgx5-jpfv](https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv) | `cb20015e04` | Use-after-free of the timezone cache when `error_log` is written outside an active request. Fix: use local time only while a request is active (`PG(modules_activated) && EG(active)`), UTC otherwise. |

Other advisories of the 2026-11-19 release were triaged against 5.4–7.3:
CVE-2026-115560 (upload-progress with mixed session serializers) is already
closed by round 1 (upload progress disabled in code); the rest are 8.x-only or
affect SAPIs/extensions outside this scope (FPM, CGI, SOAP).

Tests for CVE-2026-126714 are in `verify/cve-126714/` (see its README).

## How to apply

```sh
# example: PHP 7.3.33 (use the patch matching your branch)
tar xjf php-7.3.33.tar.bz2
cd php-7.3.33
patch -p1 < /path/to/patches/php-7.3-CVE-2026-109618-109619.patch
patch -p1 < /path/to/patches/php-7.3-CVE-2026-126714-129496.patch
./configure <your options>
make && make install
```

For distribution packages, apply the patch to the package source (e.g. the
SRPM) and rebuild the package.

## Build verification

Each patch was applied to the official source tarball, compiled, and checked
that:

- an out-of-memory fatal ends the process (no shutdown handler runs → no
  `longjmp` back into corrupted state);
- `max_multipart_body_parts` caps the number of parsed parts;
- a request that drives the worker to OOM does not break the **next** request on
  the same worker.

Tested with the CLI built-in web server. Verify on your target SAPI (mod_php /
PHP-FPM) before use.

## Verifying a deployed fix

`verify/` contains a small, controlled, **non-destructive** validator (not an
exploit) to confirm a build is patched on the real SAPI after deployment: a
token-gated endpoint (`cvecheck.php`) plus a driver that reports PASS/FAIL
(`run-cvecheck.sh` for Linux/macOS, `run-cvecheck.ps1` for Windows PowerShell).
It covers CVE-2026-109618/109619 and CVE-2026-126714 over HTTP;
CVE-2026-129496 is checked locally with `verify/check-129496.sh`.
See `verify/README.md`. Remove the endpoint after testing.

## Disclaimer

Provided as-is, with no warranty. Review the diff before building.

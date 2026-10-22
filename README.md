# PHP EOL backports — CVE-2026-109618 & CVE-2026-109619

Unofficial, **minimal** source backports of the two critical PHP core
remote-code-execution fixes released on 2026-10-21, for **end-of-life PHP
branches that the PHP project does not patch**.

One patch per branch, each against the **last release of that branch**:

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
> minimal source backports for 7.4 / 8.0 / 8.1. These two patches extend that
> same minimal approach to 5.4 and 7.3 for people building those branches from
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
   initialized request state (CVE-2026-109618).
2. **Reset request-owned global state** — error/exception handlers,
   superglobals, SAPI request fields, `modules_activated` and the object store
   are cleared at request shutdown so a later request cannot consume stale
   values (CVE-2026-109619).
3. **Disable session upload-progress in code** — closes the confirmed
   producer/consumer path of CVE-2026-109619.
4. **Harden multipart parsing** — keep only the headers actually used (ignoring
   duplicates) and add a `max_multipart_body_parts` INI limit.

### Scope / limitations

These are **minimal** backports. They do **not** include the integer-overflow
hardening in the generated VM (`zend_vm_execute.h`) from the full 8.2 patch,
which would require regenerating the VM. That part is DoS hardening, not the
confirmed RCE path.

## How to apply

```sh
# example: PHP 7.3.33 (use the patch matching your branch)
tar xjf php-7.3.33.tar.bz2
cd php-7.3.33
patch -p1 < /path/to/patches/php-7.3-CVE-2026-109618-109619.patch
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
See `verify/README.md`. Remove the endpoint after testing.

## Disclaimer

Provided as-is, with no warranty. Review the diff before building.

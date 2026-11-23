# Mitigation verifier — CVE-2026-109618 / 109619 / 126714 / 129496

A small, **controlled, non-destructive** validator to confirm a build is
patched on the real SAPI (mod_php / PHP-FPM) **after** you deploy the fix.

It is **not an exploit**. It does not attempt code execution. It probes the
observable behaviour that the patch changes and reports PASS/FAIL. Run it only
against systems you are authorised to test.

## Files

| File | Purpose |
|---|---|
| `cvecheck.php` | Temporary endpoint. Reports build info and exposes three safe probes. Token-gated. |
| `run-cvecheck.sh` | Driver for Linux/macOS (bash + curl). Prints PASS/FAIL per check. |
| `run-cvecheck.ps1` | Same driver for Windows PowerShell (5.1+ or 7+). |
| `check-126714.sh` | Local check for CVE-2026-126714 with the PHP CLI; same probe as test 3, without the posix extension. |
| `check-129496.sh` | Local check for CVE-2026-129496, run on the server with the PHP CLI of the same build. |
| `check-local.php` | Local checks of 109618 (OOM), 129496 and 126714 with any PHP CLI, **Windows included** (`php check-local.php [--src=<source tree>]`). 126714 is behavioural with `posix_mkfifo`, a source check otherwise. See `docs/WINDOWS-BUILD.md`. |
| `cve-126714/` | Local reproduction tests for CVE-2026-126714 (interrupted session write). |

## What it checks

| # | Probe | Patched build | Unpatched build |
|---|---|---|---|
| 1 | `max_multipart_body_parts` INI exists | PRESENT | ABSENT (the INI is added by the fix) |
| 1 | `session.upload_progress.enabled` | off | on (producer path of CVE-2026-109619) |
| 2 | POST with 3000 parts | parsed count capped | see note below |
| 3 | throw-away session stored on a FIFO (CVE-2026-126714) | `ftruncate() failed` reported: the handler always truncates before writing | `write failed` only: the truncate is skipped |
| 4 | request driven to OOM | worker ends, no graceful fatal (CVE-2026-109618 `_exit` path) | graceful `Allowed memory size … exhausted` fatal (old `longjmp` path) |
| 5 | requests after the OOM | all HTTP 200 (no stale state — CVE-2026-109619) | may wedge / serve corrupted state |

Strong discriminators: **test 4** (round 1) and **test 3** (round 2).

Weak signals, read with care:

- `max_multipart_body_parts` (test 1) is a marker of *this* patch only on
  vanilla php.net sources. Distribution / third-party builds (e.g. Remi) that
  backported the 2023 multipart fix (CVE-2023-0662) already have this INI, so
  it is PRESENT even without these patches.
- Test 2 is also capped by `max_input_vars` (default 1000), so an unpatched
  build usually passes it as well.

Test 3 needs the `posix` extension (`php-process` on RHEL/CentOS) and a
writable `sys_get_temp_dir()`; otherwise it reports INCONCLUSIVE. On hosts
without `php-process`, run `./check-126714.sh /usr/bin/php` on the server
instead: it creates the FIFO with `mkfifo(1)` and runs the same probe with the
CLI of the same package (the session code is shared by every SAPI). It creates a
private temp dir with a FIFO, uses its own session id and save path, and
removes both. Application sessions are not touched. It runs before the OOM
test on purpose, because test 4 recycles the worker (and ends `php -S`).

### CVE-2026-129496 (`check-129496.sh`)

This one cannot be triggered over HTTP: the affected path is `error_log`
writing while no request is active (startup / shutdown). The fix lives in
`main/main.c`, which every SAPI of a build shares, so check it with the CLI
binary from the same build or package, on the server:

```sh
./check-129496.sh /usr/bin/php
```

It starts PHP with a removed directive (`safe_mode=1`) and a non-UTC
`date.timezone`. The startup error is stamped in **UTC** on a patched build
and in **local time** on an unpatched one. PHP exits at startup and nothing
else runs. Exit code: 0 PASS, 1 FAIL, 2 inconclusive.

## Usage

1. Edit `cvecheck.php` and set `CVECHECK_TOKEN` to a random value.
2. Copy it to an **isolated path** on the target, e.g.
   `DOCUMENT_ROOT/_cvecheck/cvecheck.php`.
3. Run the driver.

   Linux/macOS:

   ```sh
   ./run-cvecheck.sh https://host/_cvecheck/cvecheck.php <token>
   # name-based vhost reached over localhost:
   ./run-cvecheck.sh http://localhost/_cvecheck/cvecheck.php <token> host.example.com
   ```

   Windows PowerShell:

   ```powershell
   .\run-cvecheck.ps1 -Url https://host/_cvecheck/cvecheck.php -Token <token>
   # name-based vhost reached over localhost:
   .\run-cvecheck.ps1 -Url http://localhost/_cvecheck/cvecheck.php -Token <token> -HostHeader host.example.com
   ```

   (If scripts are blocked, run it once with
   `powershell -ExecutionPolicy Bypass -File .\run-cvecheck.ps1 ...`.
   `-HostHeader` requires PowerShell 7+; on Windows PowerShell 5.1 target the
   real hostname in `-Url` instead.)

4. **Delete `cvecheck.php` from the server when finished.**

Exit code is `0` when every check passes, `1` otherwise.

## Safety notes

- The endpoint refuses every request without the correct `?k=<token>`, so it is
  not left as an open, unauthenticated OOM trigger while installed. Still,
  remove it after the test — do not leave it deployed.
- The OOM probe sets `memory_limit` to 32M **for its own request only**; it
  exhausts that worker's request budget, not the host's RAM. It will recycle
  one worker process; run it in a maintenance window if that matters.
- Behaviour depends on the SAPI and the process manager; read the per-check
  output, not only the summary line.

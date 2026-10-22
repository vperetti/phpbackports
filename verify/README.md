# Mitigation verifier — CVE-2026-109618 / 109619

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

## What it checks

| # | Probe | Patched build | Unpatched build |
|---|---|---|---|
| 1 | `max_multipart_body_parts` INI exists | PRESENT | ABSENT (the INI is added by the fix) |
| 1 | `session.upload_progress.enabled` | off | on (producer path of CVE-2026-109619) |
| 2 | POST with 3000 parts | parsed count capped | all 3000 accepted |
| 3 | request driven to OOM | worker ends, no graceful fatal (CVE-2026-109618 `_exit` path) | graceful `Allowed memory size … exhausted` fatal (old `longjmp` path) |
| 4 | requests after the OOM | all HTTP 200 (no stale state — CVE-2026-109619) | may wedge / serve corrupted state |

The two strong discriminators are **the OOM killing the worker with no graceful
fatal** and **the multipart cap**; together they distinguish a patched build
from an unpatched one of the same version.

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

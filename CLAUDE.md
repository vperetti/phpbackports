# phpbackports: notes for agents

Security patches for end-of-life PHP (5.4 – 7.4). Read `README.md` first.

## Building on Windows

Follow `docs/WINDOWS-BUILD.md` step by step. It covers the patch to use per
version, the line-ending check, applying with `git apply`, building with the
PHP SDK, and checking the result with `verify/check-local.php`.

Rules:

- One patch per build: `patches/remi/php-X.Y-remi-security-backports.patch`
  (recommended on 5.6 / 7.x) **or** our `patches/php-X.Y-CVE-*` files, never both.
- Apply only to a freshly extracted official php.net tarball of that exact
  version, outside any git working tree.
- Never edit a `.patch` by hand or "fix" a failing hunk. If `git apply --check`
  fails, stop and report the exact error (see Troubleshooting in the guide).
- Report results as: PHP version, toolset, configure line, the full output of
  `verify/check-local.php --src=.`, and any test that fails only on the patched
  build (with its `.diff`).
- Do not commit build output, tarballs or extracted sources to this repository.

## Changing the patches

The patches are generated, not hand-written: `tools/aplica54.py` (5.x) and
`tools/aplica73.py` (7.x) for our own patches, `tools/remi-export.sh` for the
Remi exports. Change the tool, regenerate, and check that applying the patch
gives the same tree as running the tool.

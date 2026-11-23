# Building patched PHP on Windows

How to build PHP 5.6 / 7.0 – 7.4 on Windows with the security patches from
this repository, and how to check the result. Written for an existing
Visual Studio + PHP SDK build environment (the steps that change are 1–4);
section "Build environment" covers a new machine.

## Which patch, which compiler

| PHP | Patch (from `patches/remi/`) | Official toolset |
|---|---|---|
| 7.4.33 | `php-7.4-remi-security-backports.patch` | VC15 (Visual Studio 2017) |
| 7.3.33 | `php-7.3-remi-security-backports.patch` | VC15 (Visual Studio 2017) |
| 7.2.34 | `php-7.2-remi-security-backports.patch` | VC15 (Visual Studio 2017) |
| 7.1.33 | `php-7.1-remi-security-backports.patch` | VC14 (Visual Studio 2015) |
| 7.0.33 | `php-7.0-remi-security-backports.patch` | VC14 (Visual Studio 2015) |
| 5.6.40 | `php-5.6-remi-security-backports.patch` | VC11 (Visual Studio 2012) |

Rules:

- **One patch per build.** Use the Remi patch *or* our
  `patches/php-*-CVE-*` patches, never both. On Windows use the Remi patch.
- Apply it to the **official php.net tarball** of exactly that version, freshly
  extracted. Not to a git checkout of php-src, not to an already patched tree.
- The patch already contains the regenerated re2c outputs and changes no
  bison / re2c sources: re2c and bison are **not** needed.
- Use `git apply`, not `patch`: the patch has binary test fixtures.

## 1. Get the repository with LF line endings

```bat
git clone https://github.com/vperetti/phpbackports.git C:\src\phpbackports
git -C C:\src\phpbackports ls-files --eol patches/remi/php-7.3-remi-security-backports.patch
```

The second command must show `w/lf` (or `w/-text`). If it shows `w/crlf`, the
checkout converted line endings and `git apply` will fail: pull the latest
version (it has a `.gitattributes` that prevents this), then
`git -C C:\src\phpbackports checkout -- patches`.

## 2. Get and extract the official tarball

Download `php-7.3.33.tar.bz2` (or your version) from
<https://www.php.net/distributions/> and check its SHA-256 against
<https://www.php.net/releases/>:

```bat
certutil -hashfile php-7.3.33.tar.bz2 SHA256
```

Extract it into the SDK build tree (Windows 10+ `tar` handles `.bz2`; 7-Zip
also works; both keep LF line endings):

```bat
cd C:\php-sdk\phpdev\vc15\x64
tar -xf C:\Downloads\php-7.3.33.tar.bz2
cd php-7.3.33
```

The extracted folder must **not** be inside another git working tree
(`git rev-parse --is-inside-work-tree` must fail there). Otherwise `git apply`
resolves paths against that repository and skips the files.

## 3. Apply the patch

```bat
git apply --check -p1 C:\src\phpbackports\patches\remi\php-7.3-remi-security-backports.patch
git apply -p1 C:\src\phpbackports\patches\remi\php-7.3-remi-security-backports.patch
```

`--check` prints nothing when the patch fits. Then confirm the fix markers:

```bat
findstr /C:"if (ftruncate(data->fd, 0) != 0)" ext\session\mod_files.c
findstr /C:"PG(modules_activated) && EG(active)" main\main.c
```

Each must print one line.

## 4. Build

In the SDK shell for your toolset (e.g. `C:\php-sdk\phpsdk-vc15-x64.bat`),
inside the patched source folder, with your usual configure options:

```bat
buildconf
configure --enable-cli --disable-zts ...your usual options...
nmake
```

The binaries land in `x64\Release` (NTS) or `x64\Release_TS` (TS).
No `config.w32` changes are needed on your side. The 5.6 patch changes the
`config.w32` of openssl / curl / ldap / snmp so they find either OpenSSL 1.0
or 1.1 libraries.

## 5. Check the build

Local checks with the new `php.exe`, no web server needed:

```bat
x64\Release\php.exe C:\src\phpbackports\verify\check-local.php --src=.
```

Expected: `PASS` for 109618, 129496 and 126714, and `present` for the three
markers. On Windows 126714 is a **source** check: its behavioural test needs
FIFOs, which Windows does not have. Exit code 0 = all PASS.

Then the PHP test suite on the areas the patch touches (it adds the GHSA
regression tests next to the code):

```bat
nmake test TESTS="Zend/tests tests ext/standard/tests ext/session ext/date"
```

Expected differences against an unpatched build:

- `tests/lang/bug45392.phpt` fails: expected. The OOM fix ends the process
  instead of running the old bailout path.
- `ghsa-f6gg-*.phpt` need the openssl extension; they skip or fail without it.
- Network and timing tests (`stream_isatty_*`, ports already in use) can fail
  on any build; rerun them alone before blaming the patch.

Anything else that fails only on the patched build: stop and report it, with
the `.diff` file that run-tests leaves next to the test.

## 6. After deploying

On the web server, publish `verify/cvecheck.php` (set its token) and run
`verify/run-cvecheck.ps1` against it. On Windows, its test [3] (126714) reports
INCONCLUSIVE because there is no `posix_mkfifo`; step 5 already covered it.
Remove `cvecheck.php` from the server afterwards.

## Build environment (new machine)

1. Visual Studio for the toolset in the table, with the C++ workload and a
   Windows SDK.
2. PHP SDK binary tools: <https://github.com/php/php-sdk-binary-tools>
   (a release that has `phpsdk-vc15-x64.bat` for VC15, `phpsdk-vc14-*` for VC14).
   In its shell: `phpsdk_buildtree phpdev`, then put the source under
   `phpdev\vc15\x64\`.
3. Dependencies (libraries for openssl, curl, ...): `phpsdk_deps --update
   --branch 7.3` inside the source folder. For end-of-life branches the
   download may no longer be served. Reuse the `deps` folder of your current
   build machine; the patch does not need newer libraries.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `git apply`: `patch does not apply`, `corrupt patch` | CRLF in the patch (step 1), wrong tarball version, or a tree that is already patched (`git apply -R --check` succeeds on a patched tree) |
| `git apply` succeeds but nothing changes | the source folder is inside another git working tree (step 2) |
| `findstr` finds no marker | patch not applied to this folder |
| check-local `INCONCLUSIVE` for 126714 | run it with `--src=<patched source folder>` |
| check-local `FAIL` | the `php.exe` tested is not the patched build (check the path it prints) |

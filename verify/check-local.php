<?php
/*
 * check-local.php: local checks of the 2026 fixes, run with the PHP CLI of
 * the build under test. Works on Windows (php.exe) and Linux, PHP 5.4 - 7.4.
 * No web server needed; each check runs in a child PHP process.
 *
 *   php check-local.php [--src=<patched source tree>]
 *
 *   [1] CVE-2026-109618  OOM fatal must not run shutdown functions
 *   [2] CVE-2026-129496  error_log outside a request must be stamped in UTC
 *   [3] CVE-2026-126714  files session handler must truncate before writing
 *       behavioural with posix_mkfifo (Linux); on Windows there are no FIFOs,
 *       so it falls back to a source check of --src (ext/session/mod_files.c)
 *
 * With --src it also prints which fix markers are present in the source.
 * Exit code: 0 all PASS, 1 any FAIL, 2 otherwise (something INCONCLUSIVE).
 * Behavioural validation, not an exploit.
 */

error_reporting(E_ALL);
$PHP = PHP_BINARY;
$SRC = null;
foreach (array_slice($argv, 1) as $a) {
    if (strncmp($a, '--src=', 6) === 0) {
        $SRC = rtrim(substr($a, 6), '/\\');
    } else {
        fwrite(STDERR, "usage: php check-local.php [--src=<patched source tree>]\n");
        exit(2);
    }
}
$WIN = strncasecmp(PHP_OS, 'WIN', 3) === 0;
$res = array();

function tmpdir_make() {
    $d = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cvechk' . getmypid() . mt_rand(1000, 9999);
    mkdir($d, 0700);
    return $d;
}
function rmtree($d) {
    foreach (glob($d . DIRECTORY_SEPARATOR . '*') ?: array() as $f) { @unlink($f); }
    @rmdir($d);
}
/* run "php <ini...> <script>" and return array(exit code, stdout+stderr).
 * proc_open with bypass_shell: on Windows no cmd.exe quoting is involved. */
function child($ini, $code, $dir) {
    global $PHP;
    $f = $dir . DIRECTORY_SEPARATOR . 'c' . mt_rand(1000, 99999) . '.php';
    $o = $f . '.out';
    file_put_contents($f, $code);
    $cmd = escapeshellarg($PHP);
    foreach ($ini as $k => $v) {
        $cmd .= ' ' . ($k === '-n' ? '-n' : '-d ' . escapeshellarg("$k=$v"));
    }
    $cmd .= ' -f ' . escapeshellarg($f);
    $e = $f . '.err';
    $spec = array(0 => array('pipe', 'r'), 1 => array('file', $o, 'w'), 2 => array('file', $e, 'w'));
    $p = proc_open($cmd, $spec, $pipes, $dir, null, array('bypass_shell' => true));
    if (!is_resource($p)) {
        return array(-1, 'proc_open failed');
    }
    fclose($pipes[0]);
    $rc = proc_close($p);
    $out = (string)@file_get_contents($o) . (string)@file_get_contents($e);
    @unlink($f); @unlink($o); @unlink($e);
    return array($rc, $out);
}
function verdict($id, $v, $msg) {
    global $res;
    $res[] = $v;
    printf("  %-12s %s - %s\n", $v, $id, $msg);
}

echo "== check-local.php: PHP " . PHP_VERSION . " " . PHP_OS . " (" . (PHP_ZTS ? 'TS' : 'NTS') . ") " . $PHP . "\n";
$T = tmpdir_make();

/* [1] CVE-2026-109618 */
echo "[1] CVE-2026-109618 OOM bailout\n";
list($rc, $out) = child(array('-n' => 1, 'memory_limit' => '8M', 'display_errors' => '1'),
    '<?php register_shutdown_function(function () { echo "SHUTDOWN-RAN\n"; });' .
    ' $a = str_repeat("x", 64 * 1024 * 1024); echo "NOT-REACHED\n";', $T);
if (strpos($out, 'SHUTDOWN-RAN') !== false) {
    verdict('109618', 'FAIL', 'shutdown function ran after the OOM fatal (unpatched)');
} elseif (stripos($out, 'Allowed memory size') !== false) {
    verdict('109618', 'PASS', "OOM fatal ended the process, no shutdown function ran (exit $rc)");
} else {
    verdict('109618', 'INCONCLUSIVE', "no OOM message seen (exit $rc): " . substr($out, 0, 200));
}

/* [2] CVE-2026-129496 */
echo "[2] CVE-2026-129496 error_log timestamp outside a request\n";
$log = $T . DIRECTORY_SEPARATOR . 'err.log';
child(array('-n' => 1, 'date.timezone' => 'Asia/Tokyo', 'log_errors' => '1', 'display_errors' => '0',
            'display_startup_errors' => '0', 'error_log' => $log, 'safe_mode' => '1'), '<?php ', $T);
$line = '';
foreach (is_file($log) ? file($log) : array() as $l) {
    if (strpos($l, 'safe_mode') !== false) { $line = trim($l); break; }
}
echo "     log> $line\n";
if ($line === '') {
    verdict('129496', 'INCONCLUSIVE', 'no startup line was logged');
} elseif (preg_match('/^\[[^\]]* UTC\]/', $line)) {
    verdict('129496', 'PASS', 'startup error stamped in UTC (patched behaviour)');
} elseif (strpos($line, 'Asia/Tokyo') !== false) {
    verdict('129496', 'FAIL', 'startup error stamped in local time (unpatched)');
} else {
    verdict('129496', 'INCONCLUSIVE', 'unexpected timestamp format');
}

/* [3] CVE-2026-126714 */
echo "[3] CVE-2026-126714 files session handler truncation\n";
if (function_exists('posix_mkfifo')) {
    $sid = 'cvechk' . mt_rand(100000, 999999);
    posix_mkfifo($T . '/sess_' . $sid, 0600);
    $code = '<?php if (!function_exists("session_start")) { echo "NO_SESSION\n"; exit; }' .
        ' $m = ""; set_error_handler(function ($n, $s) use (&$m) { $m .= $s . "\n"; return true; });' .
        ' session_id(' . var_export($sid, true) . '); session_start(); $_SESSION["a"] = str_repeat("b", 64);' .
        ' session_write_close(); echo $m;';
    $ini = array('session.save_handler' => 'files', 'session.save_path' => $T, 'session.use_cookies' => '0',
                 'session.use_strict_mode' => '0');
    list($rc, $out) = child(array('-n' => 1) + $ini, $code, $T);
    if (strpos($out, 'NO_SESSION') !== false) {
        list($rc, $out) = child($ini, $code, $T);   /* session is a shared extension: use php.ini */
    }
    if (strpos($out, 'NO_SESSION') !== false) {
        verdict('126714', 'INCONCLUSIVE', 'session extension not loaded');
    } elseif (stripos($out, 'ftruncate() failed') !== false) {
        verdict('126714', 'PASS', 'handler checks ftruncate() before writing (patched behaviour)');
    } elseif (stripos($out, 'write failed') !== false) {
        verdict('126714', 'FAIL', 'write went ahead without a truncate check (unpatched)');
    } else {
        verdict('126714', 'INCONCLUSIVE', 'unexpected result: ' . substr(trim($out), 0, 200));
    }
} elseif ($SRC !== null) {
    $mf = @file_get_contents($SRC . '/ext/session/mod_files.c');
    if ($mf === false) {
        verdict('126714', 'INCONCLUSIVE', "cannot read $SRC/ext/session/mod_files.c");
    } elseif (strpos($mf, 'if (ftruncate(data->fd, 0) != 0)') !== false) {
        verdict('126714', 'PASS', 'source check: mod_files.c always truncates (source only: the behavioural test needs posix_mkfifo)');
    } else {
        verdict('126714', 'FAIL', 'source check: mod_files.c lacks the fix');
    }
} else {
    verdict('126714', 'INCONCLUSIVE', ($WIN ? 'Windows has no FIFOs' : 'posix extension missing') .
        '; rerun with --src=<patched source tree> for a source check');
}

/* source markers */
if ($SRC !== null) {
    echo "[src] fix markers in $SRC\n";
    $marks = array(
        array('ext/session/mod_files.c', 'if (ftruncate(data->fd, 0) != 0)', 'CVE-2026-126714'),
        array('main/main.c', 'PG(modules_activated) && EG(active)', 'CVE-2026-129496'),
        array('main/main.c', 'max_multipart_body_parts', 'multipart part limit'),
    );
    foreach ($marks as $m) {
        $s = @file_get_contents($SRC . '/' . $m[0]);
        printf("  %-7s %s (%s)\n", ($s !== false && strpos($s, $m[1]) !== false) ? 'present' : 'MISSING', $m[2], $m[0]);
    }
}

rmtree($T);
$fail = in_array('FAIL', $res, true);
$pass = count(array_keys($res, 'PASS', true));
echo "== summary: PASS=$pass FAIL=" . count(array_keys($res, 'FAIL', true)) .
     " INCONCLUSIVE=" . count(array_keys($res, 'INCONCLUSIVE', true)) . "\n";
exit($fail ? 1 : ($pass === count($res) ? 0 : 2));

<?php
/*
 * cvecheck.php — temporary mitigation validator for CVE-2026-109618 / 109619
 * (round 1) and CVE-2026-126714 (round 2).
 *
 * This is NOT an exploit. It probes the observable *behaviour* that the patch
 * changes, so an operator can confirm a build is patched on the real SAPI
 * (mod_php / PHP-FPM) after deploying it. It never attempts code execution.
 *
 * SAFETY:
 *   - Access is gated by a token (?k=). Set CVECHECK_TOKEN below before deploy.
 *   - The OOM probe caps memory_limit to 32M for its own request only, so it
 *     exhausts that worker's request budget, not the host's RAM.
 *   - Deploy it to an isolated path, run the checks, then DELETE it. Do not
 *     leave it installed.
 */

$CVECHECK_TOKEN = 'CHANGE_ME';   // set a random value; pass it as ?k=<token>

if (!isset($_GET['k']) || !(function_exists('hash_equals') ? hash_equals($CVECHECK_TOKEN, (string)$_GET['k']) : $CVECHECK_TOKEN === (string)$_GET['k'])) {
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/plain');
    echo "forbidden\n";
    exit;
}

$t = isset($_GET['t']) ? $_GET['t'] : 'info';
header('Content-Type: text/plain');

if ($t === 'info') {
    /* max_multipart_body_parts does not exist in vanilla php.net 5.4-7.3
       sources, so there it marks this patch. Distribution builds (e.g. Remi)
       that backported CVE-2023-0662 already have it: weak signal only, the
       OOM probe (t=oom) is the real discriminator for round 1. */
    $mmbp = ini_get('max_multipart_body_parts');
    echo "php=" . PHP_VERSION . "\n";
    echo "max_multipart_body_parts=" . $mmbp . "\n";
    echo "max_input_vars=" . ini_get('max_input_vars') . "\n";
    echo "session.upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
    echo "memory_limit=" . ini_get('memory_limit') . "\n";
    echo "pid=" . getmypid() . "\n";
    echo "fix_marker=" . (($mmbp === '' || $mmbp === false) ? "ABSENT" : "PRESENT") . "\n";
    echo "posix_mkfifo=" . (function_exists('posix_mkfifo') ? "yes" : "no") . "\n";
    echo "ok\n";

} elseif ($t === 'multipart') {
    /* The runner POSTs more parts than max_input_vars. A patched/hardened
       parser caps the number of parsed parts; count($_POST) reflects the cap. */
    echo "POST_count=" . count($_POST) . "\n";
    echo "FILES_count=" . count($_FILES) . "\n";
    echo "pid=" . getmypid() . "\n";
    echo "ok\n";

} elseif ($t === 'oom') {
    /* Drive this request to an allocation failure under a low, request-local
       memory_limit. In a PATCHED build the worker ends the process (_exit)
       instead of longjmp-ing back through partially-initialised request state,
       so the client sees the connection close with no graceful
       "Allowed memory size ... exhausted" fatal in the body. */
    @ini_set('memory_limit', '32M');
    echo "before_oom pid=" . getmypid() . "\n";
    for (ob_start(); ob_get_level(); ) { ob_end_flush(); }
    flush();
    $a = array();
    while (true) { $a[] = str_repeat('x', 1048576); }
    echo "AFTER_OOM_SHOULD_NOT_PRINT\n";

} elseif ($t === 'session126714') {
    /* CVE-2026-126714: the patched "files" session handler ALWAYS truncates
       the session file before writing and aborts the write if ftruncate()
       fails. The probe points a throw-away session at a FIFO in a private
       temp dir: ftruncate() on a FIFO fails, so only a patched build reports
       "ftruncate() failed". An unpatched build skips the truncate and fails
       later with "write failed". Touches no real session and no app data. */
    if (!function_exists('posix_mkfifo')) {
        echo "result=INCONCLUSIVE (posix extension not loaded)\nok\n"; exit;
    }
    if (function_exists('session_status') && session_status() === PHP_SESSION_ACTIVE) {
        echo "result=INCONCLUSIVE (a session is already active, e.g. session.auto_start)\nok\n"; exit;
    }
    $msgs = array();
    set_error_handler(function ($no, $str) use (&$msgs) { $msgs[] = $str; return true; });
    $dir = rtrim(sys_get_temp_dir(), '/') . '/cvecheck_' . getmypid() . '_' . mt_rand();
    $id  = 'cvechk' . mt_rand(100000, 999999);
    $made = @mkdir($dir, 0700) && @posix_mkfifo("$dir/sess_$id", 0600);
    if ($made) {
        ini_set('session.save_handler', 'files');
        ini_set('session.save_path', $dir);
        ini_set('session.use_cookies', '0');
        ini_set('session.use_strict_mode', '0');
        session_id($id);
        session_start();
        $_SESSION['cvecheck'] = 'probe';
        session_write_close();
    }
    restore_error_handler();
    @unlink("$dir/sess_$id");
    @rmdir($dir);
    if (!$made) { echo "result=INCONCLUSIVE (cannot create FIFO in " . sys_get_temp_dir() . ")\nok\n"; exit; }
    $trunc = 0;
    foreach ($msgs as $m) {
        echo "msg=" . str_replace(array("\r", "\n"), ' ', $m) . "\n";
        if (stripos($m, 'ftruncate') !== false) $trunc = 1;
    }
    echo "result=" . ($trunc ? "PATCHED" : "UNPATCHED") . "\n";
    echo "ok\n";

} else {
    echo "unknown t\n";
}

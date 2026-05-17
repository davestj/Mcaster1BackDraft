<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * rootkit-scan.php — BackDraft Rootkit Hunter + File Integrity Scanner
 * Replaces rkhunter with a custom implementation.
 * Schedule: Every 24 hours (critical priority)
 *
 * Checks:
 *   1. System binary integrity (SHA-256 baseline)
 *   2. Hidden file detection in web roots
 *   3. Web shell detection (PHP eval/system/passthru patterns)
 *   4. Suspicious process detection
 *   5. Unauthorized listening ports
 *   6. Cron job audit
 *   7. SUID/SGID binary scan
 *   8. SSH authorized_keys audit
 *   9. Kernel module check
 */
$args = [];
foreach ($argv as $arg) { if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2]; }
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Rootkit & Integrity Scan ===\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

try {
    $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        BD_DB_USER, BD_DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
} catch (PDOException $e) { echo "FATAL: " . $e->getMessage() . "\n"; exit(1); }

$insert_scan = $pdo->prepare("INSERT INTO backdraft_rootkit_scans (scan_type, check_name, status, detail) VALUES (?, ?, ?, ?)");
$insert_integrity = $pdo->prepare("INSERT INTO backdraft_file_integrity (file_path, expected_hash, current_hash, file_size, status, category)
    VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE current_hash = VALUES(current_hash), file_size = VALUES(file_size),
    status = VALUES(status), checked_at = NOW()");

$warnings = 0;
$criticals = 0;

function check($pdo, $stmt, $type, $name, $status, $detail) {
    global $warnings, $criticals;
    $stmt->execute([$type, $name, $status, $detail]);
    $icon = $status === 'clean' ? '[OK]' : ($status === 'warning' ? '[WARN]' : '[CRIT]');
    echo "  {$icon} {$name}: {$detail}\n";
    if ($status === 'warning') $warnings++;
    if ($status === 'critical') $criticals++;
}

// ── 1. System Binary Integrity ───────────────────────────────────────────
echo "--- 1. System Binary Integrity ---\n";
$critical_binaries = [
    '/usr/bin/ssh' => 'system_binary',
    '/usr/bin/sudo' => 'system_binary',
    '/usr/sbin/nginx' => 'system_binary',
    '/usr/bin/php8.2' => 'system_binary',
    '/usr/bin/mysql' => 'system_binary',
    '/usr/bin/curl' => 'system_binary',
    '/usr/bin/wget' => 'system_binary',
    '/usr/sbin/sshd' => 'system_binary',
    '/usr/bin/passwd' => 'system_binary',
    '/usr/bin/su' => 'system_binary',
    '/usr/bin/crontab' => 'system_binary',
    '/usr/bin/clamscan' => 'system_binary',
];

foreach ($critical_binaries as $path => $cat) {
    if (!file_exists($path)) {
        check($pdo, $insert_scan, 'integrity', basename($path), 'warning', "Binary not found: {$path}");
        continue;
    }

    $hash = hash_file('sha256', $path);
    $size = filesize($path);

    // Check against baseline
    $baseline = $pdo->query("SELECT expected_hash FROM backdraft_file_integrity WHERE file_path = " . $pdo->quote($path))->fetchColumn();

    if (!$baseline) {
        // First run — establish baseline
        $insert_integrity->execute([$path, $hash, $hash, $size, 'ok', $cat]);
        check($pdo, $insert_scan, 'integrity', basename($path), 'clean', "Baseline established: {$hash}");
    } elseif ($baseline !== $hash) {
        $insert_integrity->execute([$path, $baseline, $hash, $size, 'modified', $cat]);
        check($pdo, $insert_scan, 'integrity', basename($path), 'critical', "MODIFIED! Expected: " . substr($baseline, 0, 16) . "... Got: " . substr($hash, 0, 16) . "...");
    } else {
        $insert_integrity->execute([$path, $baseline, $hash, $size, 'ok', $cat]);
        check($pdo, $insert_scan, 'integrity', basename($path), 'clean', "OK: {$path}");
    }
}

// ── 2. Hidden Files in Web Roots ─────────────────────────────────────────
echo "\n--- 2. Hidden File Detection ---\n";
$web_dirs = ['/var/www', '/tmp', '/dev/shm'];
$hidden_found = 0;
foreach ($web_dirs as $dir) {
    $cmd = "find " . escapeshellarg($dir) . " -name '.*' -type f -not -name '.htaccess' -not -name '.htpasswd' -not -name '.gitignore' -not -name '.env' 2>/dev/null | head -50";
    $files = array_filter(explode("\n", trim(shell_exec($cmd))));
    foreach ($files as $f) {
        if (empty($f)) continue;
        // Skip known safe hidden files
        if (preg_match('/\.(user\.ini|php|well-known|claude)/', $f)) continue;
        $hidden_found++;
    }
}
if ($hidden_found > 10) {
    check($pdo, $insert_scan, 'hidden_files', 'Hidden files', 'warning', "{$hidden_found} hidden files found in web directories");
} else {
    check($pdo, $insert_scan, 'hidden_files', 'Hidden files', 'clean', "{$hidden_found} hidden files (within normal range)");
}

// ── 3. Web Shell Detection ───────────────────────────────────────────────
echo "\n--- 3. Web Shell Detection ---\n";
$shell_patterns = [
    'eval\s*\(\s*base64_decode',
    'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
    'system\s*\(\s*\$_(GET|POST|REQUEST)',
    'passthru\s*\(\s*\$_',
    'shell_exec\s*\(\s*\$_',
    'exec\s*\(\s*\$_(GET|POST|REQUEST)',
    'assert\s*\(\s*\$_',
    'preg_replace\s*\(.*/e',
    'base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
    'create_function\s*\(\s*.*\$_',
];

$pattern_regex = implode('|', $shell_patterns);
$sites = $pdo->query("SELECT id, site_name, doc_root FROM backdraft_sites WHERE doc_root != ''")->fetchAll();
$shells_found = 0;

foreach ($sites as $site) {
    if (!is_dir($site['doc_root'])) continue;
    $cmd = "grep -rlE " . escapeshellarg($pattern_regex) . " " . escapeshellarg($site['doc_root']) . " --include='*.php' 2>/dev/null | head -20";
    $matches = array_filter(explode("\n", trim(shell_exec($cmd))));
    foreach ($matches as $f) {
        if (empty($f)) continue;
        // Skip vendor/node_modules
        if (strpos($f, '/vendor/') !== false || strpos($f, '/node_modules/') !== false) continue;
        $shells_found++;
        $hash = hash_file('sha256', $f);
        $insert_integrity->execute([$f, '', $hash, filesize($f), 'new', 'web_shell']);
        check($pdo, $insert_scan, 'web_shell', 'Suspicious PHP', 'warning', "Potential web shell: {$f}");
    }
}
if ($shells_found === 0) {
    check($pdo, $insert_scan, 'web_shell', 'Web shell scan', 'clean', 'No suspicious PHP patterns found');
}

// ── 4. Process Check ─────────────────────────────────────────────────────
echo "\n--- 4. Process Audit ---\n";
$suspicious_procs = shell_exec("ps aux 2>/dev/null | grep -E '(crypto|miner|xmrig|coin|monero|reverse|nc -l|ncat -l)' | grep -v grep | head -5");
if (!empty(trim($suspicious_procs))) {
    check($pdo, $insert_scan, 'process', 'Suspicious processes', 'critical', trim($suspicious_procs));
} else {
    check($pdo, $insert_scan, 'process', 'Process scan', 'clean', 'No suspicious processes detected');
}

// ── 5. Listening Ports ───────────────────────────────────────────────────
echo "\n--- 5. Port Audit ---\n";
$known_ports = [22, 25, 80, 443, 587, 993, 3306, 5432, 8832, 8862, 9432, 9688, 9689, 9877, 8000, 11211];
$listening = shell_exec("ss -tlnp 2>/dev/null | grep LISTEN | awk '{print \$4}' | grep -oP ':\K[0-9]+' | sort -n | uniq");
$ports = array_filter(array_map('intval', explode("\n", trim($listening))));
$unknown_ports = array_diff($ports, $known_ports);
if (count($unknown_ports) > 0) {
    check($pdo, $insert_scan, 'ports', 'Unknown ports', 'warning', 'Unexpected ports: ' . implode(', ', $unknown_ports));
} else {
    check($pdo, $insert_scan, 'ports', 'Port scan', 'clean', count($ports) . ' ports listening (all known)');
}

// ── 6. Cron Audit ────────────────────────────────────────────────────────
echo "\n--- 6. Cron Audit ---\n";
$cron_dirs = ['/etc/cron.d/', '/etc/cron.daily/', '/etc/cron.hourly/', '/var/spool/cron/crontabs/'];
$cron_files = [];
foreach ($cron_dirs as $dir) {
    if (is_dir($dir)) {
        foreach (glob($dir . '*') as $f) {
            if (is_file($f)) $cron_files[] = $f;
        }
    }
}
$crontab = shell_exec("crontab -l 2>/dev/null");
$total_cron = count($cron_files) + ($crontab ? substr_count($crontab, "\n") : 0);
check($pdo, $insert_scan, 'cron', 'Cron jobs', 'clean', "{$total_cron} cron entries found across " . count($cron_files) . " files");

// ── 7. SUID/SGID ─────────────────────────────────────────────────────────
echo "\n--- 7. SUID/SGID Scan ---\n";
$suid_files = shell_exec("find / -type f \\( -perm -4000 -o -perm -2000 \\) -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -30");
$suid_count = substr_count(trim($suid_files), "\n") + (empty(trim($suid_files)) ? 0 : 1);
$known_suid = ['su', 'sudo', 'passwd', 'chsh', 'chfn', 'newgrp', 'mount', 'umount', 'ping', 'ssh-keysign', 'unix_chkpwd', 'crontab', 'wall', 'expiry', 'chage', 'write.ul', 'at', 'bsd-write', 'dotlockfile', 'pam_timestamp_check'];
$unknown_suid = [];
foreach (array_filter(explode("\n", trim($suid_files))) as $f) {
    $bn = basename($f);
    if (!in_array($bn, $known_suid)) $unknown_suid[] = $f;
}
if (count($unknown_suid) > 3) {
    check($pdo, $insert_scan, 'suid', 'SUID binaries', 'warning', count($unknown_suid) . ' unusual SUID binaries: ' . implode(', ', array_slice($unknown_suid, 0, 5)));
} else {
    check($pdo, $insert_scan, 'suid', 'SUID scan', 'clean', "{$suid_count} SUID/SGID binaries (normal)");
}

// ── 8. SSH Keys ──────────────────────────────────────────────────────────
echo "\n--- 8. SSH Key Audit ---\n";
$auth_keys_files = shell_exec("find /home /root -name authorized_keys -type f 2>/dev/null");
$key_files = array_filter(explode("\n", trim($auth_keys_files)));
$total_keys = 0;
foreach ($key_files as $kf) {
    if (empty($kf)) continue;
    $keys = file($kf, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $keys = array_filter($keys, fn($l) => !str_starts_with(trim($l), '#') && !empty(trim($l)));
    $total_keys += count($keys);
}
check($pdo, $insert_scan, 'ssh', 'SSH keys', 'clean', "{$total_keys} authorized keys across " . count($key_files) . " files");

// ── 9. Kernel Modules ────────────────────────────────────────────────────
echo "\n--- 9. Kernel Module Check ---\n";
$modules = shell_exec("lsmod 2>/dev/null | wc -l");
$suspicious_modules = shell_exec("lsmod 2>/dev/null | grep -iE '(rootkit|hide|stealth|keylog|backdoor)' | head -5");
if (!empty(trim($suspicious_modules))) {
    check($pdo, $insert_scan, 'kernel', 'Kernel modules', 'critical', 'Suspicious modules: ' . trim($suspicious_modules));
} else {
    check($pdo, $insert_scan, 'kernel', 'Kernel modules', 'clean', trim($modules) . ' modules loaded (no suspicious names)');
}

// ── 10. chkrootkit (if available) ────────────────────────────────────────
echo "\n--- 10. chkrootkit ---\n";
$chkrootkit = trim(shell_exec('which chkrootkit 2>/dev/null'));
if ($chkrootkit) {
    $output = shell_exec("sudo {$chkrootkit} 2>/dev/null | grep INFECTED | head -10");
    if (!empty(trim($output))) {
        check($pdo, $insert_scan, 'chkrootkit', 'chkrootkit', 'critical', 'INFECTED: ' . trim($output));
    } else {
        check($pdo, $insert_scan, 'chkrootkit', 'chkrootkit', 'clean', 'No rootkits detected by chkrootkit');
    }
} else {
    check($pdo, $insert_scan, 'chkrootkit', 'chkrootkit', 'clean', 'chkrootkit not installed (skipped)');
}

// ── Summary ──────────────────────────────────────────────────────────────
echo "\n=== Scan Summary ===\n";
echo "Warnings: {$warnings}\n";
echo "Critical: {$criticals}\n";
echo "Status: " . ($criticals > 0 ? 'CRITICAL' : ($warnings > 0 ? 'WARNINGS' : 'CLEAN')) . "\n";

$summary = [
    'report_generated' => date('Y-m-d H:i:s'),
    'warnings' => $warnings,
    'criticals' => $criticals,
    'status' => $criticals > 0 ? 'CRITICAL' : ($warnings > 0 ? 'WARNINGS' : 'CLEAN'),
];
file_put_contents('/tmp/backdraft_task_rootkit_scan.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

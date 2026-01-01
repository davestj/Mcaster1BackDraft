<?php
/**
 * error-log-parse.php — Parse nginx error logs into backdraft_error_log
 *
 * Reads error logs for all log_analysis=1 sites, parses nginx error format,
 * inserts structured entries into backdraft_error_log table.
 *
 * Schedule: Every 15 minutes
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Error Log Parser ===\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

try {
    $pdo = new PDO(
        'mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        'DUMMY_MARIADB_USER_SET_VIA_VAULT', 'DUMMY_MARIADB_PWD_SET_VIA_VAULT',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (PDOException $e) {
    echo "FATAL: DB connect failed: " . $e->getMessage() . "\n";
    exit(1);
}

$sites = $pdo->query("SELECT id, site_name, error_log_path FROM backdraft_sites WHERE log_analysis = 1 AND error_log_path != ''")->fetchAll();
echo "Sites: " . count($sites) . "\n\n";

// nginx error log format:
// 2026/03/20 17:37:44 [error] 12345#12345: *67890 message, client: 1.2.3.4, server: host, request: "GET /path HTTP/1.1"
$pattern = '/^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] .*?: (.+)/';
$client_pat = '/client: ([\d.]+)/';
$request_pat = '/request: "(\w+) (\S+)/';
$upstream_pat = '/upstream: "([^"]+)"/';

$total_parsed = 0;

$insert = $pdo->prepare(
    "INSERT IGNORE INTO backdraft_error_log (site_id, logged_at, level, message, client_ip, request_path, upstream_url) VALUES (?,?,?,?,?,?,?)"
);

foreach ($sites as $site) {
    $sid = $site['id'];
    $name = $site['site_name'];
    $path = $site['error_log_path'];

    if (!is_readable($path)) { echo "[{$name}] Not readable: {$path}\n"; continue; }

    // High-water mark
    $hwm_key = "errlog_hwm_{$sid}";
    $hwm = (int)$pdo->query("SELECT COALESCE(config_value,'0') FROM backdraft_config WHERE config_key = " . $pdo->quote($hwm_key))->fetchColumn();

    $filesize = filesize($path);
    if ($hwm > $filesize) $hwm = 0; // rotated
    if ($filesize - $hwm <= 0) { echo "[{$name}] No new data\n"; continue; }

    $fp = fopen($path, 'r');
    fseek($fp, $hwm);
    $count = 0;

    while (($line = fgets($fp)) !== false && $count < 50000) {
        if (!preg_match($pattern, $line, $m)) continue;
        $count++;

        $ts = str_replace('/', '-', $m[1]);
        $level = strtolower($m[2]);
        $msg = substr($m[3], 0, 2000);

        $client_ip = '';
        if (preg_match($client_pat, $msg, $cm)) $client_ip = $cm[1];

        $req_path = '';
        if (preg_match($request_pat, $msg, $rm)) $req_path = $rm[2];

        $upstream = '';
        if (preg_match($upstream_pat, $msg, $um)) $upstream = $um[1];

        $insert->execute([$sid, $ts, $level, $msg, $client_ip, $req_path, $upstream]);
    }

    $new_hwm = ftell($fp);
    fclose($fp);

    $pdo->prepare("INSERT INTO backdraft_config (config_key, config_value, description) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)")
        ->execute([$hwm_key, $new_hwm, "Error log HWM for {$name}"]);

    $total_parsed += $count;
    echo "[{$name}] Parsed {$count} error entries\n";
}

echo "\nTotal: {$total_parsed} entries\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";

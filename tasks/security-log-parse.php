<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * security-log-parse.php — Parse nginx security event logs into DB
 * Schedule: Every 15 minutes
 */
echo "=== BackDraft Security Log Parser ===\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

try {
    $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        BD_DB_USER, BD_DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
} catch (PDOException $e) { echo "FATAL: " . $e->getMessage() . "\n"; exit(1); }

$sites = $pdo->query("SELECT id, site_name, security_log_path FROM backdraft_sites WHERE security_log_enabled = 1 AND security_log_path != ''")->fetchAll();
echo "Sites with security logging: " . count($sites) . "\n\n";

// Map log filenames to block types
$log_type_map = [
    'agent_blocks' => 'bad_agent',
    'ip_blocks' => 'banned_ip',
    'path_blocks' => 'bad_path',
    'attack_blocks' => 'bad_payload',
];

// nginx log pattern: IP - user [timestamp] "METHOD URI PROTO" status bytes "referer" "UA" "MESSAGE"
$pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "[^"]*" "([^"]*)"/';

$total = 0;
$insert = $pdo->prepare("INSERT INTO backdraft_security_events
    (site_id, detected_at, client_ip, block_type, request_method, request_uri, user_agent, http_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)");

foreach ($sites as $site) {
    $log_dir = $site['security_log_path'];
    if (!is_dir($log_dir)) continue;

    foreach (glob("$log_dir/*.log") as $log_file) {
        $basename = pathinfo($log_file, PATHINFO_FILENAME);
        $block_type = $log_type_map[$basename] ?? 'bad_payload';

        $hwm_key = "seclog_hwm_{$site['id']}_{$basename}";
        $hwm = (int)$pdo->query("SELECT COALESCE(config_value,'0') FROM backdraft_config WHERE config_key = " . $pdo->quote($hwm_key))->fetchColumn();

        $filesize = filesize($log_file);
        if ($hwm > $filesize) $hwm = 0;
        if ($filesize - $hwm <= 0) continue;

        $fp = fopen($log_file, 'r');
        fseek($fp, $hwm);
        $count = 0;

        while (($line = fgets($fp)) !== false && $count < 10000) {
            if (!preg_match($pattern, $line, $m)) continue;
            $count++;

            $ts_str = preg_replace('/^(\d{2})\/(\w+)\/(\d{4}):/', '$3-$2-$1 ', $m[2]);
            $ts = date('Y-m-d H:i:s', strtotime($ts_str) ?: time());

            $insert->execute([
                $site['id'], $ts, $m[1], $block_type, $m[3],
                substr($m[4], 0, 2048), substr($m[6], 0, 1024), (int)$m[5]
            ]);
        }

        $new_hwm = ftell($fp);
        fclose($fp);

        $pdo->prepare("INSERT INTO backdraft_config (config_key, config_value, description) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)")
            ->execute([$hwm_key, $new_hwm, "Security log HWM: {$site['site_name']}/{$basename}"]);

        $total += $count;
        if ($count > 0) echo "[{$site['site_name']}] {$basename}: {$count} events\n";
    }
}

echo "\nTotal events parsed: {$total}\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";

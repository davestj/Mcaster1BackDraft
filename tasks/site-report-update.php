<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * site-report-update.php — Lightweight site analytics pre-computation
 *
 * Pre-computes per-site metrics that the real-time dashboard reads,
 * so the dashboard queries are fast and don't hit raw log tables.
 * Updates backdraft_log_realtime counters from recent request data.
 *
 * Schedule: Every 2 minutes (lightweight — only counts and aggregates)
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Site Report Update ===\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

try {
    $pdo = new PDO(
        'mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        BD_DB_USER, BD_DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (PDOException $e) {
    echo "FATAL: DB connect failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Get all sites with WAF or log analysis enabled
$sites = $pdo->query("SELECT id, site_name FROM backdraft_sites WHERE waf_enabled = 1 OR log_analysis = 1")->fetchAll();
echo "Sites to update: " . count($sites) . "\n\n";

$upsert = $pdo->prepare(
    "INSERT INTO backdraft_log_realtime (site_id, requests_1m, requests_5m, requests_15m, bytes_1m, errors_1m, active_ips)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
      requests_1m=VALUES(requests_1m), requests_5m=VALUES(requests_5m), requests_15m=VALUES(requests_15m),
      bytes_1m=VALUES(bytes_1m), errors_1m=VALUES(errors_1m), active_ips=VALUES(active_ips)"
);

foreach ($sites as $site) {
    $sid = $site['id'];
    $name = $site['site_name'];

    // Count from WAF requests (page_id starts with site_name)
    $r1m = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND request_time > DATE_SUB(NOW(), INTERVAL 1 MINUTE)")->fetchColumn();
    $r5m = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND request_time > DATE_SUB(NOW(), INTERVAL 5 MINUTE)")->fetchColumn();
    $r15m = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND request_time > DATE_SUB(NOW(), INTERVAL 15 MINUTE)")->fetchColumn();
    $b1m = (int)$pdo->query("SELECT COALESCE(SUM(response_bytes),0) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND request_time > DATE_SUB(NOW(), INTERVAL 1 MINUTE)")->fetchColumn();
    $e1m = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND threat_score > 0 AND request_time > DATE_SUB(NOW(), INTERVAL 1 MINUTE)")->fetchColumn();
    $ips = (int)$pdo->query("SELECT COUNT(DISTINCT client_ip) FROM backdraft_requests WHERE page_id LIKE '{$name}%' AND request_time > DATE_SUB(NOW(), INTERVAL 5 MINUTE)")->fetchColumn();

    $upsert->execute([$sid, $r1m, $r5m, $r15m, $b1m, $e1m, $ips]);

    if ($r5m > 0) {
        echo "  {$name}: 1m={$r1m} 5m={$r5m} 15m={$r15m} ips={$ips}\n";
    }
}

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

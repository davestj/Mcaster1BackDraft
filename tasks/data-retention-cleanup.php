<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * data-retention-cleanup.php — Purge expired data per retention policy
 *
 * Reads retention settings from backdraft_config and batch-deletes old records.
 * Prevents DB bloat from high-volume tables.
 *
 * Schedule: Every 24 hours (disabled by default — enable when ready)
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$batch_size = (int)($args['batch-size'] ?? 500);
$dry_run = isset($args['dry-run']);
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Data Retention Cleanup ===\n";
echo "Batch size: {$batch_size}\n";
echo "Dry run: " . ($dry_run ? 'YES' : 'no') . "\n";
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

// Load retention settings
$cfg = [];
$rows = $pdo->query("SELECT config_key, config_value FROM backdraft_config WHERE config_key LIKE '%retention%' OR config_key LIKE '%cleanup%'")->fetchAll();
foreach ($rows as $r) $cfg[$r['config_key']] = $r['config_value'];

$request_days  = (int)($cfg['request_log_retention_days'] ?? 90);
$threat_days   = (int)($cfg['threat_log_retention_days'] ?? 365);
$perf_hours    = 24;       // Always keep last 24h of perf metrics
$session_hours = 24;       // Expired sessions older than 24h
$hourly_days   = 90;       // Log stats hourly
$page_days     = 90;       // Page stats daily
$error_days    = 30;       // Error log entries
$task_run_days = 90;       // Task run history

echo "--- Retention Policy ---\n";
echo "  backdraft_requests: {$request_days} days\n";
echo "  backdraft_threats: {$threat_days} days\n";
echo "  backdraft_perf_metrics: {$perf_hours} hours\n";
echo "  backdraft_sessions: expired + {$session_hours}h\n";
echo "  backdraft_log_stats_hourly: {$hourly_days} days\n";
echo "  backdraft_log_page_stats: {$page_days} days\n";
echo "  backdraft_error_log: {$error_days} days\n";
echo "  backdraft_task_runs: {$task_run_days} days\n\n";

$total_purged = 0;

// Batch delete helper
function purge($pdo, $table, $where, $batch_size, $dry_run) {
    $count = (int)$pdo->query("SELECT COUNT(*) FROM {$table} WHERE {$where}")->fetchColumn();
    if ($count === 0) {
        echo "  {$table}: nothing to purge\n";
        return 0;
    }
    echo "  {$table}: {$count} rows eligible\n";
    if ($dry_run) return 0;

    $purged = 0;
    do {
        $deleted = $pdo->exec("DELETE FROM {$table} WHERE {$where} LIMIT {$batch_size}");
        $purged += $deleted;
        if ($deleted > 0) echo "    deleted batch: {$deleted} (total: {$purged})\n";
    } while ($deleted >= $batch_size);

    if ($purged > 1000) {
        echo "    optimizing table...\n";
        $pdo->exec("OPTIMIZE TABLE {$table}");
    }
    return $purged;
}

echo "--- Purging ---\n";

$total_purged += purge($pdo, 'backdraft_requests',
    "request_time < DATE_SUB(NOW(), INTERVAL {$request_days} DAY)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_threats',
    "detected_at < DATE_SUB(NOW(), INTERVAL {$threat_days} DAY)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_perf_metrics',
    "recorded_at < DATE_SUB(NOW(), INTERVAL {$perf_hours} HOUR)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_sessions',
    "expires_at < DATE_SUB(NOW(), INTERVAL {$session_hours} HOUR)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_log_stats_hourly',
    "hour_bucket < DATE_SUB(NOW(), INTERVAL {$hourly_days} DAY)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_log_page_stats',
    "day_bucket < DATE_SUB(NOW(), INTERVAL {$page_days} DAY)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_error_log',
    "logged_at < DATE_SUB(NOW(), INTERVAL {$error_days} DAY)", $batch_size, $dry_run);

$total_purged += purge($pdo, 'backdraft_task_runs',
    "started_at < DATE_SUB(NOW(), INTERVAL {$task_run_days} DAY) AND status != 'running'", $batch_size, $dry_run);

// Clean up orphaned audit log
$total_purged += purge($pdo, 'backdraft_audit_log',
    "created_at < DATE_SUB(NOW(), INTERVAL 365 DAY)", $batch_size, $dry_run);

// BotProof expired challenges and sessions
$total_purged += purge($pdo, 'backdraft_botproof_challenges',
    "expires_at < NOW()", $batch_size, $dry_run);
$total_purged += purge($pdo, 'backdraft_botproof_sessions',
    "expires_at < NOW()", $batch_size, $dry_run);

echo "\n--- Complete ---\n";
echo "Total rows purged: {$total_purged}\n";

$summary = ['report_generated' => date('Y-m-d H:i:s'), 'total_purged' => $total_purged, 'dry_run' => $dry_run];
file_put_contents('/tmp/backdraft_task_data_retention_cleanup.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "Completed: " . date('Y-m-d H:i:s') . "\n";

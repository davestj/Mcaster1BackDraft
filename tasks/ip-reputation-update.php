<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * ip-reputation-update.php — Recalculate IP reputation scores
 *
 * Scans backdraft_requests and backdraft_threats to build/update
 * IP reputation profiles in backdraft_ip_reputation.
 *
 * For each IP seen:
 *   - total_requests, total_threats, max_score, avg_score
 *   - first_seen, last_seen
 *   - Auto-ban if critical threat count exceeds threshold
 *
 * Schedule: Every 6 hours
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$hours = (int)($args['hours'] ?? 6);
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft IP Reputation Update ===\n";
echo "Window: last {$hours} hours\n";
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

// Get auto-ban threshold from config
$ban_threshold = (int)$pdo->query("SELECT config_value FROM backdraft_config WHERE config_key = 'ip_ban_auto_threshold'")->fetchColumn() ?: 3;
echo "Auto-ban threshold: {$ban_threshold} critical threats\n\n";

// ── 1. Aggregate IP stats from requests ──────────────────────────────────
echo "--- Aggregating IP data from requests ---\n";

$ip_data = $pdo->query("
    SELECT
        client_ip,
        COUNT(*) as total_requests,
        SUM(CASE WHEN threat_score >= 75 THEN 1 ELSE 0 END) as total_threats,
        MAX(threat_score) as max_score,
        AVG(threat_score) as avg_score,
        MIN(request_time) as first_seen,
        MAX(request_time) as last_seen
    FROM backdraft_requests
    GROUP BY client_ip
")->fetchAll();

echo "Unique IPs in request log: " . count($ip_data) . "\n";

// ── 2. Count critical threats per IP ─────────────────────────────────────
$critical_counts = [];
$criticals = $pdo->query("
    SELECT client_ip, COUNT(*) as cnt
    FROM backdraft_threats
    WHERE severity = 'critical' AND dismissed = 0
    GROUP BY client_ip
")->fetchAll();
foreach ($criticals as $c) {
    $critical_counts[$c['client_ip']] = (int)$c['cnt'];
}

// ── 3. Upsert into ip_reputation ─────────────────────────────────────────
echo "--- Updating IP reputation records ---\n";

$upsert = $pdo->prepare("
    INSERT INTO backdraft_ip_reputation
        (ip_addr, total_requests, total_threats, max_score, avg_score, first_seen, last_seen)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
        total_requests = VALUES(total_requests),
        total_threats  = VALUES(total_threats),
        max_score      = GREATEST(max_score, VALUES(max_score)),
        avg_score      = VALUES(avg_score),
        first_seen     = LEAST(first_seen, VALUES(first_seen)),
        last_seen      = GREATEST(last_seen, VALUES(last_seen))
");

$updated = 0;
$auto_banned = 0;

foreach ($ip_data as $ip) {
    $upsert->execute([
        $ip['client_ip'],
        $ip['total_requests'],
        $ip['total_threats'],
        $ip['max_score'],
        round($ip['avg_score'], 2),
        $ip['first_seen'],
        $ip['last_seen'],
    ]);
    $updated++;

    // Auto-ban check
    $crit_count = $critical_counts[$ip['client_ip']] ?? 0;
    if ($ban_threshold > 0 && $crit_count >= $ban_threshold) {
        $check = $pdo->prepare("SELECT banned FROM backdraft_ip_reputation WHERE ip_addr = ?");
        $check->execute([$ip['client_ip']]);
        $already_banned = (int)$check->fetchColumn();

        if (!$already_banned) {
            $pdo->prepare("
                UPDATE backdraft_ip_reputation
                SET banned = 1, banned_at = NOW(),
                    banned_reason = CONCAT('Auto-banned: ', ?, ' critical threats (threshold: ', ?, ')')
                WHERE ip_addr = ?
            ")->execute([$crit_count, $ban_threshold, $ip['client_ip']]);
            $auto_banned++;
            echo "  AUTO-BANNED: {$ip['client_ip']} ({$crit_count} critical threats)\n";
        }
    }
}

echo "Updated: {$updated} IPs\n";
echo "Auto-banned: {$auto_banned} IPs\n\n";

// ── 4. Summary stats ─────────────────────────────────────────────────────
$total_ips     = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_ip_reputation")->fetchColumn();
$banned_count  = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1")->fetchColumn();
$high_risk     = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE max_score >= 75 AND banned = 0")->fetchColumn();
$top_offenders = $pdo->query("SELECT ip_addr, total_requests, total_threats, max_score, banned FROM backdraft_ip_reputation ORDER BY max_score DESC LIMIT 10")->fetchAll();

echo "--- IP Reputation Summary ---\n";
echo "Total tracked IPs: {$total_ips}\n";
echo "Banned: {$banned_count}\n";
echo "High-risk (score>=75, not banned): {$high_risk}\n";
echo "\nTop 10 offenders:\n";
foreach ($top_offenders as $o) {
    $ban_label = $o['banned'] ? ' [BANNED]' : '';
    echo "  {$o['ip_addr']}: {$o['total_threats']} threats, max_score={$o['max_score']}, reqs={$o['total_requests']}{$ban_label}\n";
}

// Write summary JSON
$summary = [
    'report_generated' => date('Y-m-d H:i:s'),
    'total_ips_updated' => $updated,
    'auto_banned' => $auto_banned,
    'total_tracked' => $total_ips,
    'total_banned' => $banned_count,
    'high_risk' => $high_risk,
    'top_offenders' => $top_offenders,
];
file_put_contents('/tmp/backdraft_task_ip_reputation_update.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

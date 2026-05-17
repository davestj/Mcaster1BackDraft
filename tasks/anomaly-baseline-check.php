<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * anomaly-baseline-check.php — Compare current traffic to learned baselines
 *
 * Reads backdraft_page_profiles (learning-mode baselines) and compares against
 * recent request patterns. Flags anomalies:
 *   - New HTTP methods not in learned baseline
 *   - Unusual content types
 *   - Abnormal request volume (>300% of baseline)
 *   - Threat score spikes
 *   - New IPs targeting high-value pages
 *
 * When WAF goes active, these anomaly detections feed into threat scoring.
 * In learning mode, they serve as early warning intelligence.
 *
 * Schedule: Every 30 minutes
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$window_min = (int)($args['window'] ?? 30);
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Anomaly Baseline Check ===\n";
echo "Window: last {$window_min} minutes\n";
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

// Load all page profiles (baselines)
$profiles = $pdo->query("SELECT * FROM backdraft_page_profiles WHERE monitoring = 1")->fetchAll();
echo "Monitored page profiles: " . count($profiles) . "\n\n";

$anomalies = [];

foreach ($profiles as $p) {
    $page_id = $p['page_id'];
    $learned_methods = array_filter(array_map('trim', explode(',', $p['learned_methods'])));
    $learned_ctypes  = array_filter(array_map('trim', explode(',', $p['learned_content_types'])));
    $baseline_avg    = (float)$p['avg_score'];
    $baseline_reqs   = (int)$p['total_requests'];

    // Get recent activity for this page
    $recent = $pdo->prepare("
        SELECT method, content_type, threat_score, client_ip, user_agent, request_time
        FROM backdraft_requests
        WHERE page_id = ? AND request_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)
        ORDER BY request_time DESC
    ");
    $recent->execute([$page_id, $window_min]);
    $requests = $recent->fetchAll();

    if (empty($requests)) continue;

    $page_anomalies = [];

    // ── Check 1: New methods not in baseline ─────────────────────────
    $current_methods = array_unique(array_column($requests, 'method'));
    foreach ($current_methods as $m) {
        if (!empty($learned_methods) && !in_array($m, $learned_methods)) {
            $page_anomalies[] = [
                'type' => 'new_method',
                'severity' => 'medium',
                'detail' => "HTTP method '{$m}' not in learned baseline [" . implode(',', $learned_methods) . "]",
            ];
        }
    }

    // ── Check 2: Unusual content types ───────────────────────────────
    $current_ctypes = array_unique(array_filter(array_column($requests, 'content_type')));
    foreach ($current_ctypes as $ct) {
        if (!empty($learned_ctypes) && !in_array($ct, $learned_ctypes)) {
            $page_anomalies[] = [
                'type' => 'new_content_type',
                'severity' => 'low',
                'detail' => "Content-Type '{$ct}' not in learned baseline",
            ];
        }
    }

    // ── Check 3: Volume spike ────────────────────────────────────────
    $req_count = count($requests);
    // Estimate expected rate: baseline total / hours since created, scaled to window
    $profile_age_hours = max(1, (time() - strtotime($p['created_at'])) / 3600);
    $expected_rate = ($baseline_reqs / $profile_age_hours) * ($window_min / 60);
    if ($expected_rate > 0 && $req_count > $expected_rate * 3) {
        $page_anomalies[] = [
            'type' => 'volume_spike',
            'severity' => 'high',
            'detail' => "{$req_count} requests in {$window_min}min (expected ~" . round($expected_rate) . " based on baseline of {$baseline_reqs} total)",
        ];
    }

    // ── Check 4: Threat score spike ──────────────────────────────────
    $scores = array_column($requests, 'threat_score');
    $current_avg = count($scores) > 0 ? array_sum($scores) / count($scores) : 0;
    $current_max = count($scores) > 0 ? max($scores) : 0;
    if ($current_avg > $baseline_avg * 2 && $current_avg > 10) {
        $page_anomalies[] = [
            'type' => 'score_spike',
            'severity' => $current_avg >= 50 ? 'critical' : 'high',
            'detail' => "Avg threat score " . round($current_avg, 1) . " (baseline: " . round($baseline_avg, 1) . ")",
        ];
    }
    if ($current_max >= 75) {
        $page_anomalies[] = [
            'type' => 'high_score_event',
            'severity' => 'critical',
            'detail' => "Max threat score {$current_max} detected on this page",
        ];
    }

    // ── Check 5: New IPs targeting this page ─────────────────────────
    $known_ips = $pdo->prepare("SELECT DISTINCT client_ip FROM backdraft_requests WHERE page_id = ? AND request_time < DATE_SUB(NOW(), INTERVAL ? MINUTE)");
    $known_ips->execute([$page_id, $window_min]);
    $known_set = array_column($known_ips->fetchAll(), 'client_ip');

    $current_ips = array_unique(array_column($requests, 'client_ip'));
    $new_ips = array_diff($current_ips, $known_set);
    if (count($new_ips) > 3 && count($known_set) > 0) {
        $page_anomalies[] = [
            'type' => 'new_ip_cluster',
            'severity' => 'medium',
            'detail' => count($new_ips) . " new IPs hitting this page: " . implode(', ', array_slice($new_ips, 0, 5)),
        ];
    }

    if (!empty($page_anomalies)) {
        $anomalies[$page_id] = [
            'page_id' => $page_id,
            'requests_in_window' => $req_count,
            'anomalies' => $page_anomalies,
        ];
    }
}

// ── Report ───────────────────────────────────────────────────────────────
echo "--- Anomaly Results ---\n";
if (empty($anomalies)) {
    echo "No anomalies detected — all pages within baseline parameters\n";
} else {
    $total_anomalies = 0;
    foreach ($anomalies as $page_id => $data) {
        echo "\n[{$page_id}] {$data['requests_in_window']} requests in window\n";
        foreach ($data['anomalies'] as $a) {
            $total_anomalies++;
            $sev_label = strtoupper($a['severity']);
            echo "  [{$sev_label}] {$a['type']}: {$a['detail']}\n";
        }
    }
    echo "\nTotal anomalies: {$total_anomalies} across " . count($anomalies) . " pages\n";
}

// Summary JSON
$summary = [
    'report_generated' => date('Y-m-d H:i:s'),
    'window_minutes' => $window_min,
    'profiles_checked' => count($profiles),
    'pages_with_anomalies' => count($anomalies),
    'anomalies' => $anomalies,
];
file_put_contents('/tmp/backdraft_task_anomaly_baseline_check.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

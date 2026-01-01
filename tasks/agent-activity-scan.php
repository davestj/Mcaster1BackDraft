<?php
/**
 * agent-activity-scan.php — Scan requests for known agent/bot signatures
 *
 * Matches user_agent strings in recent requests against backdraft_agent_signatures.
 * Identifies new scanners/bots not yet in the signature database.
 * Updates IP reputation for scanner-associated IPs.
 *
 * Schedule: Every 2 hours
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$hours = (int)($args['hours'] ?? 2);
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Agent Activity Scan ===\n";
echo "Window: last {$hours} hours\n";
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

// Load active agent signatures
$signatures = $pdo->query("SELECT id, pattern, match_type, classification, disposition, name FROM backdraft_agent_signatures WHERE active = 1")->fetchAll();
echo "Active signatures: " . count($signatures) . "\n";

// Get distinct user-agents from recent requests
$agents = $pdo->query("
    SELECT user_agent, COUNT(*) as cnt, COUNT(DISTINCT client_ip) as ips,
           GROUP_CONCAT(DISTINCT client_ip ORDER BY client_ip SEPARATOR ',') as ip_list
    FROM backdraft_requests
    WHERE request_time > DATE_SUB(NOW(), INTERVAL {$hours} HOUR)
      AND user_agent != ''
    GROUP BY user_agent
    ORDER BY cnt DESC
")->fetchAll();

echo "Distinct user-agents: " . count($agents) . "\n\n";

$matched = [];
$unmatched = [];
$scanner_ips = [];

foreach ($agents as $a) {
    $ua = $a['user_agent'];
    $found = false;

    foreach ($signatures as $sig) {
        $hit = false;
        if ($sig['match_type'] === 'contains') {
            $hit = stripos($ua, $sig['pattern']) !== false;
        } elseif ($sig['match_type'] === 'regex') {
            $hit = @preg_match('/' . $sig['pattern'] . '/i', $ua);
        } elseif ($sig['match_type'] === 'equals') {
            $hit = strtolower($ua) === strtolower($sig['pattern']);
        }

        if ($hit) {
            $matched[] = [
                'agent' => substr($ua, 0, 120),
                'sig_name' => $sig['name'],
                'classification' => $sig['classification'],
                'disposition' => $sig['disposition'],
                'requests' => $a['cnt'],
                'ips' => $a['ips'],
            ];
            $found = true;

            // Track scanner IPs for reputation update
            if ($sig['disposition'] === 'block' || $sig['disposition'] === 'flag') {
                foreach (explode(',', $a['ip_list']) as $ip) {
                    $scanner_ips[trim($ip)] = $sig['name'];
                }
            }
            break;
        }
    }

    if (!$found) {
        $unmatched[] = [
            'agent' => substr($ua, 0, 200),
            'requests' => $a['cnt'],
            'ips' => $a['ips'],
        ];
    }
}

echo "--- Matched Agents ---\n";
foreach ($matched as $m) {
    $disp_color = $m['disposition'] === 'block' ? 'BLOCK' : strtoupper($m['disposition']);
    echo "  [{$disp_color}] {$m['sig_name']} ({$m['classification']}): {$m['requests']} reqs from {$m['ips']} IPs\n";
    echo "    UA: {$m['agent']}\n";
}

echo "\n--- Unmatched Agents (potential new signatures) ---\n";
// Flag suspicious unmatched agents
$suspicious = [];
foreach ($unmatched as $u) {
    $ua = $u['agent'];
    $is_suspicious = false;
    $reason = '';

    // Heuristics for suspicious user-agents
    if (strlen($ua) < 15 && stripos($ua, 'Mozilla') === false) {
        $is_suspicious = true; $reason = 'Very short, non-browser';
    } elseif (preg_match('/^Mozilla\/5\.0$/', $ua)) {
        $is_suspicious = true; $reason = 'Minimal Mozilla stub (no browser details)';
    } elseif (preg_match('/(scan|crawl|spider|probe|attack|exploit|hack|vuln)/i', $ua)) {
        $is_suspicious = true; $reason = 'Contains scanning keywords';
    } elseif (preg_match('/(python|ruby|perl|java|go-http|node-fetch|axios|httpie)/i', $ua)) {
        $is_suspicious = true; $reason = 'Programmatic HTTP client';
    } elseif (preg_match('/(Palo Alto|Censys|Shodan|Masscan|ZoomEye)/i', $ua)) {
        $is_suspicious = true; $reason = 'Known commercial/research scanner';
    }

    if ($is_suspicious) {
        $suspicious[] = array_merge($u, ['reason' => $reason]);
        echo "  ** SUSPICIOUS: {$ua}\n";
        echo "     Reason: {$reason} | {$u['requests']} reqs, {$u['ips']} IPs\n";
    }
}

if (empty($suspicious)) echo "  No suspicious unmatched agents detected\n";

echo "\n--- Scanner IP Reputation Updates ---\n";
foreach ($scanner_ips as $ip => $scanner_name) {
    // Ensure scanner IPs exist in reputation table
    $pdo->prepare("
        INSERT INTO backdraft_ip_reputation (ip_addr, total_requests, total_threats, max_score, first_seen, last_seen)
        VALUES (?, 0, 0, 50, NOW(), NOW())
        ON DUPLICATE KEY UPDATE last_seen = NOW()
    ")->execute([$ip]);
    echo "  {$ip} ({$scanner_name})\n";
}
echo "Scanner IPs flagged: " . count($scanner_ips) . "\n";

// Summary JSON
$summary = [
    'report_generated' => date('Y-m-d H:i:s'),
    'window_hours' => $hours,
    'signatures_loaded' => count($signatures),
    'agents_scanned' => count($agents),
    'matched' => $matched,
    'suspicious_unmatched' => $suspicious,
    'scanner_ips_flagged' => count($scanner_ips),
];
file_put_contents('/tmp/backdraft_task_agent_activity_scan.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

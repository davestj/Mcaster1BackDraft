<?php
/**
 * /app/api/logs.php — Log file API (strict JSON)
 *
 * Routes:
 *   GET ?action=tail&file=backdraft&lines=100  Read last N lines of a log file
 *   GET ?action=search&file=backdraft&q=ERROR  Search log file for pattern
 *   GET ?action=stats                          Live WAF activity stats for dashboard
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$action = $_GET['action'] ?? '';

$file_map = [
    'backdraft' => '/var/www/mcaster1.com/Mcaster1BackDraft/logs/backdraft.log',
    'error'     => '/var/www/mcaster1.com/Mcaster1BackDraft/logs/error.log',
    'debug'     => '/var/www/mcaster1.com/Mcaster1BackDraft/logs/debug.log',
    'access'    => '/var/www/mcaster1.com/Mcaster1BackDraft/logs/access.log',
];

if ($action === 'tail') {
    $which = $_GET['file'] ?? 'backdraft';
    $path = $file_map[$which] ?? $file_map['backdraft'];
    $lines = min(500, max(10, (int)($_GET['lines'] ?? 100)));

    $result = [];
    if (is_readable($path)) {
        $fp = fopen($path, 'r');
        if ($fp) {
            fseek($fp, 0, SEEK_END);
            $size = ftell($fp);
            $read_size = min($size, $lines * 256);
            fseek($fp, -$read_size, SEEK_END);
            $chunk = fread($fp, $read_size);
            fclose($fp);
            $all_lines = explode("\n", $chunk);
            if ($read_size < $size) array_shift($all_lines);
            while (!empty($all_lines) && end($all_lines) === '') array_pop($all_lines);
            $result = array_slice($all_lines, -$lines);
        }
    }

    $filesize = is_file($path) ? filesize($path) : 0;
    echo json_encode([
        'ok' => true, 'file' => $which, 'path' => $path,
        'size' => $filesize,
        'size_human' => $filesize > 1048576 ? round($filesize/1048576,1).'M' : round($filesize/1024,1).'K',
        'lines' => $result, 'count' => count($result),
    ]); return;
}

if ($action === 'search') {
    $which = $_GET['file'] ?? 'backdraft';
    $path = $file_map[$which] ?? $file_map['backdraft'];
    $query = $_GET['q'] ?? '';
    $max_results = min(200, max(10, (int)($_GET['limit'] ?? 100)));

    if (!$query) { echo json_encode(['ok'=>false,'error'=>'Search query required']); return; }

    $results = [];
    if (is_readable($path)) {
        $fp = fopen($path, 'r');
        if ($fp) {
            $line_num = 0;
            while (($line = fgets($fp)) !== false) {
                $line_num++;
                if (stripos($line, $query) !== false) {
                    $results[] = ['line' => $line_num, 'text' => rtrim($line)];
                    if (count($results) >= $max_results) break;
                }
            }
            fclose($fp);
        }
    }

    echo json_encode(['ok'=>true,'file'=>$which,'query'=>$query,'results'=>$results,'count'=>count($results)]); return;
}

if ($action === 'stats') {
    // Live WAF activity stats for the real-time dashboard
    $now = date('Y-m-d H:i:s');

    // Requests in last 5 minutes
    $recent_requests = db_rows("SELECT request_time, client_ip, method, host, path, threat_score, action_taken, user_agent
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 5 MINUTE) ORDER BY request_time DESC LIMIT 50");

    // Action distribution (last hour)
    $actions_1h = db_rows("SELECT action_taken, COUNT(*) as cnt FROM backdraft_requests
        WHERE request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR) GROUP BY action_taken");

    // Requests per minute (last 30 minutes for chart)
    $rpm = db_rows("SELECT DATE_FORMAT(request_time, '%H:%i') as minute, COUNT(*) as cnt,
        AVG(threat_score) as avg_score, SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as flagged
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
        GROUP BY minute ORDER BY minute");

    // Top IPs (last hour)
    $top_ips = db_rows("SELECT client_ip, COUNT(*) as cnt, MAX(threat_score) as max_score,
        SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as threats
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY client_ip ORDER BY cnt DESC LIMIT 10");

    // Top paths (last hour)
    $top_paths = db_rows("SELECT path, COUNT(*) as cnt, AVG(threat_score) as avg_score
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY path ORDER BY cnt DESC LIMIT 10");

    // Agent breakdown (last hour)
    $agents = db_rows("SELECT
        CASE
            WHEN user_agent LIKE '%bot%' OR user_agent LIKE '%crawler%' OR user_agent LIKE '%spider%' THEN 'bot'
            WHEN user_agent LIKE '%curl%' OR user_agent LIKE '%wget%' OR user_agent LIKE '%python%' THEN 'library'
            WHEN user_agent LIKE '%scanner%' OR user_agent LIKE '%nikto%' OR user_agent LIKE '%sqlmap%' OR user_agent LIKE '%zgrab%' THEN 'scanner'
            WHEN user_agent = '' THEN 'empty'
            ELSE 'browser'
        END as agent_type, COUNT(*) as cnt
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY agent_type ORDER BY cnt DESC");

    // Flagged requests (score > 0, last hour)
    $flagged = db_rows("SELECT request_time, client_ip, path, threat_score, action_taken, matched_rules, user_agent
        FROM backdraft_requests WHERE threat_score > 0 AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ORDER BY threat_score DESC LIMIT 20");

    // Hourly trend (last 24h for sparkline)
    $hourly = db_rows("SELECT DATE_FORMAT(request_time, '%Y-%m-%d %H:00') as hour,
        COUNT(*) as reqs, SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as threats
        FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY hour ORDER BY hour");

    // Site realtime counters
    $realtime = db_rows("SELECT s.site_name, r.requests_1m, r.requests_5m, r.requests_15m, r.errors_1m, r.active_ips
        FROM backdraft_log_realtime r JOIN backdraft_sites s ON s.id = r.site_id
        WHERE r.requests_1m > 0 OR r.requests_5m > 0 ORDER BY r.requests_5m DESC LIMIT 10");

    echo json_encode([
        'ok' => true, 'timestamp' => $now,
        'recent_requests' => $recent_requests,
        'actions_1h' => $actions_1h,
        'rpm' => $rpm,
        'top_ips' => $top_ips,
        'top_paths' => $top_paths,
        'agents' => $agents,
        'flagged' => $flagged,
        'hourly_24h' => $hourly,
        'realtime' => $realtime,
    ]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);

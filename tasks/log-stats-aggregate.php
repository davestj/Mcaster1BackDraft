<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * log-stats-aggregate.php — Nginx access log parser + hourly stats aggregator
 *
 * Reads nginx access logs for all sites with log_analysis=1.
 * Parses combined log format, aggregates into:
 *   - backdraft_log_stats_hourly  (hourly buckets per site)
 *   - backdraft_log_page_stats    (daily per-path stats)
 *   - backdraft_log_realtime      (rolling 1m/5m/15m counters)
 *
 * Uses a high-water-mark in backdraft_config to track last-parsed byte offset
 * per log file, so it only processes new lines on each run.
 *
 * Schedule: Every 1 hour (also safe to run more frequently)
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}
$run_id = (int)($args['run-id'] ?? 0);

echo "=== BackDraft Log Stats Aggregation ===\n";
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

// Get all sites with log analysis enabled
$sites = $pdo->query(
    "SELECT id, site_name, access_log_path, error_log_path FROM backdraft_sites WHERE log_analysis = 1"
)->fetchAll();

echo "Sites with log_analysis=1: " . count($sites) . "\n\n";

$total_lines = 0;
$total_new = 0;
$site_stats = [];

foreach ($sites as $site) {
    $sid = $site['id'];
    $name = $site['site_name'];
    $log_path = $site['access_log_path'];

    if (!$log_path || !is_readable($log_path)) {
        echo "[{$name}] Log not readable: {$log_path}\n";
        continue;
    }

    $filesize = filesize($log_path);

    // Get high-water mark (last parsed byte offset)
    $hwm_key = "log_hwm_{$sid}";
    $hwm = (int)$pdo->query("SELECT COALESCE(config_value,'0') FROM backdraft_config WHERE config_key = " . $pdo->quote($hwm_key))->fetchColumn();

    // If file shrank (rotation), reset
    if ($hwm > $filesize) {
        echo "[{$name}] Log rotated (was {$hwm}, now {$filesize}) — resetting HWM\n";
        $hwm = 0;
    }

    $new_bytes = $filesize - $hwm;
    if ($new_bytes <= 0) {
        echo "[{$name}] No new data (at {$filesize} bytes)\n";
        continue;
    }

    echo "[{$name}] Parsing {$new_bytes} new bytes from offset {$hwm}...\n";

    $fp = fopen($log_path, 'r');
    if (!$fp) { echo "[{$name}] Failed to open\n"; continue; }
    fseek($fp, $hwm);

    // Parse nginx combined log format:
    // 1.2.3.4 - - [20/Mar/2026:19:20:11 -0700] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
    $pattern = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+) "([^"]*)" "([^"]*)"/';

    // Collect per-hour, per-path aggregates
    $hourly = [];     // hour_bucket => stats
    $pages = [];      // day:path => stats
    $recent_ts = [];  // timestamps for realtime counters
    $line_count = 0;
    $max_lines = 500000; // safety cap per site per run

    while (($line = fgets($fp)) !== false && $line_count < $max_lines) {
        $line_count++;
        if (!preg_match($pattern, $line, $m)) continue;

        $ip       = $m[1];
        $time_str = $m[2]; // 20/Mar/2026:19:20:11 -0700
        $method   = $m[3];
        $path     = $m[4];
        $status   = (int)$m[5];
        $bytes    = (int)$m[6];
        $referer  = $m[7];
        $agent    = $m[8];

        // Parse timestamp: "20/Mar/2026:19:20:11 -0700" → replace first : with space, then / with -
        $ts_str = preg_replace('/^(\d{2})\/(\w+)\/(\d{4}):/', '$3-$2-$1 ', $time_str);
        $ts = strtotime($ts_str);
        if (!$ts) continue;

        $hour_bucket = date('Y-m-d H:00:00', $ts);
        $day_bucket  = date('Y-m-d', $ts);

        // Hourly aggregation
        if (!isset($hourly[$hour_bucket])) {
            $hourly[$hour_bucket] = [
                'requests' => 0, 'bytes' => 0,
                '2xx' => 0, '3xx' => 0, '4xx' => 0, '5xx' => 0,
                'ips' => [], 'paths' => [], 'ip_counts' => [],
                'agents' => [], 'referers' => [], 'errors' => [],
            ];
        }
        $h = &$hourly[$hour_bucket];
        $h['requests']++;
        $h['bytes'] += $bytes;
        $h['ips'][$ip] = true;

        if ($status >= 200 && $status < 300) $h['2xx']++;
        elseif ($status >= 300 && $status < 400) $h['3xx']++;
        elseif ($status >= 400 && $status < 500) $h['4xx']++;
        elseif ($status >= 500) $h['5xx']++;

        // Track top paths/IPs/agents (limited to top 20 each)
        $h['paths'][$path] = ($h['paths'][$path] ?? 0) + 1;
        $h['ip_counts'][$ip] = ($h['ip_counts'][$ip] ?? 0) + 1;
        if ($agent !== '-') $h['agents'][$agent] = ($h['agents'][$agent] ?? 0) + 1;
        if ($referer !== '-') $h['referers'][$referer] = ($h['referers'][$referer] ?? 0) + 1;
        if ($status >= 400) $h['errors'][$status . ' ' . $path] = ($h['errors'][$status . ' ' . $path] ?? 0) + 1;

        // Page stats (daily)
        $page_key = $day_bucket . '|' . substr($path, 0, 255);
        if (!isset($pages[$page_key])) {
            $pages[$page_key] = ['day' => $day_bucket, 'path' => substr($path, 0, 255),
                                 'hits' => 0, 'bytes' => 0, 'ips' => [], 'status_sum' => 0, 'errors' => 0];
        }
        $pages[$page_key]['hits']++;
        $pages[$page_key]['bytes'] += $bytes;
        $pages[$page_key]['ips'][$ip] = true;
        $pages[$page_key]['status_sum'] += $status;
        if ($status >= 400) $pages[$page_key]['errors']++;

        // Realtime tracking (last 15 min)
        $age = time() - $ts;
        if ($age < 900) $recent_ts[] = ['ts' => $ts, 'bytes' => $bytes, 'error' => ($status >= 400)];
    }

    $new_hwm = ftell($fp);
    fclose($fp);
    $total_lines += $line_count;
    $total_new += $line_count;

    echo "  Parsed {$line_count} lines, " . count($hourly) . " hour buckets, " . count($pages) . " page entries\n";

    // ── Write hourly stats ──────────────────────────────────────────
    $ins_hourly = $pdo->prepare(
        "INSERT INTO backdraft_log_stats_hourly
         (site_id, hour_bucket, total_requests, total_bytes, status_2xx, status_3xx, status_4xx, status_5xx,
          unique_ips, avg_response_ms, top_paths, top_ips, top_agents, top_referers, error_count, top_errors)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
          total_requests = total_requests + VALUES(total_requests),
          total_bytes = total_bytes + VALUES(total_bytes),
          status_2xx = status_2xx + VALUES(status_2xx),
          status_3xx = status_3xx + VALUES(status_3xx),
          status_4xx = status_4xx + VALUES(status_4xx),
          status_5xx = status_5xx + VALUES(status_5xx),
          unique_ips = VALUES(unique_ips),
          top_paths = VALUES(top_paths),
          top_ips = VALUES(top_ips),
          top_agents = VALUES(top_agents),
          top_referers = VALUES(top_referers),
          error_count = error_count + VALUES(error_count),
          top_errors = VALUES(top_errors)"
    );

    foreach ($hourly as $hb => $h) {
        arsort($h['paths']); arsort($h['ip_counts']); arsort($h['agents']); arsort($h['referers']); arsort($h['errors']);
        $ins_hourly->execute([
            $sid, $hb, $h['requests'], $h['bytes'],
            $h['2xx'], $h['3xx'], $h['4xx'], $h['5xx'],
            count($h['ips']),
            json_encode(array_slice($h['paths'], 0, 20, true)),
            json_encode(array_slice($h['ip_counts'], 0, 20, true)),
            json_encode(array_slice($h['agents'], 0, 20, true)),
            json_encode(array_slice($h['referers'], 0, 20, true)),
            $h['4xx'] + $h['5xx'],
            json_encode(array_slice($h['errors'], 0, 20, true)),
        ]);
    }

    // ── Write daily page stats ──────────────────────────────────────
    $ins_page = $pdo->prepare(
        "INSERT INTO backdraft_log_page_stats (site_id, path, day_bucket, hits, bytes, unique_ips, avg_status, error_count)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
          hits = hits + VALUES(hits), bytes = bytes + VALUES(bytes),
          unique_ips = VALUES(unique_ips), avg_status = VALUES(avg_status),
          error_count = error_count + VALUES(error_count)"
    );

    foreach ($pages as $p) {
        $avg_status = $p['hits'] > 0 ? round($p['status_sum'] / $p['hits'], 1) : 0;
        $ins_page->execute([$sid, $p['path'], $p['day'], $p['hits'], $p['bytes'],
                            count($p['ips']), $avg_status, $p['errors']]);
    }

    // ── Write realtime counters ─────────────────────────────────────
    $now = time();
    $r1m = $r5m = $r15m = $b1m = $e1m = 0;
    $active_ips = [];
    foreach ($recent_ts as $r) {
        $age = $now - $r['ts'];
        if ($age < 60)  { $r1m++; $b1m += $r['bytes']; if ($r['error']) $e1m++; }
        if ($age < 300) $r5m++;
        if ($age < 900) $r15m++;
        $active_ips[$r['ts']] = true; // approximate
    }

    $pdo->prepare(
        "INSERT INTO backdraft_log_realtime (site_id, requests_1m, requests_5m, requests_15m, bytes_1m, errors_1m, active_ips)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
          requests_1m=VALUES(requests_1m), requests_5m=VALUES(requests_5m), requests_15m=VALUES(requests_15m),
          bytes_1m=VALUES(bytes_1m), errors_1m=VALUES(errors_1m), active_ips=VALUES(active_ips)"
    )->execute([$sid, $r1m, $r5m, $r15m, $b1m, $e1m, count($active_ips)]);

    // ── Update high-water mark ──────────────────────────────────────
    $pdo->prepare(
        "INSERT INTO backdraft_config (config_key, config_value, description)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE config_value = VALUES(config_value)"
    )->execute([$hwm_key, $new_hwm, "Log parse HWM for site {$name}"]);

    $site_stats[$name] = ['lines' => $line_count, 'hours' => count($hourly), 'pages' => count($pages)];
    echo "  Done. HWM updated to {$new_hwm}\n\n";
}

echo "=== Summary ===\n";
echo "Total lines parsed: {$total_new}\n";
foreach ($site_stats as $name => $st) {
    echo "  {$name}: {$st['lines']} lines, {$st['hours']} hours, {$st['pages']} pages\n";
}

// Write summary JSON sidecar
$summary = [
    'report_generated' => date('Y-m-d H:i:s'),
    'sites_processed' => count($site_stats),
    'total_lines' => $total_new,
    'site_stats' => $site_stats,
];
file_put_contents('/tmp/backdraft_task_log_stats_aggregate.json', json_encode($summary, JSON_PRETTY_PRINT));

echo "\nCompleted: " . date('Y-m-d H:i:s') . "\n";

<?php
/**
 * /app/api/site-report.php — Per-site real-time analytics API (strict JSON)
 *
 * Routes:
 *   GET ?action=live&site_id=N         Real-time WAF activity for one site
 *   GET ?action=traffic&site_id=N      Hourly traffic data (24h)
 *   GET ?action=geo&site_id=N          GeoIP analysis of visitors
 *   GET ?action=ip_detail&ip=X         Deep IP analysis with rDNS + geo + history
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$action  = $_GET['action'] ?? '';
$site_id = (int)($_GET['site_id'] ?? 0);

// ── GeoIP + rDNS helper ─────────────────────────────────────────────────
function geo_lookup(string $ip): array {
    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];

    $country_code = '--';
    $country_name = 'Unknown';
    $out = shell_exec("geoiplookup " . escapeshellarg($ip) . " 2>/dev/null");
    if ($out && preg_match('/: ([A-Z]{2}), (.+)/', $out, $m)) {
        $country_code = $m[1];
        $country_name = trim($m[2]);
    }

    $result = ['country_code' => $country_code, 'country_name' => $country_name];
    $cache[$ip] = $result;
    return $result;
}

function rdns_lookup(string $ip): string {
    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];
    $host = gethostbyaddr($ip);
    $cache[$ip] = ($host !== $ip) ? $host : '';
    return $cache[$ip];
}

// Get site name for page_id matching
function get_site_name(int $site_id): string {
    static $names = [];
    if (isset($names[$site_id])) return $names[$site_id];
    $name = db_scalar("SELECT site_name FROM backdraft_sites WHERE id = ?", [$site_id]) ?: '';
    $names[$site_id] = $name;
    return $name;
}

// ═══════════════════════════════════════════════════════════════════════════
if ($action === 'live') {
    $site_name = get_site_name($site_id);
    if (!$site_name) { echo json_encode(['ok'=>false,'error'=>'Site not found']); return; }

    // Recent WAF requests for this site (last 10 min)
    $recent = db_rows("SELECT request_time, client_ip, method, path, query_string, threat_score,
        action_taken, matched_rules, user_agent, response_bytes, upstream_ms
        FROM backdraft_requests WHERE page_id LIKE ? AND request_time > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        ORDER BY request_time DESC LIMIT 50", [$site_name . '%']);

    // Enrich with geo
    foreach ($recent as &$r) {
        $geo = geo_lookup($r['client_ip']);
        $r['country_code'] = $geo['country_code'];
        $r['country_name'] = $geo['country_name'];
    }

    // RPM for last 30 min
    $rpm = db_rows("SELECT DATE_FORMAT(request_time, '%H:%i') as minute, COUNT(*) as cnt,
        AVG(threat_score) as avg_score,
        SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as flagged,
        SUM(response_bytes) as bytes
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
        GROUP BY minute ORDER BY minute", [$site_name . '%']);

    // Action breakdown
    $actions = db_rows("SELECT action_taken, COUNT(*) as cnt
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY action_taken", [$site_name . '%']);

    // Top IPs (1h) with geo
    $top_ips = db_rows("SELECT client_ip, COUNT(*) as cnt, MAX(threat_score) as max_score,
        AVG(threat_score) as avg_score,
        SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as threats
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY client_ip ORDER BY cnt DESC LIMIT 15", [$site_name . '%']);

    foreach ($top_ips as &$ip) {
        $geo = geo_lookup($ip['client_ip']);
        $ip['country_code'] = $geo['country_code'];
        $ip['country_name'] = $geo['country_name'];
        $ip['rdns'] = rdns_lookup($ip['client_ip']);
    }

    // Top paths
    $top_paths = db_rows("SELECT path, COUNT(*) as cnt, AVG(threat_score) as avg_score,
        AVG(upstream_ms) as avg_ms
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY path ORDER BY cnt DESC LIMIT 15", [$site_name . '%']);

    // Top agents
    $top_agents = db_rows("SELECT user_agent, COUNT(*) as cnt,
        COUNT(DISTINCT client_ip) as ips, MAX(threat_score) as max_score
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        GROUP BY user_agent ORDER BY cnt DESC LIMIT 10", [$site_name . '%']);

    // Flagged/threat requests
    $flagged = db_rows("SELECT request_time, client_ip, path, threat_score, action_taken,
        matched_rules, user_agent
        FROM backdraft_requests WHERE page_id LIKE ? AND threat_score > 0
        AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ORDER BY threat_score DESC LIMIT 20", [$site_name . '%']);

    foreach ($flagged as &$f) {
        $geo = geo_lookup($f['client_ip']);
        $f['country_code'] = $geo['country_code'];
    }

    // Realtime counters
    $realtime = db_row("SELECT requests_1m, requests_5m, requests_15m, bytes_1m, errors_1m, active_ips
        FROM backdraft_log_realtime WHERE site_id = ?", [$site_id]);

    // Totals
    $total_1h = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE ? AND request_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)", [$site_name . '%']);
    $total_24h = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE ? AND request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)", [$site_name . '%']);

    // BotProof + Secure Lock metrics for this site
    $bp_challenges_total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_challenges WHERE page_id LIKE ?", [$site_name . '%']);
    $bp_challenges_pending = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_challenges WHERE page_id LIKE ? AND expires_at > NOW()", [$site_name . '%']);
    $bp_sessions_active = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_sessions WHERE site_id = ? AND expires_at > NOW()", [$site_id]);
    $bp_sessions_total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_sessions WHERE site_id = ?", [$site_id]);
    $sl_otp_total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_secure_otp WHERE page_id LIKE ?", [$site_name . '%']);
    $sl_otp_verified = (int)db_scalar("SELECT COUNT(*) FROM backdraft_secure_otp WHERE page_id LIKE ? AND verified_at IS NOT NULL", [$site_name . '%']);

    // Page profiles with protection status
    $page_profiles = db_rows("SELECT page_id, display_name, total_requests, total_threats, avg_score,
        botproof_enabled, botproof_threshold, secure_lock_enabled, monitoring, last_request_at
        FROM backdraft_page_profiles WHERE site_id = ?", [$site_id]);

    // BotProof pass rate: sessions_total / challenges_total
    $bp_pass_rate = ($bp_challenges_total > 0) ? round(($bp_sessions_total / $bp_challenges_total) * 100, 1) : 0;
    $bp_fail_count = max(0, $bp_challenges_total - $bp_sessions_total);

    echo json_encode([
        'ok' => true, 'site_name' => $site_name,
        'recent' => $recent, 'rpm' => $rpm, 'actions' => $actions,
        'top_ips' => $top_ips, 'top_paths' => $top_paths,
        'top_agents' => $top_agents, 'flagged' => $flagged,
        'realtime' => $realtime,
        'total_1h' => $total_1h, 'total_24h' => $total_24h,
        'botproof' => [
            'challenges_total' => $bp_challenges_total,
            'challenges_pending' => $bp_challenges_pending,
            'sessions_active' => $bp_sessions_active,
            'sessions_total' => $bp_sessions_total,
            'pass_rate' => $bp_pass_rate,
            'failed' => $bp_fail_count,
        ],
        'secure_lock' => [
            'otp_total' => $sl_otp_total,
            'otp_verified' => $sl_otp_verified,
        ],
        'page_profiles' => $page_profiles,
    ]); return;
}

// ═══════════════════════════════════════════════════════════════════════════
if ($action === 'traffic') {
    $site_name = get_site_name($site_id);

    // Hourly stats from aggregated table (last 24h)
    $hourly = db_rows("SELECT hour_bucket, total_requests, total_bytes,
        status_2xx, status_3xx, status_4xx, status_5xx, unique_ips, avg_response_ms,
        error_count, top_paths, top_ips, top_agents
        FROM backdraft_log_stats_hourly WHERE site_id = ?
        AND hour_bucket > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY hour_bucket", [$site_id]);

    // Decode JSON fields
    foreach ($hourly as &$h) {
        $h['top_paths']  = json_decode($h['top_paths'] ?: '{}', true);
        $h['top_ips']    = json_decode($h['top_ips'] ?: '{}', true);
        $h['top_agents'] = json_decode($h['top_agents'] ?: '{}', true);
    }

    // Daily page stats
    $pages = db_rows("SELECT path, SUM(hits) as hits, SUM(bytes) as bytes,
        MAX(unique_ips) as max_ips, AVG(avg_status) as avg_status, SUM(error_count) as errors
        FROM backdraft_log_page_stats WHERE site_id = ?
        AND day_bucket >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY path ORDER BY hits DESC LIMIT 30", [$site_id]);

    // Response time distribution from WAF requests
    $response_times = db_rows("SELECT
        CASE
            WHEN upstream_ms < 50 THEN '<50ms'
            WHEN upstream_ms < 200 THEN '50-200ms'
            WHEN upstream_ms < 500 THEN '200-500ms'
            WHEN upstream_ms < 1000 THEN '500ms-1s'
            ELSE '>1s'
        END as bucket, COUNT(*) as cnt
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND upstream_ms > 0
        GROUP BY bucket ORDER BY MIN(upstream_ms)", [$site_name . '%']);

    echo json_encode([
        'ok' => true, 'hourly' => $hourly, 'pages' => $pages,
        'response_times' => $response_times,
    ]); return;
}

// ═══════════════════════════════════════════════════════════════════════════
if ($action === 'geo') {
    $site_name = get_site_name($site_id);

    // Get all unique IPs for this site (last 24h)
    $ips = db_rows("SELECT client_ip, COUNT(*) as cnt, MAX(threat_score) as max_score,
        SUM(CASE WHEN threat_score > 0 THEN 1 ELSE 0 END) as threats,
        MIN(request_time) as first_seen, MAX(request_time) as last_seen
        FROM backdraft_requests WHERE page_id LIKE ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY client_ip ORDER BY cnt DESC LIMIT 100", [$site_name . '%']);

    // Also pull from hourly stats for broader coverage
    $hourly_ips_raw = db_rows("SELECT top_ips FROM backdraft_log_stats_hourly
        WHERE site_id = ? AND hour_bucket > DATE_SUB(NOW(), INTERVAL 24 HOUR)", [$site_id]);

    // Merge IPs from hourly
    $all_ips = [];
    foreach ($ips as $ip) $all_ips[$ip['client_ip']] = (int)$ip['cnt'];
    foreach ($hourly_ips_raw as $h) {
        $hip = json_decode($h['top_ips'] ?: '{}', true);
        foreach ($hip as $ip => $cnt) {
            $all_ips[$ip] = ($all_ips[$ip] ?? 0) + $cnt;
        }
    }
    arsort($all_ips);
    $all_ips = array_slice($all_ips, 0, 200, true);

    // Geo lookup all IPs
    $countries = [];
    $geo_ips = [];
    foreach ($all_ips as $ip => $cnt) {
        $geo = geo_lookup($ip);
        $cc = $geo['country_code'];
        $countries[$cc] = ($countries[$cc] ?? ['name' => $geo['country_name'], 'count' => 0, 'ips' => 0]);
        $countries[$cc]['count'] += $cnt;
        $countries[$cc]['ips']++;
        $geo_ips[] = [
            'ip' => $ip, 'requests' => $cnt,
            'country_code' => $cc, 'country_name' => $geo['country_name'],
            'rdns' => rdns_lookup($ip),
        ];
    }

    // Sort countries by request count
    uasort($countries, fn($a, $b) => $b['count'] - $a['count']);

    echo json_encode([
        'ok' => true,
        'countries' => $countries,
        'ips' => array_slice($geo_ips, 0, 100),
        'total_unique_ips' => count($all_ips),
    ]); return;
}

// ═══════════════════════════════════════════════════════════════════════════
if ($action === 'ip_detail') {
    $ip = $_GET['ip'] ?? '';
    if (!$ip) { echo json_encode(['ok'=>false,'error'=>'IP required']); return; }

    $geo = geo_lookup($ip);
    $rdns = rdns_lookup($ip);

    // IP reputation from DB
    $rep = db_row("SELECT * FROM backdraft_ip_reputation WHERE ip_addr = ?", [$ip]);

    // Recent requests from this IP (last 24h)
    $requests = db_rows("SELECT request_time, method, host, path, threat_score, action_taken,
        matched_rules, user_agent, response_bytes, upstream_ms
        FROM backdraft_requests WHERE client_ip = ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ORDER BY request_time DESC LIMIT 50", [$ip]);

    // Threat events from this IP
    $threats = db_rows("SELECT t.detected_at, t.threat_score, t.category, t.severity,
        t.action_taken, t.matched_rules, r.path
        FROM backdraft_threats t JOIN backdraft_requests r ON r.id = t.request_id
        WHERE t.client_ip = ? ORDER BY t.detected_at DESC LIMIT 20", [$ip]);

    // Sites this IP has hit
    $sites_hit = db_rows("SELECT host, COUNT(*) as cnt, MAX(threat_score) as max_score
        FROM backdraft_requests WHERE client_ip = ?
        GROUP BY host ORDER BY cnt DESC", [$ip]);

    // Hourly activity pattern
    $hourly = db_rows("SELECT HOUR(request_time) as hour, COUNT(*) as cnt
        FROM backdraft_requests WHERE client_ip = ?
        AND request_time > DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY hour ORDER BY hour", [$ip]);

    // User agents used by this IP
    $agents = db_rows("SELECT user_agent, COUNT(*) as cnt
        FROM backdraft_requests WHERE client_ip = ?
        GROUP BY user_agent ORDER BY cnt DESC LIMIT 10", [$ip]);

    echo json_encode([
        'ok' => true,
        'ip' => $ip,
        'geo' => $geo,
        'rdns' => $rdns,
        'reputation' => $rep,
        'requests' => $requests,
        'threats' => $threats,
        'sites_hit' => $sites_hit,
        'hourly_pattern' => $hourly,
        'user_agents' => $agents,
    ]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);

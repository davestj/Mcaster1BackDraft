<?php
/**
 * /app/api/site-management.php — Site Security Management API (strict JSON)
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$action = $_GET['action'] ?? '';

if ($action === 'status') {
    $site_id = (int)($_GET['site_id'] ?? 0);
    $site = db_row("SELECT site_name, maintenance_active, maintenance_started, maintenance_duration, maintenance_reason,
        security_blocking, block_bad_agent, block_banned_ip, block_bad_path, block_bad_payload, block_bad_cookie, block_bad_referer,
        security_log_enabled, rate_limit_login FROM backdraft_sites WHERE id = ?", [$site_id]);
    if (!$site) { echo json_encode(['ok'=>false,'error'=>'Not found']); return; }

    $events_24h = (int)db_scalar("SELECT COUNT(*) FROM backdraft_security_events WHERE site_id = ? AND detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)", [$site_id]);
    $banned_ips = (int)db_scalar("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1");
    $blocked_agents = (int)db_scalar("SELECT COUNT(*) FROM backdraft_agent_signatures WHERE disposition = 'block' AND active = 1");
    $bot_defs = (int)db_scalar("SELECT COUNT(*) FROM backdraft_bot_definitions WHERE active = 1");
    $last_sync = db_scalar("SELECT config_value FROM backdraft_config WHERE config_key = 'blacklist_last_sync'");

    $site['events_24h'] = $events_24h;
    $site['banned_ips'] = $banned_ips;
    $site['blocked_agents'] = $blocked_agents;
    $site['bot_definitions'] = $bot_defs;
    $site['last_blacklist_sync'] = $last_sync ?: 'Never';

    echo json_encode(['ok'=>true,'data'=>$site]); return;
}

if ($action === 'security_events') {
    $site_id = (int)($_GET['site_id'] ?? 0);
    $limit = min(200, (int)($_GET['limit'] ?? 50));
    $type = $_GET['type'] ?? '';
    $where = "site_id = ?"; $params = [$site_id];
    if ($type) { $where .= " AND block_type = ?"; $params[] = $type; }
    $events = db_rows("SELECT * FROM backdraft_security_events WHERE $where ORDER BY detected_at DESC LIMIT $limit", $params);
    echo json_encode(['ok'=>true,'data'=>$events]); return;
}

if ($action === 'audit') {
    $site_id = (int)($_GET['site_id'] ?? 0);
    $limit = min(100, (int)($_GET['limit'] ?? 20));
    $where = $site_id > 0 ? "WHERE site_id = $site_id OR site_id = 0" : "";
    $entries = db_rows("SELECT * FROM backdraft_security_audit $where ORDER BY created_at DESC LIMIT $limit");
    echo json_encode(['ok'=>true,'data'=>$entries]); return;
}

if ($action === 'all_sites') {
    $sites = db_rows("SELECT id, site_name, maintenance_active, security_blocking, block_bad_agent, block_banned_ip,
        block_bad_path, block_bad_payload, block_bad_cookie, block_bad_referer, security_log_enabled, rate_limit_login
        FROM backdraft_sites ORDER BY site_name");
    echo json_encode(['ok'=>true,'data'=>$sites]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);

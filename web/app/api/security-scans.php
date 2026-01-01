<?php
/**
 * /app/api/security-scans.php — Security Scans API (strict JSON)
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$action = $_GET['action'] ?? '';

if ($action === 'overview') {
    // Last malware scan
    $last_malware = db_row("SELECT started_at, ended_at, status, summary_json FROM backdraft_task_runs WHERE task_id = 'malware_scan' AND status = 'success' ORDER BY started_at DESC LIMIT 1");
    $malware_threats = (int)db_scalar("SELECT COUNT(*) FROM backdraft_malware_scans WHERE scanned_at > DATE_SUB(NOW(), INTERVAL 7 DAY)");
    $malware_quarantined = (int)db_scalar("SELECT COUNT(*) FROM backdraft_malware_scans WHERE action_taken = 'quarantined'");

    // Last rootkit scan
    $last_rootkit = db_row("SELECT started_at, ended_at, status, summary_json FROM backdraft_task_runs WHERE task_id = 'rootkit_scan' AND status = 'success' ORDER BY started_at DESC LIMIT 1");
    $rootkit_warnings = (int)db_scalar("SELECT COUNT(*) FROM backdraft_rootkit_scans WHERE status = 'warning' AND scanned_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    $rootkit_critical = (int)db_scalar("SELECT COUNT(*) FROM backdraft_rootkit_scans WHERE status = 'critical' AND scanned_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");

    // File integrity
    $integrity_ok = (int)db_scalar("SELECT COUNT(*) FROM backdraft_file_integrity WHERE status = 'ok'");
    $integrity_modified = (int)db_scalar("SELECT COUNT(*) FROM backdraft_file_integrity WHERE status = 'modified'");
    $integrity_total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_file_integrity");

    // ClamAV signature age
    $sig_file = '/var/lib/clamav/freshclam.dat';
    $sig_age_hours = file_exists($sig_file) ? round((time() - filemtime($sig_file)) / 3600) : -1;

    // Bot definitions
    $bot_total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_bot_definitions WHERE active = 1");
    $bot_last_update = db_scalar("SELECT config_value FROM backdraft_config WHERE config_key = 'bot_definitions_last_update'");

    echo json_encode(['ok'=>true,'data'=>[
        'malware' => ['last_scan' => $last_malware['started_at'] ?? 'Never', 'threats_7d' => $malware_threats, 'quarantined' => $malware_quarantined, 'sig_age_hours' => $sig_age_hours],
        'rootkit' => ['last_scan' => $last_rootkit['started_at'] ?? 'Never', 'warnings' => $rootkit_warnings, 'critical' => $rootkit_critical],
        'integrity' => ['total' => $integrity_total, 'ok' => $integrity_ok, 'modified' => $integrity_modified],
        'bots' => ['total' => $bot_total, 'last_update' => $bot_last_update ?: 'Never'],
    ]]); return;
}

if ($action === 'malware_results') {
    $limit = min(100, (int)($_GET['limit'] ?? 50));
    $results = db_rows("SELECT m.*, s.site_name FROM backdraft_malware_scans m LEFT JOIN backdraft_sites s ON s.id = m.site_id ORDER BY m.scanned_at DESC LIMIT $limit");
    echo json_encode(['ok'=>true,'data'=>$results]); return;
}

if ($action === 'rootkit_results') {
    $limit = min(100, (int)($_GET['limit'] ?? 50));
    $results = db_rows("SELECT * FROM backdraft_rootkit_scans ORDER BY scanned_at DESC LIMIT $limit");
    echo json_encode(['ok'=>true,'data'=>$results]); return;
}

if ($action === 'integrity') {
    $status = $_GET['status'] ?? '';
    $where = $status ? "WHERE status = " . bd_pdo()->quote($status) : "";
    $results = db_rows("SELECT * FROM backdraft_file_integrity $where ORDER BY checked_at DESC LIMIT 100");
    echo json_encode(['ok'=>true,'data'=>$results]); return;
}

if ($action === 'bot_definitions') {
    $class = $_GET['classification'] ?? '';
    $where = $class ? "WHERE classification = " . bd_pdo()->quote($class) . " AND active = 1" : "WHERE active = 1";
    $limit = min(200, (int)($_GET['limit'] ?? 100));
    $results = db_rows("SELECT * FROM backdraft_bot_definitions $where ORDER BY hit_count DESC LIMIT $limit");
    echo json_encode(['ok'=>true,'data'=>$results]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);

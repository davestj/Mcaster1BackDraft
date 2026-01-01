<?php
/**
 * /app/api/pages.php — Page Profiles API (strict JSON)
 *
 * Routes (via C++ FastCGI):
 *   GET  ?action=list[&site_id=N]     List page profiles
 *   GET  ?action=detail&id=N          Page profile detail + requests + threats
 *   GET  ?action=site_files&site_id=N List PHP files in site webroot
 *   POST action=save_profile          Create/update page profile
 *   POST action=toggle_monitoring     Toggle monitoring on/off
 *   POST action=toggle_botproof       Toggle BotProof on/off
 *   POST action=toggle_secure_lock    Toggle Secure Lock on/off
 *   POST action=save_botproof         Save BotProof settings
 *   POST action=save_secure_lock      Save Secure Lock settings
 *   POST action=reset_profile         Reset baseline
 *   POST action=delete_profile        Delete profile
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }

$method = $_SERVER['REQUEST_METHOD'];
$action = ($method === 'POST') ? ($_POST['action'] ?? '') : ($_GET['action'] ?? '');

// ── GET endpoints ────────────────────────────────────────────────────────
if ($method === 'GET') {

    if ($action === 'list') {
        $site_id = isset($_GET['site_id']) ? (int)$_GET['site_id'] : null;
        $where = "1=1"; $params = [];
        if ($site_id !== null) { $where = "p.site_id = ?"; $params[] = $site_id; }
        $pages = db_rows("SELECT p.*, s.site_name,
            (SELECT COUNT(DISTINCT client_ip) FROM backdraft_requests WHERE page_id = p.page_id) as unique_ips
            FROM backdraft_page_profiles p LEFT JOIN backdraft_sites s ON s.id = p.site_id
            WHERE $where ORDER BY p.total_requests DESC", $params);
        echo json_encode(['ok'=>true,'data'=>$pages]); return;
    }

    if ($action === 'detail') {
        $id = (int)($_GET['id'] ?? 0);
        $profile = db_row("SELECT p.*, s.site_name FROM backdraft_page_profiles p LEFT JOIN backdraft_sites s ON s.id = p.site_id WHERE p.id = ?", [$id]);
        if (!$profile) { echo json_encode(['ok'=>false,'error'=>'Not found']); return; }

        $requests = db_rows("SELECT request_time, client_ip, method, path, threat_score, action_taken, user_agent, response_bytes, upstream_ms FROM backdraft_requests WHERE page_id = ? ORDER BY request_time DESC LIMIT 25", [$profile['page_id']]);
        $threats = db_rows("SELECT t.detected_at, t.client_ip, t.threat_score, t.category, t.severity, t.action_taken, t.matched_rules FROM backdraft_threats t JOIN backdraft_requests r ON r.id = t.request_id WHERE r.page_id = ? ORDER BY t.detected_at DESC LIMIT 10", [$profile['page_id']]);
        $unique_ips = (int)db_scalar("SELECT COUNT(DISTINCT client_ip) FROM backdraft_requests WHERE page_id = ?", [$profile['page_id']]);
        $methods = db_rows("SELECT method, COUNT(*) as cnt FROM backdraft_requests WHERE page_id = ? GROUP BY method ORDER BY cnt DESC", [$profile['page_id']]);
        $statuses = db_rows("SELECT upstream_status, COUNT(*) as cnt FROM backdraft_requests WHERE page_id = ? AND upstream_status > 0 GROUP BY upstream_status ORDER BY cnt DESC", [$profile['page_id']]);
        $avg_ms = (float)db_scalar("SELECT AVG(upstream_ms) FROM backdraft_requests WHERE page_id = ? AND upstream_ms > 0", [$profile['page_id']]);
        $scoped_rules = db_rows("SELECT id, name, target, action, score FROM backdraft_rules WHERE page_scope LIKE ? AND active=1", ['%' . $profile['page_id'] . '%']);

        echo json_encode(['ok'=>true,'profile'=>$profile,'requests'=>$requests,'threats'=>$threats,'unique_ips'=>$unique_ips,'methods'=>$methods,'statuses'=>$statuses,'avg_response_ms'=>round($avg_ms,1),'scoped_rules'=>$scoped_rules]); return;
    }

    if ($action === 'site_files') {
        $site_id = (int)($_GET['site_id'] ?? 0);
        $site = db_row("SELECT doc_root, site_name FROM backdraft_sites WHERE id = ?", [$site_id]);
        $files = [];
        if ($site && !empty($site['doc_root']) && is_dir($site['doc_root'])) {
            $root = rtrim($site['doc_root'], '/');
            // Only PHP files — HTML/static files can't be WAF-proxied through FastCGI
            foreach (glob($root . '/*.php') as $f) $files[] = basename($f);
            foreach (glob($root . '/*/*.php') as $f) $files[] = substr($f, strlen($root) + 1);
            sort($files);
        }
        echo json_encode(['ok'=>true,'files'=>$files,'site_name'=>$site['site_name'] ?? '']); return;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown action']); return;
}

// ── POST endpoints (admin only) ──────────────────────────────────────────
if ($method === 'POST') {
    if (!bd_is_admin()) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); return; }

    if ($action === 'toggle_monitoring') {
        $id = (int)($_POST['id'] ?? 0);
        db_run("UPDATE backdraft_page_profiles SET monitoring = IF(monitoring=1,0,1) WHERE id = ?", [$id]);
        echo json_encode(['ok'=>true]); return;
    }

    if ($action === 'toggle_botproof') {
        $id = (int)($_POST['id'] ?? 0);
        db_run("UPDATE backdraft_page_profiles SET botproof_enabled = IF(botproof_enabled=1,0,1) WHERE id = ?", [$id]);
        echo json_encode(['ok'=>true]); return;
    }

    if ($action === 'toggle_secure_lock') {
        $id = (int)($_POST['id'] ?? 0);
        db_run("UPDATE backdraft_page_profiles SET secure_lock_enabled = IF(secure_lock_enabled=1,0,1) WHERE id = ?", [$id]);
        echo json_encode(['ok'=>true]); return;
    }

    if ($action === 'save_botproof') {
        $id = (int)($_POST['id'] ?? 0);
        $threshold = max(0, min(100, (int)($_POST['threshold'] ?? 0)));
        $session_mins = max(5, min(1440, (int)($_POST['session_mins'] ?? 60)));
        $max_attempts = max(1, min(10, (int)($_POST['max_attempts'] ?? 3)));
        db_run("UPDATE backdraft_page_profiles SET botproof_threshold=?, botproof_session_mins=?, botproof_max_attempts=? WHERE id=?", [$threshold, $session_mins, $max_attempts, $id]);
        echo json_encode(['ok'=>true,'message'=>'BotProof settings saved']); return;
    }

    if ($action === 'save_secure_lock') {
        $id = (int)($_POST['id'] ?? 0);
        $session_mins = max(5, min(1440, (int)($_POST['session_mins'] ?? 60)));
        $allowed_emails = trim($_POST['allowed_emails'] ?? '');
        db_run("UPDATE backdraft_page_profiles SET secure_lock_session_mins=?, secure_lock_allowed_emails=? WHERE id=?", [$session_mins, $allowed_emails, $id]);
        echo json_encode(['ok'=>true,'message'=>'Secure Lock settings saved']); return;
    }

    if ($action === 'save_profile') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            db_run("UPDATE backdraft_page_profiles SET display_name=?, monitoring=? WHERE id=?", [$_POST['display_name'] ?? '', isset($_POST['monitoring']) ? 1 : 0, $id]);
        } else {
            $page_id = trim($_POST['page_id'] ?? '');
            if (!$page_id) { echo json_encode(['ok'=>false,'error'=>'page_id required']); return; }
            $site_id = (int)($_POST['site_id'] ?? 0);
            try {
                bd_pdo()->prepare("INSERT INTO backdraft_page_profiles (site_id, page_id, display_name, monitoring) VALUES (?, ?, ?, ?)")
                    ->execute([$site_id, $page_id, $_POST['display_name'] ?? $page_id, isset($_POST['monitoring']) ? 1 : 0]);
            } catch (PDOException $e) {
                echo json_encode(['ok'=>false,'error'=>'Failed: ' . $e->getMessage()]); return;
            }
        }
        echo json_encode(['ok'=>true,'message'=>'Profile saved']); return;
    }

    if ($action === 'reset_profile') {
        $id = (int)($_POST['id'] ?? 0);
        db_run("UPDATE backdraft_page_profiles SET total_requests=0, total_threats=0, avg_score=0, last_request_at=NULL, learned_methods='', learned_content_types='', learned_avg_size=0 WHERE id = ?", [$id]);
        echo json_encode(['ok'=>true,'message'=>'Baseline reset']); return;
    }

    if ($action === 'delete_profile') {
        $id = (int)($_POST['id'] ?? 0);
        db_run("DELETE FROM backdraft_page_profiles WHERE id = ?", [$id]);
        echo json_encode(['ok'=>true,'message'=>'Profile deleted']); return;
    }

    echo json_encode(['ok'=>false,'error'=>'Unknown action']); return;
}

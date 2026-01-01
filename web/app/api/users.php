<?php
/**
 * /app/api/users.php — User Management API (strict JSON)
 *
 * Routes:
 *   POST action=edit_user        Edit user (email, role, password, active, mfa)
 *   POST action=reactivate_user  Reactivate deactivated user
 *   POST action=send_email       Send email to user via SMTP
 */
header('Content-Type: application/json');
require_once __DIR__ . '/../inc/db.php';
require_once __DIR__ . '/../inc/auth.php';

if (!bd_is_authed()) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'Unauthorized']); return; }
if (!bd_is_admin()) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); return; }

$action = $_POST['action'] ?? '';

// ── SMTP config ──────────────────────────────────────────────────────────
define('BD_SMTP_HOST', 'smtp.gmail.com');
define('BD_SMTP_PORT', 587);
define('BD_SMTP_USER', 'davestj@casterclub.com');
define('BD_SMTP_PASS', 'hlgz kyuu mcnt gxhk');
define('BD_SMTP_FROM', 'davestj@casterclub.com');
define('BD_SMTP_FROM_NAME', 'Mcaster1 BackDraft WAF');

if ($action === 'edit_user') {
    $id = (int)($_POST['id'] ?? 0);
    if (!$id) { echo json_encode(['ok'=>false,'error'=>'Missing user ID']); return; }

    $sets = []; $params = [];
    if (!empty($_POST['email'])) { $sets[] = "email = ?"; $params[] = $_POST['email']; }
    if (!empty($_POST['role']) && in_array($_POST['role'], ['user','admin','superadmin'])) { $sets[] = "role = ?"; $params[] = $_POST['role']; }
    if (!empty($_POST['password'])) { $sets[] = "password_hash = SHA2(?, 256)"; $params[] = $_POST['password']; }
    if (isset($_POST['active'])) { $sets[] = "active = ?"; $params[] = (int)$_POST['active']; }
    if (isset($_POST['mfa_enabled'])) { $sets[] = "mfa_enabled = ?"; $params[] = (int)$_POST['mfa_enabled']; }

    if (empty($sets)) { echo json_encode(['ok'=>false,'error'=>'No changes']); return; }
    $params[] = $id;
    db_run("UPDATE backdraft_users SET " . implode(', ', $sets) . " WHERE id = ?", $params);
    echo json_encode(['ok'=>true,'message'=>'User updated']); return;
}

if ($action === 'reactivate_user') {
    $id = (int)($_POST['id'] ?? 0);
    db_run("UPDATE backdraft_users SET active = 1 WHERE id = ?", [$id]);
    echo json_encode(['ok'=>true,'message'=>'User reactivated']); return;
}

if ($action === 'send_email') {
    $user_id = (int)($_POST['user_id'] ?? 0);
    $subject = trim($_POST['subject'] ?? '');
    $body    = trim($_POST['body'] ?? '');
    if (!$subject || !$body) { echo json_encode(['ok'=>false,'error'=>'Subject and body required']); return; }

    $user = db_row("SELECT username, email FROM backdraft_users WHERE id = ?", [$user_id]);
    if (!$user || empty($user['email'])) { echo json_encode(['ok'=>false,'error'=>'User has no email']); return; }

    $sent = bd_send_email_api($user['email'], $subject, $body, $user['username']);
    echo json_encode($sent === true ? ['ok'=>true,'message'=>"Email sent to {$user['email']}"] : ['ok'=>false,'error'=>"Send failed: {$sent}"]); return;
}

echo json_encode(['ok'=>false,'error'=>'Unknown action']);

// ── SMTP send function ───────────────────────────────────────────────────
function bd_send_email_api(string $to, string $subject, string $body, string $to_name = ''): mixed {
    $sock = @fsockopen(BD_SMTP_HOST, BD_SMTP_PORT, $errno, $errstr, 10);
    if (!$sock) return "Connect failed: {$errstr}";

    $read = function() use ($sock) { $r = ''; while ($l = fgets($sock, 1024)) { $r .= $l; if (isset($l[3]) && $l[3] === ' ') break; } return $r; };
    $send = function(string $cmd) use ($sock, $read) { fwrite($sock, $cmd . "\r\n"); return $read(); };

    $greeting = $read();
    if (strpos($greeting, '220') !== 0) { fclose($sock); return "Bad greeting"; }

    $send("EHLO backdraft.mcaster1.com");
    $resp = $send("STARTTLS");
    if (strpos($resp, '220') !== 0) { fclose($sock); return "STARTTLS failed"; }

    if (!stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT)) { fclose($sock); return "TLS failed"; }

    $send("EHLO backdraft.mcaster1.com");
    $send("AUTH LOGIN");
    $send(base64_encode(BD_SMTP_USER));
    $resp = $send(base64_encode(BD_SMTP_PASS));
    if (strpos($resp, '235') !== 0) { fclose($sock); return "Auth failed"; }

    $send("MAIL FROM:<" . BD_SMTP_FROM . ">");
    $resp = $send("RCPT TO:<{$to}>");
    if (strpos($resp, '250') !== 0) { fclose($sock); return "RCPT failed"; }

    $send("DATA");

    $html_body = '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="margin:0;padding:0;background:#0a0e1a;font-family:Arial,sans-serif"><div style="max-width:600px;margin:0 auto;padding:20px"><div style="background:#1e293b;border:1px solid #334155;border-radius:10px;overflow:hidden"><div style="background:linear-gradient(135deg,#f59e0b,#ef4444);padding:16px 24px;text-align:center"><span style="font-size:18px;font-weight:900;color:#fff">BackDraft</span></div><div style="padding:24px;color:#e2e8f0;font-size:14px;line-height:1.6">' . $body . '</div><div style="padding:12px 24px;border-top:1px solid #334155;text-align:center;font-size:11px;color:#64748b">Mcaster1 BackDraft WAF</div></div></div></body></html>';

    $display_to = $to_name ? "{$to_name} <{$to}>" : $to;
    $msg = "From: " . BD_SMTP_FROM_NAME . " <" . BD_SMTP_FROM . ">\r\nTo: {$display_to}\r\nSubject: {$subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" . $html_body . "\r\n.\r\n";
    fwrite($sock, $msg);
    $resp = $read();
    $send("QUIT"); fclose($sock);

    return (strpos($resp, '250') === 0) ? true : "Send failed: {$resp}";
}

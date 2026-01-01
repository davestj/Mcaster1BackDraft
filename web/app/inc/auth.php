<?php
/**
 * auth.php — Authentication helpers
 * Reads X-BackDraft-* headers injected by C++ FastCGI proxy
 */
if (!defined('BD_CONFIG')) require_once __DIR__ . '/config.php';

function bd_is_authed(): bool {
    return ($_SERVER['HTTP_X_BACKDRAFT_AUTHENTICATED'] ?? '0') === '1';
}

function bd_authed_user(): string {
    return $_SERVER['HTTP_X_BACKDRAFT_USER'] ?? '';
}

function bd_authed_role(): string {
    return $_SERVER['HTTP_X_BACKDRAFT_ROLE'] ?? '';
}

function bd_is_admin(): bool {
    $role = bd_authed_role();
    return $role === 'admin' || $role === 'superadmin';
}

function bd_require_auth(): void {
    if (!bd_is_authed()) {
        header('Location: /login.php');
        exit;
    }
}

function bd_require_auth_json(): void {
    if (!bd_is_authed()) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Unauthorized']);
        exit;
    }
}

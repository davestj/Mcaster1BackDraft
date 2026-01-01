<?php
/**
 * session-cleanup.php — Purge expired auth sessions
 *
 * Deletes sessions past their expires_at from backdraft_sessions.
 * Keeps the sessions table lean for fast auth lookups.
 *
 * Schedule: Every 1 hour
 */

$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2];
}

echo "=== BackDraft Session Cleanup ===\n";
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

$before = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_sessions")->fetchColumn();
$expired = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_sessions WHERE expires_at < NOW()")->fetchColumn();

echo "Total sessions: {$before}\n";
echo "Expired: {$expired}\n";

if ($expired > 0) {
    $pdo->exec("DELETE FROM backdraft_sessions WHERE expires_at < NOW()");
    echo "Purged {$expired} expired sessions\n";
}

$after = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_sessions")->fetchColumn();
echo "Remaining: {$after}\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";

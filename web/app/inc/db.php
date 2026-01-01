<?php
/**
 * db.php — Database helper + XSS escape
 */
if (!defined('BD_CONFIG')) require_once __DIR__ . '/config.php';

function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8'); }

function bd_pdo(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . BD_DB_HOST . ';port=' . BD_DB_PORT . ';dbname=' . BD_DB_NAME . ';charset=utf8mb4';
        $pdo = new PDO($dsn, BD_DB_USER, BD_DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

function db_row(string $sql, array $params = []): ?array {
    $stmt = bd_pdo()->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();
    return $row ?: null;
}

function db_rows(string $sql, array $params = []): array {
    $stmt = bd_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function db_scalar(string $sql, array $params = []) {
    $stmt = bd_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

function db_run(string $sql, array $params = []): int {
    $stmt = bd_pdo()->prepare($sql);
    $stmt->execute($params);
    return $stmt->rowCount();
}

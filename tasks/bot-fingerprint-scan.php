<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * bot-fingerprint-scan.php — Scan requests for unknown UAs, classify, fingerprint
 * Schedule: Every 2 hours
 */
$args = [];
foreach ($argv as $arg) { if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) $args[$m[1]] = $m[2]; }
$hours = (int)($args['hours'] ?? 2);

echo "=== BackDraft Bot Fingerprint Scan ===\n";
echo "Window: last {$hours} hours\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

try {
    $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        BD_DB_USER, BD_DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
} catch (PDOException $e) { echo "FATAL: " . $e->getMessage() . "\n"; exit(1); }

// Get distinct UAs from recent requests
$agents = $pdo->query("
    SELECT user_agent, COUNT(*) as cnt, COUNT(DISTINCT client_ip) as ips
    FROM backdraft_requests
    WHERE user_agent != '' AND request_time > DATE_SUB(NOW(), INTERVAL {$hours} HOUR)
    GROUP BY user_agent ORDER BY cnt DESC
")->fetchAll();

echo "Distinct user-agents: " . count($agents) . "\n";

// Load existing definitions for comparison
$existing = [];
$rows = $pdo->query("SELECT pattern, id FROM backdraft_bot_definitions")->fetchAll();
foreach ($rows as $r) $existing[strtolower($r['pattern'])] = $r['id'];

// Also load agent signatures
$sigs = [];
$sig_rows = $pdo->query("SELECT pattern FROM backdraft_agent_signatures WHERE active = 1")->fetchAll();
foreach ($sig_rows as $r) $sigs[] = strtolower($r['pattern']);

$new_count = 0;
$updated_count = 0;

$insert = $pdo->prepare("INSERT INTO backdraft_bot_definitions
    (name, pattern, match_type, classification, disposition, source, fingerprint_hash, first_seen, last_seen, hit_count)
    VALUES (?, ?, 'contains', ?, ?, 'learned', ?, NOW(), NOW(), ?)
    ON DUPLICATE KEY UPDATE last_seen = NOW(), hit_count = hit_count + VALUES(hit_count)");

foreach ($agents as $a) {
    $ua = $a['user_agent'];
    $ua_lower = strtolower($ua);

    // Skip if already in definitions
    if (isset($existing[$ua_lower])) {
        // Update hit count
        $pdo->prepare("UPDATE backdraft_bot_definitions SET last_seen = NOW(), hit_count = hit_count + ? WHERE id = ?")
            ->execute([$a['cnt'], $existing[$ua_lower]]);
        $updated_count++;
        continue;
    }

    // Skip if matches an existing signature
    $matched = false;
    foreach ($sigs as $sig) {
        if (stripos($ua, $sig) !== false) { $matched = true; break; }
    }
    if ($matched) continue;

    // Classify the UA
    $classification = 'unknown';
    $disposition = 'monitor';
    $name = substr($ua, 0, 80);

    // Scanner detection
    if (preg_match('/(nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|nuclei|burp|wpscan|hydra|openvas)/i', $ua, $m)) {
        $classification = 'scanner'; $disposition = 'block'; $name = ucfirst(strtolower($m[1]));
    }
    // Known bots/crawlers
    elseif (preg_match('/(googlebot|bingbot|yandexbot|baiduspider|duckduckbot|slurp)/i', $ua, $m)) {
        $classification = 'search_engine'; $disposition = 'allow'; $name = $m[1];
    }
    elseif (preg_match('/(facebookexternalhit|facebot|twitterbot|linkedinbot|pinterestbot|discordbot|telegrambot|whatsapp|slackbot)/i', $ua, $m)) {
        $classification = 'social'; $disposition = 'allow'; $name = $m[1];
    }
    elseif (preg_match('/(pingdom|uptimerobot|statuscake|datadog|newrelic|zabbix|nagios|site24x7)/i', $ua, $m)) {
        $classification = 'monitoring'; $disposition = 'allow'; $name = $m[1];
    }
    elseif (preg_match('/(cloudflare|fastly|akamai|cloudfront|varnish)/i', $ua, $m)) {
        $classification = 'cdn'; $disposition = 'allow'; $name = $m[1];
    }
    elseif (preg_match('/(feedly|feedspot|feedbin|feedburner|newsblur|inoreader)/i', $ua, $m)) {
        $classification = 'rss'; $disposition = 'allow'; $name = $m[1];
    }
    elseif (preg_match('/(gptbot|chatgpt|claudebot|claude-web|anthropic|bard|perplexity|cohere|ai2bot)/i', $ua, $m)) {
        $classification = 'ai_crawler'; $disposition = 'monitor'; $name = $m[1];
    }
    // Libraries
    elseif (preg_match('/(curl|wget|python-requests|python-urllib|go-http|java|ruby|perl|php|axios|node-fetch|httpie)/i', $ua, $m)) {
        $classification = 'library'; $disposition = 'monitor'; $name = $m[1];
    }
    // Bot/crawler/spider in name
    elseif (preg_match('/(bot|crawl|spider|scraper)/i', $ua)) {
        $classification = 'scraper'; $disposition = 'monitor';
    }
    // Real browser pattern
    elseif (preg_match('/Mozilla.*?(Chrome|Firefox|Safari|Edge|Opera)\/[\d.]+/i', $ua, $m)) {
        $classification = 'browser'; $disposition = 'allow'; $name = $m[1] . ' Browser';
    }
    // Minimal/suspicious UA
    elseif (strlen($ua) < 20) {
        $classification = 'unknown'; $disposition = 'monitor'; $name = 'Short UA: ' . $ua;
    }

    // Generate fingerprint hash
    $fingerprint = hash('sha256', $ua_lower);

    $insert->execute([$name, $ua, $classification, $disposition, $fingerprint, $a['cnt']]);
    $new_count++;
    echo "  NEW [{$classification}/{$disposition}] {$name}: {$a['cnt']} reqs, {$a['ips']} IPs\n";
}

echo "\nNew definitions: {$new_count}\n";
echo "Updated: {$updated_count}\n";
echo "Total in DB: " . (int)$pdo->query("SELECT COUNT(*) FROM backdraft_bot_definitions")->fetchColumn() . "\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";

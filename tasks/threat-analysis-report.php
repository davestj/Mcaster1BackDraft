<?php

require_once __DIR__ . '/../web/app/inc/config.php';
/**
 * threat-analysis-report.php — BackDraft Threat Analysis Report Generator
 *
 * Queries backdraft DB for threat events, log analytics, IP reputation,
 * agent signatures, and WAF rules to produce a comprehensive threat
 * intelligence report with preset response algorithms and remediation guidance.
 *
 * Output:
 *   stdout                           -> captured to output_log
 *   /tmp/backdraft_task_{id}.json    -> summary_json (structured metrics)
 *   /tmp/backdraft_task_{id}.html    -> export_html (pretty HTML5 report)
 *
 * CLI args (passed by TaskRunner from params JSON):
 *   --hours=24       Analysis window in hours
 *   --export=html,pdf,excel  Export formats to generate
 *   --run-id=123     Run record ID (auto-injected by TaskRunner)
 */

// ── Parse CLI arguments ──────────────────────────────────────────────────
$args = [];
foreach ($argv as $arg) {
    if (preg_match('/^--([a-z_-]+)=(.+)$/', $arg, $m)) {
        $args[$m[1]] = $m[2];
    }
}

$hours   = (int)($args['hours'] ?? 24);
$run_id  = (int)($args['run-id'] ?? 0);
$exports = $args['export'] ?? 'html,pdf,excel';

$task_id = 'threat_analysis_report';
$json_path = "/tmp/backdraft_task_{$task_id}.json";
$html_path = "/tmp/backdraft_task_{$task_id}.html";

echo "=== BackDraft Threat Analysis Report ===\n";
echo "Window: last {$hours} hours\n";
echo "Run ID: {$run_id}\n";
echo "Started: " . date('Y-m-d H:i:s') . "\n\n";

// ── Database connection ──────────────────────────────────────────────────
try {
    $pdo = new PDO(
        'mysql:host=127.0.0.1;port=3306;dbname=mcaster1_backdraft;charset=utf8mb4',
        BD_DB_USER,
        BD_DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
    );
} catch (PDOException $e) {
    echo "FATAL: Database connection failed: " . $e->getMessage() . "\n";
    exit(1);
}

$window = "DATE_SUB(NOW(), INTERVAL {$hours} HOUR)";

// ── 1. Executive Summary ─────────────────────────────────────────────────
echo "--- Gathering executive summary ---\n";

$total_requests = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_requests WHERE request_time > {$window}")->fetchColumn();
$total_threats  = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > {$window} AND dismissed = 0")->fetchColumn();
$total_blocked  = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > {$window} AND action_taken = 'blocked'")->fetchColumn();
$total_flagged  = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > {$window} AND action_taken = 'flagged'")->fetchColumn();
$unique_ips     = (int)$pdo->query("SELECT COUNT(DISTINCT client_ip) FROM backdraft_threats WHERE detected_at > {$window}")->fetchColumn();
$avg_score      = (float)$pdo->query("SELECT COALESCE(AVG(threat_score),0) FROM backdraft_threats WHERE detected_at > {$window}")->fetchColumn();
$max_score      = (int)$pdo->query("SELECT COALESCE(MAX(threat_score),0) FROM backdraft_threats WHERE detected_at > {$window}")->fetchColumn();
$banned_ips     = (int)$pdo->query("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1")->fetchColumn();

$threat_rate = ($total_requests > 0) ? round(($total_threats / $total_requests) * 100, 4) : 0;

echo "Total requests: {$total_requests}\n";
echo "Total threats: {$total_threats}\n";
echo "Threat rate: {$threat_rate}%\n";
echo "Unique threat IPs: {$unique_ips}\n";
echo "Avg threat score: " . round($avg_score, 1) . "\n";
echo "Max threat score: {$max_score}\n\n";

// ── 2. Threat Breakdown by Category ──────────────────────────────────────
echo "--- Threat categories ---\n";

$categories = $pdo->query(
    "SELECT category, severity, COUNT(*) as cnt, AVG(threat_score) as avg_score
     FROM backdraft_threats
     WHERE detected_at > {$window} AND dismissed = 0
     GROUP BY category, severity
     ORDER BY cnt DESC"
)->fetchAll();

$cat_summary = [];
foreach ($categories as $c) {
    $key = $c['category'];
    if (!isset($cat_summary[$key])) {
        $cat_summary[$key] = ['total' => 0, 'avg_score' => 0, 'by_severity' => []];
    }
    $cat_summary[$key]['total'] += $c['cnt'];
    $cat_summary[$key]['avg_score'] = round($c['avg_score'], 1);
    $cat_summary[$key]['by_severity'][$c['severity']] = (int)$c['cnt'];
    echo "  {$c['category']} [{$c['severity']}]: {$c['cnt']} events (avg score: " . round($c['avg_score'],1) . ")\n";
}
echo "\n";

// ── 3. Severity Distribution ─────────────────────────────────────────────
echo "--- Severity distribution ---\n";

$severities = $pdo->query(
    "SELECT severity, COUNT(*) as cnt
     FROM backdraft_threats
     WHERE detected_at > {$window} AND dismissed = 0
     GROUP BY severity ORDER BY FIELD(severity, 'critical','high','medium','low')"
)->fetchAll();

$severity_map = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
foreach ($severities as $s) {
    $severity_map[$s['severity']] = (int)$s['cnt'];
    echo "  {$s['severity']}: {$s['cnt']}\n";
}
echo "\n";

// ── 4. Top 10 Offending IPs ──────────────────────────────────────────────
echo "--- Top offending IPs ---\n";

$top_ips = $pdo->query(
    "SELECT t.client_ip, COUNT(*) as threat_count, MAX(t.threat_score) as max_score,
            AVG(t.threat_score) as avg_score,
            COALESCE(r.banned, 0) as banned,
            COALESCE(r.country_code, '--') as country,
            COALESCE(r.total_requests, 0) as total_requests
     FROM backdraft_threats t
     LEFT JOIN backdraft_ip_reputation r ON r.ip_addr = t.client_ip
     WHERE t.detected_at > {$window} AND t.dismissed = 0
     GROUP BY t.client_ip
     ORDER BY threat_count DESC
     LIMIT 10"
)->fetchAll();

foreach ($top_ips as $ip) {
    $status = $ip['banned'] ? ' [BANNED]' : '';
    echo "  {$ip['client_ip']} ({$ip['country']}): {$ip['threat_count']} threats, max={$ip['max_score']}, avg=" . round($ip['avg_score'],1) . "{$status}\n";
}
echo "\n";

// ── 5. Top Triggered Rules ───────────────────────────────────────────────
echo "--- Top triggered rules ---\n";

$top_rules = $pdo->query(
    "SELECT r.id, r.name, r.target, r.action, r.score,
            COUNT(DISTINCT t.id) as trigger_count
     FROM backdraft_rules r
     JOIN backdraft_threats t ON FIND_IN_SET(r.id, t.matched_rules)
     WHERE t.detected_at > {$window}
     GROUP BY r.id
     ORDER BY trigger_count DESC
     LIMIT 10"
)->fetchAll();

foreach ($top_rules as $r) {
    echo "  Rule #{$r['id']} \"{$r['name']}\" ({$r['target']}/{$r['action']}): {$r['trigger_count']} triggers\n";
}
echo "\n";

// ── 6. Agent/Bot Activity ────────────────────────────────────────────────
echo "--- Agent/bot activity ---\n";

$agent_activity = $pdo->query(
    "SELECT a.name, a.classification, a.disposition, COUNT(DISTINCT req.id) as hits
     FROM backdraft_agent_signatures a
     JOIN backdraft_requests req ON req.user_agent LIKE CONCAT('%', a.pattern, '%')
     WHERE req.request_time > {$window} AND a.active = 1
     GROUP BY a.id
     ORDER BY hits DESC
     LIMIT 15"
)->fetchAll();

foreach ($agent_activity as $a) {
    echo "  {$a['name']} ({$a['classification']}/{$a['disposition']}): {$a['hits']} requests\n";
}
echo "\n";

// ── 7. Hourly Threat Trend ───────────────────────────────────────────────
echo "--- Hourly threat trend ---\n";

$hourly = $pdo->query(
    "SELECT DATE_FORMAT(detected_at, '%Y-%m-%d %H:00') as hour_bucket,
            COUNT(*) as cnt, AVG(threat_score) as avg_score
     FROM backdraft_threats
     WHERE detected_at > {$window} AND dismissed = 0
     GROUP BY hour_bucket ORDER BY hour_bucket"
)->fetchAll();

foreach ($hourly as $h) {
    $bar = str_repeat('#', min(50, (int)$h['cnt']));
    echo "  {$h['hour_bucket']} | {$h['cnt']} threats | avg " . round($h['avg_score'],1) . " | {$bar}\n";
}
echo "\n";

// ── 8. Preset Response Algorithms ────────────────────────────────────────
echo "--- Generating response algorithms ---\n";

/**
 * Threat Assessment Response Framework
 *
 * Each severity level gets a standardized response template based on
 * NIST SP 800-61 incident response adapted for web application threats.
 */
$response_algorithms = [
    'critical' => [
        'threat_level'     => 'CRITICAL',
        'color'            => '#ef4444',
        'response_time'    => 'Immediate (< 15 minutes)',
        'auto_actions'     => [
            'IP automatically banned via backdraft_ip_reputation',
            'WAF rule auto-escalated to BLOCK mode for matched patterns',
            'Alert sent to security team via configured SMTP',
        ],
        'manual_actions'   => [
            'Review full request payload in threat detail view',
            'Check if attack was successful — inspect upstream response codes',
            'Correlate IP across all sites for lateral movement indicators',
            'Check server access logs for post-exploitation indicators',
            'Consider temporary geo-blocking if IP cluster from single region',
        ],
        'remediation'      => [
            'If SQLi confirmed: audit all database queries for parameterization',
            'If XSS confirmed: review output encoding in affected templates',
            'If RCE/command injection: patch application immediately, rotate credentials',
            'Deploy additional WAF rules targeting the specific attack vector',
            'Report IP to abuse contacts if originating from known ASN',
        ],
        'escalation'       => 'Notify infrastructure team + application owner within 15 minutes',
    ],
    'high' => [
        'threat_level'     => 'HIGH',
        'color'            => '#f59e0b',
        'response_time'    => 'Within 1 hour',
        'auto_actions'     => [
            'IP flagged in reputation system — auto-ban after 3 critical events',
            'WAF rule match logged with full request context',
            'Threat event created with matched rule details',
        ],
        'manual_actions'   => [
            'Review threat event details and matched rules',
            'Check if multiple high-severity events from same IP (escalation pattern)',
            'Verify WAF rules are catching all variants of the attack',
            'Review agent/bot classification — may be automated scanner',
        ],
        'remediation'      => [
            'Tighten WAF rules for the specific target (path/query/body)',
            'Add custom rules for novel attack patterns not covered by builtins',
            'Consider rate limiting on affected endpoints',
            'Review application logs for related anomalies',
        ],
        'escalation'       => 'Security team review within 1 hour — escalate to CRITICAL if pattern persists',
    ],
    'medium' => [
        'threat_level'     => 'MEDIUM',
        'color'            => '#0891b2',
        'response_time'    => 'Within 4 hours',
        'auto_actions'     => [
            'Threat event logged with rule match details',
            'IP reputation score updated incrementally',
        ],
        'manual_actions'   => [
            'Monitor for escalation — multiple medium events may indicate probing',
            'Review if events cluster around specific endpoints or time windows',
            'Check user-agent classification — legitimate bot vs scanner',
        ],
        'remediation'      => [
            'No immediate action required — monitor trend over 24-48 hours',
            'If pattern repeats: promote specific WAF rules from LOG to FLAG action',
            'Review and update agent signature database if new scanner detected',
        ],
        'escalation'       => 'Escalate to HIGH if 10+ events from same source within analysis window',
    ],
    'low' => [
        'threat_level'     => 'LOW',
        'color'            => '#64748b',
        'response_time'    => 'Next scheduled review cycle',
        'auto_actions'     => [
            'Event logged for trend analysis',
            'IP included in reputation baseline calculations',
        ],
        'manual_actions'   => [
            'Review during next scheduled threat analysis report',
            'Verify low-severity rules are appropriately scored',
        ],
        'remediation'      => [
            'No action required — informational only',
            'Use as baseline data for learning mode profile refinement',
            'Aggregate patterns may inform future rule creation',
        ],
        'escalation'       => 'No escalation unless volume exceeds normal baseline by 300%',
    ],
];

// Compute which response level is recommended based on current data
$recommended_response = 'low';
if ($severity_map['critical'] > 0) $recommended_response = 'critical';
elseif ($severity_map['high'] > 5) $recommended_response = 'critical';
elseif ($severity_map['high'] > 0) $recommended_response = 'high';
elseif ($severity_map['medium'] > 10) $recommended_response = 'high';
elseif ($severity_map['medium'] > 0) $recommended_response = 'medium';

echo "Recommended response level: " . strtoupper($recommended_response) . "\n";
$active_algo = $response_algorithms[$recommended_response];
echo "Response time: {$active_algo['response_time']}\n";
echo "Auto actions: " . count($active_algo['auto_actions']) . "\n";
echo "Manual actions: " . count($active_algo['manual_actions']) . "\n";
echo "Remediation steps: " . count($active_algo['remediation']) . "\n\n";

// ── 9. Build Summary JSON ────────────────────────────────────────────────
echo "--- Building summary JSON ---\n";

$summary = [
    'report_generated'      => date('Y-m-d H:i:s'),
    'analysis_window_hours' => $hours,
    'executive_summary'     => [
        'total_requests'  => $total_requests,
        'total_threats'   => $total_threats,
        'total_blocked'   => $total_blocked,
        'total_flagged'   => $total_flagged,
        'unique_ips'      => $unique_ips,
        'avg_score'       => round($avg_score, 1),
        'max_score'       => $max_score,
        'threat_rate_pct' => $threat_rate,
        'banned_ips'      => $banned_ips,
    ],
    'severity_distribution'    => $severity_map,
    'categories'               => $cat_summary,
    'top_offending_ips'        => $top_ips,
    'top_triggered_rules'      => $top_rules,
    'agent_activity'           => $agent_activity,
    'hourly_trend'             => $hourly,
    'recommended_response'     => $recommended_response,
    'response_algorithm'       => $active_algo,
    'all_response_algorithms'  => $response_algorithms,
];

file_put_contents($json_path, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "Summary JSON written to {$json_path}\n\n";

// ── 10. Build Pretty HTML5 Report ────────────────────────────────────────
echo "--- Building HTML5 report ---\n";

$report_date = date('F j, Y g:i A');
$resp_color  = $active_algo['color'];
$resp_level  = strtoupper($recommended_response);

// Helper: severity badge
function sev_badge($sev) {
    $colors = ['critical'=>'#ef4444','high'=>'#f59e0b','medium'=>'#0891b2','low'=>'#64748b'];
    $c = $colors[$sev] ?? '#64748b';
    return "<span style=\"display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;background:{$c}22;color:{$c};border:1px solid {$c}44\">" . strtoupper($sev) . "</span>";
}

$html = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BackDraft Threat Analysis Report — {$report_date}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');
  :root {
    --bg: #0a0e1a; --bg2: #111827; --card: #1e293b; --border: #334155;
    --amber: #f59e0b; --red: #ef4444; --green: #22c55e; --cyan: #0891b2;
    --text: #e2e8f0; --muted: #94a3b8; --dim: #64748b;
  }
  * { box-sizing:border-box; margin:0; padding:0 }
  body {
    font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 40px 20px;
  }
  .container { max-width: 1000px; margin: 0 auto }
  .header {
    text-align: center; padding: 40px 0 30px;
    border-bottom: 2px solid var(--border); margin-bottom: 30px;
  }
  .header h1 { font-size: 28px; font-weight: 800; margin-bottom: 8px }
  .header .subtitle { color: var(--muted); font-size: 14px }
  .header .logo {
    display: inline-block; width: 50px; height: 50px; border-radius: 12px;
    background: linear-gradient(135deg, var(--amber), var(--red));
    color: #fff; font-weight: 900; font-size: 20px;
    line-height: 50px; text-align: center; margin-bottom: 12px;
  }

  .response-banner {
    background: {$resp_color}15; border: 2px solid {$resp_color}44;
    border-radius: 12px; padding: 24px; margin-bottom: 30px; text-align: center;
  }
  .response-banner h2 { font-size: 22px; color: {$resp_color}; margin-bottom: 4px }
  .response-banner .time { color: var(--muted); font-size: 13px }

  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 30px }
  .stat-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px 20px; text-align: center;
  }
  .stat-card .val { font-size: 32px; font-weight: 800; line-height: 1.1 }
  .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px }
  .val-amber { color: var(--amber) }
  .val-red { color: var(--red) }
  .val-green { color: var(--green) }
  .val-cyan { color: var(--cyan) }

  .section { margin-bottom: 30px }
  .section h3 {
    font-size: 16px; font-weight: 700; margin-bottom: 16px; padding-bottom: 8px;
    border-bottom: 1px solid var(--border); color: var(--amber);
  }

  table {
    width: 100%; border-collapse: collapse; font-size: 13px;
    background: var(--card); border-radius: 10px; overflow: hidden;
  }
  th {
    background: var(--bg2); padding: 10px 14px; text-align: left; font-weight: 600;
    color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  }
  td { padding: 10px 14px; border-bottom: 1px solid var(--border) }
  tr:hover td { background: rgba(255,255,255,0.02) }

  .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px }

  .algo-section { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 16px }
  .algo-section h4 { font-size: 14px; font-weight: 700; margin-bottom: 12px; color: var(--cyan) }
  .algo-section ul { padding-left: 20px; margin-bottom: 0 }
  .algo-section li { margin-bottom: 6px; font-size: 13px; color: var(--text) }

  .bar { display: inline-block; height: 12px; border-radius: 6px; min-width: 4px }
  .bar-critical { background: var(--red) }
  .bar-high { background: var(--amber) }
  .bar-medium { background: var(--cyan) }
  .bar-low { background: var(--dim) }

  .trend-bar { display: inline-block; background: var(--amber); height: 8px; border-radius: 4px; min-width: 2px }

  @media print {
    body { background: #fff; color: #111; padding: 20px }
    .stat-card, .algo-section, table { border: 1px solid #ddd }
    .val-amber, .val-red, .val-cyan, .val-green { color: #111 }
    .response-banner { border-color: #666 }
  }

  .footer { text-align: center; padding: 30px 0; border-top: 1px solid var(--border); margin-top: 30px; color: var(--dim); font-size: 12px }
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="header">
  <div class="logo">BD</div>
  <h1>Threat Analysis Report</h1>
  <div class="subtitle">
    Mcaster1 BackDraft WAF &mdash; {$report_date}<br>
    Analysis window: last {$hours} hours
  </div>
</div>

<!-- Response Level Banner -->
<div class="response-banner">
  <h2>Recommended Response Level: {$resp_level}</h2>
  <div class="time">Response time: {$active_algo['response_time']}</div>
</div>

<!-- Executive Summary Stats -->
<div class="stat-grid">
  <div class="stat-card"><div class="val val-amber">{$total_requests}</div><div class="label">Total Requests</div></div>
  <div class="stat-card"><div class="val val-red">{$total_threats}</div><div class="label">Threat Events</div></div>
  <div class="stat-card"><div class="val val-cyan">{$unique_ips}</div><div class="label">Unique Threat IPs</div></div>
  <div class="stat-card"><div class="val val-amber">{$threat_rate}%</div><div class="label">Threat Rate</div></div>
  <div class="stat-card"><div class="val val-red">{$max_score}</div><div class="label">Max Threat Score</div></div>
  <div class="stat-card"><div class="val val-green">{$banned_ips}</div><div class="label">Banned IPs</div></div>
</div>

<!-- Severity Distribution -->
<div class="section">
  <h3>Severity Distribution</h3>
  <div class="stat-grid">
HTML;

$sev_total = max(1, array_sum($severity_map));
foreach (['critical','high','medium','low'] as $sev) {
    $cnt = $severity_map[$sev];
    $pct = round(($cnt / $sev_total) * 100, 1);
    $w   = max(4, $pct * 3);
    $colors = ['critical'=>'var(--red)','high'=>'var(--amber)','medium'=>'var(--cyan)','low'=>'var(--dim)'];
    $c = $colors[$sev];
    $html .= <<<HTML
    <div class="stat-card" style="text-align:left">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span style="font-weight:700;text-transform:uppercase;font-size:12px;color:{$c}">{$sev}</span>
        <span style="font-size:20px;font-weight:800;color:{$c}">{$cnt}</span>
      </div>
      <div style="background:rgba(255,255,255,0.05);border-radius:6px;height:12px;overflow:hidden">
        <div class="bar bar-{$sev}" style="width:{$w}px"></div>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-top:4px">{$pct}% of threats</div>
    </div>
HTML;
}

$html .= <<<HTML
  </div>
</div>

<!-- Top Offending IPs -->
<div class="section">
  <h3>Top Offending IPs</h3>
  <table>
    <thead><tr><th>IP Address</th><th>Country</th><th>Threats</th><th>Max Score</th><th>Avg Score</th><th>Total Reqs</th><th>Status</th></tr></thead>
    <tbody>
HTML;

foreach ($top_ips as $ip) {
    $ban_badge = $ip['banned'] ? '<span style="color:var(--red);font-weight:700">BANNED</span>' : '<span style="color:var(--green)">Active</span>';
    $html .= "<tr><td class=\"mono\">{$ip['client_ip']}</td><td>{$ip['country']}</td><td style=\"font-weight:700\">{$ip['threat_count']}</td><td>{$ip['max_score']}</td><td>" . round($ip['avg_score'],1) . "</td><td>{$ip['total_requests']}</td><td>{$ban_badge}</td></tr>\n";
}
if (empty($top_ips)) {
    $html .= '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:30px">No threat IPs detected in analysis window</td></tr>';
}

$html .= <<<HTML
    </tbody>
  </table>
</div>

<!-- Top Triggered Rules -->
<div class="section">
  <h3>Top Triggered WAF Rules</h3>
  <table>
    <thead><tr><th>Rule</th><th>Target</th><th>Action</th><th>Score</th><th>Triggers</th></tr></thead>
    <tbody>
HTML;

foreach ($top_rules as $r) {
    $html .= "<tr><td style=\"font-weight:600\">{$r['name']}</td><td>{$r['target']}</td><td>{$r['action']}</td><td>{$r['score']}</td><td style=\"font-weight:700\">{$r['trigger_count']}</td></tr>\n";
}
if (empty($top_rules)) {
    $html .= '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:30px">No rules triggered in analysis window</td></tr>';
}

$html .= <<<HTML
    </tbody>
  </table>
</div>

<!-- Agent/Bot Activity -->
<div class="section">
  <h3>Agent &amp; Bot Activity</h3>
  <table>
    <thead><tr><th>Agent</th><th>Classification</th><th>Disposition</th><th>Requests</th></tr></thead>
    <tbody>
HTML;

foreach ($agent_activity as $a) {
    $disp_color = $a['disposition'] === 'block' ? 'var(--red)' : ($a['disposition'] === 'allow' ? 'var(--green)' : 'var(--amber)');
    $html .= "<tr><td style=\"font-weight:600\">{$a['name']}</td><td>{$a['classification']}</td><td style=\"color:{$disp_color};font-weight:600\">" . strtoupper($a['disposition']) . "</td><td>{$a['hits']}</td></tr>\n";
}
if (empty($agent_activity)) {
    $html .= '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px">No bot/scanner activity detected</td></tr>';
}

$html .= <<<HTML
    </tbody>
  </table>
</div>

<!-- Hourly Trend -->
<div class="section">
  <h3>Hourly Threat Trend</h3>
  <table>
    <thead><tr><th>Hour</th><th>Threats</th><th>Avg Score</th><th>Trend</th></tr></thead>
    <tbody>
HTML;

$max_hourly = max(1, max(array_column($hourly, 'cnt') ?: [1]));
foreach ($hourly as $h) {
    $bar_w = max(4, round(($h['cnt'] / $max_hourly) * 200));
    $html .= "<tr><td class=\"mono\">{$h['hour_bucket']}</td><td style=\"font-weight:700\">{$h['cnt']}</td><td>" . round($h['avg_score'],1) . "</td><td><span class=\"trend-bar\" style=\"width:{$bar_w}px\"></span></td></tr>\n";
}
if (empty($hourly)) {
    $html .= '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:30px">No threat data for trend analysis</td></tr>';
}

$html .= <<<HTML
    </tbody>
  </table>
</div>

<!-- Response Algorithm -->
<div class="section">
  <h3>Recommended Response Algorithm</h3>
HTML;

// Show the active response algorithm and all levels
foreach ($response_algorithms as $level => $algo) {
    $is_active = ($level === $recommended_response) ? ' style="border:2px solid ' . $algo['color'] . '44;box-shadow:0 0 20px ' . $algo['color'] . '15"' : '';
    $active_label = ($level === $recommended_response) ? ' <span style="font-size:11px;background:' . $algo['color'] . '22;color:' . $algo['color'] . ';padding:2px 8px;border-radius:10px;font-weight:700">ACTIVE</span>' : '';

    $html .= "<div class=\"algo-section\"{$is_active}>\n";
    $html .= "<h4 style=\"color:{$algo['color']}\">{$algo['threat_level']} Response{$active_label}</h4>\n";
    $html .= "<p style=\"font-size:12px;color:var(--muted);margin-bottom:12px\">Response time: {$algo['response_time']} | Escalation: {$algo['escalation']}</p>\n";

    $html .= "<div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px\">\n";

    $html .= "<div><h4 style=\"font-size:12px;color:var(--muted);margin-bottom:8px\">AUTOMATED ACTIONS</h4><ul>\n";
    foreach ($algo['auto_actions'] as $a) $html .= "<li>{$a}</li>\n";
    $html .= "</ul></div>\n";

    $html .= "<div><h4 style=\"font-size:12px;color:var(--muted);margin-bottom:8px\">MANUAL REVIEW</h4><ul>\n";
    foreach ($algo['manual_actions'] as $a) $html .= "<li>{$a}</li>\n";
    $html .= "</ul></div>\n";

    $html .= "<div><h4 style=\"font-size:12px;color:var(--muted);margin-bottom:8px\">REMEDIATION</h4><ul>\n";
    foreach ($algo['remediation'] as $a) $html .= "<li>{$a}</li>\n";
    $html .= "</ul></div>\n";

    $html .= "</div></div>\n";
}

$html .= <<<HTML
</div>

<!-- Footer -->
<div class="footer">
  Generated by Mcaster1 BackDraft WAF v0.0.1a &mdash; {$report_date}<br>
  Analysis window: {$hours} hours | Total requests: {$total_requests} | Threats: {$total_threats}
</div>

</div>
</body>
</html>
HTML;

file_put_contents($html_path, $html);
echo "HTML report written to {$html_path}\n\n";

// ── 11. Update run record with summary_json directly ─────────────────────
if ($run_id > 0) {
    echo "--- Updating run record #{$run_id} ---\n";
    try {
        $stmt = $pdo->prepare("UPDATE backdraft_task_runs SET summary_json = ?, export_html = ?, export_formats = 'html,pdf,excel' WHERE id = ?");
        $stmt->execute([json_encode($summary, JSON_UNESCAPED_SLASHES), $html, $run_id]);
        echo "Run record updated directly via PDO\n";
    } catch (Exception $e) {
        echo "Warning: direct run update failed: " . $e->getMessage() . "\n";
        echo "TaskRunner will pick up sidecar files instead\n";
    }
}

echo "\n=== Threat Analysis Report Complete ===\n";
echo "Completed: " . date('Y-m-d H:i:s') . "\n";

<?php
$page_title = 'Threats';
$active_nav = 'threats';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();

// ── Filters ──────────────────────────────────────────────────────────────
$severity_filter = $_GET['severity'] ?? '';
$category_filter = $_GET['category'] ?? '';
$view = $_GET['view'] ?? 'all'; // 'all', 'threats', 'suspicious', 'ips', 'agents'
$page = max(1, intval($_GET['page'] ?? 1));
$limit = 50;
$offset = ($page - 1) * $limit;

// ── Stats ────────────────────────────────────────────────────────────────
$total_requests  = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests") ?: 0;
$total_threats   = (int)db_scalar("SELECT COUNT(*) FROM backdraft_threats WHERE dismissed = 0") ?: 0;
$total_flagged   = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE action_taken IN ('flag','block','challenge')") ?: 0;
$total_suspicious = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE threat_score > 0") ?: 0;
$total_blocked   = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE action_taken = 'block'") ?: 0;
$banned_ips      = (int)db_scalar("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1") ?: 0;
$unique_threat_ips = (int)db_scalar("SELECT COUNT(DISTINCT client_ip) FROM backdraft_requests WHERE threat_score > 0") ?: 0;
$max_score       = (int)db_scalar("SELECT COALESCE(MAX(threat_score), 0) FROM backdraft_requests") ?: 0;
?>

<style>
.view-tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}
.view-tab{padding:6px 14px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text-dim);transition:all .15s}
.view-tab:hover{background:rgba(255,255,255,.05)}
.view-tab.active{background:var(--amber);color:#000;border-color:var(--amber)}
.view-tab .count{font-size:10px;opacity:.7;margin-left:4px}

.threat-detail{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;align-items:center;justify-content:center}
.threat-detail.open{display:flex}
.threat-detail .modal{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:700px;max-height:85vh;overflow-y:auto}
.ip-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;display:flex;align-items:center;gap:16px;margin-bottom:8px}
.ip-card .ip-addr{font-family:var(--font-mono);font-size:14px;font-weight:700;min-width:140px}
.ip-card .ip-stats{display:flex;gap:16px;flex:1;font-size:12px}
.ip-card .ip-stats span{color:var(--muted)}
.ip-card .ip-stats strong{color:var(--text)}
</style>

<!-- Stat Cards -->
<div class="stat-grid">
    <div class="stat-card stat-amber"><div class="stat-val"><?= number_format($total_requests) ?></div><div class="stat-label">Total Requests</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= number_format($total_threats) ?></div><div class="stat-label">Threat Events</div></div>
    <div class="stat-card stat-amber"><div class="stat-val"><?= number_format($total_suspicious) ?></div><div class="stat-label">Suspicious (score &gt; 0)</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= number_format($total_flagged) ?></div><div class="stat-label">Flagged/Blocked</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val"><?= $unique_threat_ips ?></div><div class="stat-label">Threat IPs</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= $banned_ips ?></div><div class="stat-label">Banned IPs</div></div>
    <div class="stat-card"><div class="stat-val"><?= $max_score ?></div><div class="stat-label">Max Score</div></div>
</div>

<!-- View Tabs -->
<div class="view-tabs">
    <a href="?view=all" class="view-tab <?= $view === 'all' ? 'active' : '' ?>">All Activity<span class="count"><?= $total_requests ?></span></a>
    <a href="?view=threats" class="view-tab <?= $view === 'threats' ? 'active' : '' ?>">Threat Events<span class="count"><?= $total_threats ?></span></a>
    <a href="?view=suspicious" class="view-tab <?= $view === 'suspicious' ? 'active' : '' ?>">Suspicious<span class="count"><?= $total_suspicious ?></span></a>
    <a href="?view=ips" class="view-tab <?= $view === 'ips' ? 'active' : '' ?>">IP Reputation<span class="count"><?= $unique_threat_ips ?></span></a>
    <a href="?view=agents" class="view-tab <?= $view === 'agents' ? 'active' : '' ?>">Agent Activity</a>
</div>

<?php if ($view === 'threats'): ?>
<!-- ── THREAT EVENTS (from backdraft_threats) ─────────────────────────── -->
<?php
    $where = "WHERE dismissed = 0";
    $bind = [];
    if ($severity_filter) { $where .= " AND severity = ?"; $bind[] = $severity_filter; }
    if ($category_filter) { $where .= " AND category = ?"; $bind[] = $category_filter; }
    $total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_threats $where", $bind);
    $threats = db_rows("SELECT t.*, r.method, r.path, r.user_agent, r.host
        FROM backdraft_threats t LEFT JOIN backdraft_requests r ON r.id = t.request_id
        $where ORDER BY t.detected_at DESC LIMIT $limit OFFSET $offset", $bind);
    $pages_total = max(1, ceil($total / $limit));
?>
<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
    <a href="?view=threats&severity=" class="btn <?= !$severity_filter ? 'btn-amber' : 'btn-ghost' ?>" style="padding:4px 10px;font-size:11px">All</a>
    <?php foreach (['critical','high','medium','low'] as $s): ?>
        <a href="?view=threats&severity=<?= $s ?>" class="btn <?= $severity_filter === $s ? 'btn-amber' : 'btn-ghost' ?>" style="padding:4px 10px;font-size:11px"><?= ucfirst($s) ?></a>
    <?php endforeach; ?>
</div>

<?php elseif ($view === 'suspicious'): ?>
<!-- ── SUSPICIOUS REQUESTS (score > 0) ────────────────────────────────── -->
<?php
    $threats = db_rows("SELECT request_time as detected_at, client_ip, threat_score, action_taken,
        matched_rules, method, path, user_agent, host, query_string
        FROM backdraft_requests WHERE threat_score > 0
        ORDER BY request_time DESC LIMIT $limit OFFSET $offset");
    $total = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE threat_score > 0");
    $pages_total = max(1, ceil($total / $limit));
?>

<?php elseif ($view === 'ips'): ?>
<!-- ── IP REPUTATION ──────────────────────────────────────────────────── -->
<?php
    $ips = db_rows("SELECT * FROM backdraft_ip_reputation ORDER BY max_score DESC, total_threats DESC LIMIT 50");
?>
<div class="card" style="margin-bottom:20px">
    <div class="card-title">IP Reputation Database (<?= count($ips) ?> IPs tracked)</div>
    <?php foreach ($ips as $ip): ?>
    <div class="ip-card">
        <div class="ip-addr" style="color:<?= $ip['banned'] ? 'var(--red)' : ($ip['max_score'] >= 75 ? 'var(--amber)' : 'var(--text)') ?>">
            <?= h($ip['ip_addr']) ?>
            <?php if ($ip['banned']): ?><span class="badge badge-red" style="margin-left:6px">BANNED</span><?php endif; ?>
        </div>
        <div class="ip-stats">
            <span>Requests: <strong><?= number_format($ip['total_requests']) ?></strong></span>
            <span>Threats: <strong style="color:<?= $ip['total_threats'] > 0 ? 'var(--red)' : 'var(--muted)' ?>"><?= $ip['total_threats'] ?></strong></span>
            <span>Max: <strong style="color:<?= $ip['max_score'] >= 75 ? 'var(--red)' : ($ip['max_score'] >= 50 ? 'var(--amber)' : 'var(--text)') ?>"><?= $ip['max_score'] ?></strong></span>
            <span>Avg: <strong><?= number_format($ip['avg_score'], 1) ?></strong></span>
            <span>First: <strong style="font-size:11px"><?= h(substr($ip['first_seen'], 0, 10)) ?></strong></span>
            <span><?= h($ip['country_code'] ?: '--') ?></span>
        </div>
        <?php if ($is_admin): ?>
        <div>
            <?php if ($ip['banned']): ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--green)" onclick="unbanIp('<?= h($ip['ip_addr']) ?>')">Unban</button>
            <?php else: ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--red)" onclick="banIp('<?= h($ip['ip_addr']) ?>')">Ban</button>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
    <?php if (empty($ips)): ?>
    <div style="text-align:center;color:var(--muted);padding:30px">No IP reputation data yet — IPs are tracked as the WAF processes requests</div>
    <?php endif; ?>
</div>

<?php elseif ($view === 'agents'): ?>
<!-- ── AGENT ACTIVITY ─────────────────────────────────────────────────── -->
<?php
    $agent_hits = db_rows("SELECT a.name, a.classification, a.disposition, a.pattern,
        COUNT(DISTINCT r.id) as hits, COUNT(DISTINCT r.client_ip) as ips,
        MAX(r.request_time) as last_seen
        FROM backdraft_agent_signatures a
        JOIN backdraft_requests r ON r.user_agent LIKE CONCAT('%', a.pattern, '%')
        WHERE a.active = 1
        GROUP BY a.id ORDER BY hits DESC");

    // Unknown/unmatched agents with suspicious patterns
    $unknown = db_rows("SELECT r2.user_agent, COUNT(*) as cnt, COUNT(DISTINCT r2.client_ip) as ips,
        MAX(r2.request_time) as last_seen
        FROM backdraft_requests r2
        WHERE r2.user_agent != '' AND r2.threat_score > 0
        AND NOT EXISTS (
            SELECT 1 FROM backdraft_agent_signatures a2
            WHERE a2.active = 1 AND r2.user_agent LIKE CONCAT('%', a2.pattern, '%')
        )
        GROUP BY r2.user_agent ORDER BY cnt DESC LIMIT 20");
?>
<div class="card" style="margin-bottom:20px">
    <div class="card-title">Known Agent Signatures (<?= count($agent_hits) ?> matched)</div>
    <div class="table-wrap">
        <table class="bd-table">
            <thead><tr><th>Agent</th><th>Classification</th><th>Disposition</th><th>Requests</th><th>IPs</th><th>Last Seen</th></tr></thead>
            <tbody>
            <?php foreach ($agent_hits as $a):
                $disp_color = $a['disposition'] === 'block' ? 'red' : ($a['disposition'] === 'allow' ? 'green' : 'amber');
            ?>
                <tr>
                    <td style="font-weight:600"><?= h($a['name']) ?></td>
                    <td><span class="badge badge-muted"><?= h($a['classification']) ?></span></td>
                    <td><span class="badge badge-<?= $disp_color ?>"><?= strtoupper(h($a['disposition'])) ?></span></td>
                    <td style="font-weight:700"><?= $a['hits'] ?></td>
                    <td><?= $a['ips'] ?></td>
                    <td style="font-family:var(--font-mono);font-size:11px"><?= h($a['last_seen']) ?></td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($agent_hits)): ?>
                <tr><td colspan="6" style="text-align:center;color:var(--muted);padding:20px">No agent signature matches in request data</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php // Check last agent scan task results
$last_scan = db_row("SELECT summary_json, started_at FROM backdraft_task_runs WHERE task_id = 'agent_activity_scan' AND status = 'success' ORDER BY started_at DESC LIMIT 1");
if ($last_scan && !empty($last_scan['summary_json'])):
    $scan_data = json_decode($last_scan['summary_json'], true);
    $suspicious_agents = $scan_data['suspicious_unmatched'] ?? [];
    if (!empty($suspicious_agents)):
?>
<div class="card">
    <div class="card-title">Suspicious Unmatched Agents (from last scan: <?= h($last_scan['started_at']) ?>)</div>
    <div class="table-wrap">
        <table class="bd-table">
            <thead><tr><th>User Agent</th><th>Reason</th><th>Requests</th><th>IPs</th></tr></thead>
            <tbody>
            <?php foreach ($suspicious_agents as $s): ?>
                <tr>
                    <td style="font-family:var(--font-mono);font-size:11px;max-width:400px;overflow:hidden;text-overflow:ellipsis"><?= h($s['agent']) ?></td>
                    <td style="color:var(--amber);font-size:12px"><?= h($s['reason']) ?></td>
                    <td style="font-weight:700"><?= $s['requests'] ?></td>
                    <td><?= $s['ips'] ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; endif; ?>

<?php else: // view === 'all' or default ?>
<!-- ── ALL ACTIVITY (requests with score breakdown) ───────────────────── -->
<?php
    $threats = db_rows("SELECT request_time as detected_at, client_ip, threat_score, action_taken,
        matched_rules, method, path, user_agent, host, query_string, response_bytes, upstream_ms
        FROM backdraft_requests
        ORDER BY request_time DESC LIMIT $limit OFFSET $offset");
    $total = $total_requests;
    $pages_total = max(1, ceil($total / $limit));
?>
<?php endif; ?>

<?php if ($view !== 'ips' && $view !== 'agents'): ?>
<!-- ── Request/Threat Table ───────────────────────────────────────────── -->
<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Client IP</th>
                    <th>Score</th>
                    <th><?= $view === 'threats' ? 'Category' : 'Method' ?></th>
                    <th><?= $view === 'threats' ? 'Severity' : 'Host' ?></th>
                    <th>Action</th>
                    <th>Path</th>
                    <th>User Agent</th>
                    <th>Rules</th>
                    <?php if ($is_admin && $view === 'threats'): ?><th></th><?php endif; ?>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($threats as $t):
                $score = (int)($t['threat_score'] ?? 0);
                $score_class = $score >= 75 ? 'badge-red' : ($score >= 50 ? 'badge-amber' : ($score > 0 ? 'badge-muted' : ''));
                $row_style = $score >= 75 ? 'background:rgba(239,68,68,.04)' : ($score >= 50 ? 'background:rgba(245,158,11,.03)' : '');
            ?>
                <tr style="<?= $row_style ?>">
                    <td style="font-family:var(--font-mono);font-size:11px;white-space:nowrap"><?= h($t['detected_at']) ?></td>
                    <td style="font-family:var(--font-mono);font-size:12px"><?= h($t['client_ip']) ?></td>
                    <td><?php if ($score > 0): ?><span class="badge <?= $score_class ?>"><?= $score ?></span><?php else: ?><span style="color:var(--muted)">0</span><?php endif; ?></td>
                    <?php if ($view === 'threats'): ?>
                        <td><?= h($t['category'] ?? '') ?></td>
                        <td><span class="badge badge-<?= ($t['severity'] ?? '') === 'critical' ? 'red' : (($t['severity'] ?? '') === 'high' ? 'amber' : 'muted') ?>"><?= h($t['severity'] ?? '') ?></span></td>
                    <?php else: ?>
                        <td><span style="font-family:var(--font-mono);font-size:12px;color:var(--cyan)"><?= h($t['method'] ?? '') ?></span></td>
                        <td style="font-size:12px;color:var(--muted)"><?= h($t['host'] ?? '') ?></td>
                    <?php endif; ?>
                    <td>
                        <?php
                        $act = $t['action_taken'] ?? 'pass';
                        $act_color = $act === 'block' ? 'red' : ($act === 'flag' ? 'amber' : ($act === 'challenge' ? 'amber' : ($act === 'log' ? 'muted' : '')));
                        ?>
                        <?php if ($act_color): ?><span class="badge badge-<?= $act_color ?>"><?= h($act) ?></span>
                        <?php else: ?><span style="color:var(--muted)"><?= h($act) ?></span><?php endif; ?>
                    </td>
                    <td style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="<?= h($t['path'] ?? '') ?>"><?= h($t['path'] ?? '') ?></td>
                    <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;color:var(--muted)" title="<?= h($t['user_agent'] ?? '') ?>"><?= h($t['user_agent'] ?? '') ?></td>
                    <td style="font-size:11px;color:var(--muted)"><?= h($t['matched_rules'] ?? '') ?></td>
                    <?php if ($is_admin && $view === 'threats'): ?>
                    <td><button class="btn btn-ghost" style="padding:2px 6px;font-size:10px" onclick="dismissThreat(<?= $t['id'] ?? 0 ?>)">Dismiss</button></td>
                    <?php endif; ?>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($threats)): ?>
                <tr><td colspan="<?= ($is_admin && $view === 'threats') ? 10 : 9 ?>" style="text-align:center;color:var(--muted);padding:40px">
                    <?php if ($view === 'threats'): ?>No threat events yet — threats are recorded when WAF score exceeds threshold (<?= db_scalar("SELECT config_value FROM backdraft_config WHERE config_key='threat_threshold'") ?: 75 ?>)
                    <?php elseif ($view === 'suspicious'): ?>No suspicious requests (score &gt; 0) detected
                    <?php else: ?>No WAF request data — enable WAF on a site to start collecting<?php endif; ?>
                </td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <?php if (isset($pages_total) && $pages_total > 1): ?>
    <div style="display:flex;gap:6px;justify-content:center;margin-top:16px;flex-wrap:wrap">
        <?php if ($page > 1): ?>
            <a href="?view=<?= h($view) ?>&page=<?= $page - 1 ?>&severity=<?= h($severity_filter) ?>" class="btn btn-ghost" style="min-width:36px;justify-content:center">&laquo;</a>
        <?php endif; ?>
        <?php
        $start_pg = max(1, $page - 4);
        $end_pg = min($pages_total, $start_pg + 9);
        for ($i = $start_pg; $i <= $end_pg; $i++): ?>
            <a href="?view=<?= h($view) ?>&page=<?= $i ?>&severity=<?= h($severity_filter) ?>" class="btn <?= $i === $page ? 'btn-amber' : 'btn-ghost' ?>" style="min-width:36px;justify-content:center"><?= $i ?></a>
        <?php endfor; ?>
        <?php if ($page < $pages_total): ?>
            <a href="?view=<?= h($view) ?>&page=<?= $page + 1 ?>&severity=<?= h($severity_filter) ?>" class="btn btn-ghost" style="min-width:36px;justify-content:center">&raquo;</a>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<script>
async function dismissThreat(id) {
    if (!confirm('Dismiss this threat event?')) return;
    const res = await bdApi('POST', '/api/threats/dismiss', { id });
    if (res.ok) { bdToast('Threat dismissed', 'success'); setTimeout(() => location.reload(), 500); }
}

async function banIp(ip) {
    if (!confirm('Ban IP ' + ip + '? This will block all requests from this IP when WAF is in active mode.')) return;
    const res = await bdApi('POST', '/api/ip-reputation/ban', { ip });
    if (res.ok) { bdToast(res.message, 'success'); setTimeout(() => location.reload(), 500); }
}

async function unbanIp(ip) {
    if (!confirm('Unban IP ' + ip + '?')) return;
    const res = await bdApi('POST', '/api/ip-reputation/unban', { ip });
    if (res.ok) { bdToast(res.message, 'success'); setTimeout(() => location.reload(), 500); }
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

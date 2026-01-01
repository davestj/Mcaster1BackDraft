<?php
$page_title = 'Dashboard';
$active_nav = 'dashboard';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$requests_24h = db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)") ?: 0;
$threats_24h  = db_scalar("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND dismissed = 0") ?: 0;
$active_rules = db_scalar("SELECT COUNT(*) FROM backdraft_rules WHERE active = 1") ?: 0;
$waf_sites    = db_scalar("SELECT COUNT(*) FROM backdraft_sites WHERE waf_enabled = 1") ?: 0;
$banned_ips   = db_scalar("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1") ?: 0;
$log_sites    = db_scalar("SELECT COUNT(*) FROM backdraft_sites WHERE log_analysis = 1") ?: 0;
$avg_score    = db_scalar("SELECT ROUND(AVG(threat_score),1) FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND threat_score > 0") ?: '0.0';
?>

<div class="stat-grid">
    <div class="stat-card stat-amber">
        <div class="stat-val"><?= number_format($requests_24h) ?></div>
        <div class="stat-label">Requests (24h)</div>
    </div>
    <div class="stat-card stat-red">
        <div class="stat-val"><?= number_format($threats_24h) ?></div>
        <div class="stat-label">Threats (24h)</div>
    </div>
    <div class="stat-card stat-cyan">
        <div class="stat-val"><?= $avg_score ?></div>
        <div class="stat-label">Avg Threat Score</div>
    </div>
    <div class="stat-card stat-green">
        <div class="stat-val"><?= $active_rules ?></div>
        <div class="stat-label">Active Rules</div>
    </div>
    <div class="stat-card stat-amber">
        <div class="stat-val"><?= $waf_sites ?></div>
        <div class="stat-label">WAF Sites</div>
    </div>
    <div class="stat-card stat-red">
        <div class="stat-val"><?= $banned_ips ?></div>
        <div class="stat-label">Banned IPs</div>
    </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
    <!-- Recent Threats -->
    <div class="card">
        <div class="card-title">Recent Threats</div>
        <div class="table-wrap">
            <table class="bd-table">
                <thead><tr><th>Time</th><th>IP</th><th>Score</th><th>Category</th><th>Severity</th></tr></thead>
                <tbody>
                <?php
                $threats = db_rows("SELECT detected_at, client_ip, threat_score, category, severity FROM backdraft_threats WHERE dismissed = 0 ORDER BY detected_at DESC LIMIT 10");
                foreach ($threats as $t): ?>
                    <tr>
                        <td style="font-family:var(--font-mono);font-size:12px"><?= h($t['detected_at']) ?></td>
                        <td><?= h($t['client_ip']) ?></td>
                        <td><span class="badge <?= $t['threat_score'] >= 75 ? 'badge-red' : ($t['threat_score'] >= 50 ? 'badge-amber' : 'badge-muted') ?>"><?= $t['threat_score'] ?></span></td>
                        <td><?= h($t['category']) ?></td>
                        <td><span class="badge badge-<?= $t['severity'] === 'critical' ? 'red' : ($t['severity'] === 'high' ? 'amber' : 'muted') ?>"><?= h($t['severity']) ?></span></td>
                    </tr>
                <?php endforeach;
                if (empty($threats)) echo '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No threats detected yet — learning mode active</td></tr>';
                ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Monitored Sites -->
    <div class="card">
        <div class="card-title">Monitored Sites</div>
        <div class="table-wrap">
            <table class="bd-table">
                <thead><tr><th>Site</th><th>WAF</th><th>Logs</th><th>Mode</th></tr></thead>
                <tbody>
                <?php
                $sites = db_rows("SELECT site_name, waf_enabled, log_analysis, waf_mode FROM backdraft_sites ORDER BY site_name LIMIT 15");
                foreach ($sites as $s): ?>
                    <tr>
                        <td><?= h($s['site_name']) ?></td>
                        <td><?= $s['waf_enabled'] ? '<span class="badge badge-green">ON</span>' : '<span class="badge badge-muted">OFF</span>' ?></td>
                        <td><?= $s['log_analysis'] ? '<span class="badge badge-green">ON</span>' : '<span class="badge badge-muted">OFF</span>' ?></td>
                        <td><span class="badge badge-<?= $s['waf_mode'] === 'active' ? 'red' : ($s['waf_mode'] === 'learning' ? 'green' : 'muted') ?>"><?= h($s['waf_mode']) ?></span></td>
                    </tr>
                <?php endforeach;
                if (empty($sites)) echo '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No sites discovered yet — check nginx integration</td></tr>';
                ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

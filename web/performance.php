<?php
$page_title = 'Performance';
$active_nav = 'performance';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

// Latest single metric row
$latest = db_row("SELECT * FROM backdraft_perf_metrics
    WHERE daemon = 'backdraft'
    ORDER BY recorded_at DESC LIMIT 1");

// Parse custom_json for extended WAF/task metrics
$extra = [];
if ($latest && !empty($latest['custom_json'])) {
    $extra = json_decode($latest['custom_json'], true) ?: [];
}

// History for charts (last 30 minutes, one row per interval)
$history = db_rows("SELECT recorded_at, cpu_percent, mem_rss_mb, threads, open_fds, waf_rps, waf_avg_ms, custom_json
    FROM backdraft_perf_metrics
    WHERE daemon = 'backdraft' AND recorded_at > DATE_SUB(NOW(), INTERVAL 30 MINUTE)
    ORDER BY recorded_at ASC");

// DB stats
$db_size_mb = (float)db_scalar("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2)
    FROM information_schema.tables WHERE table_schema = 'mcaster1_backdraft'") ?: 0;
$request_count = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)") ?: 0;
$threat_count = (int)db_scalar("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)") ?: 0;

// Uptime from first metric
$first_metric = db_scalar("SELECT MIN(recorded_at) FROM backdraft_perf_metrics WHERE daemon = 'backdraft'");
$uptime_str = 'Unknown';
if ($first_metric) {
    $diff = time() - strtotime($first_metric);
    $days = floor($diff / 86400);
    $hours = floor(($diff % 86400) / 3600);
    $mins = floor(($diff % 3600) / 60);
    $uptime_str = ($days > 0 ? "{$days}d " : '') . "{$hours}h {$mins}m";
}
?>

<style>
.perf-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.perf-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;position:relative;overflow:hidden}
.perf-card .label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-weight:600;margin-bottom:4px}
.perf-card .val{font-size:26px;font-weight:800;line-height:1.1}
.perf-card .sub{font-size:11px;color:var(--muted);margin-top:4px}
.perf-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px}
.perf-amber::after{background:var(--amber)}
.perf-red::after{background:var(--red)}
.perf-green::after{background:var(--green)}
.perf-cyan::after{background:var(--cyan)}

.section-title{font-size:14px;font-weight:700;color:var(--amber);margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border)}

.mini-chart{height:60px;display:flex;align-items:flex-end;gap:2px;margin-top:8px}
.mini-chart .bar{flex:1;background:var(--amber);border-radius:2px 2px 0 0;min-height:2px;transition:height .3s}
</style>

<!-- Daemon Identity -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div>
        <h2 style="font-size:18px;font-weight:700">Mcaster1BackDraft Performance</h2>
        <p style="font-size:12px;color:var(--muted)">Single C++ daemon — PID <?= $latest ? $latest['pid'] : '—' ?> — Uptime: <?= $uptime_str ?> — Metrics every 10s</p>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
        <?php $waf_mode = $extra['waf_mode'] ?? 'learning'; ?>
        <span class="badge badge-<?= $waf_mode === 'active' ? 'red' : ($waf_mode === 'learning' ? 'green' : 'muted') ?>" style="font-size:12px;padding:4px 12px">
            WAF: <?= strtoupper($waf_mode) ?>
        </span>
        <span style="font-size:11px;color:var(--muted)"><?= $latest ? h($latest['recorded_at']) : 'No data' ?></span>
    </div>
</div>

<?php if (!$latest): ?>
<div class="card" style="text-align:center;padding:40px;color:var(--muted)">
    No performance metrics yet — daemon may not be running, or PerfMonitor is still initializing.
</div>
<?php else: ?>

<!-- Core System Metrics -->
<div class="section-title">System Resources</div>
<div class="perf-grid">
    <div class="perf-card perf-amber">
        <div class="label">CPU Usage</div>
        <div class="val" style="color:var(--<?= $latest['cpu_percent'] > 80 ? 'red' : ($latest['cpu_percent'] > 50 ? 'amber' : 'green') ?>)"><?= number_format($latest['cpu_percent'], 1) ?>%</div>
        <div class="sub">Process CPU</div>
    </div>
    <div class="perf-card perf-cyan">
        <div class="label">Memory (RSS)</div>
        <div class="val" style="color:var(--cyan)"><?= number_format($latest['mem_rss_mb'], 1) ?> <span style="font-size:14px;font-weight:600">MB</span></div>
        <div class="sub">VMS: <?= number_format($latest['mem_vms_mb'], 1) ?> MB</div>
    </div>
    <div class="perf-card perf-green">
        <div class="label">Threads</div>
        <div class="val" style="color:var(--green)"><?= $latest['threads'] ?></div>
        <div class="sub">Worker + system</div>
    </div>
    <div class="perf-card perf-amber">
        <div class="label">Open FDs</div>
        <div class="val" style="color:var(--amber)"><?= $latest['open_fds'] ?></div>
        <div class="sub">File descriptors</div>
    </div>
    <div class="perf-card perf-cyan">
        <div class="label">DB Size</div>
        <div class="val" style="color:var(--cyan)"><?= $db_size_mb ?> <span style="font-size:14px;font-weight:600">MB</span></div>
        <div class="sub">mcaster1_backdraft</div>
    </div>
</div>

<!-- WAF Engine Metrics -->
<div class="section-title">WAF Engine</div>
<div class="perf-grid">
    <div class="perf-card perf-amber">
        <div class="label">Requests/sec</div>
        <div class="val" style="color:var(--amber)"><?= number_format($latest['waf_rps'], 1) ?></div>
        <div class="sub">Current interval RPS</div>
    </div>
    <div class="perf-card perf-cyan">
        <div class="label">Avg Latency</div>
        <div class="val" style="color:var(--cyan)"><?= number_format($latest['waf_avg_ms'], 1) ?> <span style="font-size:14px;font-weight:600">ms</span></div>
        <div class="sub">Per-request average</div>
    </div>
    <div class="perf-card perf-amber">
        <div class="label">Total Requests</div>
        <div class="val" style="color:var(--amber)"><?= number_format($extra['waf_total_requests'] ?? 0) ?></div>
        <div class="sub">Since daemon start</div>
    </div>
    <div class="perf-card perf-red">
        <div class="label">Threats Detected</div>
        <div class="val" style="color:var(--red)"><?= number_format($extra['waf_total_threats'] ?? 0) ?></div>
        <div class="sub">Score &ge; threshold</div>
    </div>
    <div class="perf-card perf-red">
        <div class="label">Blocked</div>
        <div class="val" style="color:var(--red)"><?= number_format($extra['waf_total_blocked'] ?? 0) ?></div>
        <div class="sub">Active mode blocks</div>
    </div>
    <div class="perf-card perf-green">
        <div class="label">Active Rules</div>
        <div class="val" style="color:var(--green)"><?= $extra['waf_active_rules'] ?? 0 ?></div>
        <div class="sub">Loaded in engine</div>
    </div>
</div>

<!-- BotProof Metrics -->
<div class="section-title">BotProof Challenge System</div>
<div class="perf-grid">
    <div class="perf-card perf-amber">
        <div class="label">Challenged</div>
        <div class="val" style="color:var(--amber)"><?= number_format($extra['total_challenged'] ?? 0) ?></div>
        <div class="sub">Challenge pages served</div>
    </div>
    <div class="perf-card perf-green">
        <div class="label">Passed</div>
        <div class="val" style="color:var(--green)"><?= number_format($extra['captcha_passed'] ?? 0) ?></div>
        <div class="sub">Humans verified</div>
    </div>
    <div class="perf-card perf-red">
        <div class="label">Failed</div>
        <div class="val" style="color:var(--red)"><?= number_format($extra['captcha_failed'] ?? 0) ?></div>
        <div class="sub">Wrong answers / blocked</div>
    </div>
    <?php
    $bp_sessions = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_sessions WHERE expires_at > NOW()");
    $bp_pending  = (int)db_scalar("SELECT COUNT(*) FROM backdraft_botproof_challenges WHERE expires_at > NOW()");
    ?>
    <div class="perf-card perf-cyan">
        <div class="label">Active Sessions</div>
        <div class="val" style="color:var(--cyan)"><?= $bp_sessions ?></div>
        <div class="sub">Verified humans</div>
    </div>
    <div class="perf-card">
        <div class="label">Pending Challenges</div>
        <div class="val"><?= $bp_pending ?></div>
        <div class="sub">Awaiting answer</div>
    </div>
</div>

<!-- Task Scheduler Metrics -->
<div class="section-title">Task Scheduler</div>
<div class="perf-grid">
    <div class="perf-card perf-green">
        <div class="label">Enabled Tasks</div>
        <div class="val" style="color:var(--green)"><?= $extra['task_enabled'] ?? 0 ?></div>
        <div class="sub">Active in scheduler</div>
    </div>
    <div class="perf-card perf-cyan">
        <div class="label">Running Now</div>
        <div class="val" style="color:var(--cyan)"><?= $extra['task_running'] ?? 0 ?></div>
        <div class="sub">Currently executing</div>
    </div>
    <div class="perf-card perf-amber">
        <div class="label">Requests (24h)</div>
        <div class="val" style="color:var(--amber)"><?= number_format($request_count) ?></div>
        <div class="sub">WAF-inspected</div>
    </div>
    <div class="perf-card perf-red">
        <div class="label">Threats (24h)</div>
        <div class="val" style="color:var(--red)"><?= number_format($threat_count) ?></div>
        <div class="sub">Flagged or blocked</div>
    </div>
</div>

<!-- Mini Trend Charts -->
<?php if (count($history) > 1): ?>
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px">
    <?php
    // CPU trend
    $cpu_vals = array_column($history, 'cpu_percent');
    $max_cpu = max(1, max($cpu_vals));
    ?>
    <div class="card">
        <div class="card-title">CPU % (30 min)</div>
        <div class="mini-chart">
        <?php foreach ($cpu_vals as $v): ?>
            <div class="bar" style="height:<?= max(2, ($v / $max_cpu) * 60) ?>px;background:var(--<?= $v > 80 ? 'red' : ($v > 50 ? 'amber' : 'green') ?>)"></div>
        <?php endforeach; ?>
        </div>
    </div>

    <?php
    // Memory trend
    $mem_vals = array_column($history, 'mem_rss_mb');
    $max_mem = max(1, max($mem_vals));
    $min_mem = min($mem_vals);
    ?>
    <div class="card">
        <div class="card-title">Memory RSS (30 min)</div>
        <div class="mini-chart">
        <?php foreach ($mem_vals as $v): ?>
            <?php $range = max(1, $max_mem - $min_mem); $pct = ($v - $min_mem) / $range; ?>
            <div class="bar" style="height:<?= max(2, $pct * 60) ?>px;background:var(--cyan)"></div>
        <?php endforeach; ?>
        </div>
    </div>

    <?php
    // WAF RPS trend
    $rps_vals = array_column($history, 'waf_rps');
    $max_rps = max(1, max($rps_vals) ?: 1);
    ?>
    <div class="card">
        <div class="card-title">WAF RPS (30 min)</div>
        <div class="mini-chart">
        <?php foreach ($rps_vals as $v): ?>
            <div class="bar" style="height:<?= max(2, ($v / $max_rps) * 60) ?>px;background:var(--amber)"></div>
        <?php endforeach; ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Metrics History Table -->
<div class="card">
    <div class="card-title">Recent Metrics History</div>
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>PID</th>
                    <th>CPU %</th>
                    <th>RSS MB</th>
                    <th>VMS MB</th>
                    <th>Threads</th>
                    <th>FDs</th>
                    <th>WAF RPS</th>
                    <th>WAF ms</th>
                    <th>Rules</th>
                    <th>Tasks Running</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $recent = db_rows("SELECT * FROM backdraft_perf_metrics
                WHERE daemon = 'backdraft'
                ORDER BY recorded_at DESC LIMIT 30");
            foreach ($recent as $m):
                $cj = json_decode($m['custom_json'] ?? '{}', true) ?: [];
            ?>
                <tr>
                    <td style="font-family:var(--font-mono);font-size:11px;white-space:nowrap"><?= h($m['recorded_at']) ?></td>
                    <td style="font-family:var(--font-mono);font-size:12px"><?= $m['pid'] ?></td>
                    <td style="color:var(--<?= $m['cpu_percent'] > 80 ? 'red' : ($m['cpu_percent'] > 50 ? 'amber' : 'green') ?>);font-weight:600"><?= number_format($m['cpu_percent'], 1) ?></td>
                    <td><?= number_format($m['mem_rss_mb'], 1) ?></td>
                    <td style="color:var(--muted)"><?= number_format($m['mem_vms_mb'], 1) ?></td>
                    <td><?= $m['threads'] ?></td>
                    <td><?= $m['open_fds'] ?></td>
                    <td style="font-weight:600"><?= number_format($m['waf_rps'], 1) ?></td>
                    <td><?= number_format($m['waf_avg_ms'], 1) ?></td>
                    <td><?= $cj['waf_active_rules'] ?? '—' ?></td>
                    <td><?= $cj['task_running'] ?? 0 ?></td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($recent)): ?>
                <tr><td colspan="11" style="text-align:center;color:var(--muted);padding:30px">No metrics in database</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php endif; ?>

<script>
// Auto-refresh via AJAX every 10s (no full page reload flicker)
let refreshTimer = setInterval(async () => {
    try {
        const resp = await fetch(location.href);
        const html = await resp.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const newContent = doc.querySelector('.main-content');
        if (newContent) {
            document.querySelector('.main-content').innerHTML = newContent.innerHTML;
        }
    } catch (e) {}
}, 10000);
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

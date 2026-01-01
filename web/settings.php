<?php
$page_title = 'Settings';
$active_nav = 'settings';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$config = db_rows("SELECT * FROM backdraft_config ORDER BY config_key");
$waf_mode = 'learning';
foreach ($config as $c) {
    if ($c['config_key'] === 'waf_mode') $waf_mode = $c['config_value'];
}
?>

<div style="margin-bottom:20px">
    <h2 style="font-size:18px;font-weight:700">Settings</h2>
    <p style="font-size:12px;color:var(--muted)">WAF configuration and runtime settings</p>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px">
    <!-- WAF Mode -->
    <div class="card">
        <div class="card-title">WAF Mode</div>
        <div style="display:flex;gap:12px;margin-top:12px">
            <button class="btn <?= $waf_mode === 'learning' ? 'btn-green' : 'btn-ghost' ?>" onclick="setMode('learning')">Learning</button>
            <button class="btn <?= $waf_mode === 'active' ? 'btn-red' : 'btn-ghost' ?>" onclick="setMode('active')">Active</button>
            <button class="btn <?= $waf_mode === 'disabled' ? 'btn-ghost' : 'btn-ghost' ?>" onclick="setMode('disabled')" style="<?= $waf_mode === 'disabled' ? 'border-color:var(--muted);color:var(--text)' : '' ?>">Disabled</button>
        </div>
        <p style="font-size:12px;color:var(--muted);margin-top:12px">
            <strong>Learning:</strong> Logs and scores all requests, never blocks.<br>
            <strong>Active:</strong> Blocks requests above threat threshold.<br>
            <strong>Disabled:</strong> Pass-through, no inspection.
        </p>
    </div>

    <!-- Daemon Health -->
    <div class="card">
        <div class="card-title">Daemon Health</div>
        <div style="margin-top:12px" id="healthStatus">Checking...</div>
    </div>
</div>

<!-- Runtime Config -->
<div class="card">
    <div class="card-title">Runtime Configuration</div>
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Key</th>
                    <th>Value</th>
                    <th>Description</th>
                    <th>Updated</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($config as $c): ?>
                <tr>
                    <td style="font-family:var(--font-mono);font-size:12px;font-weight:600"><?= h($c['config_key']) ?></td>
                    <td style="font-family:var(--font-mono);font-size:12px;color:var(--amber)"><?= h($c['config_value']) ?></td>
                    <td style="font-size:12px;color:var(--muted)"><?= h($c['description'] ?? '') ?></td>
                    <td style="font-size:11px;color:var(--muted)"><?= h($c['updated_at']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- System Info -->
<div class="card" style="margin-top:16px">
    <div class="card-title">System Info</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px;font-size:13px">
        <div><span style="color:var(--muted)">Version:</span> <span style="color:var(--amber)">v0.0.1a</span></div>
        <div><span style="color:var(--muted)">PHP:</span> <?= phpversion() ?></div>
        <div><span style="color:var(--muted)">Server:</span> <?= php_uname('n') ?></div>
        <div><span style="color:var(--muted)">OS:</span> <?= php_uname('s') . ' ' . php_uname('r') ?></div>
        <div><span style="color:var(--muted)">MySQL:</span> <?= bd_pdo()->getAttribute(PDO::ATTR_SERVER_VERSION) ?></div>
        <div><span style="color:var(--muted)">Memory:</span> <?= ini_get('memory_limit') ?></div>
    </div>
</div>

<script>
async function setMode(mode) {
    const res = await bdApi('POST', '/api/mode', { mode });
    if (res.ok) {
        bdToast('WAF mode changed to ' + mode, 'success');
        setTimeout(() => location.reload(), 1000);
    }
}

// Check daemon health
async function checkHealth() {
    const el = document.getElementById('healthStatus');
    let html = '';

    try {
        const admin = await (await fetch('/api/health')).json();
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
            '<span style="width:8px;height:8px;border-radius:50%;background:var(--green)"></span>' +
            '<span>C++ Admin — v' + admin.version + ', uptime ' + admin.uptime_secs + 's</span></div>';
    } catch (e) {
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
            '<span style="width:8px;height:8px;border-radius:50%;background:var(--red)"></span>' +
            '<span style="color:var(--red)">C++ Admin — offline</span></div>';
    }

    // WAF and logd are on different ports — can't fetch cross-origin from browser
    // Show status from the /api/status endpoint instead
    try {
        const status = await bdApi('GET', '/api/status');
        if (status.ok) {
            html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
                '<span style="width:8px;height:8px;border-radius:50%;background:var(--green)"></span>' +
                '<span>Status — ' + status.active_rules + ' rules, ' + status.waf_sites + ' WAF sites</span></div>';
        }
    } catch (e) {}

    el.innerHTML = html || '<span style="color:var(--muted)">Unable to check</span>';
}
checkHealth();
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

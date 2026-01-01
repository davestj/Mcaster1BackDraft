<?php
$page_title = 'Site Security';
$active_nav = 'site-security';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();
$sites = db_rows("SELECT id, site_name, maintenance_active, security_blocking,
    block_bad_agent, block_banned_ip, block_bad_path, block_bad_payload, block_bad_cookie, block_bad_referer,
    security_log_enabled, rate_limit_login, waf_enabled, log_analysis
    FROM backdraft_sites ORDER BY site_name");

$maint_count = count(array_filter($sites, fn($s) => $s['maintenance_active']));
$blocking_count = count(array_filter($sites, fn($s) => $s['security_blocking']));
$banned_ips = (int)db_scalar("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1");
$blocked_agents = (int)db_scalar("SELECT COUNT(*) FROM backdraft_agent_signatures WHERE disposition = 'block' AND active = 1");
$events_24h = (int)db_scalar("SELECT COUNT(*) FROM backdraft_security_events WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
$bot_defs = (int)db_scalar("SELECT COUNT(*) FROM backdraft_bot_definitions WHERE active = 1");
?>

<style>
.sec-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:12px}
.sec-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.sec-row .name{flex:1;min-width:200px}
.sec-row .name h3{font-size:14px;font-weight:700;margin-bottom:2px}
.sec-row .name .sub{font-size:11px;color:var(--muted)}
.sec-toggles{display:flex;gap:6px;flex-wrap:wrap}
.sec-toggle{padding:3px 8px;border-radius:6px;font-size:10px;font-weight:700;border:1px solid;cursor:pointer;transition:all .15s}
.sec-toggle.on{background:var(--green)22;color:var(--green);border-color:var(--green)44}
.sec-toggle.off{background:var(--bg3);color:var(--muted);border-color:var(--border)}
.sec-toggle:hover{opacity:.8}
.sec-actions{display:flex;gap:4px;flex-shrink:0}
.maint-on{background:var(--red)15;border-color:var(--red)33}
.maint-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;background:var(--red)22;color:var(--red);border:1px solid var(--red)44;animation:pulse 1.5s infinite}
</style>

<!-- Stat Cards -->
<div class="stat-grid" style="grid-template-columns:repeat(6,1fr)">
    <div class="stat-card stat-amber"><div class="stat-val"><?= count($sites) ?></div><div class="stat-label">Sites</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= $maint_count ?></div><div class="stat-label">In Maintenance</div></div>
    <div class="stat-card stat-green"><div class="stat-val"><?= $blocking_count ?></div><div class="stat-label">Security Active</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= $banned_ips ?></div><div class="stat-label">Banned IPs</div></div>
    <div class="stat-card stat-amber"><div class="stat-val"><?= $blocked_agents ?></div><div class="stat-label">Blocked Agents</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val"><?= $events_24h ?></div><div class="stat-label">Events (24h)</div></div>
</div>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">Site Security Management</h2>
    <div style="display:flex;gap:8px">
        <?php if ($is_admin): ?>
        <button class="btn btn-ghost" onclick="syncBlacklists()">Sync Blacklists</button>
        <button class="btn btn-red" style="background:var(--red);color:#fff" onclick="emergencyLockdown()">Emergency Lockdown All</button>
        <?php endif; ?>
    </div>
</div>

<!-- Site Cards -->
<?php foreach ($sites as $s): ?>
<div class="sec-card <?= $s['maintenance_active'] ? 'maint-on' : '' ?>" id="site-<?= $s['id'] ?>">
    <div class="sec-row">
        <div class="name">
            <h3>
                <?= h($s['site_name']) ?>
                <?php if ($s['maintenance_active']): ?>
                    <span class="maint-badge">MAINTENANCE</span>
                <?php endif; ?>
            </h3>
            <div class="sub">
                <?php if ($s['waf_enabled']): ?><span class="badge badge-green" style="font-size:9px">WAF</span><?php endif; ?>
                <?php if ($s['log_analysis']): ?><span class="badge badge-muted" style="font-size:9px">LOGS</span><?php endif; ?>
                <?php if ($s['rate_limit_login']): ?><span class="badge badge-cyan" style="font-size:9px">RATE LIMIT</span><?php endif; ?>
            </div>
        </div>

        <!-- Security block toggles -->
        <div class="sec-toggles">
            <span class="sec-toggle <?= $s['block_bad_agent'] ? 'on' : 'off' ?>" title="Block malicious user agents">Agent</span>
            <span class="sec-toggle <?= $s['block_banned_ip'] ? 'on' : 'off' ?>" title="Block banned IPs">IP</span>
            <span class="sec-toggle <?= $s['block_bad_path'] ? 'on' : 'off' ?>" title="Block bad paths (SQLi, traversal, etc.)">Path</span>
            <span class="sec-toggle <?= $s['block_bad_payload'] ? 'on' : 'off' ?>" title="Block bad payloads">Payload</span>
            <span class="sec-toggle <?= $s['block_bad_cookie'] ? 'on' : 'off' ?>" title="Block bad cookies">Cookie</span>
            <span class="sec-toggle <?= $s['block_bad_referer'] ? 'on' : 'off' ?>" title="Block bad referers">Referer</span>
        </div>

        <!-- Actions -->
        <?php if ($is_admin): ?>
        <div class="sec-actions">
            <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="toggleMaint(<?= $s['id'] ?>, '<?= h($s['site_name']) ?>', <?= $s['maintenance_active'] ? 'false' : 'true' ?>)">
                <?= $s['maintenance_active'] ? 'End Maint' : 'Maint On' ?>
            </button>
            <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="openSecurityModal(<?= $s['id'] ?>, <?= h(json_encode($s)) ?>)">Configure</button>
            <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--red)" onclick="lockdownSite(<?= $s['id'] ?>, '<?= h($s['site_name']) ?>')">Lockdown</button>
        </div>
        <?php endif; ?>
    </div>
</div>
<?php endforeach; ?>

<!-- Security Config Modal -->
<div class="modal-overlay" id="secModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;align-items:center;justify-content:center">
    <div style="background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:550px;max-height:85vh;overflow-y:auto">
        <h3 style="color:var(--amber);margin-bottom:16px" id="secModalTitle">Security Configuration</h3>

        <div style="margin-bottom:16px">
            <div style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:600;margin-bottom:8px">Security Blocks</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_agent"> Block Bad Agents</label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_ip"> Block Banned IPs</label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_path"> Block Bad Paths</label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_payload"> Block Bad Payloads</label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_cookie"> Block Bad Cookies</label>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_referer"> Block Bad Referers</label>
            </div>
        </div>

        <div style="margin-bottom:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_logging" checked> Enable Security Event Logging</label>
        </div>

        <div style="margin-bottom:16px">
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px"><input type="checkbox" id="cb_ratelimit"> Enable Login Rate Limiting (5 req/min)</label>
        </div>

        <div style="margin-bottom:16px">
            <button class="btn btn-ghost" style="font-size:11px" onclick="selectAllBlocks(true)">Enable All Blocks</button>
            <button class="btn btn-ghost" style="font-size:11px" onclick="selectAllBlocks(false)">Disable All</button>
        </div>

        <input type="hidden" id="sec_site_id">
        <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn btn-ghost" onclick="document.getElementById('secModal').style.display='none'">Cancel</button>
            <button class="btn btn-amber" onclick="applySecurityConfig()">Apply & Reload nginx</button>
        </div>
    </div>
</div>

<script>
async function toggleMaint(siteId, siteName, active) {
    let reason = '';
    if (active) {
        reason = prompt('Maintenance reason (optional):') || 'Maintenance mode';
    }
    const res = await bdApi('POST', '/api/sites/maintenance', {
        site_id: siteId, active, duration_secs: 3600, reason
    });
    if (res.ok) { bdToast(res.message, 'success'); setTimeout(() => location.reload(), 800); }
}

function openSecurityModal(siteId, data) {
    document.getElementById('secModalTitle').textContent = 'Security — ' + data.site_name;
    document.getElementById('sec_site_id').value = siteId;
    document.getElementById('cb_agent').checked = !!data.block_bad_agent;
    document.getElementById('cb_ip').checked = !!data.block_banned_ip;
    document.getElementById('cb_path').checked = !!data.block_bad_path;
    document.getElementById('cb_payload').checked = !!data.block_bad_payload;
    document.getElementById('cb_cookie').checked = !!data.block_bad_cookie;
    document.getElementById('cb_referer').checked = !!data.block_bad_referer;
    document.getElementById('cb_logging').checked = !!data.security_log_enabled;
    document.getElementById('cb_ratelimit').checked = !!data.rate_limit_login;
    document.getElementById('secModal').style.display = 'flex';
}

function selectAllBlocks(val) {
    ['cb_agent','cb_ip','cb_path','cb_payload','cb_cookie','cb_referer'].forEach(id => {
        document.getElementById(id).checked = val;
    });
}

async function applySecurityConfig() {
    const siteId = parseInt(document.getElementById('sec_site_id').value);

    // Apply security blocks
    const blockRes = await bdApi('POST', '/api/sites/security-blocks', {
        site_id: siteId,
        block_bad_agent: document.getElementById('cb_agent').checked,
        block_banned_ip: document.getElementById('cb_ip').checked,
        block_bad_path: document.getElementById('cb_path').checked,
        block_bad_payload: document.getElementById('cb_payload').checked,
        block_bad_cookie: document.getElementById('cb_cookie').checked,
        block_bad_referer: document.getElementById('cb_referer').checked,
        security_log_enabled: document.getElementById('cb_logging').checked
    });

    // Apply rate limits
    await bdApi('POST', '/api/sites/rate-limits', {
        site_id: siteId,
        rate_limit_login: document.getElementById('cb_ratelimit').checked
    });

    if (blockRes.ok) {
        bdToast('Security config applied & nginx reloaded', 'success');
        document.getElementById('secModal').style.display = 'none';
        setTimeout(() => location.reload(), 800);
    } else {
        bdToast(blockRes.error || 'Failed', 'error');
    }
}

async function lockdownSite(siteId, siteName) {
    if (!confirm('EMERGENCY LOCKDOWN for ' + siteName + '?\n\nThis will enable maintenance mode AND all security blocks immediately.')) return;
    const res = await bdApi('POST', '/api/sites/emergency-lockdown', { site_id: siteId });
    if (res.ok) { bdToast(res.message, 'success'); setTimeout(() => location.reload(), 800); }
}

async function emergencyLockdown() {
    if (!confirm('EMERGENCY LOCKDOWN ALL SITES?\n\nThis will put ALL sites into maintenance mode with full security blocks.\n\nAre you absolutely sure?')) return;
    const res = await bdApi('POST', '/api/sites/emergency-lockdown', { all: true });
    if (res.ok) { bdToast(res.message, 'success'); setTimeout(() => location.reload(), 1000); }
}

async function syncBlacklists() {
    const res = await bdApi('POST', '/api/sites/sync-blacklists', {});
    bdToast(res.ok ? 'Blacklists synced' : (res.error || 'Failed'), res.ok ? 'success' : 'error');
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

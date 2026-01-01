<?php
$page_title = 'Sites';
$active_nav = 'sites';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();

// ── Page data ────────────────────────────────────────────────────────────
$sites = db_rows("SELECT s.*,
    (SELECT COUNT(*) FROM backdraft_page_profiles WHERE site_id = s.id) as page_count,
    (SELECT COUNT(*) FROM backdraft_page_profiles WHERE site_id = s.id AND botproof_enabled = 1) as botproof_count,
    (SELECT COUNT(*) FROM backdraft_page_profiles WHERE site_id = s.id AND secure_lock_enabled = 1) as secure_count,
    (SELECT SUM(total_requests) FROM backdraft_page_profiles WHERE site_id = s.id) as profile_requests
    FROM backdraft_sites s ORDER BY s.site_name");

$waf_on = 0; $log_on = 0; $bp_total = 0; $sl_total = 0;
foreach ($sites as $s) {
    if ($s['waf_enabled']) $waf_on++;
    if ($s['log_analysis']) $log_on++;
    $bp_total += (int)$s['botproof_count'];
    $sl_total += (int)$s['secure_count'];
}
?>

<style>
.site-row{cursor:pointer;transition:background .15s}
.site-row:hover td{background:rgba(255,255,255,.03)}
.site-expand{display:none;background:var(--bg3)}
.site-expand.open{display:table-row}
.site-expand td{padding:16px 20px}
.page-grid{display:grid;gap:10px}
.page-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;display:flex;align-items:center;gap:12px}
.page-card .info{flex:1;min-width:0}
.page-card .info .name{font-weight:600;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bd-table{table-layout:auto;width:100%}
.bd-table td,.bd-table th{word-break:break-word}
.page-card .info .meta{font-size:11px;color:var(--muted);font-family:var(--font-mono)}
.page-card .badges{display:flex;gap:4px;flex-shrink:0}
.page-card .stats{display:flex;gap:12px;font-size:12px;flex-shrink:0}
.page-card .stats span{color:var(--muted)}
.page-card .stats strong{color:var(--text)}
.page-card .actions{display:flex;gap:4px;flex-shrink:0}
.shield-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700}
.shield-bp{background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44}
.shield-sl{background:#0891b222;color:#0891b2;border:1px solid #0891b244}
.expand-arrow{transition:transform .2s;display:inline-block;color:var(--muted)}
.expand-arrow.open{transform:rotate(90deg)}
</style>

<!-- Stat Cards -->
<div class="stat-grid">
    <div class="stat-card stat-amber"><div class="stat-val"><?= count($sites) ?></div><div class="stat-label">Total Sites</div></div>
    <div class="stat-card stat-green"><div class="stat-val"><?= $waf_on ?></div><div class="stat-label">WAF Enabled</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val"><?= $log_on ?></div><div class="stat-label">Log Analysis</div></div>
    <div class="stat-card stat-amber"><div class="stat-val"><?= $bp_total ?></div><div class="stat-label">BotProof Pages</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= $sl_total ?></div><div class="stat-label">Secure Lock Pages</div></div>
</div>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">nginx Sites</h2>
    <button class="btn btn-amber" onclick="bdApi('GET','/api/sites').then(()=>location.reload())">Refresh Sites</button>
</div>

<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th style="width:30px"></th>
                    <th>Site</th>
                    <th>Port</th>
                    <th>SSL</th>
                    <th>WAF</th>
                    <th>Logs</th>
                    <th>Mode</th>
                    <th>Pages</th>
                    <th>Protection</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($sites as $s): ?>
                <tr class="site-row" onclick="toggleExpand(<?= $s['id'] ?>)">
                    <td><span class="expand-arrow" id="arrow-<?= $s['id'] ?>">&#9654;</span></td>
                    <td style="font-weight:600"><?= h($s['site_name']) ?></td>
                    <td><?= $s['listen_port'] ?></td>
                    <td><?= $s['ssl_enabled'] ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-muted">No</span>' ?></td>
                    <td><?= $s['waf_enabled'] ? '<span class="badge badge-green">On</span>' : '<span class="badge badge-muted">Off</span>' ?></td>
                    <td><?= $s['log_analysis'] ? '<span class="badge badge-green">On</span>' : '<span class="badge badge-muted">Off</span>' ?></td>
                    <td><span class="badge badge-<?= $s['waf_mode'] === 'active' ? 'red' : ($s['waf_mode'] === 'learning' ? 'green' : 'muted') ?>"><?= h($s['waf_mode']) ?></span></td>
                    <td>
                        <?php if ($s['page_count'] > 0): ?>
                            <span style="font-weight:700"><?= $s['page_count'] ?></span>
                            <span style="font-size:11px;color:var(--muted)">profiled</span>
                        <?php else: ?>
                            <span style="color:var(--muted)">—</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($s['botproof_count'] > 0): ?>
                            <span class="shield-badge shield-bp">&#x1F6E1; <?= $s['botproof_count'] ?> BotProof</span>
                        <?php endif; ?>
                        <?php if ($s['secure_count'] > 0): ?>
                            <span class="shield-badge shield-sl">&#x1F512; <?= $s['secure_count'] ?> SecureLock</span>
                        <?php endif; ?>
                        <?php if (!$s['botproof_count'] && !$s['secure_count']): ?>
                            <span style="color:var(--muted);font-size:11px">None</span>
                        <?php endif; ?>
                    </td>
                    <td style="white-space:normal" onclick="event.stopPropagation()">
                        <?php if ($s['waf_enabled']): ?>
                        <a href="/site-report.php?id=<?= $s['id'] ?>" class="btn btn-amber" style="padding:4px 8px;font-size:11px">&#x1F4E1; Live</a>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px"
                            onclick="toggleSite(<?= $s['id'] ?>,'waf_enabled',0)">Disable WAF</button>
                        <?php else: ?>
                        <a href="/site-enroll.php?id=<?= $s['id'] ?>" class="btn btn-amber" style="padding:4px 8px;font-size:11px">Enable WAF</a>
                        <?php endif; ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px"
                            onclick="toggleSite(<?= $s['id'] ?>,'log_analysis',<?= $s['log_analysis'] ? 0 : 1 ?>)">
                            <?= $s['log_analysis'] ? 'Disable Logs' : 'Enable Logs' ?>
                        </button>
                        <a href="/site-report.php?id=<?= $s['id'] ?>" class="btn btn-ghost" style="padding:4px 8px;font-size:11px">Report</a>
                    </td>
                </tr>
                <!-- Expandable page profiles row -->
                <tr class="site-expand" id="expand-<?= $s['id'] ?>">
                    <td colspan="10">
                        <div id="pages-<?= $s['id'] ?>" class="page-grid">
                            <div style="color:var(--muted);font-size:13px;text-align:center;padding:12px">Loading page profiles...</div>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($sites)): ?>
                <tr><td colspan="10" style="color:var(--muted);text-align:center;padding:30px">No sites discovered — check nginx configuration</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
let expandedSites = {};

async function toggleExpand(siteId) {
    const row = document.getElementById('expand-' + siteId);
    const arrow = document.getElementById('arrow-' + siteId);

    if (row.classList.contains('open')) {
        row.classList.remove('open');
        arrow.classList.remove('open');
        return;
    }

    row.classList.add('open');
    arrow.classList.add('open');

    // Load pages if not cached
    if (!expandedSites[siteId]) {
        const resp = await fetch('/app/api/pages.php?action=list&site_id=' + siteId);
        const json = await resp.json();
        expandedSites[siteId] = json.data || [];
    }

    renderPages(siteId, expandedSites[siteId]);
}

function renderPages(siteId, pages) {
    const container = document.getElementById('pages-' + siteId);

    if (pages.length === 0) {
        container.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:20px">' +
            'No page profiles for this site — profiles are built when the WAF processes requests. ' +
            '<a href="/pages.php?site=' + siteId + '" style="color:var(--amber)">Go to Page Profiles</a></div>';
        return;
    }

    let html = '';
    pages.forEach(p => {
        const scoreColor = p.avg_score >= 50 ? 'var(--red)' : p.avg_score >= 20 ? 'var(--amber)' : 'var(--green)';
        const bpBadge = p.botproof_enabled ?
            '<span class="shield-badge shield-bp">&#x1F6E1; BotProof</span>' :
            '';
        const slBadge = p.secure_lock_enabled ?
            '<span class="shield-badge shield-sl">&#x1F512; Locked</span>' :
            '';

        html += '<div class="page-card">' +
            '<div class="info">' +
                '<div class="name">' + esc(p.display_name || p.page_id) + '</div>' +
                '<div class="meta">' + esc(p.page_id) + '</div>' +
            '</div>' +
            '<div class="stats">' +
                '<span>Reqs: <strong>' + (p.total_requests || 0) + '</strong></span>' +
                '<span>Threats: <strong style="color:' + (p.total_threats > 0 ? 'var(--red)' : 'var(--muted)') + '">' + (p.total_threats || 0) + '</strong></span>' +
                '<span>Score: <strong style="color:' + scoreColor + '">' + Number(p.avg_score || 0).toFixed(1) + '</strong></span>' +
            '</div>' +
            '<div class="badges">' + bpBadge + slBadge + '</div>';

<?php if ($is_admin): ?>
        html += '<div class="actions">' +
            '<button class="btn btn-ghost" style="padding:3px 7px;font-size:10px;color:var(--amber)" onclick="togglePageBotproof(' + p.id + ',' + siteId + ')">' +
                (p.botproof_enabled ? 'BP Off' : 'BP On') + '</button>' +
            '<button class="btn btn-ghost" style="padding:3px 7px;font-size:10px;color:var(--cyan)" onclick="togglePageSecureLock(' + p.id + ',' + siteId + ')">' +
                (p.secure_lock_enabled ? 'Lock Off' : 'Lock On') + '</button>' +
            '<a href="/pages.php?site=' + siteId + '" class="btn btn-ghost" style="padding:3px 7px;font-size:10px">Settings</a>' +
            '</div>';
<?php endif; ?>

        html += '</div>';
    });

    container.innerHTML = html;
}

async function togglePageBotproof(profileId, siteId) {
    const form = new FormData();
    form.append('action', 'toggle_botproof');
    form.append('id', profileId);
    await fetch('/app/api/pages.php', { method: 'POST', body: form });
    delete expandedSites[siteId];
    bdToast('BotProof toggled', 'success');
    setTimeout(() => location.reload(), 500);
}

async function togglePageSecureLock(profileId, siteId) {
    const form = new FormData();
    form.append('action', 'toggle_secure_lock');
    form.append('id', profileId);
    await fetch('/app/api/pages.php', { method: 'POST', body: form });
    delete expandedSites[siteId];
    bdToast('Secure Lock toggled', 'success');
    setTimeout(() => location.reload(), 500);
}

async function toggleSite(id, field, value) {
    const data = { id };
    data[field] = value;
    const res = await bdApi('POST', '/api/sites', data);
    if (res.ok) {
        bdToast('Site updated', 'success');
        setTimeout(() => location.reload(), 500);
    }
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

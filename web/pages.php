<?php
$page_title = 'Page Profiles';
$active_nav = 'pages';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();

// ── Main page data ───────────────────────────────────────────────────────
$site_filter = $_GET['site'] ?? '';
$where = "1=1";
$params = [];
if ($site_filter) {
    $where = "p.site_id = ?";
    $params[] = (int)$site_filter;
}

$profiles = db_rows(
    "SELECT p.*, s.site_name,
            (SELECT COUNT(DISTINCT client_ip) FROM backdraft_requests WHERE page_id = p.page_id) as unique_ips
     FROM backdraft_page_profiles p
     LEFT JOIN backdraft_sites s ON s.id = p.site_id
     WHERE $where
     ORDER BY p.total_requests DESC", $params
);

$sites = db_rows("SELECT id, site_name FROM backdraft_sites WHERE waf_enabled = 1 ORDER BY site_name");
$total_profiles = count($profiles);
$monitored = count(array_filter($profiles, fn($p) => $p['monitoring']));
$total_reqs = array_sum(array_column($profiles, 'total_requests'));
$total_threats = array_sum(array_column($profiles, 'total_threats'));
?>

<style>
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-height:85vh;overflow-y:auto;box-shadow:0 16px 48px rgba(0,0,0,.5)}
.modal h3{font-size:16px;font-weight:700;margin-bottom:16px;color:var(--amber)}
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:12px;font-weight:600;color:var(--text-dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.form-group input,.form-group select{width:100%;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}
.detail-stat{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px;text-align:center}
.detail-stat .v{font-size:22px;font-weight:800;line-height:1.1}
.detail-stat .l{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.method-pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;font-family:var(--font-mono);background:var(--bg3);color:var(--cyan);border:1px solid var(--border);margin:2px}
.baseline-bar{height:6px;border-radius:3px;background:var(--bg3);overflow:hidden;margin-top:4px}
.baseline-fill{height:100%;border-radius:3px;background:var(--green);transition:width .3s}
</style>

<!-- Stat Cards -->
<div class="stat-grid">
    <div class="stat-card stat-amber"><div class="stat-val"><?= $total_profiles ?></div><div class="stat-label">Page Profiles</div></div>
    <div class="stat-card stat-green"><div class="stat-val"><?= $monitored ?></div><div class="stat-label">Monitored</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val"><?= number_format($total_reqs) ?></div><div class="stat-label">Total Requests</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= number_format($total_threats) ?></div><div class="stat-label">Total Threats</div></div>
</div>

<!-- Learning mode info -->
<div class="card" style="margin-bottom:20px;padding:12px 20px;background:var(--bg3);border-color:var(--border2)">
    <span style="font-size:12px;color:var(--muted)">Page profiles are built automatically as the WAF processes requests in learning mode. Each page tracks its behavioral baseline — normal HTTP methods, content types, response sizes, and threat scores. When WAF switches to active mode, deviations from these baselines can trigger alerts.</span>
</div>

<!-- Header + Controls -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">
    <h2 style="font-size:18px;font-weight:700">Page Profiles</h2>
    <div style="display:flex;gap:8px;align-items:center">
        <!-- Site Filter -->
        <select onchange="location.href='?site='+this.value" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:12px">
            <option value="">All Sites</option>
            <?php foreach ($sites as $s): ?>
                <option value="<?= $s['id'] ?>" <?= $site_filter == $s['id'] ? 'selected' : '' ?>><?= h($s['site_name']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php if ($is_admin): ?>
        <button class="btn btn-amber" onclick="openCreateModal()">+ Add Profile</button>
        <?php endif; ?>
    </div>
</div>

<!-- Page Profile Cards -->
<div id="profileCards">
<div style="display:grid;gap:12px">
            <?php foreach ($profiles as $p):
                $score_color = $p['avg_score'] >= 50 ? 'red' : ($p['avg_score'] >= 20 ? 'amber' : 'green');
            ?>
    <div class="card" style="padding:14px 18px">
        <!-- Row 1: Name + badges + stats -->
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
            <div style="flex:1;min-width:180px">
                <div style="font-weight:700;font-size:14px"><?= h($p['display_name'] ?: $p['page_id']) ?></div>
                <div style="font-family:var(--font-mono);font-size:10px;color:var(--muted)"><?= h($p['page_id']) ?> &mdash; <?= h($p['site_name'] ?? '') ?></div>
            </div>
            <div style="display:flex;gap:3px;flex-shrink:0">
                <span class="badge badge-<?= $p['monitoring'] ? 'green' : 'muted' ?>"><?= $p['monitoring'] ? 'Active' : 'Paused' ?></span>
                <?php if (!empty($p['botproof_enabled'])): ?><span class="badge badge-amber">&#x1F6E1; BP</span><?php endif; ?>
                <?php if (!empty($p['secure_lock_enabled'])): ?><span class="badge badge-red">&#x1F512; SL</span><?php endif; ?>
            </div>
            <div style="display:flex;gap:12px;font-size:11px;flex-shrink:0">
                <span style="color:var(--muted)">Reqs <strong style="color:var(--text)"><?= number_format($p['total_requests']) ?></strong></span>
                <span style="color:var(--muted)">Threats <strong style="color:<?= $p['total_threats'] > 0 ? 'var(--red)' : 'var(--muted)' ?>"><?= $p['total_threats'] ?></strong></span>
                <span style="color:var(--muted)">Score <strong style="color:var(--<?= $score_color ?>)"><?= number_format($p['avg_score'], 1) ?></strong></span>
                <span style="color:var(--muted)">IPs <strong><?= $p['unique_ips'] ?? 0 ?></strong></span>
            </div>
        </div>
        <!-- Row 2: Methods + actions -->
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <div style="display:flex;gap:3px;align-items:center;flex:1;min-width:0">
                <?php foreach (array_filter(explode(',', $p['learned_methods'])) as $m): ?>
                    <span class="method-pill"><?= h(trim($m)) ?></span>
                <?php endforeach; ?>
                <span style="font-family:var(--font-mono);font-size:10px;color:var(--muted);margin-left:6px"><?= h($p['last_request_at'] ?? 'Never') ?></span>
            </div>
            <div style="display:flex;gap:3px;flex-wrap:wrap;flex-shrink:0">
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="viewDetail(<?= $p['id'] ?>)">Detail</button>
                <?php if ($is_admin): ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="editProfile(<?= $p['id'] ?>, <?= h(json_encode($p)) ?>)">Edit</button>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="toggleMonitoring(<?= $p['id'] ?>)"><?= $p['monitoring'] ? 'Pause' : 'Resume' ?></button>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--amber)" onclick="toggleBotproof(<?= $p['id'] ?>)"><?= !empty($p['botproof_enabled']) ? 'BP Off' : 'BP On' ?></button>
                <?php if (!empty($p['botproof_enabled'])): ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="openBotproofSettings(<?= $p['id'] ?>, <?= (int)$p['botproof_threshold'] ?>, <?= (int)$p['botproof_session_mins'] ?>, <?= (int)$p['botproof_max_attempts'] ?>)">BP Cfg</button>
                <?php endif; ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--cyan)" onclick="toggleSecureLock(<?= $p['id'] ?>)"><?= !empty($p['secure_lock_enabled']) ? 'SL Off' : 'SL On' ?></button>
                <?php if (!empty($p['secure_lock_enabled'])): ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px" onclick="openSecureLockSettings(<?= $p['id'] ?>, <?= (int)($p['secure_lock_session_mins'] ?? 60) ?>, '<?= h($p['secure_lock_allowed_emails'] ?? '') ?>')">SL Cfg</button>
                <?php endif; ?>
                <button class="btn btn-ghost" style="padding:3px 8px;font-size:10px;color:var(--red)" onclick="deleteProfile(<?= $p['id'] ?>, '<?= h($p['page_id']) ?>')">Delete</button>
                <?php endif; ?>
            </div>
        </div>
    </div>
            <?php endforeach; ?>
            <?php if (empty($profiles)): ?>
    <div class="card" style="text-align:center;color:var(--muted);padding:40px">No page profiles yet — profiles are built as the WAF processes requests in learning mode</div>
            <?php endif; ?>
</div>
</div>

<!-- Create/Edit Modal -->
<div class="modal-overlay" id="profileModal">
    <div class="modal" style="width:500px">
        <h3 id="profileModalTitle">Add Page Profile</h3>
        <form id="profileForm" onsubmit="submitProfile(event)">
            <input type="hidden" name="action" value="save_profile">
            <input type="hidden" name="id" id="pfId" value="">
            <div class="form-group" id="pfSiteGroup">
                <label>Site</label>
                <select name="site_id" id="pfSiteId" onchange="onSiteSelected(this.value)">
                    <option value="0">— Select a site —</option>
                    <?php foreach ($sites as $s): ?>
                        <option value="<?= $s['id'] ?>" data-name="<?= h($s['site_name']) ?>"><?= h($s['site_name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="form-group" id="pfPageIdGroup">
                <label>Page</label>
                <select name="page_id_select" id="pfPageSelect" onchange="onPageFileSelected(this.value)" style="margin-bottom:8px">
                    <option value="">— Select a site first —</option>
                </select>
                <input type="text" name="page_id" id="pfPageId" placeholder="Or type manually: site.com/page.php" required style="font-size:12px">
                <div style="font-size:11px;color:var(--muted);margin-top:4px">Select from discovered files above, or type a custom page ID. Format: <code>hostname/path.php</code></div>
            </div>
            <div class="form-group">
                <label>Display Name</label>
                <input type="text" name="display_name" id="pfDisplayName" placeholder="Friendly name for this page">
            </div>
            <div class="form-group">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                    <input type="checkbox" name="monitoring" id="pfMonitoring" checked style="width:auto">
                    <span>Monitoring Enabled</span>
                </label>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-ghost" onclick="closeModal('profileModal')">Cancel</button>
                <button type="submit" class="btn btn-amber" id="pfSubmit">Save</button>
            </div>
        </form>
    </div>
</div>

<!-- BotProof Settings Modal -->
<div class="modal-overlay" id="botproofModal">
    <div class="modal" style="width:450px">
        <h3 style="color:var(--amber)">&#x1F6E1; BotProof Settings</h3>
        <form id="bpForm" onsubmit="submitBotproof(event)">
            <input type="hidden" id="bp_id">
            <div class="form-group">
                <label>Challenge Threshold (WAF score)</label>
                <input type="range" id="bp_threshold" min="0" max="100" value="0" style="width:100%" oninput="document.getElementById('bp_thresh_val').textContent=this.value">
                <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted)">
                    <span>0 (challenge all flagged)</span>
                    <span id="bp_thresh_val" style="color:var(--amber);font-weight:700">0</span>
                    <span>100 (critical only)</span>
                </div>
            </div>
            <div class="form-group" style="margin-top:16px">
                <label>Session Duration</label>
                <select id="bp_session" class="form-group input" style="width:100%;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px">
                    <option value="15">15 minutes</option>
                    <option value="30">30 minutes</option>
                    <option value="60" selected>1 hour</option>
                    <option value="120">2 hours</option>
                    <option value="240">4 hours</option>
                    <option value="480">8 hours</option>
                    <option value="1440">24 hours</option>
                </select>
            </div>
            <div class="form-group" style="margin-top:16px">
                <label>Max Attempts Before Block</label>
                <select id="bp_attempts" style="width:100%;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px">
                    <option value="1">1 attempt</option>
                    <option value="2">2 attempts</option>
                    <option value="3" selected>3 attempts</option>
                    <option value="5">5 attempts</option>
                </select>
            </div>
            <div class="form-actions" style="margin-top:20px">
                <button type="button" class="btn btn-ghost" onclick="closeModal('botproofModal')">Cancel</button>
                <button type="submit" class="btn btn-amber">Save Settings</button>
            </div>
        </form>
    </div>
</div>

<!-- Secure Lock Settings Modal -->
<div class="modal-overlay" id="secureLockModal">
    <div class="modal" style="width:450px">
        <h3 style="color:var(--cyan)">&#x1F512; Secure Lock Settings</h3>
        <form id="slForm" onsubmit="submitSecureLock(event)">
            <input type="hidden" id="sl_id">
            <div class="form-group">
                <label>Session Duration (after OTP verified)</label>
                <select id="sl_session" style="width:100%;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px">
                    <option value="15">15 minutes</option>
                    <option value="30">30 minutes</option>
                    <option value="60" selected>1 hour</option>
                    <option value="120">2 hours</option>
                    <option value="240">4 hours</option>
                    <option value="480">8 hours</option>
                    <option value="1440">24 hours</option>
                </select>
            </div>
            <div class="form-group" style="margin-top:16px">
                <label>Allowed Email Addresses</label>
                <textarea id="sl_emails" style="width:100%;min-height:80px;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;font-family:var(--font-mono);resize:vertical" placeholder="Leave empty to allow any email&#10;Or enter patterns, one per line:&#10;admin@company.com&#10;*@company.com"></textarea>
                <div style="font-size:11px;color:var(--muted);margin-top:4px">Comma-separated. Use <code>*@domain.com</code> for domain wildcards. Empty = any email allowed.</div>
            </div>
            <div class="form-actions" style="margin-top:16px">
                <button type="button" class="btn btn-ghost" onclick="closeModal('secureLockModal')">Cancel</button>
                <button type="submit" class="btn btn-amber">Save Settings</button>
            </div>
        </form>
    </div>
</div>

<!-- Detail Modal -->
<div class="modal-overlay" id="detailModal">
    <div class="modal" style="width:850px">
        <h3 id="detailTitle">Page Detail</h3>
        <div id="detailContent"><p style="color:var(--muted)">Loading...</p></div>
        <div class="form-actions">
            <?php if ($is_admin): ?>
            <button class="btn btn-ghost" style="color:var(--amber)" id="detailResetBtn" onclick="resetProfile(0)">Reset Baseline</button>
            <?php endif; ?>
            <button class="btn btn-ghost" onclick="closeModal('detailModal')">Close</button>
        </div>
    </div>
</div>

<script>
async function onSiteSelected(siteId) {
    const sel = document.getElementById('pfPageSelect');
    const pageInput = document.getElementById('pfPageId');

    sel.innerHTML = '<option value="">Loading files...</option>';
    pageInput.value = '';

    if (!siteId || siteId === '0') {
        sel.innerHTML = '<option value="">— Select a site first —</option>';
        return;
    }

    const siteOpt = document.querySelector('#pfSiteId option[value="' + siteId + '"]');
    const siteName = siteOpt ? siteOpt.dataset.name : '';

    try {
        const resp = await fetch('/app/api/pages.php?action=site_files&site_id=' + siteId);
        const json = await resp.json();
        if (json.ok && json.files.length > 0) {
            let html = '<option value="">— Select a page —</option>';
            json.files.forEach(f => {
                const pageId = siteName + '/' + f;
                html += '<option value="' + esc(pageId) + '" data-file="' + esc(f) + '">' + esc(f) + '</option>';
            });
            sel.innerHTML = html;
        } else {
            sel.innerHTML = '<option value="">No PHP files found in webroot</option>';
        }
    } catch (e) {
        sel.innerHTML = '<option value="">Error loading files</option>';
    }
}

function onPageFileSelected(pageId) {
    const pageInput = document.getElementById('pfPageId');
    const displayInput = document.getElementById('pfDisplayName');
    if (pageId) {
        pageInput.value = pageId;
        const sel = document.getElementById('pfPageSelect');
        const opt = sel.options[sel.selectedIndex];
        const fileName = opt ? (opt.dataset.file || '') : '';
        if (fileName && !displayInput.value) {
            displayInput.value = fileName.replace('.php', '').replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        }
    }
}

function openCreateModal() {
    document.getElementById('profileModalTitle').textContent = 'Add Page Profile';
    document.getElementById('pfId').value = '';
    document.getElementById('pfPageIdGroup').style.display = '';
    document.getElementById('pfSiteGroup').style.display = '';
    document.getElementById('pfPageId').value = '';
    document.getElementById('pfPageSelect').innerHTML = '<option value="">— Select a site first —</option>';
    document.getElementById('pfSiteId').value = '0';
    document.getElementById('pfDisplayName').value = '';
    document.getElementById('pfMonitoring').checked = true;
    document.getElementById('pfSubmit').textContent = 'Create';
    document.getElementById('profileModal').classList.add('open');
}

function editProfile(id, data) {
    document.getElementById('profileModalTitle').textContent = 'Edit: ' + (data.display_name || data.page_id);
    document.getElementById('pfId').value = id;
    document.getElementById('pfPageIdGroup').style.display = 'none';
    document.getElementById('pfSiteGroup').style.display = 'none';
    document.getElementById('pfDisplayName').value = data.display_name || '';
    document.getElementById('pfMonitoring').checked = !!data.monitoring;
    document.getElementById('pfSubmit').textContent = 'Save';
    document.getElementById('profileModal').classList.add('open');
}

function closeModal(id) { document.getElementById(id).classList.remove('open'); }

async function submitProfile(e) {
    e.preventDefault();
    const form = new FormData(document.getElementById('profileForm'));
    if (!document.getElementById('pfMonitoring').checked) form.delete('monitoring');
    const resp = await fetch('/app/api/pages.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast(json.message || 'Saved', 'success'); setTimeout(() => location.reload(), 800); }
    else bdToast(json.error || 'Failed', 'error');
}

async function toggleMonitoring(id) {
    const form = new FormData();
    form.append('action', 'toggle_monitoring');
    form.append('id', id);
    await fetch('/app/api/pages.php', { method: 'POST', body: form });
    location.reload();
}

async function deleteProfile(id, name) {
    if (!confirm('Delete profile "' + name + '"? This only removes the baseline — request data is kept.')) return;
    const form = new FormData();
    form.append('action', 'delete_profile');
    form.append('id', id);
    const resp = await fetch('/app/api/pages.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast('Profile deleted', 'success'); setTimeout(() => location.reload(), 800); }
}

async function resetProfile(id) {
    if (!confirm('Reset this page baseline? All learned patterns will be cleared and rebuilt from new traffic.')) return;
    const form = new FormData();
    form.append('action', 'reset_profile');
    form.append('id', id);
    const resp = await fetch('/app/api/pages.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast('Baseline reset', 'success'); setTimeout(() => location.reload(), 800); }
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

async function toggleSecureLock(id) {
    const form = new FormData();
    form.append('action', 'toggle_secure_lock');
    form.append('id', id);
    await fetch('/app/api/pages.php', { method: 'POST', body: form });
    location.reload();
}

function openSecureLockSettings(id, sessionMins, allowedEmails) {
    document.getElementById('sl_id').value = id;
    document.getElementById('sl_session').value = sessionMins;
    document.getElementById('sl_emails').value = (allowedEmails || '').replace(/,/g, '\n');
    document.getElementById('secureLockModal').classList.add('open');
}

async function submitSecureLock(e) {
    e.preventDefault();
    const form = new FormData();
    form.append('action', 'save_secure_lock');
    form.append('id', document.getElementById('sl_id').value);
    form.append('session_mins', document.getElementById('sl_session').value);
    // Convert newlines to commas
    const emails = document.getElementById('sl_emails').value.split('\n').map(s => s.trim()).filter(Boolean).join(',');
    form.append('allowed_emails', emails);
    const resp = await fetch('/app/api/pages.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast(json.message, 'success'); closeModal('secureLockModal'); setTimeout(() => location.reload(), 800); }
    else bdToast(json.error, 'error');
}

async function toggleBotproof(id) {
    const form = new FormData();
    form.append('action', 'toggle_botproof');
    form.append('id', id);
    await fetch('/app/api/pages.php', { method: 'POST', body: form });
    location.reload();
}

function openBotproofSettings(id, threshold, sessionMins, maxAttempts) {
    document.getElementById('bp_id').value = id;
    document.getElementById('bp_threshold').value = threshold;
    document.getElementById('bp_thresh_val').textContent = threshold;
    document.getElementById('bp_session').value = sessionMins;
    document.getElementById('bp_attempts').value = maxAttempts;
    document.getElementById('botproofModal').classList.add('open');
}

async function submitBotproof(e) {
    e.preventDefault();
    const form = new FormData();
    form.append('action', 'save_botproof');
    form.append('id', document.getElementById('bp_id').value);
    form.append('threshold', document.getElementById('bp_threshold').value);
    form.append('session_mins', document.getElementById('bp_session').value);
    form.append('max_attempts', document.getElementById('bp_attempts').value);
    const resp = await fetch('/app/api/pages.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast(json.message, 'success'); closeModal('botproofModal'); setTimeout(() => location.reload(), 800); }
    else bdToast(json.error, 'error');
}

async function viewDetail(id) {
    document.getElementById('detailModal').classList.add('open');
    document.getElementById('detailContent').innerHTML = '<p style="color:var(--muted)">Loading...</p>';

    const resp = await fetch('/app/api/pages.php?action=detail&id=' + id);
    const json = await resp.json();
    if (!json.ok) { document.getElementById('detailContent').innerHTML = '<p style="color:var(--red)">Load failed</p>'; return; }

    const p = json.profile;
    const score_color = p.avg_score >= 50 ? 'var(--red)' : p.avg_score >= 20 ? 'var(--amber)' : 'var(--green)';
    document.getElementById('detailTitle').textContent = p.display_name || p.page_id;
    document.getElementById('detailResetBtn').onclick = () => resetProfile(p.id);

    let html = '';

    // Stats grid
    html += '<div class="detail-grid">';
    html += '<div class="detail-stat"><div class="v" style="color:var(--amber)">' + p.total_requests + '</div><div class="l">Requests</div></div>';
    html += '<div class="detail-stat"><div class="v" style="color:var(--red)">' + p.total_threats + '</div><div class="l">Threats</div></div>';
    html += '<div class="detail-stat"><div class="v" style="color:' + score_color + '">' + Number(p.avg_score).toFixed(1) + '</div><div class="l">Avg Score</div></div>';
    html += '<div class="detail-stat"><div class="v" style="color:var(--cyan)">' + json.unique_ips + '</div><div class="l">Unique IPs</div></div>';
    html += '<div class="detail-stat"><div class="v" style="color:var(--cyan)">' + json.avg_response_ms + 'ms</div><div class="l">Avg Response</div></div>';
    html += '<div class="detail-stat"><div class="v" style="color:var(--green)">' + (p.learned_avg_size||0) + 'B</div><div class="l">Avg Size</div></div>';
    html += '</div>';

    // Baseline info
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">';

    // Methods
    html += '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:600">Learned Methods</div>';
    if (json.methods.length) {
        json.methods.forEach(m => {
            html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px"><span class="method-pill">' + esc(m.method) + '</span><span style="font-weight:700;font-size:13px">' + m.cnt + '</span></div>';
        });
    } else html += '<span style="color:var(--muted);font-size:12px">No data</span>';
    html += '</div>';

    // Status codes
    html += '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:600">Status Codes</div>';
    if (json.statuses.length) {
        json.statuses.forEach(s => {
            const c = s.upstream_status < 300 ? 'var(--green)' : s.upstream_status < 400 ? 'var(--cyan)' : s.upstream_status < 500 ? 'var(--amber)' : 'var(--red)';
            html += '<div style="display:flex;justify-content:space-between;margin-bottom:4px"><span style="font-family:var(--font-mono);font-size:12px;color:' + c + ';font-weight:700">' + s.upstream_status + '</span><span style="font-size:13px;font-weight:600">' + s.cnt + '</span></div>';
        });
    } else html += '<span style="color:var(--muted);font-size:12px">No upstream status data</span>';
    html += '</div></div>';

    // Scoped rules
    if (json.scoped_rules.length) {
        html += '<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:600">Rules Scoped to This Page</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
        json.scoped_rules.forEach(r => {
            html += '<span style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-size:11px"><strong>' + esc(r.name) + '</strong> <span style="color:var(--muted)">' + r.target + '/' + r.action + ' +' + r.score + '</span></span>';
        });
        html += '</div></div>';
    }

    // Recent requests
    html += '<div style="margin-bottom:16px"><div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:600">Recent Requests (last 25)</div>';
    if (json.requests.length) {
        html += '<div style="max-height:200px;overflow-y:auto"><table class="bd-table" style="font-size:12px"><thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Score</th><th>Action</th><th>Size</th><th>ms</th></tr></thead><tbody>';
        json.requests.forEach(r => {
            const sc = r.threat_score >= 75 ? 'var(--red)' : r.threat_score >= 20 ? 'var(--amber)' : 'var(--text)';
            html += '<tr><td style="font-family:var(--font-mono);font-size:10px;white-space:nowrap">' + esc(r.request_time) + '</td>';
            html += '<td style="font-family:var(--font-mono);font-size:11px">' + esc(r.client_ip) + '</td>';
            html += '<td><span class="method-pill">' + esc(r.method) + '</span></td>';
            html += '<td style="color:' + sc + ';font-weight:600">' + r.threat_score + '</td>';
            html += '<td>' + esc(r.action_taken) + '</td>';
            html += '<td>' + (r.response_bytes||0) + '</td>';
            html += '<td>' + (r.upstream_ms||0) + '</td></tr>';
        });
        html += '</tbody></table></div>';
    } else html += '<p style="color:var(--muted);font-size:12px">No requests recorded</p>';
    html += '</div>';

    // Threats
    if (json.threats.length) {
        html += '<div><div style="font-size:11px;color:var(--muted);text-transform:uppercase;margin-bottom:8px;font-weight:600">Threats (last 10)</div>';
        html += '<table class="bd-table" style="font-size:12px"><thead><tr><th>Time</th><th>IP</th><th>Score</th><th>Category</th><th>Severity</th><th>Rules</th></tr></thead><tbody>';
        json.threats.forEach(t => {
            const sevC = t.severity === 'critical' ? 'red' : t.severity === 'high' ? 'amber' : 'muted';
            html += '<tr><td style="font-family:var(--font-mono);font-size:10px;white-space:nowrap">' + esc(t.detected_at) + '</td>';
            html += '<td style="font-family:var(--font-mono);font-size:11px">' + esc(t.client_ip) + '</td>';
            html += '<td style="font-weight:700;color:var(--red)">' + t.threat_score + '</td>';
            html += '<td>' + esc(t.category) + '</td>';
            html += '<td><span class="badge badge-' + sevC + '">' + esc(t.severity) + '</span></td>';
            html += '<td style="font-size:11px;color:var(--muted)">' + esc(t.matched_rules) + '</td></tr>';
        });
        html += '</tbody></table></div>';
    }

    document.getElementById('detailContent').innerHTML = html;
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

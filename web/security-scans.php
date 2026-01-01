<?php
$page_title = 'Security Scans';
$active_nav = 'security-scans';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();
?>

<style>
.scan-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-bottom:20px}
.scan-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px;position:relative;overflow:hidden}
.scan-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px}
.scan-ok::after{background:var(--green)}
.scan-warn::after{background:var(--amber)}
.scan-crit::after{background:var(--red)}
.scan-card h3{font-size:14px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.scan-card .icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.scan-stat{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid rgba(255,255,255,.03)}
.scan-stat .label{color:var(--muted)}
.scan-stat .value{font-weight:700}
.scan-actions{display:flex;gap:4px;margin-top:12px}

.results-panel{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:16px}
.results-panel h3{font-size:13px;font-weight:700;color:var(--amber);margin-bottom:12px}
.result-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px}
.result-row:hover{background:rgba(255,255,255,.02)}
.result-status{min-width:50px;flex-shrink:0}
</style>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">Security Scans & File Integrity</h2>
    <div style="display:flex;gap:8px">
        <?php if ($is_admin): ?>
        <button class="btn btn-ghost" onclick="runScan('malware_scan')">Run ClamAV Scan</button>
        <button class="btn btn-ghost" onclick="runScan('rootkit_scan')">Run Rootkit Scan</button>
        <button class="btn btn-ghost" onclick="runScan('bot_fingerprint_scan')">Scan Bots</button>
        <?php endif; ?>
    </div>
</div>

<!-- Scan Overview Cards -->
<div class="scan-grid" id="scanCards">
    <div style="color:var(--muted);text-align:center;padding:30px">Loading scan status...</div>
</div>

<!-- Results Panels -->
<div id="resultsArea">
    <!-- Filled by AJAX -->
</div>

<script>
async function loadOverview() {
    const resp = await fetch('/app/api/security-scans.php?action=overview');
    const d = await resp.json();
    if (!d.ok) return;

    const m = d.data.malware;
    const r = d.data.rootkit;
    const i = d.data.integrity;
    const b = d.data.bots;

    document.getElementById('scanCards').innerHTML = `
    <div class="scan-card ${m.threats_7d > 0 ? 'scan-crit' : 'scan-ok'}">
        <h3><span class="icon" style="background:${m.threats_7d > 0 ? 'var(--red)22' : 'var(--green)22'}">&#x1F6E1;</span> ClamAV Malware</h3>
        <div class="scan-stat"><span class="label">Last Scan</span><span class="value">${m.last_scan}</span></div>
        <div class="scan-stat"><span class="label">Threats (7d)</span><span class="value" style="color:${m.threats_7d > 0 ? 'var(--red)' : 'var(--green)'}">${m.threats_7d}</span></div>
        <div class="scan-stat"><span class="label">Quarantined</span><span class="value">${m.quarantined}</span></div>
        <div class="scan-stat"><span class="label">Signature Age</span><span class="value" style="color:${m.sig_age_hours > 48 ? 'var(--red)' : 'var(--green)'}">${m.sig_age_hours}h</span></div>
        <div class="scan-actions"><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="loadResults('malware')">View Results</button></div>
    </div>

    <div class="scan-card ${r.critical > 0 ? 'scan-crit' : r.warnings > 0 ? 'scan-warn' : 'scan-ok'}">
        <h3><span class="icon" style="background:${r.critical > 0 ? 'var(--red)22' : r.warnings > 0 ? 'var(--amber)22' : 'var(--green)22'}">&#x1F50D;</span> Rootkit Hunter</h3>
        <div class="scan-stat"><span class="label">Last Scan</span><span class="value">${r.last_scan}</span></div>
        <div class="scan-stat"><span class="label">Warnings</span><span class="value" style="color:${r.warnings > 0 ? 'var(--amber)' : 'var(--green)'}">${r.warnings}</span></div>
        <div class="scan-stat"><span class="label">Critical</span><span class="value" style="color:${r.critical > 0 ? 'var(--red)' : 'var(--green)'}">${r.critical}</span></div>
        <div class="scan-actions"><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="loadResults('rootkit')">View Results</button></div>
    </div>

    <div class="scan-card ${i.modified > 0 ? 'scan-crit' : 'scan-ok'}">
        <h3><span class="icon" style="background:${i.modified > 0 ? 'var(--red)22' : 'var(--green)22'}">&#x1F512;</span> File Integrity</h3>
        <div class="scan-stat"><span class="label">Baselined</span><span class="value">${i.total}</span></div>
        <div class="scan-stat"><span class="label">OK</span><span class="value" style="color:var(--green)">${i.ok}</span></div>
        <div class="scan-stat"><span class="label">Modified</span><span class="value" style="color:${i.modified > 0 ? 'var(--red)' : 'var(--green)'}">${i.modified}</span></div>
        <div class="scan-actions"><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="loadResults('integrity')">View Details</button></div>
    </div>

    <div class="scan-card scan-ok">
        <h3><span class="icon" style="background:var(--cyan)22">&#x1F916;</span> Bot Definitions</h3>
        <div class="scan-stat"><span class="label">Active Definitions</span><span class="value" style="color:var(--cyan)">${b.total}</span></div>
        <div class="scan-stat"><span class="label">Last Update</span><span class="value">${b.last_update}</span></div>
        <div class="scan-actions"><button class="btn btn-ghost" style="font-size:10px;padding:3px 8px" onclick="loadResults('bots')">View Definitions</button></div>
    </div>`;
}

async function loadResults(type) {
    const area = document.getElementById('resultsArea');
    area.innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px">Loading...</div>';

    let endpoint = '';
    if (type === 'malware') endpoint = '/app/api/security-scans.php?action=malware_results';
    else if (type === 'rootkit') endpoint = '/app/api/security-scans.php?action=rootkit_results';
    else if (type === 'integrity') endpoint = '/app/api/security-scans.php?action=integrity';
    else if (type === 'bots') endpoint = '/app/api/security-scans.php?action=bot_definitions&limit=100';

    const resp = await fetch(endpoint);
    const d = await resp.json();
    if (!d.ok) { area.innerHTML = '<p style="color:var(--red)">Failed to load</p>'; return; }

    let html = '<div class="results-panel">';

    if (type === 'malware') {
        html += '<h3>ClamAV Scan Results</h3>';
        if (d.data.length === 0) html += '<div style="color:var(--green);text-align:center;padding:20px">No malware detected</div>';
        else d.data.forEach(r => {
            html += '<div class="result-row"><span class="result-status"><span class="badge badge-' + (r.action_taken === 'quarantined' ? 'amber' : 'red') + '">' + r.action_taken + '</span></span>' +
                '<span style="font-family:var(--font-mono);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.file_path) + '</span>' +
                '<span style="color:var(--red);font-weight:700">' + esc(r.threat_name) + '</span>' +
                '<span style="color:var(--muted);font-size:10px">' + esc(r.scanned_at) + '</span></div>';
        });
    } else if (type === 'rootkit') {
        html += '<h3>Rootkit & Integrity Scan Results</h3>';
        d.data.forEach(r => {
            const c = r.status === 'clean' ? 'green' : r.status === 'warning' ? 'amber' : 'red';
            html += '<div class="result-row"><span class="result-status"><span class="badge badge-' + c + '">' + r.status + '</span></span>' +
                '<span style="font-weight:600;min-width:120px">' + esc(r.scan_type) + '/' + esc(r.check_name) + '</span>' +
                '<span style="flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.detail || '') + '</span>' +
                '<span style="color:var(--muted);font-size:10px">' + esc(r.scanned_at) + '</span></div>';
        });
    } else if (type === 'integrity') {
        html += '<h3>File Integrity Baseline</h3>';
        d.data.forEach(r => {
            const c = r.status === 'ok' ? 'green' : r.status === 'modified' ? 'red' : 'amber';
            html += '<div class="result-row"><span class="result-status"><span class="badge badge-' + c + '">' + r.status + '</span></span>' +
                '<span style="font-family:var(--font-mono);flex:1;font-size:11px;overflow:hidden;text-overflow:ellipsis">' + esc(r.file_path) + '</span>' +
                '<span style="color:var(--muted);font-size:10px;font-family:var(--font-mono)">' + esc((r.expected_hash || '').substr(0, 12)) + '...</span></div>';
        });
    } else if (type === 'bots') {
        html += '<h3>Bot Definitions (' + d.data.length + ')</h3>';
        d.data.forEach(r => {
            const dc = r.disposition === 'block' ? 'red' : r.disposition === 'allow' ? 'green' : 'amber';
            html += '<div class="result-row">' +
                '<span class="result-status"><span class="badge badge-' + dc + '">' + r.disposition + '</span></span>' +
                '<span style="min-width:80px"><span class="badge badge-muted">' + r.classification + '</span></span>' +
                '<span style="font-weight:600;min-width:100px">' + esc(r.name) + '</span>' +
                '<span style="font-family:var(--font-mono);flex:1;font-size:10px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.pattern) + '</span>' +
                '<span style="min-width:60px;text-align:right;font-weight:700">' + (r.hit_count || 0) + ' hits</span></div>';
        });
    }

    html += '</div>';
    area.innerHTML = html;
}

async function runScan(taskId) {
    bdToast('Queuing ' + taskId + '...', 'info');
    const res = await bdApi('POST', '/api/tasks/run', { task_id: taskId });
    if (res.ok) bdToast('Scan queued — will execute within 1 second', 'success');
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

loadOverview();
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

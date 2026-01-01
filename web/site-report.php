<?php
/**
 * site-report.php — Per-Site Real-Time Analytics Dashboard
 * High-res Chart.js graphs, GeoIP, reverse DNS, WAF deep analysis
 */
$page_title = 'Site Report';
$active_nav = 'analytics';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$site_id = intval($_GET['id'] ?? 0);
$site = $site_id ? db_row("SELECT * FROM backdraft_sites WHERE id = ?", [$site_id]) : null;
if (!$site) {
    echo '<div class="card" style="text-align:center;padding:40px;color:var(--red)">Site not found. <a href="/sites.php">Back to Sites</a></div>';
    require_once __DIR__ . '/app/inc/footer.php';
    return;
}

$site_name = $site['site_name'];
$waf_reqs = (int)db_scalar("SELECT COUNT(*) FROM backdraft_requests WHERE page_id LIKE ?", [$site_name . '%']);
$log_mb = ($site['access_log_path'] && file_exists($site['access_log_path'])) ? round(filesize($site['access_log_path'])/1048576, 1) : 0;
$profiles = db_rows("SELECT page_id, botproof_enabled, secure_lock_enabled FROM backdraft_page_profiles WHERE site_id = ?", [$site_id]);
?>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
.site-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.site-badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700}
.site-waf{background:var(--green)22;color:var(--green);border:1px solid var(--green)44}
.site-log{background:var(--cyan)22;color:var(--cyan);border:1px solid var(--cyan)44}

.dash-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.dash-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}
.dash-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px;position:relative}
.dash-card .dtitle{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-weight:600;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.dash-card .dtitle .live{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
.dash-card canvas{max-height:220px}

.geo-bar{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px}
.geo-bar .flag{font-size:16px;min-width:24px;text-align:center}
.geo-bar .name{flex:1}
.geo-bar .bar-wrap{width:100px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden}
.geo-bar .bar-fill{height:100%;border-radius:3px;background:var(--amber)}
.geo-bar .val{min-width:50px;text-align:right;font-weight:700;font-family:var(--font-mono)}

.ip-row{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;cursor:pointer;transition:background .1s}
.ip-row:hover{background:rgba(255,255,255,.02)}
.ip-row .ip{font-family:var(--font-mono);font-weight:600;min-width:130px;color:var(--cyan)}
.ip-row .cc{min-width:30px;text-align:center;font-size:14px}
.ip-row .rdns{flex:1;color:var(--muted);font-family:var(--font-mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ip-row .reqs{min-width:50px;text-align:right;font-weight:700}

.feed{max-height:300px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;line-height:1.7}
.feed-row{display:flex;gap:8px;padding:2px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.feed-row:hover{background:rgba(255,255,255,.02)}

/* IP detail modal */
.ip-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;align-items:center;justify-content:center}
.ip-modal.open{display:flex}
.ip-modal .modal{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:800px;max-height:85vh;overflow-y:auto}

@media(max-width:900px){.dash-grid,.dash-grid-3{grid-template-columns:1fr}}
</style>

<!-- Site Header -->
<div class="site-header">
    <div>
        <h2 style="font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <?= h($site_name) ?>
        </h2>
        <div style="display:flex;gap:8px;margin-top:4px;align-items:center">
            <?php if ($site['waf_enabled']): ?><span class="site-badge site-waf">WAF <?= strtoupper($site['waf_mode']) ?></span><?php endif; ?>
            <?php if ($site['log_analysis']): ?><span class="site-badge site-log">LOG ANALYSIS</span><?php endif; ?>
            <span style="font-size:11px;color:var(--muted)"><?= number_format($waf_reqs) ?> WAF requests &middot; <?= $log_mb ?>MB access log &middot; <?= count($profiles) ?> page profiles</span>
        </div>
    </div>
    <div style="display:flex;gap:8px">
        <a href="/sites.php" class="btn btn-ghost">Back</a>
        <button class="btn btn-amber" onclick="refreshAll()">Refresh</button>
    </div>
</div>

<!-- Stat Cards -->
<div class="stat-grid" style="grid-template-columns:repeat(6,1fr)">
    <div class="stat-card stat-amber"><div class="stat-val" id="s-rpm">—</div><div class="stat-label">Req/min</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val" id="s-1h">—</div><div class="stat-label">1h Requests</div></div>
    <div class="stat-card stat-green"><div class="stat-val" id="s-24h">—</div><div class="stat-label">24h Requests</div></div>
    <div class="stat-card stat-red"><div class="stat-val" id="s-flagged">0</div><div class="stat-label">Flagged (1h)</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val" id="s-ips">—</div><div class="stat-label">Unique IPs</div></div>
    <div class="stat-card"><div class="stat-val" id="s-countries">—</div><div class="stat-label">Countries</div></div>
</div>

<!-- BotProof + Secure Lock + Page Profiles -->
<div class="dash-grid" style="grid-template-columns:1fr 1fr 1fr">
    <!-- BotProof Stats -->
    <div class="dash-card">
        <div class="dtitle">BotProof CAPTCHA</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--amber)" id="bp-challenges">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">Challenges</div></div>
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--green)" id="bp-passed">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">Passed</div></div>
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--red)" id="bp-failed">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">Failed</div></div>
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--cyan)" id="bp-active">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">Active Sessions</div></div>
        </div>
        <div style="margin-top:12px;text-align:center">
            <div style="background:var(--bg3);border-radius:8px;height:10px;overflow:hidden;margin-bottom:4px">
                <div id="bp-bar" style="height:100%;background:var(--green);border-radius:8px;width:0%;transition:width .5s"></div>
            </div>
            <span style="font-size:11px;color:var(--muted)">Pass rate: <strong id="bp-rate" style="color:var(--green)">—</strong></span>
        </div>
    </div>

    <!-- Secure Lock Stats -->
    <div class="dash-card">
        <div class="dtitle">Secure Lock OTP</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--cyan)" id="sl-total">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">OTPs Sent</div></div>
            <div style="text-align:center"><div style="font-size:22px;font-weight:800;color:var(--green)" id="sl-verified">—</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">Verified</div></div>
        </div>
        <div style="margin-top:16px;font-size:11px;color:var(--muted);text-align:center" id="sl-status">Loading...</div>
    </div>

    <!-- Page Profiles -->
    <div class="dash-card">
        <div class="dtitle">Protected Pages</div>
        <div id="page-profiles" style="max-height:200px;overflow-y:auto"><div style="color:var(--muted);text-align:center;padding:12px">Loading...</div></div>
    </div>
</div>

<!-- Row 1: RPM Chart + Live Feed -->
<div class="dash-grid">
    <div class="dash-card">
        <div class="dtitle">Requests Per Minute (30 min) <span class="live"></span></div>
        <canvas id="chart-rpm" height="180"></canvas>
    </div>
    <div class="dash-card">
        <div class="dtitle">Live Request Feed <span class="live"></span></div>
        <div class="feed" id="live-feed"><div style="color:var(--muted);text-align:center;padding:30px">Loading...</div></div>
    </div>
</div>

<!-- Row 2: Top IPs with Geo + Country Distribution -->
<div class="dash-grid">
    <div class="dash-card">
        <div class="dtitle">Top Visitors with GeoIP + rDNS</div>
        <div id="top-ips" style="max-height:320px;overflow-y:auto"><div style="color:var(--muted);text-align:center;padding:20px">Loading...</div></div>
    </div>
    <div class="dash-card">
        <div class="dtitle">Country Distribution (24h)</div>
        <div id="geo-dist" style="max-height:320px;overflow-y:auto"><div style="color:var(--muted);text-align:center;padding:20px">Loading...</div></div>
    </div>
</div>

<!-- Row 3: 24h Hourly Traffic + Response Times -->
<div class="dash-grid">
    <div class="dash-card">
        <div class="dtitle">24-Hour Traffic (Requests + Errors)</div>
        <canvas id="chart-24h" height="180"></canvas>
    </div>
    <div class="dash-card">
        <div class="dtitle">Response Time Distribution</div>
        <canvas id="chart-rt" height="180"></canvas>
    </div>
</div>

<!-- Row 4: Status Codes + Agent Breakdown -->
<div class="dash-grid">
    <div class="dash-card">
        <div class="dtitle">Status Code Breakdown (1h)</div>
        <canvas id="chart-status" height="180"></canvas>
    </div>
    <div class="dash-card">
        <div class="dtitle">User Agents (1h)</div>
        <div id="top-agents" style="max-height:280px;overflow-y:auto"><div style="color:var(--muted);text-align:center;padding:20px">Loading...</div></div>
    </div>
</div>

<!-- Row 5: Top Paths + Flagged Requests -->
<div class="dash-grid">
    <div class="dash-card">
        <div class="dtitle">Top Paths (1h)</div>
        <div id="top-paths" style="max-height:280px;overflow-y:auto"></div>
    </div>
    <div class="dash-card">
        <div class="dtitle">Flagged Requests <span id="flagged-count" style="font-size:10px;color:var(--red)"></span></div>
        <div class="feed" id="flagged-feed" style="max-height:280px"><div style="color:var(--muted);text-align:center;padding:20px">Loading...</div></div>
    </div>
</div>

<!-- IP Detail Modal -->
<div class="ip-modal" id="ipModal">
    <div class="modal">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
            <h3 style="color:var(--amber)" id="ipModalTitle">IP Detail</h3>
            <button class="btn btn-ghost" onclick="document.getElementById('ipModal').classList.remove('open')">Close</button>
        </div>
        <div id="ipModalContent"><div style="color:var(--muted);text-align:center;padding:30px">Loading...</div></div>
    </div>
</div>

<script>
const SITE_ID = <?= $site_id ?>;
let rpmChart, hourlyChart, statusChart, rtChart;
let pollTimer = null;

// Chart.js defaults
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#1e293b';
Chart.defaults.font.family = "'Inter',system-ui,sans-serif";

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Country code → flag emoji
function flag(cc) {
    if (!cc || cc === '--') return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ── Poll live data ───────────────────────────────────────────────────────
async function pollLive() {
    try {
        const resp = await fetch('/app/api/site-report.php?action=live&site_id=' + SITE_ID);
        const d = await resp.json();
        if (!d.ok) return;

        // Stats
        const rpm = d.rpm.length > 0 ? d.rpm[d.rpm.length - 1].cnt : 0;
        const flagged = d.flagged.length;
        document.getElementById('s-rpm').textContent = rpm;
        document.getElementById('s-1h').textContent = d.total_1h.toLocaleString();
        document.getElementById('s-24h').textContent = d.total_24h.toLocaleString();
        document.getElementById('s-flagged').textContent = flagged;
        document.getElementById('s-ips').textContent = d.top_ips.length;

        // BotProof metrics
        if (d.botproof) {
            const bp = d.botproof;
            document.getElementById('bp-challenges').textContent = bp.challenges_total.toLocaleString();
            document.getElementById('bp-passed').textContent = bp.sessions_total.toLocaleString();
            document.getElementById('bp-failed').textContent = bp.failed.toLocaleString();
            document.getElementById('bp-active').textContent = bp.sessions_active;
            document.getElementById('bp-rate').textContent = bp.pass_rate + '%';
            document.getElementById('bp-bar').style.width = Math.min(100, bp.pass_rate) + '%';
            document.getElementById('bp-bar').style.background = bp.pass_rate > 50 ? 'var(--green)' : bp.pass_rate > 20 ? 'var(--amber)' : 'var(--red)';
        }

        // Secure Lock metrics
        if (d.secure_lock) {
            document.getElementById('sl-total').textContent = d.secure_lock.otp_total;
            document.getElementById('sl-verified').textContent = d.secure_lock.otp_verified;
            document.getElementById('sl-status').textContent = d.secure_lock.otp_total > 0
                ? 'Verify rate: ' + (d.secure_lock.otp_total > 0 ? Math.round(d.secure_lock.otp_verified / d.secure_lock.otp_total * 100) : 0) + '%'
                : 'No OTP activity yet';
        }

        // Page profiles
        if (d.page_profiles && d.page_profiles.length) {
            document.getElementById('page-profiles').innerHTML = d.page_profiles.map(p => {
                const bpBadge = p.botproof_enabled ? '<span style="background:var(--amber)22;color:var(--amber);border:1px solid var(--amber)44;padding:1px 6px;border-radius:8px;font-size:9px;font-weight:700">BP</span>' : '';
                const slBadge = p.secure_lock_enabled ? '<span style="background:var(--cyan)22;color:var(--cyan);border:1px solid var(--cyan)44;padding:1px 6px;border-radius:8px;font-size:9px;font-weight:700">SL</span>' : '';
                const scoreColor = p.avg_score >= 50 ? 'var(--red)' : p.avg_score > 0 ? 'var(--amber)' : 'var(--green)';
                return '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px">' +
                    '<span style="font-family:var(--font-mono);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(p.page_id) + '</span>' +
                    '<span style="color:var(--muted);font-size:10px">' + (p.total_requests || 0) + ' reqs</span>' +
                    '<span style="color:' + scoreColor + ';font-weight:700;font-size:10px">' + Number(p.avg_score || 0).toFixed(0) + '</span>' +
                    bpBadge + slBadge + '</div>';
            }).join('');
        } else {
            document.getElementById('page-profiles').innerHTML = '<div style="color:var(--muted);text-align:center;padding:12px;font-size:12px">No page profiles</div>';
        }

        // RPM chart
        const rpmLabels = d.rpm.map(r => r.minute);
        const rpmData = d.rpm.map(r => parseInt(r.cnt));
        const rpmFlagged = d.rpm.map(r => parseInt(r.flagged || 0));
        if (rpmChart) rpmChart.destroy();
        rpmChart = new Chart(document.getElementById('chart-rpm'), {
            type: 'bar', data: {
                labels: rpmLabels,
                datasets: [
                    { label: 'Requests', data: rpmData, backgroundColor: 'rgba(245,158,11,0.5)', borderColor: '#f59e0b', borderWidth: 1, borderRadius: 3 },
                    { label: 'Flagged', data: rpmFlagged, backgroundColor: 'rgba(239,68,68,0.7)', borderColor: '#ef4444', borderWidth: 1, borderRadius: 3 }
                ]
            }, options: { responsive: true, plugins: { legend: { display: true, position: 'top', labels: { boxWidth: 12, padding: 8, font: { size: 10 } } } },
                scales: { x: { grid: { display: false }, ticks: { font: { size: 9 }, maxRotation: 45 } }, y: { beginAtZero: true, grid: { color: '#1e293b' } } } }
        });

        // Live feed
        const feedEl = document.getElementById('live-feed');
        feedEl.innerHTML = d.recent.map(r => {
            const sc = parseInt(r.threat_score);
            const scColor = sc >= 75 ? 'var(--red)' : sc > 0 ? 'var(--amber)' : 'var(--muted)';
            const time = (r.request_time || '').substr(11, 8);
            return '<div class="feed-row">' +
                '<span style="color:var(--muted);min-width:65px">' + time + '</span>' +
                '<span style="min-width:18px">' + flag(r.country_code) + '</span>' +
                '<span style="color:var(--cyan);min-width:120px">' + esc(r.client_ip) + '</span>' +
                '<span style="color:var(--green);min-width:35px;font-weight:700">' + esc(r.method) + '</span>' +
                '<span style="flex:1;color:var(--text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r.path) + '">' + esc(r.path) + '</span>' +
                '<span style="color:' + scColor + ';min-width:25px;text-align:right;font-weight:700">' + sc + '</span>' +
                '</div>';
        }).join('') || '<div style="color:var(--muted);text-align:center;padding:20px">No recent requests</div>';

        // Top IPs with geo + rDNS
        document.getElementById('top-ips').innerHTML = d.top_ips.map(ip =>
            '<div class="ip-row" onclick="showIpDetail(\'' + esc(ip.client_ip) + '\')">' +
            '<span class="cc">' + flag(ip.country_code) + '</span>' +
            '<span class="ip">' + esc(ip.client_ip) + '</span>' +
            '<span class="rdns">' + (ip.rdns ? esc(ip.rdns) : '<span style="color:var(--muted)">no rDNS</span>') + '</span>' +
            (ip.threats > 0 ? '<span class="badge badge-red" style="font-size:9px">' + ip.threats + '</span>' : '') +
            '<span class="reqs">' + ip.cnt + '</span>' +
            '</div>'
        ).join('') || '<div style="color:var(--muted);text-align:center;padding:20px">No traffic</div>';

        // Top paths
        const maxPath = d.top_paths.length ? Math.max(...d.top_paths.map(p => parseInt(p.cnt))) : 1;
        document.getElementById('top-paths').innerHTML = d.top_paths.map(p => {
            const pct = Math.round(parseInt(p.cnt) / maxPath * 100);
            const sc = Number(p.avg_score || 0);
            return '<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px">' +
                '<div style="display:flex;justify-content:space-between"><span style="font-family:var(--font-mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">' + esc(p.path) + '</span>' +
                (sc > 0 ? '<span style="color:var(--amber);font-size:10px;margin:0 4px">score:' + sc.toFixed(0) + '</span>' : '') +
                '<span style="font-weight:700;min-width:40px;text-align:right">' + p.cnt + '</span></div>' +
                '<div style="background:var(--bg3);height:4px;border-radius:2px;margin-top:3px"><div style="width:' + pct + '%;height:100%;background:var(--cyan);border-radius:2px"></div></div></div>';
        }).join('');

        // Top agents
        document.getElementById('top-agents').innerHTML = d.top_agents.map(a => {
            const ua = esc(a.user_agent || '(empty)');
            const short = ua.length > 70 ? ua.substr(0, 67) + '...' : ua;
            const isSuspicious = a.max_score > 0 || !a.user_agent || a.user_agent.length < 15;
            return '<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:11px">' +
                '<div style="display:flex;justify-content:space-between;gap:8px">' +
                '<span style="font-family:var(--font-mono);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:' + (isSuspicious ? 'var(--amber)' : 'var(--text-dim)') + '" title="' + ua + '">' + short + '</span>' +
                '<span style="color:var(--muted);flex-shrink:0">' + a.ips + ' IPs</span>' +
                '<span style="font-weight:700;flex-shrink:0;min-width:30px;text-align:right">' + a.cnt + '</span></div></div>';
        }).join('');

        // Flagged
        document.getElementById('flagged-count').textContent = flagged > 0 ? flagged + ' events' : '';
        document.getElementById('flagged-feed').innerHTML = d.flagged.map(f => {
            const time = (f.request_time || '').substr(11, 8);
            return '<div class="feed-row" style="background:rgba(239,68,68,.04)">' +
                '<span style="color:var(--muted);min-width:65px">' + time + '</span>' +
                '<span style="min-width:18px">' + flag(f.country_code) + '</span>' +
                '<span style="color:var(--cyan);min-width:120px">' + esc(f.client_ip) + '</span>' +
                '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(f.path) + '</span>' +
                '<span style="color:var(--red);font-weight:700;min-width:25px;text-align:right">' + f.threat_score + '</span>' +
                '<span style="min-width:40px"><span class="badge badge-' + (f.action_taken === 'flag' ? 'amber' : 'red') + '">' + f.action_taken + '</span></span></div>';
        }).join('') || '<div style="color:var(--green);text-align:center;padding:20px">No flagged requests</div>';

        // Status from actions
        const statusMap = { pass: 0, log: 0, flag: 0, block: 0, challenge: 0 };
        d.actions.forEach(a => statusMap[a.action_taken] = parseInt(a.cnt));
        if (statusChart) statusChart.destroy();
        statusChart = new Chart(document.getElementById('chart-status'), {
            type: 'doughnut', data: {
                labels: ['Pass', 'Log', 'Flag', 'Block', 'Challenge'],
                datasets: [{ data: [statusMap.pass, statusMap.log, statusMap.flag, statusMap.block, statusMap.challenge],
                    backgroundColor: ['#22c55e', '#64748b', '#f59e0b', '#ef4444', '#0891b2'], borderWidth: 0, hoverOffset: 6 }]
            }, options: { responsive: true, cutout: '55%', plugins: { legend: { position: 'bottom', labels: { padding: 10, usePointStyle: true, pointStyle: 'circle', font: { size: 11 } } } } }
        });

    } catch (e) { console.error('Poll error:', e); }

    pollTimer = setTimeout(pollLive, 5000);
}

// ── Load traffic data (24h charts) ───────────────────────────────────────
async function loadTraffic() {
    try {
        const resp = await fetch('/app/api/site-report.php?action=traffic&site_id=' + SITE_ID);
        const d = await resp.json();
        if (!d.ok) return;

        // 24h hourly chart
        if (hourlyChart) hourlyChart.destroy();
        hourlyChart = new Chart(document.getElementById('chart-24h'), {
            type: 'line', data: {
                labels: d.hourly.map(h => h.hour_bucket.substr(11, 5)),
                datasets: [
                    { label: 'Requests', data: d.hourly.map(h => parseInt(h.total_requests)),
                      borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.08)', fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2 },
                    { label: 'Errors (4xx+5xx)', data: d.hourly.map(h => parseInt(h.status_4xx) + parseInt(h.status_5xx)),
                      borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)', fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2 }
                ]
            }, options: { responsive: true, interaction: { intersect: false, mode: 'index' },
                plugins: { legend: { position: 'top', labels: { boxWidth: 12, padding: 8, font: { size: 10 } } } },
                scales: { x: { grid: { display: false }, ticks: { font: { size: 9 }, maxRotation: 45 } }, y: { beginAtZero: true } } }
        });

        // Response time chart
        if (rtChart) rtChart.destroy();
        rtChart = new Chart(document.getElementById('chart-rt'), {
            type: 'bar', data: {
                labels: d.response_times.map(r => r.bucket),
                datasets: [{ data: d.response_times.map(r => parseInt(r.cnt)),
                    backgroundColor: ['#22c55e', '#14b8a6', '#f59e0b', '#ef4444', '#7f1d1d'], borderWidth: 0, borderRadius: 4 }]
            }, options: { responsive: true, plugins: { legend: { display: false } },
                scales: { x: { grid: { display: false } }, y: { beginAtZero: true } } }
        });

    } catch (e) { console.error('Traffic error:', e); }
}

// ── Load geo data ────────────────────────────────────────────────────────
async function loadGeo() {
    try {
        const resp = await fetch('/app/api/site-report.php?action=geo&site_id=' + SITE_ID);
        const d = await resp.json();
        if (!d.ok) return;

        document.getElementById('s-countries').textContent = Object.keys(d.countries).length;

        const maxCountry = Math.max(...Object.values(d.countries).map(c => c.count)) || 1;
        document.getElementById('geo-dist').innerHTML = Object.entries(d.countries).map(([cc, c]) => {
            const pct = Math.round(c.count / maxCountry * 100);
            return '<div class="geo-bar">' +
                '<span class="flag">' + flag(cc) + '</span>' +
                '<span class="name">' + esc(c.name) + ' <span style="color:var(--muted);font-size:10px">(' + c.ips + ' IPs)</span></span>' +
                '<span class="bar-wrap"><span class="bar-fill" style="width:' + pct + '%"></span></span>' +
                '<span class="val">' + c.count.toLocaleString() + '</span></div>';
        }).join('') || '<div style="color:var(--muted);text-align:center;padding:20px">No geo data</div>';

    } catch (e) { console.error('Geo error:', e); }
}

// ── IP Detail Modal ──────────────────────────────────────────────────────
async function showIpDetail(ip) {
    document.getElementById('ipModal').classList.add('open');
    document.getElementById('ipModalTitle').textContent = ip;
    document.getElementById('ipModalContent').innerHTML = '<div style="color:var(--muted);text-align:center;padding:30px">Loading IP analysis...</div>';

    try {
        const resp = await fetch('/app/api/site-report.php?action=ip_detail&ip=' + encodeURIComponent(ip));
        const d = await resp.json();
        if (!d.ok) { document.getElementById('ipModalContent').innerHTML = '<p style="color:var(--red)">Failed to load</p>'; return; }

        const rep = d.reputation || {};
        const banBadge = rep.banned ? '<span class="badge badge-red" style="margin-left:8px">BANNED</span>' : '';

        let html = '<div class="stat-grid" style="grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin-bottom:16px">' +
            '<div class="stat-card stat-cyan" style="padding:12px"><div class="stat-val" style="font-size:18px">' + flag(d.geo.country_code) + ' ' + esc(d.geo.country_name) + '</div><div class="stat-label">Country</div></div>' +
            '<div class="stat-card" style="padding:12px"><div class="stat-val" style="font-size:14px;word-break:break-all">' + esc(d.rdns || 'No rDNS') + '</div><div class="stat-label">Reverse DNS</div></div>' +
            '<div class="stat-card stat-amber" style="padding:12px"><div class="stat-val" style="font-size:18px">' + (rep.total_requests || d.requests.length) + '</div><div class="stat-label">Requests</div></div>' +
            '<div class="stat-card stat-red" style="padding:12px"><div class="stat-val" style="font-size:18px">' + (rep.total_threats || 0) + banBadge + '</div><div class="stat-label">Threats</div></div>' +
            '<div class="stat-card" style="padding:12px"><div class="stat-val" style="font-size:18px">' + (rep.max_score || 0) + '</div><div class="stat-label">Max Score</div></div>' +
            '</div>';

        // Sites hit
        if (d.sites_hit.length) {
            html += '<div style="margin-bottom:12px"><span style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:600">Sites Hit</span>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">';
            d.sites_hit.forEach(s => {
                html += '<span style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-size:11px">' + esc(s.host) + ' <strong>' + s.cnt + '</strong></span>';
            });
            html += '</div></div>';
        }

        // User agents
        if (d.user_agents.length) {
            html += '<div style="margin-bottom:12px"><span style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:600">User Agents</span>';
            d.user_agents.forEach(a => {
                html += '<div style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)">' + esc(a.user_agent || '(empty)') + ' <strong style="color:var(--amber)">' + a.cnt + '</strong></div>';
            });
            html += '</div>';
        }

        // Recent requests
        html += '<div><span style="font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:600">Recent Requests (24h)</span>';
        html += '<div style="max-height:200px;overflow-y:auto;margin-top:4px"><table class="bd-table" style="font-size:11px"><thead><tr><th>Time</th><th>Method</th><th>Host</th><th>Path</th><th>Score</th><th>Action</th></tr></thead><tbody>';
        d.requests.forEach(r => {
            const sc = parseInt(r.threat_score);
            const scC = sc >= 75 ? 'var(--red)' : sc > 0 ? 'var(--amber)' : 'var(--muted)';
            html += '<tr><td style="font-family:var(--font-mono);font-size:10px;white-space:nowrap">' + esc((r.request_time||'').substr(11,8)) + '</td>' +
                '<td style="font-weight:700;color:var(--cyan)">' + esc(r.method) + '</td>' +
                '<td style="font-size:10px">' + esc(r.host) + '</td>' +
                '<td style="font-family:var(--font-mono);font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">' + esc(r.path) + '</td>' +
                '<td style="color:' + scC + ';font-weight:700">' + sc + '</td>' +
                '<td>' + (r.action_taken !== 'pass' ? '<span class="badge badge-' + (r.action_taken === 'flag' ? 'amber' : r.action_taken === 'block' ? 'red' : 'muted') + '">' + r.action_taken + '</span>' : '<span style="color:var(--muted)">pass</span>') + '</td></tr>';
        });
        html += '</tbody></table></div></div>';

        document.getElementById('ipModalContent').innerHTML = html;
    } catch (e) {
        document.getElementById('ipModalContent').innerHTML = '<p style="color:var(--red)">Error: ' + e.message + '</p>';
    }
}

// ── Init ──────────────────────────────────────────────────────────────────
function refreshAll() {
    if (pollTimer) clearTimeout(pollTimer);
    pollLive();
    loadTraffic();
    loadGeo();
}

refreshAll();
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

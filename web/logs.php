<?php
$page_title = 'Live Monitor';
$active_nav = 'logs';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';
?>

<style>
.monitor-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.monitor-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px;position:relative;overflow:hidden}
.monitor-card .title{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}
.monitor-card .title .live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}

/* Live chart area */
.chart-area{height:100px;position:relative;display:flex;align-items:flex-end;gap:1px}
.chart-bar{flex:1;border-radius:2px 2px 0 0;min-height:1px;transition:height .3s;position:relative}
.chart-bar:hover{opacity:.8}
.chart-bar .tip{display:none;position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:10px;white-space:nowrap;z-index:10}
.chart-bar:hover .tip{display:block}

/* Live feed */
.live-feed{height:280px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;line-height:1.7;background:#0a0e14;border-radius:var(--radius-sm);padding:10px 14px}
.feed-line{border-bottom:1px solid rgba(255,255,255,.03);padding:2px 0;display:flex;gap:10px;align-items:baseline}
.feed-line:hover{background:rgba(255,255,255,.02)}
.feed-time{color:var(--muted);min-width:75px;flex-shrink:0}
.feed-ip{color:var(--cyan);min-width:120px;flex-shrink:0}
.feed-method{min-width:40px;flex-shrink:0;font-weight:700}
.feed-path{color:var(--text-dim);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.feed-score{min-width:30px;text-align:right;font-weight:700;flex-shrink:0}
.feed-action{min-width:45px;flex-shrink:0}

.top-list{max-height:200px;overflow-y:auto}
.top-item{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px}
.top-item .label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;margin-right:8px}
.top-item .value{font-weight:700;flex-shrink:0}

.search-bar{display:flex;gap:8px;margin-bottom:16px}
.search-bar input{flex:1;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;font-family:var(--font-mono)}
.search-bar input:focus{outline:none;border-color:var(--amber)}
.search-results{max-height:300px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;background:#0a0e14;border-radius:var(--radius-sm);padding:10px 14px}
.search-hit{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.search-hit .line-num{color:var(--amber);min-width:60px;display:inline-block}
.search-hit mark{background:var(--amber);color:#000;border-radius:2px;padding:0 2px}

.tab-bar{display:flex;gap:4px;margin-bottom:16px}
.tab-btn{padding:8px 16px;border-radius:8px 8px 0 0;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);border-bottom:none;background:var(--bg2);color:var(--text-dim);transition:all .15s}
.tab-btn:hover{background:var(--bg3)}
.tab-btn.active{background:var(--card-bg);color:var(--amber);border-bottom:1px solid var(--card-bg);margin-bottom:-1px;position:relative;z-index:1}

.agent-badge{display:inline-block;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700}
.agent-browser{background:var(--green)22;color:var(--green)}
.agent-bot{background:var(--amber)22;color:var(--amber)}
.agent-scanner{background:var(--red)22;color:var(--red)}
.agent-library{background:var(--cyan)22;color:var(--cyan)}
.agent-empty{background:var(--muted)22;color:var(--muted)}
</style>

<!-- Tab Bar -->
<div class="tab-bar">
    <div class="tab-btn active" onclick="switchTab('live')" id="tab-live">Live Activity</div>
    <div class="tab-btn" onclick="switchTab('logs')" id="tab-logs">Log Files</div>
    <div class="tab-btn" onclick="switchTab('search')" id="tab-search">Search</div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: LIVE ACTIVITY (CloudWatch-style real-time dashboard)              -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div id="panel-live">

<!-- Top stat bar -->
<div class="stat-grid" style="grid-template-columns:repeat(6,1fr)">
    <div class="stat-card stat-amber"><div class="stat-val" id="s-rpm">0</div><div class="stat-label">Req/min</div></div>
    <div class="stat-card stat-red"><div class="stat-val" id="s-flagged">0</div><div class="stat-label">Flagged (1h)</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val" id="s-ips">0</div><div class="stat-label">Active IPs</div></div>
    <div class="stat-card stat-green"><div class="stat-val" id="s-pass">0</div><div class="stat-label">Passed (1h)</div></div>
    <div class="stat-card stat-amber"><div class="stat-val" id="s-agents">—</div><div class="stat-label">Top Agent</div></div>
    <div class="stat-card"><div class="stat-val" id="s-sites">0</div><div class="stat-label">Active Sites</div></div>
</div>

<div class="monitor-grid">
    <!-- RPM Chart (30 min) -->
    <div class="monitor-card">
        <div class="title">Requests Per Minute (30 min) <span class="live-dot"></span></div>
        <div class="chart-area" id="chart-rpm"></div>
    </div>

    <!-- Agent Distribution -->
    <div class="monitor-card">
        <div class="title">Agent Classification (1h)</div>
        <div id="agent-dist" class="top-list"></div>
    </div>

    <!-- Live Request Feed -->
    <div class="monitor-card" style="grid-column:1/3">
        <div class="title">Live WAF Request Feed <span class="live-dot"></span></div>
        <div class="live-feed" id="live-feed">
            <div style="color:var(--muted);text-align:center;padding:20px">Loading live feed...</div>
        </div>
    </div>

    <!-- Top IPs -->
    <div class="monitor-card">
        <div class="title">Top IPs (1h)</div>
        <div id="top-ips" class="top-list"></div>
    </div>

    <!-- Top Paths -->
    <div class="monitor-card">
        <div class="title">Top Paths (1h)</div>
        <div id="top-paths" class="top-list"></div>
    </div>

    <!-- Flagged Requests -->
    <div class="monitor-card" style="grid-column:1/3">
        <div class="title">Flagged Requests (score &gt; 0, last 1h) <span style="font-size:10px;color:var(--red)" id="flagged-count"></span></div>
        <div class="live-feed" id="flagged-feed" style="height:180px">
            <div style="color:var(--muted);text-align:center;padding:20px">Loading...</div>
        </div>
    </div>

    <!-- 24h Hourly Trend -->
    <div class="monitor-card" style="grid-column:1/3">
        <div class="title">24-Hour Traffic Trend</div>
        <div class="chart-area" id="chart-24h" style="height:80px"></div>
    </div>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: LOG FILES                                                         -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div id="panel-logs" style="display:none">
<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
    <button class="btn btn-amber" onclick="switchLogFile('backdraft')" id="lbtn-backdraft">Main</button>
    <button class="btn btn-ghost" onclick="switchLogFile('error')" id="lbtn-error">Error</button>
    <button class="btn btn-ghost" onclick="switchLogFile('debug')" id="lbtn-debug">Debug</button>
    <button class="btn btn-ghost" onclick="switchLogFile('access')" id="lbtn-access">Access</button>
    <span style="width:1px;height:24px;background:var(--border);display:inline-block"></span>
    <button class="btn btn-ghost" onclick="toggleLogPause()" id="lbtn-pause">Pause</button>
    <button class="btn btn-ghost" onclick="document.getElementById('logOutput').textContent=''">Clear</button>
    <button class="btn btn-ghost" onclick="refreshLogTail()">Refresh</button>
    <span style="flex:1"></span>
    <span style="font-size:11px;color:var(--muted)" id="logStatusText">Initializing...</span>
</div>
<div class="card" style="padding:0">
    <pre id="logOutput" style="background:#0a0e14;color:#a2aabc;font-family:var(--font-mono);font-size:12px;line-height:1.6;padding:16px 20px;height:calc(100vh - 280px);overflow-y:auto;margin:0;border-radius:var(--radius);white-space:pre-wrap;word-break:break-all">Loading log...</pre>
</div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!-- TAB: SEARCH                                                            -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->
<div id="panel-search" style="display:none">
<div class="search-bar">
    <select id="searchFile" style="padding:10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;min-width:120px">
        <option value="backdraft">Main Log</option>
        <option value="error">Error Log</option>
        <option value="debug">Debug Log</option>
        <option value="access">Access Log</option>
    </select>
    <input type="text" id="searchQuery" placeholder="Search pattern (case-insensitive)..." onkeydown="if(event.key==='Enter')runSearch()">
    <button class="btn btn-amber" onclick="runSearch()">Search</button>
</div>
<div id="searchStatus" style="font-size:12px;color:var(--muted);margin-bottom:8px"></div>
<div class="card" style="padding:0">
    <div class="search-results" id="searchResults" style="height:calc(100vh - 320px)">
        <div style="color:var(--muted);text-align:center;padding:40px">Enter a search term above to find matching log entries</div>
    </div>
</div>
</div>

<script>
// ── Tab switching ────────────────────────────────────────────────────────
function switchTab(tab) {
    ['live','logs','search'].forEach(t => {
        document.getElementById('panel-' + t).style.display = (t === tab) ? '' : 'none';
        document.getElementById('tab-' + t).classList.toggle('active', t === tab);
    });
    if (tab === 'live') pollLiveStats();
    if (tab === 'logs' && !logInitialized) { logInitialized = true; switchLogFile('backdraft'); }
}

// ── LIVE ACTIVITY TAB ────────────────────────────────────────────────────
let liveTimer = null;

async function pollLiveStats() {
    try {
        const resp = await fetch('/app/api/logs.php?action=stats');
        const d = await resp.json();
        if (!d.ok) return;

        // Stat cards
        const rpm = d.rpm.length > 0 ? d.rpm[d.rpm.length - 1].cnt : 0;
        const flagged1h = d.actions_1h.filter(a => a.action_taken !== 'pass').reduce((s,a) => s + parseInt(a.cnt), 0);
        const passed1h = d.actions_1h.filter(a => a.action_taken === 'pass').reduce((s,a) => s + parseInt(a.cnt), 0);
        document.getElementById('s-rpm').textContent = rpm;
        document.getElementById('s-flagged').textContent = flagged1h;
        document.getElementById('s-pass').textContent = passed1h;
        document.getElementById('s-ips').textContent = d.top_ips.length;
        document.getElementById('s-sites').textContent = d.realtime.length;
        document.getElementById('s-agents').textContent = d.agents.length > 0 ? d.agents[0].agent_type : '—';

        // RPM chart
        renderBarChart('chart-rpm', d.rpm.map(r => ({
            value: parseInt(r.cnt),
            label: r.minute,
            color: r.flagged > 0 ? 'var(--red)' : 'var(--amber)',
            tip: r.minute + ': ' + r.cnt + ' reqs' + (r.flagged > 0 ? ', ' + r.flagged + ' flagged' : '')
        })));

        // 24h trend
        renderBarChart('chart-24h', d.hourly_24h.map(h => ({
            value: parseInt(h.reqs),
            label: h.hour,
            color: h.threats > 0 ? 'var(--red)' : 'var(--green)',
            tip: h.hour.substr(11,5) + ': ' + h.reqs + ' reqs, ' + h.threats + ' threats'
        })));

        // Agent distribution
        const agentEl = document.getElementById('agent-dist');
        const totalAgent = d.agents.reduce((s,a) => s + parseInt(a.cnt), 0) || 1;
        agentEl.innerHTML = d.agents.map(a => {
            const pct = Math.round(parseInt(a.cnt) / totalAgent * 100);
            const cls = 'agent-' + a.agent_type;
            return '<div class="top-item"><span class="label"><span class="agent-badge ' + cls + '">' + a.agent_type + '</span></span>' +
                   '<span style="flex:1;margin:0 8px"><div style="background:var(--bg3);border-radius:3px;height:8px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:var(--amber);border-radius:3px"></div></div></span>' +
                   '<span class="value">' + a.cnt + ' <span style="color:var(--muted);font-weight:400;font-size:10px">(' + pct + '%)</span></span></div>';
        }).join('');

        // Top IPs
        document.getElementById('top-ips').innerHTML = d.top_ips.map(ip =>
            '<div class="top-item"><span class="label" style="font-family:var(--font-mono);font-size:11px">' + esc(ip.client_ip) + '</span>' +
            (ip.threats > 0 ? '<span class="badge badge-red" style="margin-right:6px;font-size:9px">' + ip.threats + ' threats</span>' : '') +
            '<span class="value">' + ip.cnt + '</span></div>'
        ).join('') || '<div style="color:var(--muted);text-align:center;padding:12px">No traffic</div>';

        // Top Paths
        document.getElementById('top-paths').innerHTML = d.top_paths.map(p =>
            '<div class="top-item"><span class="label" style="font-family:var(--font-mono);font-size:11px">' + esc(p.path) + '</span>' +
            (p.avg_score > 0 ? '<span style="color:var(--amber);font-size:10px;margin-right:4px">score:' + Number(p.avg_score).toFixed(0) + '</span>' : '') +
            '<span class="value">' + p.cnt + '</span></div>'
        ).join('') || '<div style="color:var(--muted);text-align:center;padding:12px">No traffic</div>';

        // Live feed
        const feedEl = document.getElementById('live-feed');
        feedEl.innerHTML = d.recent_requests.map(r => {
            const sc = parseInt(r.threat_score);
            const scoreColor = sc >= 75 ? 'var(--red)' : sc >= 50 ? 'var(--amber)' : sc > 0 ? 'var(--cyan)' : 'var(--muted)';
            const actColor = r.action_taken === 'block' ? 'badge-red' : r.action_taken === 'flag' ? 'badge-amber' : r.action_taken === 'log' ? 'badge-muted' : '';
            const time = (r.request_time || '').substr(11, 8);
            return '<div class="feed-line">' +
                '<span class="feed-time">' + time + '</span>' +
                '<span class="feed-ip">' + esc(r.client_ip) + '</span>' +
                '<span class="feed-method" style="color:var(--cyan)">' + esc(r.method) + '</span>' +
                '<span class="feed-path" title="' + esc(r.path) + '">' + esc(r.host || '') + esc(r.path) + '</span>' +
                '<span class="feed-score" style="color:' + scoreColor + '">' + sc + '</span>' +
                (actColor ? '<span class="feed-action"><span class="badge ' + actColor + '">' + r.action_taken + '</span></span>' : '<span class="feed-action" style="color:var(--muted)">pass</span>') +
                '</div>';
        }).join('') || '<div style="color:var(--muted);text-align:center;padding:20px">No recent requests</div>';

        // Flagged feed
        const flagEl = document.getElementById('flagged-feed');
        document.getElementById('flagged-count').textContent = d.flagged.length > 0 ? d.flagged.length + ' events' : '';
        flagEl.innerHTML = d.flagged.map(r => {
            const time = (r.request_time || '').substr(11, 8);
            return '<div class="feed-line" style="background:rgba(239,68,68,.04)">' +
                '<span class="feed-time">' + time + '</span>' +
                '<span class="feed-ip">' + esc(r.client_ip) + '</span>' +
                '<span class="feed-path" title="' + esc(r.path) + '">' + esc(r.path) + '</span>' +
                '<span class="feed-score" style="color:var(--red);font-size:13px">' + r.threat_score + '</span>' +
                '<span class="feed-action"><span class="badge badge-' + (r.action_taken === 'flag' ? 'amber' : 'red') + '">' + r.action_taken + '</span></span>' +
                '<span style="color:var(--muted);font-size:10px">' + esc(r.matched_rules || '') + '</span>' +
                '</div>';
        }).join('') || '<div style="color:var(--muted);text-align:center;padding:20px">No flagged requests — looking good</div>';

    } catch (e) { console.error('Live stats error:', e); }

    // Poll every 5 seconds
    if (liveTimer) clearTimeout(liveTimer);
    liveTimer = setTimeout(pollLiveStats, 5000);
}

function renderBarChart(containerId, data) {
    const el = document.getElementById(containerId);
    if (!data.length) { el.innerHTML = '<div style="color:var(--muted);font-size:11px;width:100%;text-align:center;align-self:center">No data</div>'; return; }
    const max = Math.max(...data.map(d => d.value)) || 1;
    const h = el.clientHeight || 100;
    el.innerHTML = data.map(d => {
        const barH = Math.max(2, (d.value / max) * (h - 4));
        return '<div class="chart-bar" style="height:' + barH + 'px;background:' + d.color + '"><div class="tip">' + d.tip + '</div></div>';
    }).join('');
}

// Start live polling
pollLiveStats();

// ── LOG FILES TAB ────────────────────────────────────────────────────────
let logInitialized = false;
let currentLogFile = 'backdraft';
let logPaused = false;
let logSSE = null;

async function switchLogFile(file) {
    currentLogFile = file;
    ['backdraft','error','debug','access'].forEach(f => {
        const b = document.getElementById('lbtn-' + f);
        b.classList.toggle('btn-amber', f === file);
        b.classList.toggle('btn-ghost', f !== file);
    });
    document.getElementById('logOutput').textContent = 'Loading...\n';
    document.getElementById('logStatusText').textContent = 'Loading...';
    await refreshLogTail();
    connectLogSSE();
}

async function refreshLogTail() {
    try {
        const resp = await fetch('/app/api/logs.php?action=tail&file=' + currentLogFile + '&lines=150');
        const json = await resp.json();
        if (json.ok && json.lines.length) {
            document.getElementById('logOutput').textContent = json.lines.join('\n') + '\n';
            document.getElementById('logOutput').scrollTop = document.getElementById('logOutput').scrollHeight;
            document.getElementById('logStatusText').textContent = json.count + ' lines | ' + json.size_human;
        }
    } catch (e) { document.getElementById('logStatusText').textContent = 'Load error'; }
}

function connectLogSSE() {
    if (logSSE) logSSE.close();
    logSSE = new EventSource('/api/logs/stream?file=' + currentLogFile);
    logSSE.onmessage = function(e) {
        if (logPaused) return;
        const out = document.getElementById('logOutput');
        const lines = out.textContent.split('\n');
        if (lines.length > 2000) out.textContent = lines.slice(-1900).join('\n');
        out.textContent += e.data + '\n';
        out.scrollTop = out.scrollHeight;
    };
    logSSE.addEventListener('connected', () => {
        document.getElementById('logStatusText').textContent += ' | Live';
    });
}

function toggleLogPause() {
    logPaused = !logPaused;
    document.getElementById('lbtn-pause').textContent = logPaused ? 'Resume' : 'Pause';
    document.getElementById('lbtn-pause').classList.toggle('btn-amber', logPaused);
}

// ── SEARCH TAB ───────────────────────────────────────────────────────────
async function runSearch() {
    const file = document.getElementById('searchFile').value;
    const query = document.getElementById('searchQuery').value.trim();
    if (!query) return;

    document.getElementById('searchStatus').textContent = 'Searching...';
    document.getElementById('searchResults').innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px">Searching...</div>';

    try {
        const resp = await fetch('/app/api/logs.php?action=search&file=' + file + '&q=' + encodeURIComponent(query) + '&limit=200');
        const json = await resp.json();
        if (!json.ok) { document.getElementById('searchResults').innerHTML = '<div style="color:var(--red);padding:20px">' + json.error + '</div>'; return; }

        document.getElementById('searchStatus').textContent = json.count + ' matches in ' + file + '.log for "' + query + '"';

        if (json.results.length === 0) {
            document.getElementById('searchResults').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">No matches found</div>';
            return;
        }

        const re = new RegExp('(' + query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
        document.getElementById('searchResults').innerHTML = json.results.map(r =>
            '<div class="search-hit"><span class="line-num">:' + r.line + '</span> ' +
            esc(r.text).replace(re, '<mark>$1</mark>') + '</div>'
        ).join('');
    } catch (e) {
        document.getElementById('searchResults').innerHTML = '<div style="color:var(--red);padding:20px">Error: ' + e.message + '</div>';
    }
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

<?php
$page_title = 'Task Monitor';
$active_nav = 'task-manager';
require_once __DIR__ . '/app/inc/db.php';

// ── Export handler — must run before header (sends download headers) ─────
if (isset($_GET['export']) && isset($_GET['format'])) {
    require_once __DIR__ . '/app/inc/auth.php';
    if (!bd_is_authed()) { header('HTTP/1.1 401 Unauthorized'); exit; }

    $run_id = (int)$_GET['export'];
    $format = $_GET['format'];

    $run = db_row("SELECT task_id, export_html, summary_json FROM backdraft_task_runs WHERE id = ?", [$run_id]);
    if (!$run) { header('HTTP/1.1 404 Not Found'); echo 'Run not found'; exit; }

    $tid = $run['task_id'];

    if ($format === 'html') {
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"{$tid}_report_{$run_id}.html\"");
        echo $run['export_html'] ?: '<html><body><h1>No HTML report available</h1><p>This task run did not generate an HTML export.</p></body></html>';
        exit;
    }

    if ($format === 'pdf') {
        // Render HTML with print-optimized styles + auto-print JS
        header('Content-Type: text/html; charset=utf-8');
        $html = $run['export_html'] ?: '<h1>No report available</h1>';
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>@media print{body{margin:0;font-size:11pt}}</style>';
        echo '<script>window.onload=function(){window.print()}</script></head><body>';
        echo $html;
        echo '</body></html>';
        exit;
    }

    if ($format === 'excel') {
        $summary = json_decode($run['summary_json'] ?: '{}', true);
        header('Content-Type: text/csv; charset=utf-8');
        header("Content-Disposition: attachment; filename=\"{$tid}_report_{$run_id}.csv\"");

        $out = fopen('php://output', 'w');

        // Executive Summary section
        fputcsv($out, ['BackDraft Threat Analysis Report']);
        fputcsv($out, ['Generated', $summary['report_generated'] ?? date('Y-m-d H:i:s')]);
        fputcsv($out, ['Analysis Window', ($summary['analysis_window_hours'] ?? 24) . ' hours']);
        fputcsv($out, []);

        $exec = $summary['executive_summary'] ?? [];
        fputcsv($out, ['--- Executive Summary ---']);
        fputcsv($out, ['Metric', 'Value']);
        foreach (['total_requests','total_threats','total_blocked','total_flagged','unique_ips','avg_score','max_score','threat_rate_pct','banned_ips'] as $k) {
            fputcsv($out, [ucwords(str_replace('_', ' ', $k)), $exec[$k] ?? 0]);
        }
        fputcsv($out, []);

        // Severity Distribution
        $sev = $summary['severity_distribution'] ?? [];
        fputcsv($out, ['--- Severity Distribution ---']);
        fputcsv($out, ['Severity', 'Count']);
        foreach ($sev as $s => $c) fputcsv($out, [ucfirst($s), $c]);
        fputcsv($out, []);

        // Top Offending IPs
        $ips = $summary['top_offending_ips'] ?? [];
        fputcsv($out, ['--- Top Offending IPs ---']);
        fputcsv($out, ['IP Address', 'Country', 'Threats', 'Max Score', 'Avg Score', 'Banned']);
        foreach ($ips as $ip) {
            fputcsv($out, [$ip['client_ip'], $ip['country'] ?? '', $ip['threat_count'], $ip['max_score'], round($ip['avg_score'],1), $ip['banned'] ? 'Yes' : 'No']);
        }
        fputcsv($out, []);

        // Top Rules
        $rules = $summary['top_triggered_rules'] ?? [];
        fputcsv($out, ['--- Top Triggered Rules ---']);
        fputcsv($out, ['Rule', 'Target', 'Action', 'Score', 'Triggers']);
        foreach ($rules as $r) {
            fputcsv($out, [$r['name'], $r['target'], $r['action'], $r['score'], $r['trigger_count']]);
        }
        fputcsv($out, []);

        // Hourly Trend
        $hourly = $summary['hourly_trend'] ?? [];
        fputcsv($out, ['--- Hourly Threat Trend ---']);
        fputcsv($out, ['Hour', 'Threats', 'Avg Score']);
        foreach ($hourly as $h) {
            fputcsv($out, [$h['hour_bucket'], $h['cnt'], round($h['avg_score'],1)]);
        }
        fputcsv($out, []);

        // Response Algorithm
        fputcsv($out, ['--- Recommended Response ---']);
        fputcsv($out, ['Level', strtoupper($summary['recommended_response'] ?? 'low')]);
        $algo = $summary['response_algorithm'] ?? [];
        fputcsv($out, ['Response Time', $algo['response_time'] ?? '']);
        fputcsv($out, []);
        fputcsv($out, ['Auto Actions']);
        foreach ($algo['auto_actions'] ?? [] as $a) fputcsv($out, ['', $a]);
        fputcsv($out, ['Manual Actions']);
        foreach ($algo['manual_actions'] ?? [] as $a) fputcsv($out, ['', $a]);
        fputcsv($out, ['Remediation']);
        foreach ($algo['remediation'] ?? [] as $a) fputcsv($out, ['', $a]);

        fclose($out);
        exit;
    }

    header('HTTP/1.1 400 Bad Request');
    echo 'Unsupported format: ' . htmlspecialchars($format);
    exit;
}

require_once __DIR__ . '/app/inc/header.php';
$is_admin = bd_is_admin();

// Recent runs for initial render
$recent_runs = db_rows(
    "SELECT r.*, t.name as task_name, t.priority
     FROM backdraft_task_runs r
     JOIN backdraft_tasks t ON t.task_id = r.task_id
     ORDER BY r.started_at DESC LIMIT 20"
);
$running_count = (int)db_scalar("SELECT COUNT(*) FROM backdraft_task_runs WHERE status = 'running'");
?>

<style>
.live-panel{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:24px}
.live-panel h3{font-size:14px;font-weight:700;color:var(--cyan);margin-bottom:12px;display:flex;align-items:center;gap:8px}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 1.5s infinite}
.live-dot.idle{background:var(--muted);animation:none}
.live-output{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;font-family:var(--font-mono);font-size:11px;white-space:pre-wrap;max-height:300px;overflow-y:auto;color:var(--text-dim)}
.run-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 16px;margin-bottom:8px;display:flex;align-items:center;gap:16px}
.run-card .run-info{flex:1}
.run-card .run-info .name{font-weight:600;font-size:13px}
.run-card .run-info .meta{font-size:11px;color:var(--muted)}
.export-btns{display:flex;gap:4px}
.export-btns a{padding:3px 8px;font-size:10px;font-weight:700;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.export-btns .ex-html{background:var(--cyan)22;color:var(--cyan);border:1px solid var(--cyan)44}
.export-btns .ex-pdf{background:var(--red)22;color:var(--red);border:1px solid var(--red)44}
.export-btns .ex-excel{background:var(--green)22;color:var(--green);border:1px solid var(--green)44}

.detail-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.detail-overlay.open{display:flex}
.detail-modal{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:800px;max-height:85vh;overflow-y:auto;box-shadow:0 16px 48px rgba(0,0,0,.5)}
.detail-modal h3{font-size:16px;font-weight:700;margin-bottom:16px;color:var(--amber)}
</style>

<!-- Live Progress Panel -->
<div class="live-panel">
    <h3>
        <span class="live-dot <?= $running_count > 0 ? '' : 'idle' ?>" id="liveDot"></span>
        <span id="liveTitle"><?= $running_count > 0 ? "{$running_count} task(s) running" : 'No tasks running' ?></span>
    </h3>
    <div class="live-output" id="liveOutput"><?= $running_count > 0 ? 'Polling for live output...' : 'Waiting for task execution...' ?></div>
</div>

<!-- Recent Runs -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">Recent Task Runs</h2>
    <a href="/tasks.php" class="btn btn-ghost">Manage Tasks</a>
</div>

<div id="runsList">
<?php foreach ($recent_runs as $r): ?>
    <div class="run-card">
        <div class="run-info">
            <div class="name"><?= h($r['task_name']) ?></div>
            <div class="meta">
                <?= h($r['task_id']) ?> &mdash;
                <span style="font-family:var(--font-mono)"><?= h($r['started_at']) ?></span>
                <?php if ($r['ended_at']): ?>
                    &rarr; <?= h($r['ended_at']) ?>
                <?php endif; ?>
            </div>
        </div>
        <span class="badge badge-<?= $r['status'] === 'success' ? 'green' : ($r['status'] === 'failed' ? 'red' : ($r['status'] === 'running' ? 'amber' : 'muted')) ?>">
            <?= h($r['status']) ?>
        </span>
        <span class="priority-<?= $r['priority'] ?>" style="font-size:11px;font-weight:700;text-transform:uppercase"><?= h($r['priority']) ?></span>
        <?php if ($r['export_formats']): ?>
        <div class="export-btns">
            <?php foreach (explode(',', $r['export_formats']) as $fmt): $fmt = trim($fmt); ?>
                <a href="?export=<?= $r['id'] ?>&format=<?= h($fmt) ?>" class="ex-<?= h($fmt) ?>"><?= strtoupper(h($fmt)) ?></a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="viewDetail(<?= $r['id'] ?>)">Detail</button>
        <?php if ($is_admin): ?>
        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px;color:var(--red)" onclick="deleteRun(<?= $r['id'] ?>)">Del</button>
        <?php endif; ?>
    </div>
<?php endforeach; ?>
<?php if (empty($recent_runs)): ?>
    <div style="text-align:center;color:var(--muted);padding:40px">No task runs yet — tasks will appear here when executed</div>
<?php endif; ?>
</div>

<!-- Run Detail Modal -->
<div class="detail-overlay" id="detailOverlay">
    <div class="detail-modal">
        <h3 id="detailTitle">Run Detail</h3>
        <div id="detailContent">Loading...</div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:20px">
            <div id="detailExports"></div>
            <button class="btn btn-ghost" onclick="closeDetail()">Close</button>
        </div>
    </div>
</div>

<script>
// ── Live polling ─────────────────────────────────────────────────────────
let pollInterval = null;

async function pollLive() {
    try {
        const resp = await fetch('/app/api/task-manager.php?action=live_status')  // PHP API (live status aggregation);
        const json = await resp.json();
        if (!json.ok) return;

        const dot = document.getElementById('liveDot');
        const title = document.getElementById('liveTitle');
        const output = document.getElementById('liveOutput');

        if (json.running.length > 0) {
            dot.classList.remove('idle');
            title.textContent = json.running.length + ' task(s) running';
            let log = '';
            json.running.forEach(r => {
                log += '=== ' + r.task_name + ' [' + r.task_id + '] ===\n';
                log += 'Priority: ' + r.priority + ' | Started: ' + r.started_at + '\n';
                log += (r.output_log || 'Waiting for output...') + '\n\n';
            });
            output.textContent = log;
            output.scrollTop = output.scrollHeight;

            // Poll faster when tasks are running
            if (!pollInterval || pollInterval > 3000) {
                clearInterval(pollInterval);
                pollInterval = setInterval(pollLive, 3000);
            }
        } else {
            dot.classList.add('idle');
            title.textContent = 'No tasks running';
            if (json.recent.length > 0) {
                const last = json.recent[0];
                output.textContent = 'Last completed: ' + last.task_name + ' [' + last.status + '] at ' + (last.ended_at || '');
            }
            // Slow down polling
            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = setInterval(pollLive, 5000);
            }
        }
    } catch (e) {}
}

pollInterval = setInterval(pollLive, 5000);
pollLive();

// ── Run detail viewer ────────────────────────────────────────────────────
async function viewDetail(runId) {
    document.getElementById('detailOverlay').classList.add('open');
    document.getElementById('detailContent').innerHTML = '<p style="color:var(--muted)">Loading...</p>';
    document.getElementById('detailExports').innerHTML = '';

    const resp = await fetch('/api/task-runs/' + runId)  // C++ daemon API;
    const json = await resp.json();
    if (!json.ok) { document.getElementById('detailContent').innerHTML = '<p style="color:var(--red)">Failed to load</p>'; return; }

    const r = json.data;
    document.getElementById('detailTitle').textContent = 'Run #' + r.id + ' — ' + r.task_id;

    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px">';
    const statusColors = { success:'var(--green)', failed:'var(--red)', partial:'var(--amber)', running:'var(--cyan)' };
    html += '<div><span style="font-size:11px;color:var(--muted);text-transform:uppercase">Status</span><br><span style="font-weight:700;color:' + (statusColors[r.status]||'var(--text)') + '">' + r.status.toUpperCase() + '</span></div>';
    html += '<div><span style="font-size:11px;color:var(--muted);text-transform:uppercase">Started</span><br><span style="font-family:var(--font-mono);font-size:12px">' + r.started_at + '</span></div>';
    html += '<div><span style="font-size:11px;color:var(--muted);text-transform:uppercase">Ended</span><br><span style="font-family:var(--font-mono);font-size:12px">' + (r.ended_at || 'Running...') + '</span></div>';
    html += '</div>';

    if (r.error_msg) html += '<div style="background:var(--red)15;border:1px solid var(--red)33;border-radius:6px;padding:10px;margin-bottom:12px;color:var(--red);font-size:13px"><strong>Error:</strong> ' + escHtml(r.error_msg) + '</div>';

    // Summary JSON preview
    if (r.summary_json && r.summary_json !== '{}') {
        try {
            const summary = typeof r.summary_json === 'string' ? JSON.parse(r.summary_json) : r.summary_json;
            if (summary.executive_summary) {
                const exec = summary.executive_summary;
                html += '<div style="margin-bottom:16px"><h4 style="font-size:13px;color:var(--amber);margin-bottom:8px">Executive Summary</h4>';
                html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px">';
                const metrics = [
                    ['Requests', exec.total_requests, 'var(--amber)'],
                    ['Threats', exec.total_threats, 'var(--red)'],
                    ['Threat Rate', exec.threat_rate_pct + '%', 'var(--cyan)'],
                    ['Unique IPs', exec.unique_ips, 'var(--cyan)'],
                    ['Max Score', exec.max_score, 'var(--red)'],
                    ['Banned', exec.banned_ips, 'var(--green)']
                ];
                metrics.forEach(m => {
                    html += '<div style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px;text-align:center"><div style="font-size:20px;font-weight:800;color:' + m[2] + '">' + (m[1]||0) + '</div><div style="font-size:10px;color:var(--muted);text-transform:uppercase">' + m[0] + '</div></div>';
                });
                html += '</div></div>';
            }
            if (summary.recommended_response) {
                const colors = {critical:'var(--red)',high:'var(--amber)',medium:'var(--cyan)',low:'var(--muted)'};
                html += '<div style="background:' + (colors[summary.recommended_response]||'var(--muted)') + '15;border:1px solid ' + (colors[summary.recommended_response]||'var(--muted)') + '33;border-radius:8px;padding:12px;margin-bottom:16px;text-align:center">';
                html += '<span style="font-size:12px;color:var(--muted)">Recommended Response</span><br>';
                html += '<span style="font-size:18px;font-weight:800;color:' + (colors[summary.recommended_response]||'var(--text)') + '">' + summary.recommended_response.toUpperCase() + '</span>';
                html += '</div>';
            }
        } catch(e) {}
    }

    // Output log
    html += '<h4 style="font-size:13px;color:var(--amber);margin-bottom:8px">Output Log</h4>';
    html += '<div class="live-output" style="max-height:250px">' + escHtml(r.output_log || 'No output') + '</div>';

    document.getElementById('detailContent').innerHTML = html;

    // Export buttons
    if (r.export_formats) {
        let exp = '';
        r.export_formats.split(',').forEach(f => {
            f = f.trim();
            const cls = f === 'html' ? 'ex-html' : f === 'pdf' ? 'ex-pdf' : 'ex-excel';
            exp += '<a href="?export=' + r.id + '&format=' + f + '" class="btn ' + cls + '" style="padding:6px 12px;font-size:11px;font-weight:700;text-decoration:none">' + f.toUpperCase() + '</a> ';
        });
        document.getElementById('detailExports').innerHTML = exp;
    }
}

function closeDetail() { document.getElementById('detailOverlay').classList.remove('open'); }

async function deleteRun(runId) {
    if (!confirm('Delete this run record?')) return;
    const resp = await bdApi('DELETE', '/api/task-runs/' + runId)  // C++ daemon API;
    const json = await resp.json();
    if (json.ok) { bdToast('Run deleted', 'success'); setTimeout(() => location.reload(), 800); }
    else bdToast(json.error || 'Failed', 'error');
}

function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

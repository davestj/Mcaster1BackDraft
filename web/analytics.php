<?php
$page_title = 'Log Analytics';
$active_nav = 'analytics';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

// Quick log stat parser — scans last ~500KB of each access log for real numbers
function quick_log_stats($path) {
    $s = ['requests' => 0, 'bytes' => 0, 'ips' => 0, '2xx' => 0, '3xx' => 0, '4xx' => 0, '5xx' => 0, 'size' => 0, 'err_size' => 0];
    if (!$path || !is_readable($path)) return $s;
    $s['size'] = filesize($path);
    $fp = fopen($path, 'r');
    if (!$fp) return $s;
    $sz = filesize($path);
    fseek($fp, max(0, $sz - 524288)); // Last 500KB
    if ($sz > 524288) fgets($fp);
    $re = '/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+\S+\s+\S+"\s+(\d+)\s+(\d+)/';
    $ip_set = [];
    while (!feof($fp)) {
        $line = fgets($fp);
        if (!$line || !preg_match($re, $line, $m)) continue;
        $s['requests']++;
        $s['bytes'] += intval($m[5]);
        $ip_set[$m[1]] = true;
        $st = intval($m[4]);
        if ($st >= 200 && $st < 300) $s['2xx']++;
        elseif ($st >= 300 && $st < 400) $s['3xx']++;
        elseif ($st >= 400 && $st < 500) $s['4xx']++;
        elseif ($st >= 500) $s['5xx']++;
    }
    fclose($fp);
    $s['ips'] = count($ip_set);
    return $s;
}

function error_log_size($path) {
    if (!$path || !file_exists($path)) return 0;
    return filesize($path);
}

$sites = db_rows("SELECT * FROM backdraft_sites ORDER BY site_name");

// Parse real stats for each site
$site_stats = [];
$total_requests = 0;
$total_bytes = 0;
$total_errors_size = 0;
$total_ips = 0;
$total_4xx = 0;
$total_5xx = 0;

foreach ($sites as &$s) {
    $st = quick_log_stats($s['access_log_path']);
    $st['err_size'] = error_log_size($s['error_log_path']);
    $s['stats'] = $st;
    $total_requests += $st['requests'];
    $total_bytes += $st['bytes'];
    $total_errors_size += $st['err_size'];
    $total_ips += $st['ips'];
    $total_4xx += $st['4xx'];
    $total_5xx += $st['5xx'];
}
unset($s);

// Sort by request count descending for charts
$sites_by_traffic = $sites;
usort($sites_by_traffic, fn($a, $b) => $b['stats']['requests'] - $a['stats']['requests']);
$top_sites = array_slice($sites_by_traffic, 0, 15);
?>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div>
        <h2 style="font-size:18px;font-weight:700;display:flex;align-items:center;gap:10px">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg>
            Log Analytics
        </h2>
        <p style="font-size:12px;color:var(--muted)"><?= count($sites) ?> sites discovered — real-time stats from nginx access logs</p>
    </div>
</div>

<!-- Global stat cards -->
<div class="stat-grid" style="margin-bottom:24px">
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(245,158,11,.15),rgba(245,158,11,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        </div>
        <div><div class="stat-val" style="color:var(--amber)"><?= number_format($total_requests) ?></div><div class="stat-label">Total Requests</div></div>
    </div>
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(8,145,178,.15),rgba(8,145,178,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
        </div>
        <div><div class="stat-val" style="color:var(--cyan)"><?= $total_bytes > 1073741824 ? number_format($total_bytes/1073741824,1).' GB' : number_format($total_bytes/1048576,1).' MB' ?></div><div class="stat-label">Bandwidth</div></div>
    </div>
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(168,85,247,.15),rgba(168,85,247,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2"/><circle cx="9" cy="7" r="4"/></svg>
        </div>
        <div><div class="stat-val" style="color:#a855f7"><?= number_format($total_ips) ?></div><div class="stat-label">Unique IPs</div></div>
    </div>
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(239,68,68,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>
        </div>
        <div><div class="stat-val" style="color:var(--red)"><?= number_format($total_4xx + $total_5xx) ?></div><div class="stat-label">Errors (4xx+5xx)</div></div>
    </div>
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(34,197,94,.15),rgba(34,197,94,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div><div class="stat-val" style="color:var(--green)"><?= count($sites) ?></div><div class="stat-label">Monitored Sites</div></div>
    </div>
    <div class="stat-card" style="display:flex;gap:14px;align-items:center">
        <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,rgba(249,115,22,.15),rgba(249,115,22,.05));display:flex;align-items:center;justify-content:center">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
        </div>
        <div><div class="stat-val" style="color:#f97316"><?= number_format($total_errors_size/1048576,1) ?> MB</div><div class="stat-label">Error Logs Total</div></div>
    </div>
</div>

<!-- Charts -->
<div style="display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px">
    <div class="card">
        <div class="card-title">Requests by Site (Top 15)</div>
        <canvas id="siteTrafficChart" style="max-height:350px"></canvas>
    </div>
    <div class="card">
        <div class="card-title">Status Code Distribution (All Sites)</div>
        <canvas id="statusChart" style="max-height:350px"></canvas>
    </div>
</div>

<!-- Per-site table -->
<div class="card">
    <div class="card-title">All Sites — Live Log Stats</div>
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Site</th>
                    <th>Requests</th>
                    <th>Bandwidth</th>
                    <th>IPs</th>
                    <th>2xx</th>
                    <th>4xx</th>
                    <th>5xx</th>
                    <th>Log Size</th>
                    <th>Error Log</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($sites_by_traffic as $s):
                $st = $s['stats'];
                if ($st['requests'] == 0 && $st['size'] == 0) continue; // Skip sites with no log
            ?>
                <tr>
                    <td style="font-weight:600"><a href="/site-report.php?id=<?= $s['id'] ?>" style="color:var(--amber)"><?= h($s['site_name']) ?></a></td>
                    <td style="font-family:var(--font-mono);font-weight:600"><?= number_format($st['requests']) ?></td>
                    <td style="font-family:var(--font-mono);font-size:12px;color:var(--muted)"><?= $st['bytes'] > 1048576 ? number_format($st['bytes']/1048576,1).'M' : number_format($st['bytes']/1024,0).'K' ?></td>
                    <td style="color:#a855f7"><?= $st['ips'] ?></td>
                    <td style="color:var(--green)"><?= number_format($st['2xx']) ?></td>
                    <td style="color:<?= $st['4xx'] > 0 ? 'var(--amber)' : 'var(--muted)' ?>"><?= $st['4xx'] ?></td>
                    <td style="color:<?= $st['5xx'] > 0 ? 'var(--red)' : 'var(--muted)' ?>"><?= $st['5xx'] ?></td>
                    <td style="font-size:11px;color:var(--muted)"><?= number_format($st['size']/1048576,1) ?> MB</td>
                    <td style="font-size:11px;color:<?= $st['err_size'] > 0 ? 'var(--red)' : 'var(--muted)' ?>"><?= $st['err_size'] > 0 ? number_format($st['err_size']/1048576,1).' MB' : '—' ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#334155';
Chart.defaults.font.family = "'Inter',system-ui,sans-serif";

// Site traffic bar chart
new Chart(document.getElementById('siteTrafficChart'), {
    type: 'bar',
    data: {
        labels: <?= json_encode(array_map(fn($s) => $s['site_name'], $top_sites)) ?>,
        datasets: [{
            label: 'Requests',
            data: <?= json_encode(array_map(fn($s) => $s['stats']['requests'], $top_sites)) ?>,
            backgroundColor: 'rgba(245,158,11,0.5)',
            borderColor: '#f59e0b',
            borderWidth: 1,
            borderRadius: 4,
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
            x: { beginAtZero: true, grid: { display: false } },
            y: { ticks: { font: { size: 11 } } }
        }
    }
});

// Status code doughnut
new Chart(document.getElementById('statusChart'), {
    type: 'doughnut',
    data: {
        labels: ['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error'],
        datasets: [{
            data: [
                <?= array_sum(array_column(array_column($sites, 'stats'), '2xx')) ?>,
                <?= array_sum(array_column(array_column($sites, 'stats'), '3xx')) ?>,
                <?= $total_4xx ?>,
                <?= $total_5xx ?>
            ],
            backgroundColor: ['#22c55e', '#0891b2', '#f59e0b', '#ef4444'],
            borderWidth: 0,
            hoverOffset: 8,
        }]
    },
    options: {
        responsive: true,
        cutout: '55%',
        plugins: {
            legend: { position: 'bottom', labels: { padding: 14, usePointStyle: true, pointStyle: 'circle' } }
        }
    }
});
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

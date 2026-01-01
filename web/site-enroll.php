<?php
/**
 * site-enroll.php — WAF Enrollment for a specific site
 * Flow: Select pages → Auto-deploy nginx config → Activate
 */
$page_title = 'WAF Enrollment';
$active_nav = 'sites';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

if (!bd_is_admin()) {
    echo '<div class="card" style="text-align:center;padding:40px;color:var(--red)">Admin access required</div>';
    require_once __DIR__ . '/app/inc/footer.php';
    return;
}

$site_id = intval($_GET['id'] ?? 0);
$site = $site_id ? db_row("SELECT * FROM backdraft_sites WHERE id = ?", [$site_id]) : null;

if (!$site) {
    echo '<div class="card" style="text-align:center;padding:40px;color:var(--red)">Site not found. <a href="/sites.php">Back to Sites</a></div>';
    require_once __DIR__ . '/app/inc/footer.php';
    return;
}

$doc_root = $site['doc_root'];
$site_name = $site['site_name'];

// Scan document root for servable files
$site_files = [];
if ($doc_root && is_dir($doc_root)) {
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($doc_root, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iter as $file) {
        if (!$file->isFile()) continue;
        $ext = strtolower($file->getExtension());
        if ($ext !== 'php') continue; // Only PHP files can be WAF-proxied (HTML goes direct through nginx)
        $rel = str_replace($doc_root, '', $file->getPathname());
        if (strpos($rel, '/.') !== false) continue;
        if (strpos($rel, '/vendor/') !== false) continue;
        if (strpos($rel, '/node_modules/') !== false) continue;
        $site_files[] = $rel;
    }
    sort($site_files);
}

// Load already enrolled pages
$enrolled_pages = db_rows("SELECT * FROM backdraft_page_profiles WHERE site_id = ?", [$site_id]);
$enrolled_map = [];
foreach ($enrolled_pages as $ep) $enrolled_map[$ep['page_id']] = $ep;

// Check current nginx config state
$conf_dir = "/etc/nginx/backdraft.d/sites/{$site_name}";
$conf_file = "{$conf_dir}/{$site_name}.conf";
$conf_exists = file_exists($conf_file);
$dir_exists = is_dir($conf_dir);

// Check if site nginx config has the wildcard include
$has_include = false;
if ($site['config_path'] && file_exists($site['config_path'])) {
    $nginx_content = file_get_contents($site['config_path']);
    $has_include = (strpos($nginx_content, "backdraft.d/sites/{$site_name}") !== false);
}
?>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div>
        <h2 style="font-size:18px;font-weight:700">WAF Enrollment — <?= h($site_name) ?></h2>
        <p style="font-size:12px;color:var(--muted)">
            Document root: <code style="color:var(--amber)"><?= h($doc_root ?: 'Not detected') ?></code>
            &middot; <?= count($site_files) ?> servable files
            &middot; <?= count($enrolled_pages) ?> already enrolled
        </p>
    </div>
    <a href="/sites.php" class="btn btn-ghost">Back to Sites</a>
</div>

<!-- Status Cards -->
<div class="stat-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
    <div class="stat-card <?= $dir_exists ? 'stat-green' : 'stat-muted' ?>">
        <div class="stat-val" style="font-size:18px"><?= $dir_exists ? 'Ready' : 'Missing' ?></div>
        <div class="stat-label">Config Directory</div>
    </div>
    <div class="stat-card <?= $conf_exists ? 'stat-green' : 'stat-muted' ?>">
        <div class="stat-val" style="font-size:18px"><?= $conf_exists ? 'Generated' : 'None' ?></div>
        <div class="stat-label">WAF Config</div>
    </div>
    <div class="stat-card <?= $has_include ? 'stat-green' : 'stat-amber' ?>">
        <div class="stat-val" style="font-size:18px"><?= $has_include ? 'Active' : 'Missing' ?></div>
        <div class="stat-label">nginx Include</div>
    </div>
    <div class="stat-card <?= $site['waf_enabled'] ? 'stat-green' : 'stat-muted' ?>">
        <div class="stat-val" style="font-size:18px"><?= $site['waf_enabled'] ? strtoupper($site['waf_mode']) : 'Off' ?></div>
        <div class="stat-label">WAF Status</div>
    </div>
</div>

<!-- Page Selection -->
<div class="card" style="margin-bottom:20px">
    <div class="card-title">1. Select Pages to Protect</div>
    <?php if (empty($site_files)): ?>
        <div style="text-align:center;color:var(--muted);padding:30px">
            <?= !$doc_root ? 'Document root not detected. Check nginx config has a <code>root</code> directive.' : 'No PHP/HTML files found in webroot.' ?>
        </div>
    <?php else: ?>
        <div style="margin-bottom:12px;display:flex;gap:8px">
            <button type="button" class="btn btn-ghost" onclick="toggleAll(true)">Select All</button>
            <button type="button" class="btn btn-ghost" onclick="toggleAll(false)">Deselect All</button>
            <input type="text" id="filterInput" placeholder="Filter files..." style="flex:1;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px">
        </div>
        <div style="max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-sm)">
            <?php foreach ($site_files as $f):
                $page_id = $site_name . $f;
                $is_enrolled = isset($enrolled_map[$page_id]);
            ?>
            <label class="file-row" data-path="<?= h(strtolower($f)) ?>" style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--border2);cursor:pointer;transition:background .1s;font-size:13px">
                <input type="checkbox" name="pages[]" value="<?= h($f) ?>" <?= $is_enrolled ? 'checked' : '' ?>>
                <code style="color:<?= $is_enrolled ? 'var(--amber)' : 'var(--text)' ?>;font-size:12px"><?= h($f) ?></code>
                <?php if ($is_enrolled): ?>
                    <span class="badge badge-green" style="margin-left:auto">Enrolled</span>
                <?php endif; ?>
            </label>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Deploy -->
<div class="card">
    <div class="card-title">2. Deploy WAF Configuration</div>
    <p style="font-size:13px;color:var(--text-dim);margin-bottom:16px">
        BackDraft will automatically:
    </p>
    <ul style="margin:0 0 16px 20px;font-size:13px;color:var(--text-dim);line-height:2">
        <li>Create page profiles for selected pages</li>
        <li>Generate nginx WAF proxy config at <code style="color:var(--amber)"><?= h($conf_dir) ?>/*.conf</code></li>
        <li>Inject the wildcard include into your site's nginx config (if not already present)</li>
        <li>Test the nginx config (<code>sudo nginx -t</code>)</li>
        <li>Reload nginx (<code>sudo nginx -s reload</code>)</li>
        <li>Enable WAF in learning mode</li>
    </ul>

    <div id="deployStatus" style="display:none;padding:14px;border-radius:var(--radius-sm);margin-bottom:16px"></div>

    <div style="display:flex;gap:8px">
        <button class="btn btn-amber" id="deployBtn" onclick="deployWaf()">Deploy WAF Config & Activate</button>
        <?php if ($conf_exists): ?>
        <button class="btn btn-ghost" onclick="deployWaf()">Re-deploy (regenerate config)</button>
        <?php endif; ?>
    </div>
</div>

<script>
function toggleAll(checked) {
    document.querySelectorAll('input[name="pages[]"]').forEach(cb => cb.checked = checked);
}

document.getElementById('filterInput')?.addEventListener('input', function() {
    const q = this.value.toLowerCase();
    document.querySelectorAll('.file-row').forEach(row => {
        row.style.display = row.dataset.path.includes(q) ? 'flex' : 'none';
    });
});

async function deployWaf() {
    const checked = Array.from(document.querySelectorAll('input[name="pages[]"]:checked')).map(cb => cb.value);
    if (checked.length === 0) { bdToast('Select at least one page', 'error'); return; }

    const btn = document.getElementById('deployBtn');
    const status = document.getElementById('deployStatus');
    btn.disabled = true;
    btn.textContent = 'Deploying...';
    status.style.display = 'block';
    status.style.background = 'rgba(245,158,11,.08)';
    status.style.border = '1px solid rgba(245,158,11,.2)';
    status.innerHTML = '<strong style="color:var(--amber)">Step 1/4:</strong> Saving page selections...';

    try {
        // Step 1: Save protected paths + enable WAF
        const saveRes = await bdApi('POST', '/api/sites', {
            id: <?= $site_id ?>,
            waf_enabled: 1,
            waf_mode: 'learning',
            log_analysis: 1,
            protected_paths: JSON.stringify(checked)
        });
        if (!saveRes.ok) throw new Error('Failed to save: ' + (saveRes.error || ''));

        // Step 2: Create page profiles for each selected page
        status.innerHTML = '<strong style="color:var(--amber)">Step 2/4:</strong> Creating page profiles...';
        for (const page of checked) {
            const pageId = '<?= h($site_name) ?>' + page;
            const form = new FormData();
            form.append('action', 'save_profile');
            form.append('page_id', pageId);
            form.append('display_name', page.replace(/^\//, ''));
            form.append('site_id', '<?= $site_id ?>');
            form.append('monitoring', '1');
            await fetch('/app/api/pages.php', { method: 'POST', body: form });
        }

        // Step 3: Deploy nginx config (auto-write + test + reload)
        status.innerHTML = '<strong style="color:var(--amber)">Step 3/4:</strong> Generating nginx config & reloading...';
        const deployRes = await bdApi('POST', '/api/sites/deploy', {
            site_name: '<?= h($site_name) ?>'
        });

        if (!deployRes.ok) throw new Error(deployRes.error || 'Deploy failed');

        // Step 4: Done
        status.style.background = 'rgba(34,197,94,.08)';
        status.style.border = '1px solid rgba(34,197,94,.2)';
        status.innerHTML = '<strong style="color:var(--green)">Deployed!</strong> ' + deployRes.message +
            '<br><span style="font-size:12px;color:var(--muted)">' + checked.length + ' pages protected. Redirecting...</span>';

        btn.textContent = 'Deployed!';
        setTimeout(() => window.location.href = '/sites.php', 2000);

    } catch (e) {
        status.style.background = 'rgba(239,68,68,.08)';
        status.style.border = '1px solid rgba(239,68,68,.2)';
        status.innerHTML = '<strong style="color:var(--red)">Error:</strong> ' + e.message;
        btn.disabled = false;
        btn.textContent = 'Retry Deploy';
    }
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

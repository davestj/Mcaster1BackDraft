<?php
$page_title = 'Agents';
$active_nav = 'agents';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$agents = db_rows("SELECT * FROM backdraft_agent_signatures ORDER BY classification, name");

$by_class = [];
foreach ($agents as $a) {
    $by_class[$a['classification']][] = $a;
}

$class_colors = [
    'scanner' => 'red', 'bot' => 'amber', 'crawler' => 'green',
    'library' => 'muted', 'browser' => 'green', 'unknown' => 'muted'
];
?>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div>
        <h2 style="font-size:18px;font-weight:700">Agent Signatures</h2>
        <p style="font-size:12px;color:var(--muted)"><?= count($agents) ?> signatures loaded — classifying user agents</p>
    </div>
</div>

<div class="stat-grid" style="margin-bottom:24px">
    <?php foreach ($by_class as $cls => $items): ?>
    <div class="stat-card stat-<?= $class_colors[$cls] ?? 'muted' ?>">
        <div class="stat-val"><?= count($items) ?></div>
        <div class="stat-label"><?= strtoupper($cls) ?></div>
    </div>
    <?php endforeach; ?>
</div>

<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Classification</th>
                    <th>Pattern</th>
                    <th>Match</th>
                    <th>Disposition</th>
                    <th>Active</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($agents as $a): ?>
                <tr>
                    <td style="font-weight:600"><?= h($a['name']) ?></td>
                    <td><span class="badge badge-<?= $class_colors[$a['classification']] ?? 'muted' ?>"><?= h($a['classification']) ?></span></td>
                    <td style="font-family:var(--font-mono);font-size:12px"><?= h($a['pattern']) ?></td>
                    <td style="font-size:12px;color:var(--muted)"><?= h($a['match_type']) ?></td>
                    <td><span class="badge badge-<?= $a['disposition'] === 'block' ? 'red' : ($a['disposition'] === 'allow' ? 'green' : 'amber') ?>"><?= h($a['disposition']) ?></span></td>
                    <td><?= $a['active'] ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-muted">No</span>' ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

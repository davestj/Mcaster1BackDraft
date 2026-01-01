<?php
$page_title = 'WAF Rules';
$active_nav = 'rules';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$rules = db_rows("SELECT * FROM backdraft_rules ORDER BY sort_order, id");
$active_count = 0;
$total_score = 0;
foreach ($rules as $r) {
    if ($r['active']) { $active_count++; $total_score += $r['score']; }
}
?>

<style>
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:24px;width:100%;max-width:600px;max-height:90vh;overflow-y:auto}
.modal-title{font-size:16px;font-weight:700;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.form-row{margin-bottom:14px}
.form-label{display:block;font-size:11px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
.form-input{width:100%;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;font-family:inherit}
.form-input:focus{outline:none;border-color:var(--amber)}
select.form-input{appearance:auto}
.form-row-half{display:grid;grid-template-columns:1fr 1fr;gap:12px}
</style>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
    <div>
        <h2 style="font-size:18px;font-weight:700">WAF Rules</h2>
        <p style="font-size:12px;color:var(--muted)"><?= $active_count ?> active rules — avg score <?= $active_count ? round($total_score / $active_count) : 0 ?></p>
    </div>
    <button class="btn btn-amber" onclick="openRuleModal()">+ New Rule</button>
</div>

<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Operator</th>
                    <th>Value</th>
                    <th>Action</th>
                    <th>Score</th>
                    <th>Active</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($rules as $r): ?>
                <tr>
                    <td style="color:var(--muted)"><?= $r['id'] ?></td>
                    <td style="font-weight:600"><?= h($r['name']) ?></td>
                    <td><span class="badge badge-<?= $r['rule_type'] === 'builtin' ? 'amber' : ($r['rule_type'] === 'learned' ? 'green' : 'muted') ?>"><?= h($r['rule_type']) ?></span></td>
                    <td style="font-size:12px"><?= h($r['target']) ?></td>
                    <td style="font-size:12px;color:var(--muted)"><?= h($r['operator']) ?></td>
                    <td style="font-family:var(--font-mono);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis"><?= h($r['value']) ?></td>
                    <td><span class="badge badge-<?= $r['action'] === 'block' ? 'red' : ($r['action'] === 'flag' ? 'amber' : 'muted') ?>"><?= h($r['action']) ?></span></td>
                    <td style="font-weight:700;color:<?= $r['score'] >= 80 ? 'var(--red)' : ($r['score'] >= 50 ? 'var(--amber)' : 'var(--muted)') ?>"><?= $r['score'] ?></td>
                    <td><?= $r['active'] ? '<span class="badge badge-green">On</span>' : '<span class="badge badge-muted">Off</span>' ?></td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick='editRule(<?= json_encode($r) ?>)'>Edit</button>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px;color:var(--red)" onclick="deleteRule(<?= $r['id'] ?>)">Del</button>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Rule Modal -->
<div class="modal-overlay" id="ruleModal">
    <div class="modal-box">
        <div class="modal-title" id="ruleModalTitle">New Rule</div>
        <form id="ruleForm">
            <input type="hidden" id="rule_id" value="0">
            <div class="form-row">
                <label class="form-label">Name</label>
                <input type="text" id="rule_name" class="form-input" required placeholder="SQL Injection — UNION">
            </div>
            <div class="form-row">
                <label class="form-label">Description</label>
                <input type="text" id="rule_desc" class="form-input" placeholder="Optional description">
            </div>
            <div class="form-row-half">
                <div class="form-row">
                    <label class="form-label">Target</label>
                    <select id="rule_target" class="form-input">
                        <option value="query">Query String</option>
                        <option value="path">Path</option>
                        <option value="body">Body</option>
                        <option value="header">Header</option>
                        <option value="agent">User Agent</option>
                        <option value="ip">IP Address</option>
                        <option value="method">HTTP Method</option>
                        <option value="cookie">Cookie</option>
                    </select>
                </div>
                <div class="form-row">
                    <label class="form-label">Field <span style="font-weight:400;color:var(--muted)">(for header/cookie)</span></label>
                    <input type="text" id="rule_field" class="form-input" placeholder="e.g. X-Custom-Header">
                </div>
            </div>
            <div class="form-row-half">
                <div class="form-row">
                    <label class="form-label">Operator</label>
                    <select id="rule_operator" class="form-input">
                        <option value="contains">Contains</option>
                        <option value="not_contains">Not Contains</option>
                        <option value="regex">Regex</option>
                        <option value="equals">Equals</option>
                        <option value="not_equals">Not Equals</option>
                        <option value="starts_with">Starts With</option>
                        <option value="ends_with">Ends With</option>
                        <option value="gt">Greater Than</option>
                        <option value="lt">Less Than</option>
                    </select>
                </div>
                <div class="form-row">
                    <label class="form-label">Action</label>
                    <select id="rule_action" class="form-input">
                        <option value="log">Log</option>
                        <option value="flag">Flag</option>
                        <option value="block">Block</option>
                        <option value="challenge">Challenge</option>
                        <option value="rate_limit">Rate Limit</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <label class="form-label">Value / Pattern</label>
                <input type="text" id="rule_value" class="form-input" required placeholder="(?i)union\s+select or ../  etc." style="font-family:var(--font-mono)">
            </div>
            <div class="form-row-half">
                <div class="form-row">
                    <label class="form-label">Score (0-100)</label>
                    <input type="number" id="rule_score" class="form-input" value="50" min="0" max="100">
                </div>
                <div class="form-row">
                    <label class="form-label">Sort Order</label>
                    <input type="number" id="rule_sort" class="form-input" value="100" min="0">
                </div>
            </div>
            <div class="form-row" style="display:flex;align-items:center;gap:8px">
                <input type="checkbox" id="rule_active" checked>
                <label for="rule_active" style="font-size:13px;cursor:pointer">Active</label>
            </div>
            <div style="display:flex;gap:8px;margin-top:20px">
                <button type="submit" class="btn btn-amber">Save Rule</button>
                <button type="button" class="btn btn-ghost" onclick="closeRuleModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
function openRuleModal(data) {
    document.getElementById('ruleModalTitle').textContent = data ? 'Edit Rule' : 'New Rule';
    document.getElementById('rule_id').value = data ? data.id : 0;
    document.getElementById('rule_name').value = data ? data.name : '';
    document.getElementById('rule_desc').value = data ? (data.description || '') : '';
    document.getElementById('rule_target').value = data ? data.target : 'query';
    document.getElementById('rule_field').value = data ? data.field : '';
    document.getElementById('rule_operator').value = data ? data.operator : 'contains';
    document.getElementById('rule_action').value = data ? data.action : 'log';
    document.getElementById('rule_value').value = data ? data.value : '';
    document.getElementById('rule_score').value = data ? data.score : 50;
    document.getElementById('rule_sort').value = data ? data.sort_order : 100;
    document.getElementById('rule_active').checked = data ? !!data.active : true;
    document.getElementById('ruleModal').classList.add('open');
}

function editRule(data) { openRuleModal(data); }

function closeRuleModal() { document.getElementById('ruleModal').classList.remove('open'); }

document.getElementById('ruleForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const data = {
        id: parseInt(document.getElementById('rule_id').value),
        name: document.getElementById('rule_name').value,
        description: document.getElementById('rule_desc').value,
        rule_type: 'custom',
        target: document.getElementById('rule_target').value,
        field: document.getElementById('rule_field').value,
        operator: document.getElementById('rule_operator').value,
        action: document.getElementById('rule_action').value,
        value: document.getElementById('rule_value').value,
        score: parseInt(document.getElementById('rule_score').value),
        sort_order: parseInt(document.getElementById('rule_sort').value),
        active: document.getElementById('rule_active').checked ? 1 : 0
    };
    const res = await bdApi('POST', '/api/rules', data);
    if (res.ok) {
        bdToast(res.message || 'Rule saved', 'success');
        closeRuleModal();
        setTimeout(() => location.reload(), 500);
    }
});

async function deleteRule(id) {
    if (!confirm('Delete this rule?')) return;
    const res = await bdApi('DELETE', '/api/rules/' + id);
    if (res.ok) {
        bdToast('Rule deleted', 'success');
        setTimeout(() => location.reload(), 500);
    }
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

<?php
$page_title = 'Task Scheduler';
$active_nav = 'tasks';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$is_admin = bd_is_admin();

// ── Main page data ───────────────────────────────────────────────────────
$tasks = db_rows(
    "SELECT t.*, (SELECT COUNT(*) FROM backdraft_task_runs r WHERE r.task_id = t.task_id) as total_runs,
            (SELECT status FROM backdraft_task_runs r WHERE r.task_id = t.task_id ORDER BY r.started_at DESC LIMIT 1) as last_status
     FROM backdraft_tasks t
     ORDER BY FIELD(t.priority, 'critical','high','normal','low'), t.name"
);

$total_tasks   = count($tasks);
$enabled_count = count(array_filter($tasks, fn($t) => $t['enabled']));
$running_count = (int)db_scalar("SELECT COUNT(*) FROM backdraft_task_runs WHERE status = 'running'");
$total_runs    = (int)db_scalar("SELECT COUNT(*) FROM backdraft_task_runs");
?>

<style>
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:600px;max-height:80vh;overflow-y:auto;box-shadow:0 16px 48px rgba(0,0,0,.5)}
.modal h3{font-size:16px;font-weight:700;margin-bottom:20px;color:var(--amber)}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:12px;font-weight:600;color:var(--text-dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.form-group input,.form-group select,.form-group textarea{
  width:100%;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-size:13px;
}
.form-group textarea{min-height:80px;resize:vertical}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}

.priority-critical{color:var(--red)}
.priority-high{color:var(--amber)}
.priority-normal{color:var(--text)}
.priority-low{color:var(--muted)}

.sched-help{font-size:11px;color:var(--muted);margin-top:4px}

.run-output{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;font-family:var(--font-mono);font-size:11px;white-space:pre-wrap;max-height:300px;overflow-y:auto;color:var(--text-dim);margin-top:8px}
</style>

<!-- Stat Cards -->
<div class="stat-grid">
    <div class="stat-card stat-amber"><div class="stat-val"><?= $total_tasks ?></div><div class="stat-label">Total Tasks</div></div>
    <div class="stat-card stat-green"><div class="stat-val"><?= $enabled_count ?></div><div class="stat-label">Enabled</div></div>
    <div class="stat-card stat-cyan"><div class="stat-val"><?= $running_count ?></div><div class="stat-label">Running Now</div></div>
    <div class="stat-card"><div class="stat-val"><?= number_format($total_runs) ?></div><div class="stat-label">Total Runs</div></div>
</div>

<!-- Schedule Format Help -->
<div class="card" style="margin-bottom:20px;padding:12px 20px;background:var(--bg3);border-color:var(--border2)">
    <span style="font-size:12px;color:var(--muted)">Schedule formats: <code style="color:var(--amber)">30s</code> (seconds) <code style="color:var(--amber)">15m</code> (minutes) <code style="color:var(--amber)">2h</code> (hours) <code style="color:var(--amber)">24h</code> (daily) — Scheduler checks every 1 second for precision timing</span>
</div>

<!-- Header + Create Button -->
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">Scheduled Tasks</h2>
    <?php if ($is_admin): ?>
    <button class="btn btn-amber" onclick="openCreateModal()">+ New Task</button>
    <?php endif; ?>
</div>

<!-- Task List -->
<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>Task</th>
                    <th>Type</th>
                    <th>Schedule</th>
                    <th>Priority</th>
                    <th>Status</th>
                    <th>Last Run</th>
                    <th>Next Run</th>
                    <th>Runs</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($tasks as $t): ?>
                <tr>
                    <td>
                        <div style="font-weight:600"><?= h($t['name']) ?></div>
                        <div style="font-size:11px;color:var(--muted)"><?= h($t['task_id']) ?> &mdash; <?= h($t['handler']) ?></div>
                    </td>
                    <td><span class="badge badge-muted"><?= h($t['task_type']) ?></span></td>
                    <td style="font-family:var(--font-mono);font-size:12px"><?= h($t['schedule']) ?></td>
                    <td><span class="priority-<?= $t['priority'] ?>" style="font-weight:700;text-transform:uppercase;font-size:11px"><?= h($t['priority']) ?></span></td>
                    <td>
                        <?php if ($t['enabled']): ?>
                            <span class="badge badge-green">Enabled</span>
                        <?php else: ?>
                            <span class="badge badge-muted">Disabled</span>
                        <?php endif; ?>
                        <?php if ($t['last_status'] === 'running'): ?>
                            <span class="badge badge-amber" style="margin-left:4px">Running</span>
                        <?php elseif ($t['last_status'] === 'failed'): ?>
                            <span class="badge badge-red" style="margin-left:4px">Failed</span>
                        <?php endif; ?>
                    </td>
                    <td style="font-size:11px;font-family:var(--font-mono);white-space:nowrap"><?= h($t['last_run_at'] ?? 'Never') ?></td>
                    <td style="font-size:11px;font-family:var(--font-mono);white-space:nowrap"><?= h($t['next_run_at'] ?? 'Pending') ?></td>
                    <td style="font-weight:600"><?= $t['total_runs'] ?></td>
                    <td style="white-space:nowrap">
                        <?php if ($is_admin): ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="editTask(<?= $t['id'] ?>, <?= h(json_encode($t)) ?>)" title="Edit">Edit</button>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="runNow('<?= h($t['task_id']) ?>')" title="Run Now">Run</button>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="toggleTask('<?= h($t['task_id']) ?>')"><?= $t['enabled'] ? 'Disable' : 'Enable' ?></button>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="viewHistory('<?= h($t['task_id']) ?>')" title="Run History">History</button>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px;color:var(--red)" onclick="deleteTask('<?= h($t['task_id']) ?>', '<?= h($t['name']) ?>')" title="Delete">Del</button>
                        <?php else: ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="viewHistory('<?= h($t['task_id']) ?>')">History</button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if (empty($tasks)): ?>
                <tr><td colspan="9" style="text-align:center;color:var(--muted);padding:40px">No tasks configured — create your first scheduled task</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Create/Edit Task Modal -->
<div class="modal-overlay" id="taskModal">
    <div class="modal">
        <h3 id="modalTitle">Create New Task</h3>
        <form id="taskForm" onsubmit="submitTaskForm(event)">
            <input type="hidden" name="action" id="formAction" value="create_task">
            <input type="hidden" name="id" id="formId" value="">

            <div class="form-group" id="taskIdGroup">
                <label>Task ID (unique slug)</label>
                <input type="text" name="task_id" id="taskIdField" placeholder="e.g. my_custom_report" pattern="[a-z0-9_-]{3,64}" required>
            </div>

            <div class="form-group">
                <label>Name</label>
                <input type="text" name="name" id="taskName" placeholder="Task display name" required>
            </div>

            <div class="form-group">
                <label>Description</label>
                <textarea name="description" id="taskDesc" placeholder="What does this task do?"></textarea>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Type</label>
                    <select name="task_type" id="taskType">
                        <option value="report">Report</option>
                        <option value="analysis">Analysis</option>
                        <option value="maintenance">Maintenance</option>
                        <option value="alert">Alert</option>
                        <option value="custom">Custom</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Priority</label>
                    <select name="priority" id="taskPriority">
                        <option value="low">Low</option>
                        <option value="normal" selected>Normal</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                    </select>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Schedule</label>
                    <input type="text" name="schedule" id="taskSchedule" placeholder="e.g. 24h, 15m, 1h" value="24h" required>
                    <div class="sched-help">30s, 15m, 2h, 24h, 7d</div>
                </div>
                <div class="form-group">
                    <label>Handler (PHP script)</label>
                    <input type="text" name="handler" id="taskHandler" placeholder="e.g. my-handler.php" required>
                </div>
            </div>

            <div class="form-group">
                <label>Parameters (JSON)</label>
                <textarea name="params" id="taskParams" placeholder='{"key": "value"}' style="min-height:60px;font-family:var(--font-mono)">{}</textarea>
            </div>

            <div class="form-group">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                    <input type="checkbox" name="enabled" id="taskEnabled" checked style="width:auto">
                    <span>Enabled</span>
                </label>
            </div>

            <div class="form-actions">
                <button type="button" class="btn btn-ghost" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-amber" id="submitBtn">Create Task</button>
            </div>
        </form>
    </div>
</div>

<!-- Run History Modal -->
<div class="modal-overlay" id="historyModal">
    <div class="modal" style="width:700px">
        <h3 id="historyTitle">Run History</h3>
        <div id="historyContent" style="color:var(--muted);text-align:center;padding:30px">Loading...</div>
        <div class="form-actions">
            <button type="button" class="btn btn-ghost" onclick="closeHistory()">Close</button>
        </div>
    </div>
</div>

<script>
function openCreateModal() {
    document.getElementById('modalTitle').textContent = 'Create New Task';
    document.getElementById('formAction').value = 'create_task';
    document.getElementById('formId').value = '';
    document.getElementById('submitBtn').textContent = 'Create Task';
    document.getElementById('taskIdGroup').style.display = '';
    document.getElementById('taskForm').reset();
    document.getElementById('taskParams').value = '{}';
    document.getElementById('taskEnabled').checked = true;
    document.getElementById('taskModal').classList.add('open');
}

function editTask(id, data) {
    document.getElementById('modalTitle').textContent = 'Edit Task: ' + data.name;
    document.getElementById('formAction').value = 'save_task';
    document.getElementById('formId').value = id;
    document.getElementById('submitBtn').textContent = 'Save Changes';
    document.getElementById('taskIdGroup').style.display = 'none';
    document.getElementById('taskIdField').removeAttribute('required');
    document.getElementById('taskName').value = data.name;
    document.getElementById('taskDesc').value = data.description || '';
    document.getElementById('taskType').value = data.task_type;
    document.getElementById('taskPriority').value = data.priority;
    document.getElementById('taskSchedule').value = data.schedule;
    document.getElementById('taskHandler').value = data.handler;
    document.getElementById('taskParams').value = typeof data.params === 'string' ? data.params : JSON.stringify(data.params || {});
    document.getElementById('taskEnabled').checked = !!data.enabled;
    document.getElementById('taskModal').classList.add('open');
}

function closeModal() { document.getElementById('taskModal').classList.remove('open'); }

async function submitTaskForm(e) {
    e.preventDefault();
    const f = document.getElementById('taskForm');
    const data = {
        task_id: f.task_id?.value || '',
        name: f.name.value,
        description: f.description?.value || '',
        task_type: f.task_type.value,
        schedule: f.schedule.value,
        handler: f.handler.value,
        params: f.params?.value || '{}',
        priority: f.priority.value,
        enabled: document.getElementById('taskEnabled').checked ? 1 : 0
    };
    const editId = document.getElementById('formId').value;
    if (editId) data.id = parseInt(editId);
    const res = await bdApi('POST', '/api/tasks', data);
    if (res.ok) { bdToast(res.message || 'Saved', 'success'); setTimeout(() => location.reload(), 800); }
}

async function toggleTask(taskId) {
    const res = await bdApi('POST', '/api/tasks/toggle', { task_id: taskId });
    if (res.ok) location.reload();
}

async function runNow(taskId) {
    const res = await bdApi('POST', '/api/tasks/run', { task_id: taskId });
    bdToast(res.message || 'Queued', res.ok ? 'success' : 'error');
    if (res.ok) setTimeout(() => location.reload(), 2000);
}

async function deleteTask(taskId, name) {
    if (!confirm('Delete task "' + name + '" and all its run history?')) return;
    const res = await bdApi('DELETE', '/api/tasks/' + taskId);
    bdToast(res.message || 'Deleted', res.ok ? 'success' : 'error');
    if (res.ok) setTimeout(() => location.reload(), 800);
}

async function viewHistory(taskId) {
    document.getElementById('historyTitle').textContent = 'Run History: ' + taskId;
    document.getElementById('historyContent').innerHTML = '<p style="color:var(--muted);padding:20px">Loading...</p>';
    document.getElementById('historyModal').classList.add('open');

    const resp = await fetch('/api/task-runs?task_id=' + encodeURIComponent(taskId))  // C++ daemon API;
    const json = await resp.json();
    if (!json.ok || !json.data.length) {
        document.getElementById('historyContent').innerHTML = '<p style="color:var(--muted);padding:20px">No runs yet</p>';
        return;
    }

    let html = '<table class="bd-table"><thead><tr><th>ID</th><th>Started</th><th>Ended</th><th>Status</th><th>Exports</th><th>Actions</th></tr></thead><tbody>';
    json.data.forEach(r => {
        const statusColors = { success: 'green', failed: 'red', partial: 'amber', running: 'amber' };
        const badge = '<span class="badge badge-' + (statusColors[r.status] || 'muted') + '">' + r.status + '</span>';
        const exports = r.export_formats ? r.export_formats.split(',').map(f =>
            '<a href="/task-manager.php?export=' + r.id + '&format=' + f.trim() + '" class="btn btn-ghost" style="padding:2px 6px;font-size:10px">' + f.trim().toUpperCase() + '</a>'
        ).join(' ') : '<span style="color:var(--muted);font-size:11px">—</span>';
        html += '<tr><td>' + r.id + '</td><td class="mono" style="font-size:11px">' + (r.started_at||'') + '</td><td class="mono" style="font-size:11px">' + (r.ended_at||'Running...') + '</td><td>' + badge + '</td><td>' + exports + '</td>';
        html += '<td><button class="btn btn-ghost" style="padding:2px 6px;font-size:10px" onclick="viewRunOutput(' + r.id + ')">Log</button></td></tr>';
    });
    html += '</tbody></table>';
    document.getElementById('historyContent').innerHTML = html;
}

function closeHistory() { document.getElementById('historyModal').classList.remove('open'); }

async function viewRunOutput(runId) {
    const resp = await fetch('/api/task-runs/' + runId)  // C++ daemon API;
    const json = await resp.json();
    if (!json.ok) return;
    const r = json.data;
    let html = '<div style="margin-bottom:12px"><strong>Status:</strong> ' + r.status + ' | <strong>Started:</strong> ' + r.started_at + ' | <strong>Ended:</strong> ' + (r.ended_at || 'Running...') + '</div>';
    if (r.error_msg) html += '<div style="color:var(--red);margin-bottom:8px"><strong>Error:</strong> ' + r.error_msg + '</div>';
    html += '<div class="run-output">' + (r.output_log || 'No output').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
    document.getElementById('historyContent').innerHTML = html;
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

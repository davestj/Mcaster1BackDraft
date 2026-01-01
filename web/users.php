<?php
$page_title = 'Users';
$active_nav = 'users';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

if (!bd_is_admin()) {
    echo '<div class="card" style="text-align:center;padding:40px;color:var(--red)">Access denied — admin role required</div>';
    require_once __DIR__ . '/app/inc/footer.php';
    return;
}

// ── Page data ────────────────────────────────────────────────────────────
$users = db_rows("SELECT * FROM backdraft_users ORDER BY id");
$active_count = count(array_filter($users, fn($u) => $u['active']));
$admin_count = count(array_filter($users, fn($u) => in_array($u['role'], ['admin','superadmin'])));
?>

<style>
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:500;display:none;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:100%;max-width:500px;max-height:85vh;overflow-y:auto;box-shadow:0 16px 48px rgba(0,0,0,.5)}
.modal-title{font-size:16px;font-weight:700;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border);color:var(--amber)}
.form-row{margin-bottom:14px}
.form-label{display:block;font-size:11px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}
.form-input{width:100%;padding:9px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;font-family:inherit}
.form-input:focus{outline:none;border-color:var(--amber)}
select.form-input{appearance:auto}
textarea.form-input{min-height:100px;resize:vertical}
.form-row-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:20px}
</style>

<!-- Stat Cards -->
<div class="stat-grid">
    <div class="stat-card stat-amber"><div class="stat-val"><?= count($users) ?></div><div class="stat-label">Total Users</div></div>
    <div class="stat-card stat-green"><div class="stat-val"><?= $active_count ?></div><div class="stat-label">Active</div></div>
    <div class="stat-card stat-red"><div class="stat-val"><?= $admin_count ?></div><div class="stat-label">Admins</div></div>
</div>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="font-size:18px;font-weight:700">User Management</h2>
    <button class="btn btn-amber" onclick="openCreateModal()">+ New User</button>
</div>

<div class="card">
    <div class="table-wrap">
        <table class="bd-table">
            <thead>
                <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Email</th>
                    <th>MFA</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
                <tr>
                    <td>
                        <div style="font-weight:600"><?= h($u['username']) ?></div>
                        <div style="font-size:11px;color:var(--muted)">ID: <?= $u['id'] ?></div>
                    </td>
                    <td><span class="badge badge-<?= $u['role'] === 'superadmin' ? 'red' : ($u['role'] === 'admin' ? 'amber' : 'muted') ?>"><?= h($u['role']) ?></span></td>
                    <td style="font-size:12px"><?= $u['email'] ? h($u['email']) : '<span style="color:var(--muted)">—</span>' ?></td>
                    <td><?= $u['mfa_enabled'] ? '<span class="badge badge-green">On</span>' : '<span class="badge badge-muted">Off</span>' ?></td>
                    <td><?= $u['active'] ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Inactive</span>' ?></td>
                    <td style="font-family:var(--font-mono);font-size:11px;color:var(--muted)"><?= h($u['last_login'] ?: 'Never') ?></td>
                    <td style="font-family:var(--font-mono);font-size:11px;color:var(--muted)"><?= h($u['created_at']) ?></td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="openEditModal(<?= h(json_encode($u)) ?>)">Edit</button>
                        <?php if ($u['email']): ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px" onclick="openEmailModal(<?= $u['id'] ?>, '<?= h($u['username']) ?>', '<?= h($u['email']) ?>')">Email</button>
                        <?php endif; ?>
                        <?php if ($u['active']): ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px;color:var(--red)" onclick="deactivateUser(<?= $u['id'] ?>,'<?= h($u['username']) ?>')">Deactivate</button>
                        <?php else: ?>
                        <button class="btn btn-ghost" style="padding:4px 8px;font-size:11px;color:var(--green)" onclick="reactivateUser(<?= $u['id'] ?>)">Reactivate</button>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Create User Modal -->
<div class="modal-overlay" id="createModal">
    <div class="modal-box">
        <div class="modal-title">Create User</div>
        <form id="createUserForm" onsubmit="submitCreate(event)">
            <div class="form-row">
                <label class="form-label">Username</label>
                <input type="text" id="new_username" class="form-input" required>
            </div>
            <div class="form-row">
                <label class="form-label">Password</label>
                <input type="password" id="new_password" class="form-input" required>
            </div>
            <div class="form-row-grid">
                <div class="form-row">
                    <label class="form-label">Email</label>
                    <input type="email" id="new_email" class="form-input" placeholder="Optional">
                </div>
                <div class="form-row">
                    <label class="form-label">Role</label>
                    <select id="new_role" class="form-input">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                        <option value="superadmin">Super Admin</option>
                    </select>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-ghost" onclick="closeModal('createModal')">Cancel</button>
                <button type="submit" class="btn btn-amber">Create User</button>
            </div>
        </form>
    </div>
</div>

<!-- Edit User Modal -->
<div class="modal-overlay" id="editModal">
    <div class="modal-box">
        <div class="modal-title" id="editTitle">Edit User</div>
        <form id="editUserForm" onsubmit="submitEdit(event)">
            <input type="hidden" id="edit_id">
            <div class="form-row-grid">
                <div class="form-row">
                    <label class="form-label">Email</label>
                    <input type="email" id="edit_email" class="form-input">
                </div>
                <div class="form-row">
                    <label class="form-label">Role</label>
                    <select id="edit_role" class="form-input">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                        <option value="superadmin">Super Admin</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <label class="form-label">New Password (leave blank to keep current)</label>
                <input type="password" id="edit_password" class="form-input" placeholder="Leave blank to keep current">
            </div>
            <div class="form-row-grid">
                <div class="form-row">
                    <label class="form-label">Status</label>
                    <select id="edit_active" class="form-input">
                        <option value="1">Active</option>
                        <option value="0">Inactive</option>
                    </select>
                </div>
                <div class="form-row">
                    <label class="form-label">MFA</label>
                    <select id="edit_mfa" class="form-input">
                        <option value="0">Disabled</option>
                        <option value="1">Enabled</option>
                    </select>
                </div>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-ghost" onclick="closeModal('editModal')">Cancel</button>
                <button type="submit" class="btn btn-amber">Save Changes</button>
            </div>
        </form>
    </div>
</div>

<!-- Email User Modal -->
<div class="modal-overlay" id="emailModal">
    <div class="modal-box">
        <div class="modal-title" id="emailTitle">Send Email</div>
        <form id="emailForm" onsubmit="submitEmail(event)">
            <input type="hidden" id="email_user_id">
            <div class="form-row">
                <label class="form-label">To</label>
                <input type="text" id="email_to_display" class="form-input" readonly style="color:var(--muted)">
            </div>
            <div class="form-row">
                <label class="form-label">Subject</label>
                <input type="text" id="email_subject" class="form-input" required placeholder="e.g. BackDraft WAF Alert">
            </div>
            <div class="form-row">
                <label class="form-label">Message (HTML supported)</label>
                <textarea id="email_body" class="form-input" required placeholder="Your message here..."></textarea>
            </div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:12px">
                Email is sent via SMTP (<?= h(BD_SMTP_HOST) ?>) from <?= h(BD_SMTP_FROM_NAME) ?> &lt;<?= h(BD_SMTP_FROM) ?>&gt;. Message is wrapped in BackDraft-branded HTML template.
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-ghost" onclick="closeModal('emailModal')">Cancel</button>
                <button type="submit" class="btn btn-amber" id="emailSendBtn">Send Email</button>
            </div>
        </form>
    </div>
</div>

<script>
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// ── Create ───────────────────────────────────────────────────────────────
function openCreateModal() { document.getElementById('createModal').classList.add('open'); }

async function submitCreate(e) {
    e.preventDefault();
    const res = await bdApi('POST', '/api/users', {
        username: document.getElementById('new_username').value,
        password: document.getElementById('new_password').value,
        email: document.getElementById('new_email').value,
        role: document.getElementById('new_role').value
    });
    if (res.ok) {
        bdToast('User created', 'success');
        closeModal('createModal');
        setTimeout(() => location.reload(), 500);
    }
}

// ── Edit ─────────────────────────────────────────────────────────────────
function openEditModal(user) {
    document.getElementById('editTitle').textContent = 'Edit User: ' + user.username;
    document.getElementById('edit_id').value = user.id;
    document.getElementById('edit_email').value = user.email || '';
    document.getElementById('edit_role').value = user.role;
    document.getElementById('edit_password').value = '';
    document.getElementById('edit_active').value = user.active ? '1' : '0';
    document.getElementById('edit_mfa').value = user.mfa_enabled ? '1' : '0';
    document.getElementById('editModal').classList.add('open');
}

async function submitEdit(e) {
    e.preventDefault();
    const form = new FormData();
    form.append('action', 'edit_user');
    form.append('id', document.getElementById('edit_id').value);
    form.append('email', document.getElementById('edit_email').value);
    form.append('role', document.getElementById('edit_role').value);
    form.append('active', document.getElementById('edit_active').value);
    form.append('mfa_enabled', document.getElementById('edit_mfa').value);
    const pw = document.getElementById('edit_password').value;
    if (pw) form.append('password', pw);

    const resp = await fetch('/app/api/users.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) {
        bdToast(json.message, 'success');
        closeModal('editModal');
        setTimeout(() => location.reload(), 500);
    } else bdToast(json.error, 'error');
}

// ── Deactivate / Reactivate ──────────────────────────────────────────────
async function deactivateUser(id, name) {
    if (!confirm('Deactivate user "' + name + '"?')) return;
    const res = await bdApi('DELETE', '/api/users/' + id);
    if (res.ok) { bdToast('User deactivated', 'success'); setTimeout(() => location.reload(), 500); }
}

async function reactivateUser(id) {
    const form = new FormData();
    form.append('action', 'reactivate_user');
    form.append('id', id);
    const resp = await fetch('/app/api/users.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) { bdToast('User reactivated', 'success'); setTimeout(() => location.reload(), 500); }
}

// ── Email ────────────────────────────────────────────────────────────────
function openEmailModal(userId, username, email) {
    document.getElementById('emailTitle').textContent = 'Email: ' + username;
    document.getElementById('email_user_id').value = userId;
    document.getElementById('email_to_display').value = username + ' <' + email + '>';
    document.getElementById('email_subject').value = '';
    document.getElementById('email_body').value = '';
    document.getElementById('emailSendBtn').textContent = 'Send Email';
    document.getElementById('emailSendBtn').disabled = false;
    document.getElementById('emailModal').classList.add('open');
}

async function submitEmail(e) {
    e.preventDefault();
    const btn = document.getElementById('emailSendBtn');
    btn.textContent = 'Sending...';
    btn.disabled = true;

    const form = new FormData();
    form.append('action', 'send_email');
    form.append('user_id', document.getElementById('email_user_id').value);
    form.append('subject', document.getElementById('email_subject').value);
    form.append('body', document.getElementById('email_body').value);

    const resp = await fetch('/app/api/users.php', { method: 'POST', body: form });
    const json = await resp.json();
    if (json.ok) {
        bdToast(json.message, 'success');
        closeModal('emailModal');
    } else {
        bdToast(json.error, 'error');
        btn.textContent = 'Send Email';
        btn.disabled = false;
    }
}
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

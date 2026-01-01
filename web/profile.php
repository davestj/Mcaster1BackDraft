<?php
$page_title = 'My Profile';
$active_nav = '';
require_once __DIR__ . '/app/inc/db.php';
require_once __DIR__ . '/app/inc/header.php';

$username = bd_authed_user();
$user = db_row("SELECT * FROM backdraft_users WHERE username = ?", [$username]);
?>

<div style="max-width:600px;margin:0 auto">
    <h2 style="font-size:18px;font-weight:700;margin-bottom:20px">My Profile</h2>

    <div class="card">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)">
            <div style="width:56px;height:56px;border-radius:50%;background:var(--amber);display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:800;color:#fff">
                <?= strtoupper(substr($username, 0, 1)) ?>
            </div>
            <div>
                <div style="font-size:16px;font-weight:700"><?= h($username) ?></div>
                <div><span class="badge badge-<?= bd_authed_role() === 'superadmin' ? 'red' : (bd_authed_role() === 'admin' ? 'amber' : 'muted') ?>"><?= h(bd_authed_role()) ?></span></div>
                <?php if ($user): ?>
                <div style="font-size:12px;color:var(--muted);margin-top:4px">Created: <?= h($user['created_at']) ?></div>
                <?php endif; ?>
            </div>
        </div>

        <form id="profileForm">
            <div style="margin-bottom:16px">
                <label style="display:block;font-size:12px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Username</label>
                <input type="text" value="<?= h($username) ?>" disabled style="width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--muted);font-size:14px">
            </div>

            <div style="margin-bottom:16px">
                <label style="display:block;font-size:12px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Email</label>
                <input type="email" id="email" name="email" value="<?= h($user['email'] ?? '') ?>" style="width:100%;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:14px" placeholder="your@email.com">
            </div>

            <div style="margin-bottom:16px">
                <label style="display:block;font-size:12px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">New Password <span style="color:var(--muted);font-weight:400;text-transform:none">(leave blank to keep current)</span></label>
                <input type="password" id="password" name="password" style="width:100%;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:14px" placeholder="Enter new password">
            </div>

            <div style="margin-bottom:16px">
                <label style="display:block;font-size:12px;color:var(--text-dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Confirm Password</label>
                <input type="password" id="password2" style="width:100%;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:14px" placeholder="Confirm new password">
            </div>

            <div style="display:flex;gap:8px;margin-top:20px">
                <button type="submit" class="btn btn-amber">Save Changes</button>
                <a href="/dashboard.php" class="btn btn-ghost">Cancel</a>
            </div>
        </form>
    </div>

    <?php if ($user): ?>
    <div class="card" style="margin-top:16px">
        <div class="card-title">Account Details</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px;font-size:13px">
            <div><span style="color:var(--muted)">Role:</span> <?= h($user['role']) ?></div>
            <div><span style="color:var(--muted)">MFA:</span> <?= $user['mfa_enabled'] ? 'Enabled' : 'Disabled' ?></div>
            <div><span style="color:var(--muted)">Status:</span> <?= $user['active'] ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Inactive</span>' ?></div>
            <div><span style="color:var(--muted)">Last Login:</span> <?= h($user['last_login'] ?: 'Never') ?></div>
        </div>
    </div>
    <?php endif; ?>
</div>

<script>
document.getElementById('profileForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const password = document.getElementById('password').value;
    const password2 = document.getElementById('password2').value;
    const email = document.getElementById('email').value;

    if (password && password !== password2) {
        bdToast('Passwords do not match', 'error');
        return;
    }

    const data = { email };
    if (password) data.password = password;

    const res = await bdApi('POST', '/api/profile', data);
    if (res.ok) {
        bdToast('Profile updated successfully', 'success');
        document.getElementById('password').value = '';
        document.getElementById('password2').value = '';
    }
});
</script>

<?php require_once __DIR__ . '/app/inc/footer.php'; ?>

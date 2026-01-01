<?php
/**
 * login.php — BackDraft login page
 */
$require_auth = false;
$page_title = 'Login';
$active_nav = '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — Mcaster1 BackDraft WAF</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-box{background:#111827;border:1px solid #334155;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.login-logo{width:56px;height:56px;border-radius:14px;background:linear-gradient(135deg,#f59e0b,#ef4444);display:flex;align-items:center;justify-content:center;font-weight:900;font-size:20px;color:#fff;margin:0 auto 16px}
.login-title{text-align:center;font-size:22px;font-weight:800;margin-bottom:4px}
.login-sub{text-align:center;font-size:13px;color:#64748b;margin-bottom:28px}
label{display:block;font-size:12px;color:#94a3b8;font-weight:600;margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em}
input[type=text],input[type=password]{width:100%;padding:12px 14px;background:#1e293b;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px;margin-bottom:16px;transition:border-color .15s}
input:focus{outline:none;border-color:#f59e0b}
.btn-login{width:100%;padding:14px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer;transition:opacity .15s}
.btn-login:hover{opacity:.9}
.login-error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:16px;display:none}
.login-footer{text-align:center;margin-top:20px;font-size:11px;color:#475569}
</style>
</head>
<body>
<div class="login-box">
    <div class="login-logo">BD</div>
    <div class="login-title">Mcaster1 BackDraft</div>
    <div class="login-sub">Web Application Firewall + Log Analyzer</div>
    <div class="login-error" id="loginError"></div>
    <form id="loginForm">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username" required autofocus>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required>
        <button type="submit" class="btn-login">Sign In</button>
    </form>
    <div class="login-footer">&copy; <?= date('Y') ?> Mcaster1 BackDraft &middot; v0.0.1a</div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const errEl = document.getElementById('loginError');
    errEl.style.display = 'none';

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const resp = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await resp.json();

        if (data.ok && data.token) {
            window.location.href = '/dashboard.php';
        } else {
            errEl.textContent = data.error || 'Login failed';
            errEl.style.display = 'block';
        }
    } catch (err) {
        errEl.textContent = 'Connection error: ' + err.message;
        errEl.style.display = 'block';
    }
});
</script>
</body>
</html>

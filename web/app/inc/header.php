<?php
/**
 * header.php — BackDraft page shell with cybersecurity dark theme
 * Requires: $page_title, $active_nav
 */
if (!defined('BD_CONFIG')) require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

if (($require_auth ?? true) && !bd_is_authed()) {
    header('Location: /login.php');
    return;
}

$nav_user = h(bd_authed_user());
$nav_role = h(bd_authed_role());
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= h($page_title ?? 'BackDraft') ?> — Mcaster1 BackDraft WAF</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<style>
:root {
  --bg:         #0a0e1a;
  --bg2:        #111827;
  --bg3:        #162032;
  --card-bg:    #1e293b;
  --card2:      #263348;
  --border:     #334155;
  --border2:    #2d3f55;
  --amber:      #f59e0b;
  --amber-dim:  #d97706;
  --amber-glow: rgba(245,158,11,.15);
  --red:        #ef4444;
  --red-glow:   rgba(239,68,68,.15);
  --green:      #22c55e;
  --green-glow: rgba(34,197,94,.15);
  --teal:       #14b8a6;
  --cyan:       #0891b2;
  --text:       #e2e8f0;
  --text-dim:   #94a3b8;
  --muted:      #64748b;
  --sidebar-w:  220px;
  --topbar-h:   56px;
  --radius:     10px;
  --radius-sm:  6px;
  --font:       'Inter','Segoe UI',system-ui,sans-serif;
  --font-mono:  'SF Mono','Fira Code',monospace;
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px;background:var(--bg);color:var(--text);height:100%}
body{font-family:var(--font);line-height:1.5;height:100%;overflow:hidden}

/* Hide scrollbars globally but allow scrolling */
*{scrollbar-width:none;-ms-overflow-style:none}
*::-webkit-scrollbar{display:none}
a{color:var(--amber);text-decoration:none}a:hover{color:var(--amber-dim)}
button{font-family:inherit;cursor:pointer}
input,select,textarea{font-family:inherit}

/* ── Topbar ──────────────────────────────────── */
.topbar{
  position:fixed;top:0;left:0;right:0;height:var(--topbar-h);
  background:var(--bg2);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:12px;padding:0 20px;z-index:100;
}
.topbar-brand{display:flex;align-items:center;gap:10px;min-width:var(--sidebar-w);margin-left:-20px;padding:0 20px;border-right:1px solid var(--border)}
.topbar-logo{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,var(--amber),var(--red));display:flex;align-items:center;justify-content:center;font-weight:900;font-size:14px;color:#fff;letter-spacing:-.5px}
.topbar-name{font-weight:700;font-size:15px;color:var(--text)}
.topbar-sub{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.topbar-title{font-size:14px;font-weight:600;color:var(--text-dim);flex:1}
.topbar-clocks{display:flex;gap:16px;font-family:var(--font-mono);font-size:13px;color:var(--text-dim)}
.clock-mil{color:var(--amber);font-weight:700}
.clock-civ{color:var(--text-dim)}
.topbar-sep{width:1px;height:28px;background:var(--border)}
.waf-pill{display:flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.waf-learning{background:var(--green-glow);border:1px solid rgba(34,197,94,.3);color:var(--green)}
.waf-active{background:var(--red-glow);border:1px solid rgba(239,68,68,.3);color:var(--red)}
.waf-disabled{background:rgba(100,116,139,.15);border:1px solid rgba(100,116,139,.3);color:var(--muted)}
.waf-dot{width:7px;height:7px;border-radius:50%;animation:pulse 1.5s infinite}
.waf-learning .waf-dot{background:var(--green)}
.waf-active .waf-dot{background:var(--red)}
.waf-disabled .waf-dot{background:var(--muted)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.topbar-user{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text-dim);cursor:pointer;padding:6px 10px;border-radius:var(--radius-sm);transition:background .15s}
.topbar-user:hover{background:rgba(255,255,255,.05)}
.topbar-user .avatar{width:28px;height:28px;border-radius:50%;background:var(--amber);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:12px}

/* ── Sidebar ─────────────────────────────────── */
.sidebar{
  position:fixed;top:var(--topbar-h);left:0;bottom:0;width:var(--sidebar-w);
  background:var(--bg2);border-right:1px solid var(--border);
  padding:16px 0;overflow-y:auto;overflow-x:hidden;z-index:90;
}
.sidebar a{
  display:flex;align-items:center;gap:10px;padding:10px 20px;
  color:var(--text-dim);font-size:13px;font-weight:500;
  transition:all .15s;border-left:3px solid transparent;
}
.sidebar a:hover{background:rgba(255,255,255,.04);color:var(--text)}
.sidebar a.active{background:rgba(245,158,11,.08);color:var(--amber);border-left-color:var(--amber);font-weight:600}
.sidebar a svg,.sidebar a .nav-icon{width:18px;height:18px;flex-shrink:0;opacity:.6}
.sidebar a.active svg,.sidebar a.active .nav-icon{opacity:1}
.sidebar-section{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;padding:20px 20px 6px;font-weight:700}

/* ── Main Content ────────────────────────────── */
.main-content{margin-left:var(--sidebar-w);margin-top:var(--topbar-h);padding:24px;height:calc(100vh - var(--topbar-h));overflow-y:auto;overflow-x:hidden}

/* ── Cards ────────────────────────────────────── */
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.card-title{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600;margin-bottom:12px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;display:flex;flex-direction:column}
.stat-val{font-size:28px;font-weight:800;line-height:1.1;margin-bottom:4px}
.stat-label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.stat-amber .stat-val{color:var(--amber)}
.stat-red .stat-val{color:var(--red)}
.stat-green .stat-val{color:var(--green)}
.stat-cyan .stat-val{color:var(--cyan)}

/* ── Tables ───────────────────────────────────── */
.table-wrap{overflow-x:auto}
table.bd-table{width:100%;border-collapse:collapse;font-size:13px}
.bd-table th{background:var(--bg3);padding:10px 14px;text-align:left;font-weight:600;color:var(--text-dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border)}
.bd-table td{padding:10px 14px;border-bottom:1px solid var(--border2);color:var(--text)}
.bd-table tr:hover td{background:rgba(255,255,255,.02)}

/* ── Buttons ──────────────────────────────────── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:var(--radius-sm);font-size:13px;font-weight:600;border:none;transition:all .15s}
.btn-amber{background:var(--amber);color:#000}.btn-amber:hover{background:var(--amber-dim)}
.btn-ghost{background:rgba(255,255,255,.05);color:var(--text);border:1px solid var(--border)}.btn-ghost:hover{background:rgba(255,255,255,.1)}
.btn-red{background:var(--red);color:#fff}.btn-red:hover{opacity:.85}
.btn-green{background:var(--green);color:#fff}.btn-green:hover{opacity:.85}

/* ── Badges ───────────────────────────────────── */
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700}
.badge-green{background:var(--green-glow);color:var(--green)}
.badge-red{background:var(--red-glow);color:var(--red)}
.badge-amber{background:var(--amber-glow);color:var(--amber)}
.badge-muted{background:rgba(100,116,139,.15);color:var(--muted)}

/* ── Toast ────────────────────────────────────── */
#toast{position:fixed;top:70px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.toast-msg{padding:12px 20px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;box-shadow:0 4px 20px rgba(0,0,0,.4);animation:slideIn .3s}
.toast-info{background:#1e3a5f;color:#93c5fd;border-left:4px solid var(--cyan)}
.toast-success{background:#14532d;color:#86efac;border-left:4px solid var(--green)}
.toast-error{background:#7f1d1d;color:#fca5a5;border-left:4px solid var(--red)}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}

@media(max-width:768px){
  .sidebar{display:none}
  .main-content{margin-left:0}
  .topbar-brand{min-width:auto}
  .topbar-clocks{display:none}
}
</style>
</head>
<body>

<!-- Topbar -->
<header class="topbar">
  <div class="topbar-brand">
    <div class="topbar-logo">BD</div>
    <div>
      <div class="topbar-name">BackDraft</div>
      <div class="topbar-sub">WAF + Log Analyzer</div>
    </div>
  </div>
  <div class="topbar-title"><?= h($page_title ?? 'Dashboard') ?></div>
  <div class="topbar-clocks">
    <span class="clock-mil" id="clockMil">00:00:00</span>
    <span class="clock-civ" id="clockCiv">12:00:00 AM</span>
  </div>
  <div class="topbar-sep"></div>
  <div class="waf-pill waf-learning" id="wafPill">
    <span class="waf-dot"></span>
    <span id="wafModeText">LEARNING</span>
  </div>
  <div class="topbar-sep"></div>
  <div class="topbar-user" id="userMenuBtn" style="position:relative">
    <div class="avatar"><?= strtoupper(substr($nav_user, 0, 1)) ?></div>
    <span><?= $nav_user ?> (<?= $nav_role ?>)</span>
    <div id="userDropdown" style="display:none;position:absolute;top:calc(100% + 4px);right:0;background:var(--card-bg);border:1px solid var(--border);border-radius:var(--radius-sm);min-width:160px;z-index:200;box-shadow:0 8px 24px rgba(0,0,0,.4)">
      <a href="/profile.php" style="display:block;padding:10px 16px;font-size:13px;color:var(--text);border-bottom:1px solid var(--border)">My Profile</a>
      <a href="#" onclick="bdLogout();return false" style="display:block;padding:10px 16px;font-size:13px;color:var(--red)">Sign Out</a>
    </div>
  </div>
</header>

<!-- Sidebar -->
<nav class="sidebar">
  <div class="sidebar-section">Monitor</div>
  <a href="/dashboard.php" class="<?= ($active_nav ?? '') === 'dashboard' ? 'active' : '' ?>">&#x1F6E1; Dashboard</a>
  <a href="/logs.php" class="<?= ($active_nav ?? '') === 'logs' ? 'active' : '' ?>">&#x1F4E1; Live Monitor</a>
  <a href="/threats.php" class="<?= ($active_nav ?? '') === 'threats' ? 'active' : '' ?>">&#x26A0; Threats</a>
  <a href="/agents.php" class="<?= ($active_nav ?? '') === 'agents' ? 'active' : '' ?>">&#x1F916; Agents</a>
  <a href="/analytics.php" class="<?= ($active_nav ?? '') === 'analytics' ? 'active' : '' ?>">&#x1F4CA; Log Analytics</a>

  <div class="sidebar-section">Manage</div>
  <a href="/rules.php" class="<?= ($active_nav ?? '') === 'rules' ? 'active' : '' ?>">&#x1F6E1; WAF Rules</a>
  <a href="/sites.php" class="<?= ($active_nav ?? '') === 'sites' ? 'active' : '' ?>">&#x1F310; Sites</a>
  <a href="/site-management.php" class="<?= ($active_nav ?? '') === 'site-security' ? 'active' : '' ?>">&#x1F512; Site Security</a>
  <a href="/pages.php" class="<?= ($active_nav ?? '') === 'pages' ? 'active' : '' ?>">&#x1F4C4; Page Profiles</a>

  <div class="sidebar-section">Scheduler</div>
  <a href="/tasks.php" class="<?= ($active_nav ?? '') === 'tasks' ? 'active' : '' ?>">&#x23F0; Tasks</a>
  <a href="/task-manager.php" class="<?= ($active_nav ?? '') === 'task-manager' ? 'active' : '' ?>">&#x1F4CB; Task Monitor</a>

  <div class="sidebar-section">Security</div>
  <a href="/security-scans.php" class="<?= ($active_nav ?? '') === 'security-scans' ? 'active' : '' ?>">&#x1F50D; Security Scans</a>

  <div class="sidebar-section">System</div>
  <a href="/performance.php" class="<?= ($active_nav ?? '') === 'performance' ? 'active' : '' ?>">&#x2699; Performance</a>
  <a href="/users.php" class="<?= ($active_nav ?? '') === 'users' ? 'active' : '' ?>">&#x1F465; Users</a>
  <a href="/settings.php" class="<?= ($active_nav ?? '') === 'settings' ? 'active' : '' ?>">&#x2699; Settings</a>
</nav>

<main class="main-content">

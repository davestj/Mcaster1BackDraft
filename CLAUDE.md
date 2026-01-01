# CLAUDE.md — Mcaster1BackDraft Project Memory

**Maintainer:** Dave St. John <davestj@mcaster1.com>
**Project:** Mcaster1BackDraft — Web Application Firewall + nginx Log Analyzer
**Repo root:** `/var/www/mcaster1.com/Mcaster1BackDraft/`
**Platform:** Linux (Debian)
**License:** Proprietary

---

## Overview

Mcaster1BackDraft is a pure C++ WAF and nginx log analyzer. Single binary, three ports, one process. No Go. No sidecars.

## Architecture — Single Binary, Three Ports

| Port | Role |
|------|------|
| 9432 | WAF proxy — receives nginx-proxied traffic, inspects, logs, forwards to PHP-FPM via FastCGI |
| 8862 | Web UI — PHP dashboard via FastCGI |
| 8832 | API — REST endpoints |

All ports use bounded thread pools (auto-sized: `nproc * 4`, capped by available memory).

## Build

```bash
./autogen.sh && ./configure && make -j$(nproc)
# Binary: src/Mcaster1BackDraft
# Run: ./src/Mcaster1BackDraft -c etc/Mcaster1BackDraft.yaml
```

## Key Source Files

| File | Purpose |
|------|---------|
| `main.cpp` | Entry point, signal handlers, 3 HTTP servers, task scheduler, lifecycle |
| `config.h/cpp` | YAML config loader (AppConfig struct) |
| `logger.h/cpp` | 4-file logging (main, error, debug, access), 50MB rotation |
| `dbpool.h/cpp` | MySQL connection pool, RAII DbConn, prepared statements |
| `http_server.h/cpp` | TLS HTTP server, FastCGI client, static files, route dispatch |
| `threadpool.h/cpp` | Bounded worker thread pool, auto-sized from CPU/memory |
| `router.h/cpp` | Route registration for web + API servers |
| `auth.h/cpp` | Master user + DB users, session tokens, role-based auth |
| `api_handler.h/cpp` | All REST endpoints (health, rules, sites, users, threats, perf, tasks) |
| `waf_handler.h/cpp` | **WAF engine** — rule loading, URL decoding, inspection, scoring, FastCGI forwarding, request logging |
| `task_runner.h` | **Task scheduler** — 1-second precision, worker pool dispatch, DB-driven scheduling |
| `rule_engine.h/cpp` | Rule engine init (stub, actual engine in waf_handler) |
| `threat_scorer.h/cpp` | Threat scoring (stub, actual scoring in waf_handler) |
| `nginx_manager.h/cpp` | nginx config read/write, snippet generation, reload |
| `site_discovery.h/cpp` | Scans /etc/nginx/sites-enabled/, extracts server_name, root, logs |
| `perf_monitor.h/cpp` | Self-monitoring — real CPU%, memory, threads, FDs, WAF RPS/latency, task/BotProof stats |
| `captcha_generator.h/cpp` | **BotProof** — libgd CAPTCHA image generation (text + math, distortion, noise, base64) |
| `botproof.h/cpp` | **BotProof** — challenge tokens, IP-bound sessions, verification, HTML templates |
| `smtp_client.h/cpp` | **Secure Lock** — C++ SMTP client with STARTTLS for OTP email delivery |

## WAF Request Flow

```
nginx → proxy_pass → BackDraft port 9432
  → HttpServer::handle_client()
    → route match "/" (catch-all)
      → WafHandler::handle_request()
        → extract X-Real-IP, X-BackDraft-Page headers
        → inspect() — load rules from DB, URL-decode, regex match, score
        → if active mode && score >= threshold: return 403
        → forward_to_fcgi() — FastCGI to PHP-FPM unix socket
        → log_request() — INSERT into backdraft_requests
        → if score >= threshold: INSERT into backdraft_threats
        → return PHP response to nginx
```

## Database

**Name:** `mcaster1_backdraft` (21 tables)
**Connection:** `mysql --defaults-extra-file=~/.my.cnf`

## Config

**Path:** `etc/Mcaster1BackDraft.yaml`

Key settings:
- `http.waf_port: 9432` — WAF listener
- `waf.mode: learning` — learning | active | disabled
- `waf.threat_threshold: 75` — score to flag/block
- `waf.upstream_fcgi: /run/php/php8.2-fpm.sock` — PHP-FPM for WAF-proxied pages
- `http.fcgi_socket: /run/php/php8.2-fpm-backdraft.sock` — PHP-FPM for admin dashboard

## nginx Integration Pattern

```nginx
# In site config:
location = /page.php {
    proxy_pass https://127.0.0.1:9432;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-BackDraft-Page "site.com/page.php";
}
```

BackDraft forwards to PHP-FPM directly. No proxy loop.

## Critical Rules

- NO Go sidecars. Everything in the C++ daemon.
- NO proxy loops. WAF talks FastCGI to PHP-FPM directly.
- NO `(?i)` in regex rules — std::regex uses icase flag, strip (?i) prefix automatically.
- URL-decode query strings and paths before rule matching.
- Always use `safe()` wrapper for MySQL row field access (prevents NULL crashes).
- NEVER change PHP-FPM configs without warning the user.

## Auth

- Master user in YAML: `auth.master_username` / `auth.master_password`
- DB users: SHA2-256 hashed, roles: user/admin/superadmin
- Sessions: `backdraft_sessions` table with TTL
- PHP auth via injected headers: `X-BackDraft-Authenticated`, `X-BackDraft-User`, `X-BackDraft-Role`

## Performance Monitor

Single unified daemon view — no Go/goroutine references anywhere.

### Metrics Collected (every 10 seconds)
- **CPU %**: Real process CPU from `/proc/self/stat` (utime + stime delta over wall clock)
- **Memory**: RSS and VMS from `/proc/self/status`
- **Threads**: Count from `/proc/self/task`
- **Open FDs**: Count from `/proc/self/fd`
- **WAF RPS**: Requests per second computed from `WafHandler::total_requests` atomic counter delta
- **WAF Avg Latency**: Average ms per request from `WafHandler::latency_sum_1m` atomic counter
- **WAF Totals**: `total_requests`, `total_threats`, `total_blocked`, `rules_loaded` — all from atomic counters on WafHandler
- **Task Scheduler**: `task_enabled` (active task count), `task_running` (currently executing)

### Storage
- Writes to `backdraft_perf_metrics` with `daemon='backdraft'` (single enum value)
- Extended metrics in `custom_json` column (WAF totals, active rules, task stats, waf_mode)
- Auto-prunes metrics older than 24 hours

### Web UI (`web/performance.php`)
- System Resources: CPU%, RSS, VMS, threads, FDs, DB size
- WAF Engine: RPS, avg latency, total requests/threats/blocked, active rules
- Task Scheduler: enabled tasks, running now, 24h request/threat counts
- Mini trend charts: CPU%, memory RSS, WAF RPS over last 30 minutes
- History table: last 30 metric snapshots with color-coded CPU values
- Auto-refreshes via AJAX every 10s (no full page reload)

## Log Viewer

### Architecture (dual approach)
1. **PHP tail endpoint** (`logs.php?ajax=tail&file=backdraft`) — Reads last N lines directly via PHP for immediate content on page load. Works without daemon rebuild.
2. **SSE live stream** (`/api/logs/stream?file=backdraft`) — C++ handler sends last 50 lines on connect + `event: connected` confirmation, then streams new lines in real-time. Keepalives every 500ms.

### Log Files
| File | Description |
|------|-------------|
| `backdraft.log` | Main daemon log (info/warn/error) |
| `error.log` | Error-level only |
| `debug.log` | Detailed debug messages |
| `access.log` | WAF request access log |

### Web UI (`web/logs.php`)
- 4 log file buttons (Main/Error/Debug/Access)
- Pause/Resume/Clear/Refresh controls
- Connection status indicator (Live streaming / Static view / Reconnecting)
- 2000-line buffer with auto-scroll
- Color-coded status: green=live, amber=paused/reconnecting, muted=static

## Task Scheduler

Built-in task scheduler with 1-second precision timing. Ported from Mcaster1YPMan's `TaskRunner` and enhanced:

### Architecture
- **Scheduler thread**: Wakes every 1 second, queries `backdraft_tasks WHERE enabled=1 AND next_run_at <= NOW()`
- **Worker pool**: Dedicated `ThreadPool` (¼ of system pool size, min 4 threads) for task execution
- **PHP handlers**: Tasks dispatch PHP scripts from `tasks/` directory with CLI args from JSON params
- **Execution tracking**: `backdraft_task_runs` table with status, output log, summary JSON, HTML export
- **Priority-aware**: Tasks ordered by priority (critical > high > normal > low) when multiple due simultaneously

### Schedule Formats
`30s` (seconds), `15m` (minutes), `2h` (hours), `24h` (daily), `7d` (weekly). Minimum 10 seconds.

### Task Handler Output Pattern
Handlers produce up to 3 artifacts:
1. **stdout/stderr** → captured to `/tmp/backdraft_task_{id}.log` → stored in `output_log`
2. **JSON sidecar** → `/tmp/backdraft_task_{id}.json` → stored in `summary_json`
3. **HTML sidecar** → `/tmp/backdraft_task_{id}.html` → stored in `export_html`

The C++ TaskRunner reads sidecar files after handler exits. Handlers can also update `backdraft_task_runs` directly via PDO.

### Default Tasks (9 handlers, all operational)
| task_id | Schedule | Handler | Purpose |
|---------|----------|---------|---------|
| `threat_analysis_report` | 24h | `threat-analysis-report.php` | Comprehensive threat intelligence report with severity breakdown, top IPs, rule triggers, agent activity, preset response algorithms, and remediation guidance. Exports: HTML5, PDF, Excel/CSV |
| `log_stats_aggregate` | 1h | `log-stats-aggregate.php` | Parses nginx access logs for all monitored sites (1.9M+ lines). Populates hourly stats, page stats, realtime counters. Uses high-water marks for incremental processing. |
| `ip_reputation_update` | 6h | `ip-reputation-update.php` | Recalculates IP reputation scores from requests/threats. Auto-bans IPs exceeding critical threat threshold. |
| `error_log_parse` | 15m | `error-log-parse.php` | Parses nginx error logs for all monitored sites into backdraft_error_log. 267K+ entries parsed. |
| `agent_activity_scan` | 2h | `agent-activity-scan.php` | Scans requests against agent signatures, identifies new scanners/bots, flags suspicious user-agents. |
| `anomaly_baseline_check` | 30m | `anomaly-baseline-check.php` | Compares current traffic to learned page profile baselines. Detects new methods, volume spikes, score spikes, IP clusters. |
| `session_cleanup` | 1h | `session-cleanup.php` | Purges expired auth sessions. |
| `data_retention_cleanup` | 24h | `data-retention-cleanup.php` | Batch-deletes expired request logs, threat records, sessions, perf metrics, task runs, BotProof challenges/sessions per retention policy. Disabled by default. |
| `site_report_update` | 2m | `site-report-update.php` | Pre-computes per-site realtime counters (requests/min, active IPs, bytes) for fast dashboard queries. |

### Threat Analysis Report
The flagship scheduled task generates a full threat intelligence report:
- **Executive summary**: Total requests, threats, block rate, unique IPs
- **Severity distribution**: Critical/high/medium/low breakdown with percentages
- **Top 10 offending IPs**: With reputation scores, country codes, ban status
- **Top triggered WAF rules**: Hit counts per rule
- **Agent/bot activity**: Scanner and crawler detection
- **Hourly trend**: Threat volume over time
- **Preset response algorithms**: NIST-inspired response framework per severity level
  - CRITICAL: Immediate IP ban, rule escalation, team alert (< 15 min response)
  - HIGH: IP flagging, manual review, rule tightening (< 1 hour)
  - MEDIUM: Trend monitoring, rule promotion (< 4 hours)
  - LOW: Informational, baseline data (next review cycle)
- **Export formats**: Pretty HTML5 (dark theme), PDF (print-optimized), Excel/CSV

### Web UI Pages
| Page | Path | Purpose |
|------|------|---------|
| Task Scheduler | `web/tasks.php` | Full CRUD: create, edit, delete, toggle, run-now, view run history. Admin role required for writes. |
| Task Monitor | `web/task-manager.php` | Live progress monitoring (5s/3s polling), recent runs, run detail viewer, export downloads (HTML/PDF/Excel) |

### Task API Endpoints
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/tasks` | Auth | List all tasks |
| GET | `/api/tasks/{task_id}` | Auth | Get single task |
| POST | `/api/tasks` | Admin | Create or update task |
| DELETE | `/api/tasks/{task_id}` | Admin | Delete task + all runs |
| POST | `/api/tasks/toggle` | Admin | Enable/disable task |
| POST | `/api/tasks/run` | Admin | Queue task for immediate execution (< 1 second) |
| GET | `/api/task-runs` | Auth | List recent runs (filterable by task_id) |
| GET | `/api/task-runs/{id}` | Auth | Get full run detail with output, summary, HTML |
| DELETE | `/api/task-runs/{id}` | Admin | Delete run record |
| GET | `/api/task-export/{id}?format=html\|pdf\|excel` | Auth | Download report export |

## WAF Live Status (as of 2026-03-20)

### Enrolled Sites
| Site | WAF Enabled | Log Analysis | Mode | nginx proxy_pass |
|------|-------------|-------------|------|------------------|
| `audiorealm.net` | Yes | Yes | Learning | `/etc/nginx/backdraft.d/audiorealm.net.conf` — `/index.php` proxied to 9432 |
| `mcaster1.com` | Yes (DB) | Yes | Learning | No proxy_pass yet — WAF flag in DB but nginx not configured |

### WAF Atomic Counters (WafHandler)
The WAF engine tracks live metrics via `std::atomic` counters on `WafHandler::instance()`:
- `total_requests`, `total_threats`, `total_blocked` — lifetime counters
- `requests_1m`, `latency_sum_1m` — rolling counters for RPS/latency calculation
- `rules_loaded` — current active rule count
- `prev_requests_`, `prev_latency_sum_` — snapshot values for delta computation by PerfMonitor

### Known Scanner Activity
- **Palo Alto Cortex Xpanse** (`147.185.132.72`) — identifies itself in UA, no agent signature exists yet
- Stealth scanners using raw IP + minimal UA `Mozilla/5.0` — not flagged by current rules

### Missing Agent Signatures (should be added)
- "Palo Alto" / "Cortex" / "Xpanse" — commercial scanner
- Minimal `Mozilla/5.0` with no browser details — suspicious UA pattern

## Web UI Pages

| Page | File | Nav Section | Purpose |
|------|------|-------------|---------|
| Dashboard | `web/dashboard.php` | Monitor | 7 stat cards, recent threats, monitored sites |
| Live Monitor | `web/logs.php` | Monitor | CloudWatch-style real-time WAF dashboard (3 tabs: Live Activity, Log Files, Search) |
| Threats | `web/threats.php` | Monitor | Multi-view: All Activity, Threat Events, Suspicious, IP Reputation (ban/unban), Agent Activity |
| Agents | `web/agents.php` | Monitor | 14 built-in agent signatures |
| Log Analytics | `web/analytics.php` | Monitor | Real-time stats from nginx logs, Chart.js |
| WAF Rules | `web/rules.php` | Manage | Rule CRUD, modal editor |
| Sites | `web/sites.php` | Manage | Expandable rows with page profiles, BotProof/SecureLock toggles, Live button for WAF sites |
| Page Profiles | `web/pages.php` | Manage | Per-page BotProof/SecureLock config, auto-discover PHP files from webroot, baseline management |
| Tasks | `web/tasks.php` | Scheduler | Full CRUD via C++ daemon `/api/tasks` (JSON POST) |
| Task Monitor | `web/task-manager.php` | Scheduler | Live progress, run details, export downloads |
| Performance | `web/performance.php` | System | Unified daemon metrics, WAF/task/BotProof stats, trend charts |
| Users | `web/users.php` | System | User CRUD, edit (role/email/mfa/password), email sending, reactivate |
| Settings | `web/settings.php` | System | Global WAF settings |
| Login | `web/login.php` | — | Auth form |
| Profile | `web/profile.php` | — | Self-edit profile |
| Site Enroll | `web/site-enroll.php` | — | Wizard to enable WAF on a site |
| Site Report | `web/site-report.php` | — | Per-site real-time analytics: GeoIP, rDNS, BotProof metrics, Chart.js, IP detail modal |

## BotProof Challenge System

Custom Cloudflare-style CAPTCHA challenge gate. Generates distorted text/math images in C++ using libgd.

### Architecture
- **Image generation**: `captcha_generator.cpp` uses libgd + FreeType. 280x80px PNG with per-character rotation, wave distortion, noise, confuser lines. Text charset excludes ambiguous chars (0/O, 1/I, 5/S).
- **Session management**: `botproof.cpp` handles challenge tokens, SHA-256 answer hashing, IP-bound sessions, attempt tracking.
- **Form POST pattern**: All BotProof/SecureLock forms use `action=""` (POST to same WAF-proxied URL) with `_bd_action` hidden field. This avoids needing extra nginx location blocks — any WAF-proxied page automatically supports verification.
- **_bd_action values**: `botproof_verify`, `secure_send_otp`, `secure_verify_otp`
- **Cookies**: `bd_botproof` (CAPTCHA session), `bd_secure` (OTP session). Both IP-bound, HttpOnly, Secure, SameSite=Lax.

### Per-page configuration (backdraft_page_profiles columns)
| Column | Default | Purpose |
|--------|---------|---------|
| botproof_enabled | 0 | Enable CAPTCHA challenge gate |
| botproof_threshold | 0 | Min WAF score to trigger (0 = challenge everyone) |
| botproof_session_mins | 60 | Session duration after passing |
| botproof_max_attempts | 3 | Max wrong answers before hard block |
| secure_lock_enabled | 0 | Enable email OTP after CAPTCHA |
| secure_lock_session_mins | 60 | OTP session duration |
| secure_lock_allowed_emails | NULL | Comma-separated email patterns (empty = any) |

### 3-tier protection flow
```
Tier 1: WAF inspection (always)
  → Tier 2: BotProof CAPTCHA (if botproof_enabled, score >= threshold)
    → Tier 3: Secure Lock OTP (if secure_lock_enabled, email + 6-digit code)
      → Page access granted (cookies set, session valid for configured duration)
```

## Secure Lock OTP

Email-based one-time password system. C++ SMTP client (`smtp_client.cpp`) with STARTTLS + AUTH LOGIN sends 6-digit codes via Gmail SMTP. BackDraft-branded HTML email template.

## API Architecture

**Strict separation — no mixed HTML/JSON in page files.**

### C++ Daemon API (port 8832 + 8862)
All JSON, handled by `api_handler.cpp`:
- `/api/health`, `/api/status` — public
- `/api/login`, `/api/logout` — auth
- `/api/tasks`, `/api/tasks/{id}`, `/api/tasks/toggle`, `/api/tasks/run` — task CRUD
- `/api/task-runs`, `/api/task-runs/{id}` — execution history
- `/api/task-export/{id}?format=html|pdf|excel` — report downloads
- `/api/threats`, `/api/threats/dismiss` — threat events
- `/api/ip-reputation`, `/api/ip-reputation/ban`, `/api/ip-reputation/unban` — IP management
- `/api/rules`, `/api/sites`, `/api/agents`, `/api/users` — CRUD
- `/api/sites/maintenance` — toggle maintenance on/off per site
- `/api/sites/security-blocks` — enable/disable per-category nginx security blocks
- `/api/sites/rate-limits` — rate limiting configuration
- `/api/sites/sync-blacklists` — sync banned IPs + blocked agents to nginx
- `/api/sites/emergency-lockdown` — one-click site/all-site shutdown
- `/api/sites/security` — full security state for a site
- `/api/security-events`, `/api/security-audit` — event log + audit trail
- `/api/perf`, `/api/mode`, `/api/profile` — system
- `/api/logs/stream` — SSE real-time log streaming

### PHP API (via FastCGI)
- `/app/api/pages.php` — page profiles, BotProof/SecureLock settings, site file scanning
- `/app/api/task-manager.php` — live task status aggregation
- `/app/api/users.php` — extended user edit, email sending
- `/app/api/logs.php` — log tail, search, live WAF activity stats
- `/app/api/site-report.php` — per-site analytics with GeoIP, rDNS, BotProof metrics

**PHP API files use `return;` not `exit;`** — the C++ FastCGI proxy doesn't respect PHP's `exit`.

## Live Monitor

CloudWatch-style real-time WAF dashboard (`logs.php`):
- **Live Activity tab**: RPM chart (30min), live request feed, agent classification, top IPs/paths, flagged alerts, 24h trend. Polls every 5 seconds.
- **Log Files tab**: SSE streaming + PHP tail fallback for backdraft/error/debug/access logs.
- **Search tab**: Full-text search across all log files with highlighted matches.

## Per-Site Analytics

Real-time per-site dashboard (`site-report.php?id=N`):
- RPM chart, live request feed with country flags (GeoIP via `geoiplookup`)
- Top visitors with reverse DNS (`gethostbyaddr`), country distribution
- 24h traffic chart, response time distribution, status code breakdown
- BotProof metrics panel: challenges/passed/failed/active sessions/pass rate
- Secure Lock metrics panel: OTPs sent/verified
- Protected pages panel with BP/SL badges
- IP detail modal: click any IP for geo, rDNS, reputation, request history, sites hit, user agents
- Top paths, user agents, flagged requests feed

## Systemd Service

```bash
sudo systemctl start|stop|restart|status mcaster1backdraft
sudo journalctl -u mcaster1backdraft -f
```
- Unit: `installer/mcaster1backdraft.service`
- User: mediacast1, PID: `logs/backdraft.pid`
- Auto-start on boot, 15s stop timeout, KillMode=mixed

## Phase Status

| Version | Description | Status |
|---------|-------------|--------|
| v0.0.1a | Foundation — single C++ daemon, 3 ports, WAF engine, FastCGI, PHP dashboard, thread pool, CRUD APIs, Chart.js analytics | COMPLETE |
| v0.0.1b | Task scheduler — 1-second precision C++ scheduler, worker pool, threat analysis reports, export (HTML5/PDF/Excel), preset response algorithms | COMPLETE |
| v0.0.1c | Performance + Logs — real CPU/WAF/task metrics, unified daemon view, log viewer with PHP tail + SSE live stream, WAF atomic counters | COMPLETE |
| v0.0.1d | BotProof CAPTCHA — libgd image generation, IP-bound sessions, per-page config, Secure Lock email OTP, C++ SMTP client | COMPLETE |
| v0.0.1e | Live Monitor + Per-site analytics — CloudWatch-style dashboard, GeoIP, rDNS, Chart.js, IP detail modals, strict API separation, 9 task handlers, systemd service | COMPLETE |
| v0.0.1f | Site Management — maintenance toggle, per-category security blocks, rate limiting, blacklist sync, emergency lockdown, bot fingerprinting (238+ defs), turnstile PoW challenge | COMPLETE |
| v0.0.1g | Security Scanning — ClamAV malware scanning, custom rootkit hunter (file integrity baseline, web shell detection, process/port/cron/SUID/SSH auditing, chkrootkit), 15 scheduled tasks, 27 tables | COMPLETE |
| v0.0.2a | DAST/SAST scanning, CAPTCHA settings management, nginx config auto-enrollment | PLANNED |
| v0.0.4a | Active mode — blocking, challenge pages, email alerts, WAF data in threat reports | PLANNED |
| v0.0.5a | AI integration — Ollama with cybersecurity-focused model for threat assessment, anomaly detection, intelligent rule suggestions | PLANNED |
| v0.1.0 | Production — battle-tested, docs, packaging | PLANNED |

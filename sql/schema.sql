-- ============================================================================
-- Mcaster1BackDraft — Database Schema
-- Version: 0.0.1a
-- Database: mcaster1_backdraft
-- Author: David St. John <davestj@mcaster1.com>
-- Created: 2026-03-17
--
-- 21 tables + seed data (WAF rules, agent signatures, default config, admin user, task scheduler, botproof)
-- No foreign key constraints (ecosystem convention).
-- ============================================================================

CREATE DATABASE IF NOT EXISTS mcaster1_backdraft
  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE mcaster1_backdraft;

SET foreign_key_checks = 0;
SET unique_checks = 0;

-- ============================================================================
-- 1. Users (admin panel)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_users (
    id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    role          ENUM('user','admin','superadmin') NOT NULL DEFAULT 'user',
    email         VARCHAR(256) NOT NULL DEFAULT '',
    mfa_enabled   TINYINT(1)   NOT NULL DEFAULT 0,
    mfa_secret    VARCHAR(128) NOT NULL DEFAULT '',
    active        TINYINT(1)   NOT NULL DEFAULT 1,
    last_login    DATETIME     DEFAULT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_username (username)
) ENGINE=InnoDB;

-- ============================================================================
-- 2. Sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_sessions (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    INT UNSIGNED NOT NULL,
    token      VARCHAR(128) NOT NULL,
    ip_addr    VARCHAR(45)  NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME     NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_token (token),
    KEY idx_user (user_id),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB;

-- ============================================================================
-- 3. Audit log
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_audit_log (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED,
    username    VARCHAR(64),
    action      VARCHAR(128) NOT NULL,
    target_type VARCHAR(64),
    target_id   VARCHAR(256),
    detail      TEXT,
    ip_addr     VARCHAR(45),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_created (created_at),
    KEY idx_user (user_id)
) ENGINE=InnoDB;

-- ============================================================================
-- 4. WAF Rules
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_rules (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(120) NOT NULL,
    description TEXT,
    rule_type   ENUM('builtin','custom','learned','imported') NOT NULL DEFAULT 'custom',
    target      ENUM('header','query','body','path','agent','ip','method','cookie') NOT NULL,
    field       VARCHAR(128) NOT NULL DEFAULT '',
    operator    ENUM('contains','not_contains','regex','equals','not_equals',
                     'starts_with','ends_with','gt','lt','in_list','cidr_match') NOT NULL,
    value       TEXT NOT NULL,
    action      ENUM('log','flag','block','challenge','rate_limit') NOT NULL DEFAULT 'log',
    score       TINYINT UNSIGNED NOT NULL DEFAULT 10,
    active      TINYINT(1) NOT NULL DEFAULT 1,
    sort_order  INT UNSIGNED NOT NULL DEFAULT 100,
    page_scope  VARCHAR(512) DEFAULT NULL COMMENT 'NULL = all pages, else comma-separated page IDs',
    created_by  VARCHAR(80) DEFAULT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_active (active),
    KEY idx_type (rule_type)
) ENGINE=InnoDB;

-- ============================================================================
-- 5. Request log (HIGH VOLUME — core WAF data)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_requests (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_time    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    site_id         INT UNSIGNED    NOT NULL DEFAULT 0,
    client_ip       VARCHAR(45)     NOT NULL,
    method          VARCHAR(10)     NOT NULL,
    host            VARCHAR(256)    NOT NULL DEFAULT '',
    path            VARCHAR(2048)   NOT NULL,
    query_string    VARCHAR(4096)   NOT NULL DEFAULT '',
    user_agent      VARCHAR(1024)   NOT NULL DEFAULT '',
    referer         VARCHAR(1024)   NOT NULL DEFAULT '',
    content_type    VARCHAR(256)    NOT NULL DEFAULT '',
    content_length  INT UNSIGNED    NOT NULL DEFAULT 0,
    page_id         VARCHAR(256)    NOT NULL DEFAULT '',
    threat_score    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    action_taken    ENUM('pass','log','flag','block','challenge') NOT NULL DEFAULT 'pass',
    matched_rules   VARCHAR(512)    NOT NULL DEFAULT '' COMMENT 'comma-separated rule IDs',
    upstream_status SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    upstream_ms     INT UNSIGNED    NOT NULL DEFAULT 0,
    response_bytes  INT UNSIGNED    NOT NULL DEFAULT 0,
    country_code    CHAR(2)         NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY idx_time (request_time),
    KEY idx_site (site_id),
    KEY idx_ip (client_ip(32)),
    KEY idx_score (threat_score),
    KEY idx_page (page_id(64)),
    KEY idx_action (action_taken)
) ENGINE=InnoDB;

-- ============================================================================
-- 6. Threat events (elevated requests that triggered rules)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_threats (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_id      BIGINT UNSIGNED NOT NULL,
    detected_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    site_id         INT UNSIGNED NOT NULL DEFAULT 0,
    client_ip       VARCHAR(45) NOT NULL,
    threat_score    TINYINT UNSIGNED NOT NULL,
    matched_rules   VARCHAR(512) NOT NULL DEFAULT '',
    rule_details    JSON,
    category        ENUM('sqli','xss','traversal','rfi','scanner','bot','brute_force',
                         'rate_abuse','bad_agent','anomaly','custom') NOT NULL DEFAULT 'anomaly',
    severity        ENUM('low','medium','high','critical') NOT NULL DEFAULT 'low',
    action_taken    ENUM('logged','flagged','blocked','challenged') NOT NULL DEFAULT 'logged',
    dismissed       TINYINT(1) NOT NULL DEFAULT 0,
    dismissed_by    VARCHAR(64) DEFAULT NULL,
    notes           TEXT,
    PRIMARY KEY (id),
    KEY idx_request (request_id),
    KEY idx_detected (detected_at),
    KEY idx_site (site_id),
    KEY idx_ip (client_ip(32)),
    KEY idx_severity (severity),
    KEY idx_dismissed (dismissed)
) ENGINE=InnoDB;

-- ============================================================================
-- 7. Agent signatures (known bots, scanners, crawlers)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_agent_signatures (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    pattern         VARCHAR(512) NOT NULL COMMENT 'regex or substring match',
    match_type      ENUM('contains','regex','equals') NOT NULL DEFAULT 'contains',
    classification  ENUM('browser','bot','crawler','scanner','library','unknown') NOT NULL,
    disposition     ENUM('allow','monitor','flag','block') NOT NULL DEFAULT 'monitor',
    name            VARCHAR(128) NOT NULL DEFAULT '',
    description     TEXT,
    active          TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_active (active)
) ENGINE=InnoDB;

-- ============================================================================
-- 8. Per-page profiles (learning mode builds these)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_page_profiles (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    site_id         INT UNSIGNED NOT NULL DEFAULT 0,
    page_id         VARCHAR(256) NOT NULL,
    display_name    VARCHAR(256) NOT NULL DEFAULT '',
    upstream_url    VARCHAR(512) NOT NULL DEFAULT '',
    total_requests  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_threats   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    avg_score       FLOAT NOT NULL DEFAULT 0,
    last_request_at DATETIME,
    learned_methods VARCHAR(64) NOT NULL DEFAULT '' COMMENT 'comma-separated methods seen',
    learned_content_types VARCHAR(512) NOT NULL DEFAULT '',
    learned_avg_size INT UNSIGNED NOT NULL DEFAULT 0,
    monitoring      TINYINT(1) NOT NULL DEFAULT 1,
    botproof_enabled      TINYINT(1) NOT NULL DEFAULT 0,
    botproof_threshold    INT NOT NULL DEFAULT 0 COMMENT '0=challenge all flagged, 50+=only high scores',
    botproof_session_mins INT NOT NULL DEFAULT 60,
    botproof_max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 3,
    secure_lock_enabled      TINYINT(1) NOT NULL DEFAULT 0,
    secure_lock_session_mins INT NOT NULL DEFAULT 60,
    secure_lock_allowed_emails TEXT COMMENT 'Comma-separated email patterns, empty = any',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_page (page_id(255)),
    KEY idx_site (site_id)
) ENGINE=InnoDB;

-- ============================================================================
-- 9. IP reputation (accumulated over time)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_ip_reputation (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_addr         VARCHAR(45) NOT NULL,
    total_requests  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_threats   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    max_score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    avg_score       FLOAT NOT NULL DEFAULT 0,
    first_seen      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    banned          TINYINT(1) NOT NULL DEFAULT 0,
    banned_at       DATETIME DEFAULT NULL,
    banned_reason   VARCHAR(256) DEFAULT NULL,
    country_code    CHAR(2) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uk_ip (ip_addr(45)),
    KEY idx_banned (banned),
    KEY idx_score (max_score)
) ENGINE=InnoDB;

-- ============================================================================
-- 10. Runtime config (key-value)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_config (
    config_key   VARCHAR(64) NOT NULL,
    config_value VARCHAR(512) NOT NULL DEFAULT '',
    description  VARCHAR(512) DEFAULT NULL,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (config_key)
) ENGINE=InnoDB;

-- ============================================================================
-- 11. nginx sites enrollment
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_sites (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    site_name       VARCHAR(256) NOT NULL COMMENT 'nginx server_name',
    config_path     VARCHAR(512) NOT NULL COMMENT '/etc/nginx/sites-enabled/filename',
    access_log_path VARCHAR(512) NOT NULL DEFAULT '',
    error_log_path  VARCHAR(512) NOT NULL DEFAULT '',
    waf_enabled     TINYINT(1) NOT NULL DEFAULT 0,
    log_analysis    TINYINT(1) NOT NULL DEFAULT 0,
    waf_mode        ENUM('learning','active','disabled') NOT NULL DEFAULT 'learning',
    doc_root        VARCHAR(512) NOT NULL DEFAULT '' COMMENT 'Web document root for FastCGI SCRIPT_FILENAME',
    upstream_url    VARCHAR(512) NOT NULL DEFAULT '',
    protected_paths TEXT COMMENT 'JSON array of location paths under WAF',
    listen_port     INT UNSIGNED NOT NULL DEFAULT 80,
    ssl_enabled     TINYINT(1) NOT NULL DEFAULT 0,
    discovered_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enrolled_at     DATETIME DEFAULT NULL,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_site (site_name(255)),
    KEY idx_waf (waf_enabled),
    KEY idx_log (log_analysis)
) ENGINE=InnoDB;

-- ============================================================================
-- 12. Log analytics — hourly aggregated stats
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_log_stats_hourly (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    site_id         INT UNSIGNED NOT NULL,
    hour_bucket     DATETIME NOT NULL COMMENT 'Truncated to hour',
    total_requests  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    total_bytes     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    status_2xx      INT UNSIGNED NOT NULL DEFAULT 0,
    status_3xx      INT UNSIGNED NOT NULL DEFAULT 0,
    status_4xx      INT UNSIGNED NOT NULL DEFAULT 0,
    status_5xx      INT UNSIGNED NOT NULL DEFAULT 0,
    unique_ips      INT UNSIGNED NOT NULL DEFAULT 0,
    avg_response_ms FLOAT NOT NULL DEFAULT 0,
    top_paths       JSON COMMENT 'Top 20 paths by hit count',
    top_ips         JSON COMMENT 'Top 20 IPs by hit count',
    top_agents      JSON COMMENT 'Top 20 user agents',
    top_referers    JSON COMMENT 'Top 20 referers',
    error_count     INT UNSIGNED NOT NULL DEFAULT 0,
    top_errors      JSON COMMENT 'Top 20 error messages',
    PRIMARY KEY (id),
    UNIQUE KEY uk_site_hour (site_id, hour_bucket),
    KEY idx_hour (hour_bucket)
) ENGINE=InnoDB;

-- ============================================================================
-- 13. Log analytics — daily per-page stats
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_log_page_stats (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    site_id         INT UNSIGNED NOT NULL,
    path            VARCHAR(2048) NOT NULL,
    day_bucket      DATE NOT NULL,
    hits            BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes           BIGINT UNSIGNED NOT NULL DEFAULT 0,
    unique_ips      INT UNSIGNED NOT NULL DEFAULT 0,
    avg_status      FLOAT NOT NULL DEFAULT 0,
    error_count     INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_site_day (site_id, day_bucket),
    KEY idx_path (path(255))
) ENGINE=InnoDB;

-- ============================================================================
-- 14. Log analytics — real-time counters
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_log_realtime (
    site_id         INT UNSIGNED NOT NULL,
    requests_1m     INT UNSIGNED NOT NULL DEFAULT 0,
    requests_5m     INT UNSIGNED NOT NULL DEFAULT 0,
    requests_15m    INT UNSIGNED NOT NULL DEFAULT 0,
    bytes_1m        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    errors_1m       INT UNSIGNED NOT NULL DEFAULT 0,
    active_ips      INT UNSIGNED NOT NULL DEFAULT 0,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (site_id)
) ENGINE=InnoDB;

-- ============================================================================
-- 15. Parsed nginx error log entries
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_error_log (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    site_id         INT UNSIGNED NOT NULL,
    logged_at       DATETIME(3) NOT NULL,
    level           ENUM('debug','info','notice','warn','error','crit','alert','emerg') NOT NULL,
    message         TEXT NOT NULL,
    client_ip       VARCHAR(45) NOT NULL DEFAULT '',
    request_path    VARCHAR(2048) NOT NULL DEFAULT '',
    upstream_url    VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    KEY idx_site_time (site_id, logged_at),
    KEY idx_level (level)
) ENGINE=InnoDB;

-- ============================================================================
-- 16. Self-performance metrics
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_perf_metrics (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    recorded_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    daemon          ENUM('backdraft') NOT NULL DEFAULT 'backdraft',
    pid             INT UNSIGNED NOT NULL,
    cpu_percent     FLOAT NOT NULL DEFAULT 0,
    mem_rss_mb      FLOAT NOT NULL DEFAULT 0,
    mem_vms_mb      FLOAT NOT NULL DEFAULT 0,
    threads         INT UNSIGNED NOT NULL DEFAULT 0,
    goroutines      INT UNSIGNED NOT NULL DEFAULT 0,
    open_fds        INT UNSIGNED NOT NULL DEFAULT 0,
    db_queries_1m   INT UNSIGNED NOT NULL DEFAULT 0,
    db_latency_p95  FLOAT NOT NULL DEFAULT 0 COMMENT 'milliseconds',
    log_bytes_read  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    log_bytes_write BIGINT UNSIGNED NOT NULL DEFAULT 0,
    waf_rps         FLOAT NOT NULL DEFAULT 0,
    waf_avg_ms      FLOAT NOT NULL DEFAULT 0,
    custom_json     JSON COMMENT 'daemon-specific extra metrics',
    PRIMARY KEY (id),
    KEY idx_time (recorded_at),
    KEY idx_daemon (daemon)
) ENGINE=InnoDB;

-- ============================================================================
-- 17. Scheduled tasks (task scheduler)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_tasks (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id         VARCHAR(64)  NOT NULL COMMENT 'Unique slug e.g. threat_analysis_report',
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    task_type       ENUM('report','maintenance','analysis','alert','custom') NOT NULL DEFAULT 'custom',
    schedule        VARCHAR(32)  NOT NULL DEFAULT '24h' COMMENT '"30s","15m","2h","24h" or cron',
    handler         VARCHAR(255) NOT NULL COMMENT 'PHP script filename in tasks/',
    params          JSON         COMMENT 'Handler parameters as JSON object',
    priority        ENUM('low','normal','high','critical') NOT NULL DEFAULT 'normal',
    enabled         TINYINT(1)   NOT NULL DEFAULT 1,
    last_run_at     DATETIME     DEFAULT NULL,
    next_run_at     DATETIME     DEFAULT NULL,
    run_count       INT UNSIGNED NOT NULL DEFAULT 0,
    created_by      VARCHAR(64)  DEFAULT NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_task_id (task_id),
    KEY idx_enabled (enabled),
    KEY idx_next_run (next_run_at),
    KEY idx_type (task_type)
) ENGINE=InnoDB;

-- ============================================================================
-- 18. Task execution history
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_task_runs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    task_id         VARCHAR(64)  NOT NULL,
    started_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at        DATETIME     DEFAULT NULL,
    status          ENUM('running','success','failed','partial') NOT NULL DEFAULT 'running',
    output_log      LONGTEXT     COMMENT 'Full handler stdout/stderr',
    error_msg       TEXT         COMMENT 'Error message if failed',
    summary_json    JSON         COMMENT 'Handler-specific metrics and report data',
    export_html     LONGTEXT     COMMENT 'Pre-rendered HTML5 report',
    export_formats  VARCHAR(128) NOT NULL DEFAULT '' COMMENT 'Available export formats csv list',
    PRIMARY KEY (id),
    KEY idx_task (task_id),
    KEY idx_started (started_at),
    KEY idx_status (status)
) ENGINE=InnoDB;

-- ============================================================================
-- 19. BotProof challenges (pending CAPTCHA tokens)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_botproof_challenges (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token           VARCHAR(64) NOT NULL,
    answer_hash     VARCHAR(64) NOT NULL COMMENT 'SHA-256 of lowercase answer',
    client_ip       VARCHAR(45) NOT NULL,
    page_id         VARCHAR(256) NOT NULL DEFAULT '',
    original_url    VARCHAR(2048) NOT NULL,
    challenge_type  ENUM('text','math') NOT NULL DEFAULT 'text',
    attempts_left   TINYINT UNSIGNED NOT NULL DEFAULT 3,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_token (token),
    KEY idx_ip (client_ip(32)),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB;

-- ============================================================================
-- 20. BotProof verified sessions (proven humans)
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_botproof_sessions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token           VARCHAR(64) NOT NULL,
    client_ip       VARCHAR(45) NOT NULL,
    site_id         INT UNSIGNED NOT NULL DEFAULT 0,
    verified_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      DATETIME NOT NULL,
    challenges_solved INT UNSIGNED NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uk_token (token),
    KEY idx_ip (client_ip(32)),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB;

-- ============================================================================
-- 21. Secure Lock OTP tokens
-- ============================================================================
CREATE TABLE IF NOT EXISTS backdraft_secure_otp (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token           VARCHAR(64) NOT NULL,
    email           VARCHAR(256) NOT NULL,
    code_hash       VARCHAR(64) NOT NULL COMMENT 'SHA-256 of the 6-digit code',
    client_ip       VARCHAR(45) NOT NULL,
    page_id         VARCHAR(256) NOT NULL DEFAULT '',
    original_url    VARCHAR(2048) NOT NULL DEFAULT '/',
    attempts_left   TINYINT UNSIGNED NOT NULL DEFAULT 3,
    sent_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at     DATETIME DEFAULT NULL,
    expires_at      DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_token (token),
    KEY idx_email (email(64)),
    KEY idx_ip (client_ip(32)),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB;

SET unique_checks = 1;
SET foreign_key_checks = 1;

-- ============================================================================
-- SEED DATA
-- ============================================================================

-- Default superadmin user
INSERT IGNORE INTO backdraft_users (username, password_hash, role, active)
VALUES ('dstjohn', SHA2('DUMMY_MARIADB_PWD_SET_VIA_VAULT', 256), 'superadmin', 1);

-- Default runtime config
INSERT IGNORE INTO backdraft_config (config_key, config_value, description) VALUES
    ('waf_mode', 'learning', 'learning | active | disabled'),
    ('threat_threshold', '75', 'Score at which to flag (learning) or block (active)'),
    ('request_log_retention_days', '90', 'Auto-purge request log after N days'),
    ('threat_log_retention_days', '365', 'Auto-purge threat log after N days'),
    ('ip_ban_auto_threshold', '3', 'Auto-ban IP after N critical threats (0=disabled)'),
    ('rule_reload_secs', '30', 'How often Go WAF polls for rule changes'),
    ('perf_metrics_interval_secs', '10', 'Self-monitoring write interval'),
    ('log_flush_interval_secs', '60', 'Log daemon aggregation flush interval');

-- Built-in WAF rules
INSERT IGNORE INTO backdraft_rules (name, description, rule_type, target, field, operator, value, action, score, active, sort_order) VALUES
    ('SQL Injection - UNION SELECT', 'Detects UNION SELECT patterns in query strings', 'builtin', 'query', '', 'regex', '(?i)union\\s+(all\\s+)?select', 'flag', 80, 1, 10),
    ('SQL Injection - OR 1=1', 'Detects OR boolean injection attempts', 'builtin', 'query', '', 'regex', '(?i)(\\bor\\b)\\s+[0-9]+\\s*=\\s*[0-9]+', 'flag', 70, 1, 20),
    ('Path Traversal', 'Detects ../ directory traversal sequences', 'builtin', 'path', '', 'contains', '../', 'flag', 90, 1, 30),
    ('XSS - Script Tag', 'Detects <script> injection attempts', 'builtin', 'query', '', 'regex', '(?i)<script[^>]*>', 'flag', 85, 1, 40),
    ('Command Injection', 'Detects shell command patterns in queries', 'builtin', 'query', '', 'regex', '(?i)(;|\\|)\\s*(wget|curl|bash|sh|cat|nc|ncat)', 'flag', 95, 1, 50),
    ('PHP Exploit Targets', 'Requests for common PHP exploit endpoints', 'builtin', 'path', '', 'regex', '(?i)/(wp-login|xmlrpc|phpmyadmin|administrator|setup)\\.php', 'flag', 60, 1, 60),
    ('Empty User-Agent', 'Requests with no user agent string', 'builtin', 'agent', '', 'equals', '', 'log', 20, 1, 70),
    ('Non-Standard HTTP Method', 'Unusual HTTP methods often used by scanners', 'builtin', 'method', '', 'regex', '^(TRACE|CONNECT|PROPFIND|PATCH|DEBUG)$', 'log', 15, 1, 80);

-- Built-in agent signatures
INSERT IGNORE INTO backdraft_agent_signatures (pattern, match_type, classification, disposition, name, description) VALUES
    ('nikto', 'contains', 'scanner', 'block', 'Nikto', 'Web server vulnerability scanner'),
    ('sqlmap', 'contains', 'scanner', 'block', 'SQLMap', 'SQL injection exploitation tool'),
    ('nmap', 'contains', 'scanner', 'block', 'Nmap', 'Network discovery and security scanner'),
    ('masscan', 'contains', 'scanner', 'block', 'Masscan', 'Mass IP port scanner'),
    ('zgrab', 'contains', 'scanner', 'block', 'ZGrab', 'Application layer scanner'),
    ('gobuster', 'contains', 'scanner', 'block', 'GoBuster', 'Directory and DNS brute-force tool'),
    ('dirbuster', 'contains', 'scanner', 'block', 'DirBuster', 'Web directory brute-force tool'),
    ('nuclei', 'contains', 'scanner', 'block', 'Nuclei', 'Template-based vulnerability scanner'),
    ('burpsuite', 'contains', 'scanner', 'block', 'Burp Suite', 'Web application security testing platform'),
    ('Googlebot', 'contains', 'crawler', 'allow', 'Googlebot', 'Google search engine crawler'),
    ('Bingbot', 'contains', 'crawler', 'allow', 'Bingbot', 'Microsoft Bing search crawler'),
    ('curl/', 'contains', 'library', 'monitor', 'cURL', 'Command-line HTTP client'),
    ('python-requests', 'contains', 'library', 'monitor', 'Python Requests', 'Python HTTP library'),
    ('wget/', 'contains', 'library', 'monitor', 'Wget', 'GNU network downloader');

-- Default scheduled tasks (8 handlers)
INSERT IGNORE INTO backdraft_tasks (task_id, name, description, task_type, schedule, handler, params, priority, enabled, next_run_at, created_by) VALUES
    ('threat_analysis_report', 'Threat Analysis Report', 'Generates comprehensive threat analysis from log data, agent signatures, IP reputation, and rule triggers. Includes severity breakdown, top offenders, remediation guidance, and exportable reports.', 'report', '24h', 'threat-analysis-report.php', '{"hours": 24, "export": "html,pdf,excel"}', 'high', 1, DATE_ADD(NOW(), INTERVAL 1 HOUR), 'system'),
    ('log_stats_aggregate', 'Log Stats Aggregation', 'Parses nginx access logs for all monitored sites. Aggregates into hourly stats, daily page stats, and realtime counters. Uses high-water marks to only process new data.', 'analysis', '1h', 'log-stats-aggregate.php', '{}', 'normal', 1, DATE_ADD(NOW(), INTERVAL 1 HOUR), 'system'),
    ('ip_reputation_update', 'IP Reputation Update', 'Recalculates IP reputation scores from requests and threats. Auto-bans IPs exceeding critical threat threshold.', 'analysis', '6h', 'ip-reputation-update.php', '{"hours": 6}', 'normal', 1, DATE_ADD(NOW(), INTERVAL 2 HOUR), 'system'),
    ('data_retention_cleanup', 'Data Retention Cleanup', 'Purges expired request logs, threat records, sessions, perf metrics, and task runs per retention policy. Batch deletes to avoid table locks.', 'maintenance', '24h', 'data-retention-cleanup.php', '{"batch_size": 500}', 'low', 0, DATE_ADD(NOW(), INTERVAL 24 HOUR), 'system'),
    ('error_log_parse', 'Error Log Parser', 'Parses nginx error logs for all monitored sites into backdraft_error_log. Tracks parse position via high-water marks for incremental processing.', 'analysis', '15m', 'error-log-parse.php', '{}', 'normal', 1, NOW(), 'system'),
    ('session_cleanup', 'Session Cleanup', 'Purges expired authentication sessions from backdraft_sessions to keep auth lookups fast.', 'maintenance', '1h', 'session-cleanup.php', '{}', 'low', 1, DATE_ADD(NOW(), INTERVAL 30 MINUTE), 'system'),
    ('agent_activity_scan', 'Agent Activity Scan', 'Scans recent requests against agent signatures, identifies new scanners/bots, flags suspicious user-agents not in signature DB, updates scanner IP reputation.', 'analysis', '2h', 'agent-activity-scan.php', '{"hours": 2}', 'normal', 1, DATE_ADD(NOW(), INTERVAL 1 HOUR), 'system'),
    ('anomaly_baseline_check', 'Anomaly Baseline Check', 'Compares current traffic patterns to learned page profile baselines. Detects new HTTP methods, content type changes, volume spikes (>300%), threat score spikes, and new IP clusters.', 'analysis', '30m', 'anomaly-baseline-check.php', '{"window": 30}', 'high', 1, DATE_ADD(NOW(), INTERVAL 15 MINUTE), 'system');

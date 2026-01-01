#ifndef BACKDRAFT_CONFIG_H
#define BACKDRAFT_CONFIG_H

#include <string>
#include <vector>
#include <cstdint>

struct LogConfig {
    std::string level = "DEBUG";
    std::string dir   = "logs";
    int max_mb        = 50;
    int keep          = 5;
};

struct AuthConfig {
    std::string master_username = "admin";
    std::string master_password;
    std::string api_token;
    int session_ttl_secs = 3600;
};

struct HttpConfig {
    std::string bind_addr   = "0.0.0.0";
    int web_port            = 8862;
    int api_port            = 8832;
    int waf_port            = 9432;
    bool enable_https       = true;
    std::string tls_cert;
    std::string tls_key;
    std::string web_root    = "web";
    std::string fcgi_socket = "/run/php/php8.2-fpm-backdraft.sock";
};

struct SmtpConfig {
    std::string host      = "smtp.gmail.com";
    int port              = 587;
    std::string username;
    std::string password;
    std::string from_addr;
    std::string from_name = "Mcaster1 BackDraft WAF";
    bool use_tls          = true;
};

struct DbConfig {
    std::string name     = "backdraft";
    std::string host     = "127.0.0.1";
    int port             = 3306;
    std::string database = "mcaster1_backdraft";
    std::string username;
    std::string password;
    std::string charset  = "utf8mb4";
    int pool_size        = 8;
};

struct NginxConfig {
    std::string sites_enabled = "/etc/nginx/sites-enabled";
    std::string conf_d        = "/etc/nginx/conf.d";
    std::string backdraft_d   = "/etc/nginx/backdraft.d";
    std::string snippets      = "/etc/nginx/snippets";
    std::string nginx_bin     = "/usr/sbin/nginx";
    bool sudo_reload          = true;
};

struct WafConfig {
    std::string mode             = "learning";
    int rule_reload_secs         = 30;
    int threat_threshold         = 75;
    int max_body_inspect         = 65536;
    bool log_all_requests        = true;
    std::string upstream_fcgi    = "/run/php/php8.2-fpm.sock";
    int botproof_challenge_ttl_secs = 300;
    int botproof_cooldown_secs     = 600;
    std::string botproof_font      = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf";
};

struct PerfConfig {
    bool enabled       = true;
    int interval_secs  = 10;
};

struct AppConfig {
    std::string app_name = "Mcaster1BackDraft";
    std::string version  = "0.0.1a";
    std::string pid_file = "/var/run/Mcaster1BackDraft.pid";
    bool daemon          = false;

    LogConfig   log;
    AuthConfig  auth;
    HttpConfig  http;
    SmtpConfig  smtp;
    std::vector<DbConfig> databases;
    NginxConfig nginx;
    WafConfig   waf;
    PerfConfig  perf;
};

class Config {
public:
    static Config& instance();
    void load(const std::string& path);
    const AppConfig& get() const { return cfg_; }

private:
    Config() = default;
    AppConfig cfg_;
};

#define CFG Config::instance().get()

#endif

#include "config.h"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
#include <iostream>

Config& Config::instance() {
    static Config inst;
    return inst;
}

void Config::load(const std::string& path) {
    YAML::Node root = YAML::LoadFile(path);

    if (root["app_name"])  cfg_.app_name = root["app_name"].as<std::string>();
    if (root["version"])   cfg_.version  = root["version"].as<std::string>();
    if (root["pid_file"])  cfg_.pid_file = root["pid_file"].as<std::string>();
    if (root["daemon"])    cfg_.daemon   = root["daemon"].as<bool>();

    if (auto n = root["log"]) {
        if (n["level"])  cfg_.log.level  = n["level"].as<std::string>();
        if (n["dir"])    cfg_.log.dir    = n["dir"].as<std::string>();
        if (n["max_mb"]) cfg_.log.max_mb = n["max_mb"].as<int>();
        if (n["keep"])   cfg_.log.keep   = n["keep"].as<int>();
    }

    if (auto n = root["auth"]) {
        if (n["master_username"])  cfg_.auth.master_username  = n["master_username"].as<std::string>();
        if (n["master_password"])  cfg_.auth.master_password  = n["master_password"].as<std::string>();
        if (n["api_token"])        cfg_.auth.api_token        = n["api_token"].as<std::string>();
        if (n["session_ttl_secs"]) cfg_.auth.session_ttl_secs = n["session_ttl_secs"].as<int>();
    }

    if (auto n = root["http"]) {
        if (n["bind_addr"])     cfg_.http.bind_addr     = n["bind_addr"].as<std::string>();
        if (n["web_port"])      cfg_.http.web_port      = n["web_port"].as<int>();
        if (n["api_port"])      cfg_.http.api_port      = n["api_port"].as<int>();
        if (n["waf_port"])      cfg_.http.waf_port      = n["waf_port"].as<int>();
        if (n["enable_https"])  cfg_.http.enable_https  = n["enable_https"].as<bool>();
        if (n["tls_cert"])      cfg_.http.tls_cert      = n["tls_cert"].as<std::string>();
        if (n["tls_key"])       cfg_.http.tls_key       = n["tls_key"].as<std::string>();
        if (n["web_root"])      cfg_.http.web_root      = n["web_root"].as<std::string>();
        if (n["fcgi_socket"])   cfg_.http.fcgi_socket   = n["fcgi_socket"].as<std::string>();
    }

    if (auto n = root["smtp"]) {
        if (n["host"])      cfg_.smtp.host      = n["host"].as<std::string>();
        if (n["port"])      cfg_.smtp.port      = n["port"].as<int>();
        if (n["username"])  cfg_.smtp.username   = n["username"].as<std::string>();
        if (n["password"])  cfg_.smtp.password   = n["password"].as<std::string>();
        if (n["from_addr"]) cfg_.smtp.from_addr  = n["from_addr"].as<std::string>();
        if (n["from_name"]) cfg_.smtp.from_name  = n["from_name"].as<std::string>();
        if (n["use_tls"])   cfg_.smtp.use_tls    = n["use_tls"].as<bool>();
    }

    if (auto dbs = root["databases"]) {
        cfg_.databases.clear();
        for (const auto& d : dbs) {
            DbConfig db;
            if (d["name"])      db.name      = d["name"].as<std::string>();
            if (d["host"])      db.host      = d["host"].as<std::string>();
            if (d["port"])      db.port      = d["port"].as<int>();
            if (d["database"])  db.database  = d["database"].as<std::string>();
            if (d["username"])  db.username  = d["username"].as<std::string>();
            if (d["password"])  db.password  = d["password"].as<std::string>();
            if (d["charset"])   db.charset   = d["charset"].as<std::string>();
            if (d["pool_size"]) db.pool_size = d["pool_size"].as<int>();
            cfg_.databases.push_back(db);
        }
    }

    if (auto n = root["nginx"]) {
        if (n["sites_enabled"]) cfg_.nginx.sites_enabled = n["sites_enabled"].as<std::string>();
        if (n["conf_d"])        cfg_.nginx.conf_d        = n["conf_d"].as<std::string>();
        if (n["backdraft_d"])   cfg_.nginx.backdraft_d   = n["backdraft_d"].as<std::string>();
        if (n["snippets"])      cfg_.nginx.snippets      = n["snippets"].as<std::string>();
        if (n["nginx_bin"])     cfg_.nginx.nginx_bin     = n["nginx_bin"].as<std::string>();
        if (n["sudo_reload"])   cfg_.nginx.sudo_reload   = n["sudo_reload"].as<bool>();
    }

    if (auto n = root["waf"]) {
        if (n["mode"])               cfg_.waf.mode               = n["mode"].as<std::string>();
        if (n["rule_reload_secs"])   cfg_.waf.rule_reload_secs   = n["rule_reload_secs"].as<int>();
        if (n["threat_threshold"])   cfg_.waf.threat_threshold   = n["threat_threshold"].as<int>();
        if (n["max_body_inspect"])   cfg_.waf.max_body_inspect   = n["max_body_inspect"].as<int>();
        if (n["log_all_requests"])   cfg_.waf.log_all_requests   = n["log_all_requests"].as<bool>();
        if (n["upstream_fcgi"])      cfg_.waf.upstream_fcgi      = n["upstream_fcgi"].as<std::string>();
    }

    if (auto n = root["perf"]) {
        if (n["enabled"])       cfg_.perf.enabled       = n["enabled"].as<bool>();
        if (n["interval_secs"]) cfg_.perf.interval_secs = n["interval_secs"].as<int>();
    }
}

#ifndef BACKDRAFT_NGINX_MANAGER_H
#define BACKDRAFT_NGINX_MANAGER_H

#include <string>
#include <vector>

namespace NginxManager {
    // Core nginx operations
    bool test_config();
    bool reload();

    // Site config directory management
    bool ensure_site_dir(const std::string& site_name);
    bool ensure_include(const std::string& site_name);

    // WAF snippet management
    bool write_waf_snippet(const std::string& site_name, int waf_port);
    bool remove_waf_snippet(const std::string& site_name);
    bool deploy_waf_config(const std::string& site_name, int waf_port);

    // Maintenance mode
    bool set_maintenance_mode(const std::string& site_name, bool active);

    // Security blocking snippets
    struct SecurityBlockConfig {
        bool bad_agent   = false;
        bool banned_ip   = false;
        bool bad_path    = false;
        bool bad_payload = false;
        bool bad_cookie  = false;
        bool bad_referer = false;
        bool logging     = false;
    };
    bool write_security_snippet(const std::string& site_name, const SecurityBlockConfig& cfg);
    bool remove_security_snippet(const std::string& site_name);

    // Rate limit snippets
    bool write_rate_limit_snippet(const std::string& site_name, bool login_limit);
    bool remove_rate_limit_snippet(const std::string& site_name);

    // Security log directory
    bool ensure_security_log_dir(const std::string& site_name);

    // Blacklist sync (DB → nginx conf files)
    bool sync_ip_blacklist();
    bool sync_agent_blacklist();

    // Emergency lockdown (atomic multi-operation)
    bool emergency_lockdown(const std::vector<std::string>& site_names);
}

#endif

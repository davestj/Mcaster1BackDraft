#include "nginx_manager.h"
#include "config.h"
#include "dbpool.h"
#include "logger.h"

#include <cstdlib>
#include <sys/wait.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;

namespace NginxManager {

// ── Helpers ──────────────────────────────────────────────────────────────

// Run shell command, optionally with sudo
// For compound commands (&&, ||, ;), wraps in sudo bash -c to ensure sudo applies to all parts
static int run_cmd(const std::string& cmd, bool use_sudo = false) {
    std::string full;
    if (use_sudo) {
        if (cmd.find("&&") != std::string::npos || cmd.find("||") != std::string::npos || cmd.find(";") != std::string::npos) {
            // Compound command — wrap in bash -c so sudo applies to everything
            // Escape single quotes in cmd
            std::string escaped = cmd;
            size_t pos = 0;
            while ((pos = escaped.find('\'', pos)) != std::string::npos) {
                escaped.replace(pos, 1, "'\\''");
                pos += 4;
            }
            full = "sudo bash -c '" + escaped + "'";
        } else {
            full = "sudo " + cmd;
        }
    } else {
        full = cmd;
    }
    return system(full.c_str());
}

// Get the site config directory: backdraft_d/sites/{site_name}/
static std::string site_conf_dir(const std::string& site_name) {
    return CFG.nginx.backdraft_d + "/sites/" + site_name;
}

// ── Public API ───────────────────────────────────────────────────────────

bool test_config() {
    std::string cmd = CFG.nginx.nginx_bin + " -t 2>/dev/null";
    int raw = run_cmd(cmd, CFG.nginx.sudo_reload);
    int ret = WEXITSTATUS(raw);
    if (ret != 0) {
        LOG_ERROR("nginx -t failed (raw=" + std::to_string(raw) + " exit=" + std::to_string(ret) + ")");
        return false;
    }
    LOG_INFO("nginx config test passed");
    return true;
}

bool reload() {
    std::string cmd = CFG.nginx.nginx_bin + " -s reload 2>/dev/null";
    int raw = run_cmd(cmd, CFG.nginx.sudo_reload);
    int ret = WEXITSTATUS(raw);
    if (ret != 0) {
        LOG_ERROR("nginx reload failed (raw=" + std::to_string(raw) + " exit=" + std::to_string(ret) + ")");
        return false;
    }
    LOG_INFO("nginx reloaded successfully");
    return true;
}

bool ensure_site_dir(const std::string& site_name) {
    std::string dir = site_conf_dir(site_name);
    if (fs::exists(dir)) return true;

    // Create with sudo since /etc/nginx is root-owned
    std::string cmd = "mkdir -p " + dir + " && chmod 755 " + dir;
    int ret = run_cmd(cmd, true);
    if (ret != 0) {
        LOG_ERROR("Failed to create site config dir: " + dir);
        return false;
    }
    LOG_INFO("Created site config dir: " + dir);
    return true;
}

bool write_waf_snippet(const std::string& site_name, int waf_port) {
    // Ensure directory exists
    if (!ensure_site_dir(site_name)) return false;

    std::string dir = site_conf_dir(site_name);
    std::string filename = dir + "/" + site_name + ".conf";

    // Get protected pages from DB
    std::vector<std::string> pages;
    try {
        auto conn = DB("backdraft");
        if (conn) {
            // First check protected_paths on the site
            MYSQL_RES* res = conn->query(
                "SELECT protected_paths FROM backdraft_sites WHERE site_name='" + site_name + "' LIMIT 1");
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row && row[0]) {
                    // Parse JSON array
                    std::string json_str = row[0];
                    // Simple JSON array parser: ["a","b","c"]
                    size_t pos = 0;
                    while ((pos = json_str.find('"', pos)) != std::string::npos) {
                        size_t end = json_str.find('"', pos + 1);
                        if (end == std::string::npos) break;
                        std::string page = json_str.substr(pos + 1, end - pos - 1);
                        if (!page.empty() && page[0] != '[' && page[0] != ']') {
                            pages.push_back(page);
                        }
                        pos = end + 1;
                    }
                }
                mysql_free_result(res);
            }

            // Also get pages from page profiles
            res = conn->query(
                "SELECT page_id FROM backdraft_page_profiles WHERE site_id = "
                "(SELECT id FROM backdraft_sites WHERE site_name='" + site_name + "')");
            if (res) {
                MYSQL_ROW row;
                while ((row = mysql_fetch_row(res))) {
                    if (row[0]) {
                        std::string page_id = row[0];
                        // Extract path: "site.com/path" → "/path"
                        auto slash = page_id.find('/');
                        if (slash != std::string::npos) {
                            std::string path = page_id.substr(slash);
                            // Check not already in list
                            bool found = false;
                            for (auto& p : pages) if ("/" + p == path || p == path.substr(1)) found = true;
                            if (!found) pages.push_back(path.substr(1)); // store without leading /
                        }
                    }
                }
                mysql_free_result(res);
            }
        }
    } catch (...) {}

    if (pages.empty()) {
        LOG_WARN("No protected pages found for " + site_name + " — skipping snippet generation");
        return false;
    }

    // Generate timestamp
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&time));

    // Write to temp file, then sudo mv (since /etc/nginx is root-owned)
    std::string tmp_file = "/tmp/backdraft_nginx_" + site_name + ".conf";
    std::ofstream f(tmp_file);
    if (!f.is_open()) {
        LOG_ERROR("Cannot write temp nginx snippet: " + tmp_file);
        return false;
    }

    f << "# ============================================================\n";
    f << "# Mcaster1BackDraft WAF — nginx config for " << site_name << "\n";
    f << "# Auto-generated: " << date_buf << "\n";
    f << "# DO NOT EDIT — regenerated by BackDraft on page enrollment\n";
    f << "# ============================================================\n\n";

    for (auto& page_path : pages) {
        std::string clean_path = page_path;
        if (!clean_path.empty() && clean_path[0] == '/') clean_path = clean_path.substr(1);
        std::string page_id = site_name + "/" + clean_path;

        f << "# WAF: /" << clean_path << "\n";
        f << "location = /" << clean_path << " {\n";
        f << "    proxy_pass https://127.0.0.1:" << waf_port << ";\n";
        f << "    proxy_http_version 1.1;\n";
        f << "    proxy_set_header Host $host;\n";
        f << "    proxy_set_header X-Real-IP $remote_addr;\n";
        f << "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n";
        f << "    proxy_set_header X-Forwarded-Proto $scheme;\n";
        f << "    proxy_set_header Connection \"\";\n";
        f << "    proxy_set_header X-BackDraft-Upstream \"http://unix:/run/php/php8.2-fpm.sock\";\n";
        f << "    proxy_set_header X-BackDraft-Page \"" << page_id << "\";\n";
        f << "    proxy_buffering off;\n";
        f << "    proxy_read_timeout 60s;\n";
        f << "}\n\n";
    }

    f.close();

    // Move to final location with sudo
    int ret = run_cmd("cp " + tmp_file + " " + filename + " && chmod 644 " + filename, true);
    std::remove(tmp_file.c_str());

    if (ret != 0) {
        LOG_ERROR("Failed to install nginx snippet: " + filename);
        return false;
    }

    LOG_INFO("Wrote nginx WAF snippet: " + filename + " (" +
             std::to_string(pages.size()) + " pages)");
    return true;
}

bool ensure_include(const std::string& site_name) {
    // Check if the site's nginx config already has the wildcard include
    std::string include_line = "include /etc/nginx/backdraft.d/sites/" + site_name + "/*.conf;";

    // Find the site config path
    std::string config_path;
    try {
        auto conn = DB("backdraft");
        if (conn) {
            MYSQL_RES* res = conn->query(
                "SELECT config_path FROM backdraft_sites WHERE site_name='" + site_name + "' LIMIT 1");
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row && row[0]) config_path = row[0];
                mysql_free_result(res);
            }
        }
    } catch (...) {}

    if (config_path.empty() || !fs::exists(config_path)) {
        LOG_WARN("Cannot find nginx config for " + site_name);
        return false;
    }

    // Read config content
    std::ifstream cf(config_path);
    if (!cf.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    cf.close();

    // Check if include already present (any form)
    if (content.find("backdraft.d/sites/" + site_name) != std::string::npos ||
        content.find("backdraft.d/" + site_name) != std::string::npos) {
        LOG_DEBUG("Include already present for " + site_name);
        return true;
    }

    // Inject include line right after the maintenance snippet include
    // Pattern: include /etc/nginx/snippets/{site}-maint.conf;
    //          include /etc/nginx/backdraft.d/sites/{site}/*.conf;  <-- inject here
    std::string maint_include = "snippets/" + site_name + "-maint.conf";
    auto maint_pos = content.find(maint_include);

    size_t inject_pos;
    if (maint_pos != std::string::npos) {
        // Found maintenance include — inject right after it
        auto maint_eol = content.find('\n', maint_pos);
        inject_pos = (maint_eol != std::string::npos) ? maint_eol + 1 : content.size();
    } else {
        // No maintenance include — inject after root/index directives
        auto server_name_pos = content.find("server_name");
        if (server_name_pos == std::string::npos) {
            LOG_WARN("Cannot find server_name in " + config_path);
            return false;
        }
        auto eol = content.find('\n', server_name_pos);
        if (eol == std::string::npos) return false;

        // Scan past root, index lines
        inject_pos = eol + 1;
        while (inject_pos < content.size()) {
            auto next_eol = content.find('\n', inject_pos);
            if (next_eol == std::string::npos) break;
            std::string line = content.substr(inject_pos, next_eol - inject_pos);
            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos) { inject_pos = next_eol + 1; continue; }
            std::string trimmed = line.substr(start);
            if (trimmed.find("root ") == 0 || trimmed.find("index ") == 0 ||
                trimmed.find("set ") == 0 || trimmed.find("include ") == 0 ||
                trimmed.empty()) {
                inject_pos = next_eol + 1;
                continue;
            }
            break;
        }
    }

    // Build new content
    std::string inject = "\n    " + include_line + "\n";
    std::string new_content = content.substr(0, inject_pos) + inject + content.substr(inject_pos);

    // Write via temp file + sudo cp
    std::string tmp = "/tmp/backdraft_nginx_site_" + site_name + ".conf";
    std::ofstream tf(tmp);
    if (!tf.is_open()) return false;
    tf << new_content;
    tf.close();

    int ret = run_cmd("cp " + tmp + " " + config_path, true);
    std::remove(tmp.c_str());

    if (ret != 0) {
        LOG_ERROR("Failed to inject include into " + config_path);
        return false;
    }

    LOG_INFO("Injected BackDraft include into " + config_path);
    return true;
}

bool remove_waf_snippet(const std::string& site_name) {
    std::string dir = site_conf_dir(site_name);
    std::string filename = dir + "/" + site_name + ".conf";

    if (fs::exists(filename)) {
        int ret = run_cmd("rm -f " + filename, true);
        if (ret == 0) {
            LOG_INFO("Removed nginx WAF snippet: " + filename);
            return true;
        }
    }
    return false;
}

bool deploy_waf_config(const std::string& site_name, int waf_port) {
    // Full automated deployment:
    // 1. Ensure site directory exists
    // 2. Generate and write WAF snippet
    // 3. Ensure include line in site nginx config
    // 4. Test nginx config
    // 5. Reload nginx

    LOG_INFO("Deploying WAF config for " + site_name);

    if (!write_waf_snippet(site_name, waf_port)) {
        LOG_ERROR("Deploy failed: could not write snippet for " + site_name);
        return false;
    }

    if (!ensure_include(site_name)) {
        LOG_WARN("Deploy: include injection skipped for " + site_name + " (may already exist)");
    }

    if (!test_config()) {
        LOG_ERROR("Deploy failed: nginx config test failed for " + site_name);
        // Rollback: remove the bad snippet
        remove_waf_snippet(site_name);
        return false;
    }

    if (!reload()) {
        LOG_ERROR("Deploy failed: nginx reload failed for " + site_name);
        return false;
    }

    LOG_INFO("WAF config deployed successfully for " + site_name);
    return true;
}

// ============================================================================
// Maintenance Mode
// ============================================================================

bool set_maintenance_mode(const std::string& site_name, bool active) {
    // Find the maint snippet file — try multiple naming patterns
    std::vector<std::string> candidates = {
        "/etc/nginx/snippets/" + site_name + "-maint.conf",
        "/etc/nginx/snippets/" + site_name.substr(0, site_name.find('.')) + "-maint.conf",
    };
    // For subdomains like yp.mcaster1.com, try yp-mcaster1.com
    auto dot = site_name.find('.');
    if (dot != std::string::npos) {
        std::string alt = site_name;
        alt[dot] = '-';
        // Try yp-mcaster1.com-maint.conf pattern
        candidates.push_back("/etc/nginx/snippets/" + alt + "-maint.conf");
    }

    std::string maint_file;
    for (auto& c : candidates) {
        if (fs::exists(c)) { maint_file = c; break; }
    }

    if (maint_file.empty()) {
        LOG_WARN("No maintenance snippet found for " + site_name);
        // Create one
        maint_file = "/etc/nginx/snippets/" + site_name + "-maint.conf";
        std::string content = "# Maintenance mode for " + site_name + "\n"
                              "set $maintenance_active " + std::string(active ? "1" : "0") + ";\n"
                              "set $maintenance_window 3600;\n";
        std::string tmp = "/tmp/backdraft_maint_" + site_name + ".conf";
        std::ofstream f(tmp);
        f << content;
        f.close();
        run_cmd("cp " + tmp + " " + maint_file + " && chmod 644 " + maint_file, true);
        std::remove(tmp.c_str());
        LOG_INFO("Created maintenance snippet: " + maint_file);
        return true;
    }

    // Read existing file
    std::ifstream inf(maint_file);
    if (!inf.is_open()) {
        LOG_ERROR("Cannot read maint file: " + maint_file);
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(inf)), std::istreambuf_iterator<char>());
    inf.close();

    // Replace $maintenance_active value
    std::string old_val = "set $maintenance_active " + std::string(active ? "0" : "1");
    std::string new_val = "set $maintenance_active " + std::string(active ? "1" : "0");
    auto pos = content.find(old_val);
    if (pos != std::string::npos) {
        content.replace(pos, old_val.size(), new_val);
    } else {
        // Maybe already set to desired value
        if (content.find(new_val) != std::string::npos) {
            LOG_INFO("Maintenance already " + std::string(active ? "ON" : "OFF") + " for " + site_name);
            return true;
        }
        LOG_WARN("Could not find maintenance_active variable in " + maint_file);
        return false;
    }

    // Write back
    std::string tmp = "/tmp/backdraft_maint_" + site_name + ".conf";
    std::ofstream outf(tmp);
    outf << content;
    outf.close();
    int ret = run_cmd("cp " + tmp + " " + maint_file, true);
    std::remove(tmp.c_str());

    if (ret != 0) {
        LOG_ERROR("Failed to write maintenance file: " + maint_file);
        return false;
    }

    LOG_INFO("Maintenance mode " + std::string(active ? "ENABLED" : "DISABLED") + " for " + site_name);
    return true;
}

// ============================================================================
// Security Blocking Snippet
// ============================================================================

bool write_security_snippet(const std::string& site_name, const SecurityBlockConfig& cfg) {
    if (!ensure_site_dir(site_name)) return false;

    std::string dir = site_conf_dir(site_name);
    std::string filename = dir + "/" + site_name + "-security.conf";

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", localtime(&time));

    std::string tmp = "/tmp/backdraft_security_" + site_name + ".conf";
    std::ofstream f(tmp);
    if (!f.is_open()) return false;

    f << "# BackDraft Security Blocks for " << site_name << "\n";
    f << "# Auto-generated: " << date_buf << " — DO NOT EDIT\n\n";

    if (cfg.bad_agent)   f << "if ($bad_agent = 1)   { return 403; }\n";
    if (cfg.banned_ip)   f << "if ($banned_ip = 1)   { return 403; }\n";
    if (cfg.bad_path)    f << "if ($bad_path = 1)    { return 403; }\n";
    if (cfg.bad_payload) f << "if ($bad_payload = 1) { return 403; }\n";
    if (cfg.bad_cookie)  f << "if ($bad_cookie = 1)  { return 403; }\n";
    if (cfg.bad_referer) f << "if ($bad_referer = 1) { return 403; }\n";

    if (cfg.logging) {
        std::string log_dir = "/var/www/" + site_name + "/logs/security";
        f << "\n# Security event logging\n";
        if (cfg.bad_agent)   f << "access_log " << log_dir << "/agent_blocks.log blocked_agents if=$bad_agent;\n";
        if (cfg.banned_ip)   f << "access_log " << log_dir << "/ip_blocks.log banned_ips if=$banned_ip;\n";
        if (cfg.bad_path)    f << "access_log " << log_dir << "/path_blocks.log bad_paths if=$bad_path;\n";
        if (cfg.bad_payload || cfg.bad_cookie || cfg.bad_referer)
            f << "access_log " << log_dir << "/attack_blocks.log known_attacks;\n";
    }

    f.close();

    int ret = run_cmd("cp " + tmp + " " + filename + " && chmod 644 " + filename, true);
    std::remove(tmp.c_str());

    if (ret != 0) {
        LOG_ERROR("Failed to write security snippet: " + filename);
        return false;
    }

    LOG_INFO("Security snippet written for " + site_name);
    return true;
}

bool remove_security_snippet(const std::string& site_name) {
    std::string filename = site_conf_dir(site_name) + "/" + site_name + "-security.conf";
    if (fs::exists(filename)) {
        run_cmd("rm -f " + filename, true);
        LOG_INFO("Removed security snippet: " + filename);
        return true;
    }
    return false;
}

// ============================================================================
// Rate Limit Snippet
// ============================================================================

bool write_rate_limit_snippet(const std::string& site_name, bool login_limit) {
    if (!ensure_site_dir(site_name)) return false;

    std::string dir = site_conf_dir(site_name);
    std::string filename = dir + "/" + site_name + "-ratelimit.conf";

    std::string tmp = "/tmp/backdraft_ratelimit_" + site_name + ".conf";
    std::ofstream f(tmp);
    if (!f.is_open()) return false;

    f << "# BackDraft Rate Limits for " << site_name << " — DO NOT EDIT\n\n";

    if (login_limit) {
        f << "location ~ ^/(admin|wp-login|login|signin)\\.php$ {\n";
        f << "    limit_req zone=login burst=5 nodelay;\n";
        f << "    include snippets/fastcgi-php.conf;\n";
        f << "    fastcgi_pass unix:/run/php/php8.2-fpm.sock;\n";
        f << "}\n";
    }

    f.close();

    int ret = run_cmd("cp " + tmp + " " + filename + " && chmod 644 " + filename, true);
    std::remove(tmp.c_str());

    if (ret != 0) return false;
    LOG_INFO("Rate limit snippet written for " + site_name);
    return true;
}

bool remove_rate_limit_snippet(const std::string& site_name) {
    std::string filename = site_conf_dir(site_name) + "/" + site_name + "-ratelimit.conf";
    if (fs::exists(filename)) {
        run_cmd("rm -f " + filename, true);
        return true;
    }
    return false;
}

// ============================================================================
// Security Log Directory
// ============================================================================

bool ensure_security_log_dir(const std::string& site_name) {
    std::string dir = "/var/www/" + site_name + "/logs/security";
    if (fs::exists(dir)) return true;
    int ret = run_cmd("mkdir -p " + dir + " && chmod 755 " + dir + " && chown www-data:www-data " + dir, true);
    if (ret == 0) LOG_INFO("Created security log dir: " + dir);
    return ret == 0;
}

// ============================================================================
// Blacklist Sync (DB → nginx conf files)
// ============================================================================

bool sync_ip_blacklist() {
    auto conn = DB("backdraft");
    if (!conn) return false;

    MYSQL_RES* res = conn->query("SELECT ip_addr FROM backdraft_ip_reputation WHERE banned = 1");
    if (!res) return false;

    std::string tmp = "/tmp/backdraft_ip_blacklist.conf";
    std::ofstream f(tmp);
    f << "# Auto-generated by BackDraft — " << std::time(nullptr) << "\n";
    f << "# Banned IPs synced from backdraft_ip_reputation\n";

    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        if (row[0]) {
            f << row[0] << " 1;\n";
            count++;
        }
    }
    mysql_free_result(res);
    f.close();

    int ret = run_cmd("cp " + tmp + " /etc/nginx/blacklists/ip_blacklist.conf", true);
    std::remove(tmp.c_str());

    if (ret == 0) LOG_INFO("IP blacklist synced: " + std::to_string(count) + " banned IPs");
    return ret == 0;
}

bool sync_agent_blacklist() {
    auto conn = DB("backdraft");
    if (!conn) return false;

    // From bot_definitions (disposition=block) + agent_signatures (disposition=block)
    MYSQL_RES* res = conn->query(
        "SELECT DISTINCT pattern FROM ("
        "  SELECT pattern FROM backdraft_agent_signatures WHERE disposition = 'block' AND active = 1"
        "  UNION"
        "  SELECT pattern FROM backdraft_bot_definitions WHERE disposition = 'block' AND active = 1"
        ") combined ORDER BY pattern");
    if (!res) return false;

    std::string tmp = "/tmp/backdraft_bot_blacklist.conf";
    std::ofstream f(tmp);
    f << "# Auto-generated by BackDraft — " << std::time(nullptr) << "\n";

    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        if (row[0]) {
            std::string pattern = row[0];
            // Ensure pattern has ~* prefix for nginx map format
            if (pattern.find("~*") != 0) pattern = "~*" + pattern;
            f << pattern << " 1;\n";
            count++;
        }
    }
    mysql_free_result(res);
    f.close();

    int ret = run_cmd("cp " + tmp + " /etc/nginx/blacklists/bot_blacklist.conf", true);
    std::remove(tmp.c_str());

    if (ret == 0) LOG_INFO("Agent blacklist synced: " + std::to_string(count) + " blocked agents");
    return ret == 0;
}

// ============================================================================
// Emergency Lockdown
// ============================================================================

bool emergency_lockdown(const std::vector<std::string>& site_names) {
    LOG_WARN("EMERGENCY LOCKDOWN initiated for " + std::to_string(site_names.size()) + " sites");

    bool all_ok = true;
    for (const auto& site : site_names) {
        if (!set_maintenance_mode(site, true)) all_ok = false;

        SecurityBlockConfig full_block;
        full_block.bad_agent = true;
        full_block.banned_ip = true;
        full_block.bad_path = true;
        full_block.bad_payload = true;
        full_block.bad_cookie = true;
        full_block.bad_referer = true;
        full_block.logging = true;
        ensure_security_log_dir(site);
        if (!write_security_snippet(site, full_block)) all_ok = false;
    }

    // Single test + reload for all changes
    if (!test_config()) {
        LOG_ERROR("LOCKDOWN: nginx config test failed — rolling back");
        for (const auto& site : site_names) {
            set_maintenance_mode(site, false);
            remove_security_snippet(site);
        }
        return false;
    }

    reload();
    LOG_WARN("EMERGENCY LOCKDOWN complete — " + std::to_string(site_names.size()) + " sites locked");
    return all_ok;
}

} // namespace NginxManager

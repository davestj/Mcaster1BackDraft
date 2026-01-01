#include "site_discovery.h"
#include "config.h"
#include "dbpool.h"
#include "logger.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>

namespace fs = std::filesystem;

namespace SiteDiscovery {

static std::string extract_directive(const std::string& content, const std::string& directive) {
    // For 'root' directive, match only at server level (4-space indent, not inside location blocks)
    // Other directives use first match
    if (directive == "root") {
        // Find root that's NOT inside a location block — look for root after server_name but before first location
        auto loc_pos = content.find("location ");
        std::string search_area = (loc_pos != std::string::npos) ? content.substr(0, loc_pos) : content;
        std::regex re("\\b" + directive + "\\s+([^;]+);");
        std::smatch m;
        if (std::regex_search(search_area, m, re)) {
            return m[1].str();
        }
    }
    std::regex re(directive + "\\s+([^;]+);");
    std::smatch m;
    if (std::regex_search(content, m, re)) {
        return m[1].str();
    }
    return "";
}

void discover() {
    std::string sites_dir = CFG.nginx.sites_enabled;
    if (!fs::exists(sites_dir)) {
        LOG_WARN("nginx sites-enabled not found: " + sites_dir);
        return;
    }

    auto conn = DB("backdraft");
    if (!conn) {
        LOG_ERROR("DB unavailable for site discovery");
        return;
    }

    int count = 0;
    for (const auto& entry : fs::directory_iterator(sites_dir)) {
        if (!entry.is_regular_file() && !entry.is_symlink()) continue;

        std::string config_path = entry.path().string();
        std::ifstream f(config_path);
        if (!f.is_open()) continue;

        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());

        std::string server_name = extract_directive(content, "server_name");
        if (server_name.empty() || server_name == "_") continue;

        // Take first server_name if multiple
        auto sp = server_name.find(' ');
        if (sp != std::string::npos) server_name = server_name.substr(0, sp);

        std::string access_log = extract_directive(content, "access_log");
        std::string error_log  = extract_directive(content, "error_log");
        std::string doc_root   = extract_directive(content, "root");

        // Extract listen port
        std::string listen_str = extract_directive(content, "listen");
        int listen_port = 80;
        bool ssl_enabled = false;
        if (!listen_str.empty()) {
            if (listen_str.find("443") != std::string::npos) { listen_port = 443; ssl_enabled = true; }
            else if (listen_str.find("ssl") != std::string::npos) ssl_enabled = true;
            try { listen_port = std::stoi(listen_str); } catch (...) {}
        }

        // Clean log paths (remove log level suffixes like " main buffer=32k")
        auto clean_path = [](std::string& p) {
            auto sp = p.find(' ');
            if (sp != std::string::npos) p = p.substr(0, sp);
        };
        clean_path(access_log);
        clean_path(error_log);
        clean_path(doc_root);

        // Check if this config file is the "canonical" one for this server_name
        // Prefer config files whose name matches the site name (e.g. mcaster1.com for server_name mcaster1.com)
        std::string config_basename = entry.path().filename().string();
        bool is_canonical = (config_basename == server_name ||
                             config_basename == server_name + ".conf" ||
                             config_basename.find(server_name) == 0);

        // Upsert into backdraft_sites
        // Only overwrite config_path/doc_root if this is the canonical config
        // or if the existing record was set by a non-canonical config
        std::string sql;
        if (is_canonical) {
            // Canonical: always overwrite
            sql = "INSERT INTO backdraft_sites "
                "(site_name, config_path, access_log_path, error_log_path, doc_root, listen_port, ssl_enabled) "
                "VALUES ('" + server_name + "', '" + config_path + "', "
                "'" + access_log + "', '" + error_log + "', '" + doc_root + "', "
                + std::to_string(listen_port) + ", " + std::to_string(ssl_enabled ? 1 : 0) + ") "
                "ON DUPLICATE KEY UPDATE config_path = VALUES(config_path), "
                "access_log_path = VALUES(access_log_path), "
                "error_log_path = VALUES(error_log_path), "
                "doc_root = VALUES(doc_root), "
                "listen_port = VALUES(listen_port), "
                "ssl_enabled = VALUES(ssl_enabled)";
        } else {
            // Non-canonical: only insert if not exists (don't overwrite canonical values)
            sql = "INSERT IGNORE INTO backdraft_sites "
                "(site_name, config_path, access_log_path, error_log_path, doc_root, listen_port, ssl_enabled) "
                "VALUES ('" + server_name + "', '" + config_path + "', "
                "'" + access_log + "', '" + error_log + "', '" + doc_root + "', "
                + std::to_string(listen_port) + ", " + std::to_string(ssl_enabled ? 1 : 0) + ")";
        }

        conn->execute(sql);
        count++;
    }

    LOG_INFO("Site discovery complete: " + std::to_string(count) + " sites found in " + sites_dir);
}

} // namespace SiteDiscovery

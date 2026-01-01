#include "api_handler.h"
#include "config.h"
#include "auth.h"
#include "dbpool.h"
#include "logger.h"
#include "site_discovery.h"
#include "nginx_manager.h"

#include <nlohmann/json.hpp>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <unistd.h>

using json = nlohmann::json;

static auto start_time = std::chrono::steady_clock::now();

// Safe string from possibly-NULL MySQL row field — prevents crashes on nullable columns
static std::string safe(const char* s) { return s ? s : ""; }

// Helper: require auth, return error response if not
static bool require_auth(const HttpRequest& req, AuthResult& auth) {
    auth = Auth::instance().resolve(req);
    return auth.authenticated;
}

static bool require_admin(const AuthResult& auth) {
    return auth.role == "admin" || auth.role == "superadmin";
}

// ============================================================================
// Public
// ============================================================================

HttpResponse ApiHandler::health(const HttpRequest&) {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time).count();

    json j = {
        {"ok", true},
        {"service", "Mcaster1BackDraft"},
        {"version", CFG.version},
        {"uptime_secs", uptime},
        {"waf_mode", CFG.waf.mode}
    };
    return HttpResponse::ok(j.dump());
}

// ============================================================================
// Auth
// ============================================================================

HttpResponse ApiHandler::login(const HttpRequest& req) {
    json body;
    try { body = json::parse(req.body); }
    catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string username = body.value("username", "");
    std::string password = body.value("password", "");

    if (username.empty() || password.empty())
        return HttpResponse::bad_req("Username and password required");

    auto result = Auth::instance().login(username, password, req.remote_addr,
        req.headers.count("user-agent") ? req.headers.at("user-agent") : "");

    if (!result.authenticated)
        return HttpResponse::unauth();

    std::string token;
    if (result.role == "superadmin" && username == CFG.auth.master_username) {
        token = CFG.auth.api_token;
    } else {
        token = Auth::instance().create_session(result.user_id, req.remote_addr,
            req.headers.count("user-agent") ? req.headers.at("user-agent") : "");
    }

    json j = {
        {"ok", true},
        {"token", token},
        {"username", result.username},
        {"role", result.role}
    };

    HttpResponse resp = HttpResponse::ok(j.dump());
    resp.headers["Set-Cookie"] = "backdraft_session=" + token +
        "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
        std::to_string(CFG.auth.session_ttl_secs);

    LOG_INFO("Login: " + username + " from " + req.remote_addr + " role=" + result.role);
    return resp;
}

HttpResponse ApiHandler::logout(const HttpRequest& req) {
    auto auth = Auth::instance().resolve(req);
    if (auth.authenticated) {
        // Try to extract token from cookie to delete session
        auto cookie_it = req.headers.find("cookie");
        if (cookie_it != req.headers.end()) {
            std::string prefix = "backdraft_session=";
            auto pos = cookie_it->second.find(prefix);
            if (pos != std::string::npos) {
                auto end = cookie_it->second.find(';', pos);
                std::string token = cookie_it->second.substr(pos + prefix.size(),
                    end == std::string::npos ? std::string::npos : end - pos - prefix.size());
                Auth::instance().logout(token);
            }
        }
    }

    HttpResponse resp = HttpResponse::ok(R"({"ok":true,"message":"Logged out"})");
    resp.headers["Set-Cookie"] = "backdraft_session=; Path=/; HttpOnly; Secure; Max-Age=0";
    return resp;
}

// ============================================================================
// Status
// ============================================================================

HttpResponse ApiHandler::status(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - start_time).count();

    json j = {
        {"ok", true},
        {"version", CFG.version},
        {"uptime_secs", uptime},
        {"waf_mode", CFG.waf.mode},
        {"threat_threshold", CFG.waf.threat_threshold}
    };

    // Get counts from DB
    auto conn = DB("backdraft");
    if (conn) {
        MYSQL_RES* res;

        res = conn->query("SELECT COUNT(*) FROM backdraft_requests WHERE request_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) j["requests_24h"] = std::stoll(safe(row[0]));
            mysql_free_result(res);
        }

        res = conn->query("SELECT COUNT(*) FROM backdraft_threats WHERE detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR) AND dismissed = 0");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) j["threats_24h"] = std::stoll(safe(row[0]));
            mysql_free_result(res);
        }

        res = conn->query("SELECT COUNT(*) FROM backdraft_rules WHERE active = 1");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) j["active_rules"] = std::stoi(safe(row[0]));
            mysql_free_result(res);
        }

        res = conn->query("SELECT COUNT(*) FROM backdraft_sites WHERE waf_enabled = 1");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) j["waf_sites"] = std::stoi(safe(row[0]));
            mysql_free_result(res);
        }

        res = conn->query("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned = 1");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) j["banned_ips"] = std::stoi(safe(row[0]));
            mysql_free_result(res);
        }
    }

    return HttpResponse::ok(j.dump());
}

// ============================================================================
// Threats
// ============================================================================

HttpResponse ApiHandler::list_threats(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    int page = 1, limit = 50;
    if (req.query_params.count("page"))  page  = std::stoi(req.query_params.at("page"));
    if (req.query_params.count("limit")) limit = std::stoi(req.query_params.at("limit"));
    if (limit > 200) limit = 200;
    int offset = (page - 1) * limit;

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Columns: 0=id, 1=request_id, 2=detected_at, 3=client_ip, 4=threat_score,
    //          5=matched_rules, 6=category, 7=severity, 8=action_taken, 9=dismissed
    std::string sql = "SELECT id, request_id, detected_at, client_ip, threat_score, "
                      "matched_rules, category, severity, action_taken, dismissed "
                      "FROM backdraft_threats ORDER BY detected_at DESC "
                      "LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

    MYSQL_RES* res = conn->query(sql);
    if (!res) return HttpResponse::internal_error("Query failed");

    json threats = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        threats.push_back({
            {"id",            std::stoll(safe(row[0]))},
            {"request_id",    std::stoll(safe(row[1]))},
            {"detected_at",   safe(row[2])},
            {"client_ip",     safe(row[3])},
            {"threat_score",  std::stoi(safe(row[4]))},
            {"matched_rules", safe(row[5])},
            {"category",      safe(row[6])},
            {"severity",      safe(row[7])},
            {"action_taken",  safe(row[8])},
            {"dismissed",     std::stoi(safe(row[9]))}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", threats}, {"page", page}}).dump());
}

HttpResponse ApiHandler::dismiss_threat(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    int id = body.value("id", 0);
    if (id <= 0) return HttpResponse::bad_req("Threat ID required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
        buf.resize(len);
        return buf;
    };

    conn->execute("UPDATE backdraft_threats SET dismissed = 1, dismissed_by = '" +
                  esc(auth.username) + "' WHERE id = " + std::to_string(id));

    LOG_INFO("Threat dismissed: id=" + std::to_string(id) + " by " + auth.username);
    return HttpResponse::ok(R"({"ok":true,"message":"Threat dismissed"})");
}

// ============================================================================
// IP Reputation
// ============================================================================

HttpResponse ApiHandler::ban_ip(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string ip = body.value("ip", "");
    if (ip.empty()) return HttpResponse::bad_req("IP address required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
        buf.resize(len);
        return buf;
    };

    // Upsert — create IP record if it doesn't exist
    conn->execute(
        "INSERT INTO backdraft_ip_reputation (ip_addr, banned, banned_at, banned_reason) "
        "VALUES ('" + esc(ip) + "', 1, NOW(), 'Manual ban by " + esc(auth.username) + "') "
        "ON DUPLICATE KEY UPDATE banned = 1, banned_at = NOW(), "
        "banned_reason = 'Manual ban by " + esc(auth.username) + "'");

    LOG_INFO("IP banned: " + ip + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "IP " + ip + " banned"}}).dump());
}

HttpResponse ApiHandler::unban_ip(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string ip = body.value("ip", "");
    if (ip.empty()) return HttpResponse::bad_req("IP address required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
        buf.resize(len);
        return buf;
    };

    conn->execute("UPDATE backdraft_ip_reputation SET banned = 0, banned_at = NULL, "
                  "banned_reason = NULL WHERE ip_addr = '" + esc(ip) + "'");

    LOG_INFO("IP unbanned: " + ip + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "IP " + ip + " unbanned"}}).dump());
}

HttpResponse ApiHandler::list_ip_reputation(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    int limit = 50;
    if (req.query_params.count("limit")) {
        limit = std::stoi(req.query_params.at("limit"));
        if (limit > 200) limit = 200;
    }

    MYSQL_RES* res = conn->query(
        "SELECT ip_addr, total_requests, total_threats, max_score, avg_score, "
        "first_seen, last_seen, banned, banned_at, banned_reason, country_code "
        "FROM backdraft_ip_reputation ORDER BY max_score DESC, total_threats DESC "
        "LIMIT " + std::to_string(limit));
    if (!res) return HttpResponse::internal_error("Query failed");

    json ips = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        ips.push_back({
            {"ip_addr",        safe(row[0])},
            {"total_requests", std::stoll(safe(row[1]))},
            {"total_threats",  std::stoll(safe(row[2]))},
            {"max_score",      std::stoi(safe(row[3]))},
            {"avg_score",      std::stof(safe(row[4]))},
            {"first_seen",     safe(row[5])},
            {"last_seen",      safe(row[6])},
            {"banned",         std::stoi(safe(row[7]))},
            {"banned_at",      safe(row[8])},
            {"banned_reason",  safe(row[9])},
            {"country_code",   safe(row[10])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", ips}}).dump());
}

// ============================================================================
// Rules
// ============================================================================

HttpResponse ApiHandler::list_rules(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Columns: 0=id, 1=name, 2=description, 3=rule_type, 4=target, 5=field,
    //          6=operator, 7=value, 8=action, 9=score, 10=active, 11=sort_order,
    //          12=page_scope, 13=created_at
    MYSQL_RES* res = conn->query(
        "SELECT id, name, description, rule_type, target, field, `operator`, value, "
        "action, score, active, sort_order, page_scope, created_at "
        "FROM backdraft_rules ORDER BY sort_order, id");
    if (!res) return HttpResponse::internal_error("Query failed");

    json rules = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        rules.push_back({
            {"id",          std::stoi(safe(row[0]))},
            {"name",        safe(row[1])},
            {"description", safe(row[2])},
            {"rule_type",   safe(row[3])},
            {"target",      safe(row[4])},
            {"field",       safe(row[5])},
            {"operator",    safe(row[6])},
            {"value",       safe(row[7])},
            {"action",      safe(row[8])},
            {"score",       std::stoi(safe(row[9]))},
            {"active",      std::stoi(safe(row[10]))},
            {"sort_order",  std::stoi(safe(row[11]))},
            {"page_scope",  safe(row[12])},
            {"created_at",  safe(row[13])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", rules}}).dump());
}

HttpResponse ApiHandler::save_rule(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    int id = body.value("id", 0);
    std::string name = body.value("name", "");
    std::string desc = body.value("description", "");
    std::string rule_type = body.value("rule_type", "custom");
    std::string target = body.value("target", "query");
    std::string field = body.value("field", "");
    std::string op = body.value("operator", "contains");
    std::string value = body.value("value", "");
    std::string action = body.value("action", "log");
    int score = body.value("score", 10);
    int active = body.value("active", 1);
    int sort_order = body.value("sort_order", 100);

    if (name.empty() || value.empty()) return HttpResponse::bad_req("Name and value required");

    // Escape single quotes for SQL
    auto esc = [](const std::string& s) {
        std::string r; r.reserve(s.size());
        for (char c : s) { if (c == '\'') r += "''"; else r += c; }
        return r;
    };

    std::string sql;
    if (id > 0) {
        sql = "UPDATE backdraft_rules SET name='" + esc(name) + "', description='" + esc(desc) +
              "', rule_type='" + esc(rule_type) + "', target='" + esc(target) +
              "', field='" + esc(field) + "', `operator`='" + esc(op) +
              "', value='" + esc(value) + "', action='" + esc(action) +
              "', score=" + std::to_string(score) + ", active=" + std::to_string(active) +
              ", sort_order=" + std::to_string(sort_order) + " WHERE id=" + std::to_string(id);
    } else {
        sql = "INSERT INTO backdraft_rules (name,description,rule_type,target,field,`operator`,value,action,score,active,sort_order,created_by) "
              "VALUES ('" + esc(name) + "','" + esc(desc) + "','" + esc(rule_type) + "','" + esc(target) +
              "','" + esc(field) + "','" + esc(op) + "','" + esc(value) + "','" + esc(action) +
              "'," + std::to_string(score) + "," + std::to_string(active) + "," + std::to_string(sort_order) +
              ",'" + esc(auth.username) + "')";
    }

    if (!conn->execute(sql)) return HttpResponse::internal_error("DB query failed");
    LOG_INFO("Rule " + std::string(id > 0 ? "updated" : "created") + ": " + name + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", id > 0 ? "Rule updated" : "Rule created"}}).dump());
}

HttpResponse ApiHandler::delete_rule(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    // Extract ID from path: /api/rules/123
    std::string id_str = req.path.substr(req.path.rfind('/') + 1);
    int id = 0;
    try { id = std::stoi(id_str); } catch (...) {}
    if (id <= 0) return HttpResponse::bad_req("Invalid rule ID");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    conn->execute("DELETE FROM backdraft_rules WHERE id = " + std::to_string(id));
    LOG_INFO("Rule deleted: id=" + std::to_string(id) + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "Rule deleted"}}).dump());
}

// ============================================================================
// Sites
// ============================================================================

HttpResponse ApiHandler::list_sites(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    // Trigger site discovery refresh
    SiteDiscovery::discover();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Columns: 0=id, 1=site_name, 2=config_path, 3=access_log_path, 4=error_log_path,
    //          5=waf_enabled, 6=log_analysis, 7=waf_mode, 8=upstream_url, 9=listen_port,
    //          10=ssl_enabled, 11=discovered_at, 12=enrolled_at
    MYSQL_RES* res = conn->query(
        "SELECT id, site_name, config_path, access_log_path, error_log_path, "
        "waf_enabled, log_analysis, waf_mode, upstream_url, listen_port, "
        "ssl_enabled, discovered_at, enrolled_at "
        "FROM backdraft_sites ORDER BY site_name");
    if (!res) return HttpResponse::internal_error("Query failed");

    json sites = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        sites.push_back({
            {"id",              std::stoi(safe(row[0]))},
            {"site_name",       safe(row[1])},
            {"config_path",     safe(row[2])},
            {"access_log_path", safe(row[3])},
            {"error_log_path",  safe(row[4])},
            {"waf_enabled",     std::stoi(safe(row[5]))},
            {"log_analysis",    std::stoi(safe(row[6]))},
            {"waf_mode",        safe(row[7])},
            {"upstream_url",    safe(row[8])},
            {"listen_port",     std::stoi(safe(row[9]))},
            {"ssl_enabled",     std::stoi(safe(row[10]))},
            {"discovered_at",   safe(row[11])},
            {"enrolled_at",     safe(row[12])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", sites}}).dump());
}

HttpResponse ApiHandler::update_site(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    int id = body.value("id", 0);
    if (id <= 0) return HttpResponse::bad_req("Site ID required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    int waf_enabled = body.value("waf_enabled", -1);
    int log_analysis = body.value("log_analysis", -1);
    std::string waf_mode = body.value("waf_mode", "");
    std::string protected_paths = body.contains("protected_paths") ? body["protected_paths"].get<std::string>() : "";

    auto esc_site = [](const std::string& s) {
        std::string r; for (char c : s) { if (c == '\'') r += "''"; else r += c; } return r;
    };

    std::string sets;
    if (waf_enabled >= 0) sets += "waf_enabled=" + std::to_string(waf_enabled) + ",";
    if (log_analysis >= 0) sets += "log_analysis=" + std::to_string(log_analysis) + ",";
    if (!waf_mode.empty()) sets += "waf_mode='" + esc_site(waf_mode) + "',";
    if (!protected_paths.empty()) sets += "protected_paths='" + esc_site(protected_paths) + "',";
    if (waf_enabled == 1 || log_analysis == 1) sets += "enrolled_at=NOW(),";

    if (sets.empty()) return HttpResponse::bad_req("No fields to update");
    sets.pop_back(); // Remove trailing comma

    conn->execute("UPDATE backdraft_sites SET " + sets + " WHERE id=" + std::to_string(id));
    LOG_INFO("Site updated: id=" + std::to_string(id) + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "Site updated"}}).dump());
}

HttpResponse ApiHandler::deploy_waf(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string site_name = body.value("site_name", "");
    if (site_name.empty()) return HttpResponse::bad_req("site_name required");

    // Full automated deploy: write snippet + ensure include + test + reload
    bool ok = NginxManager::deploy_waf_config(site_name, CFG.http.waf_port);

    if (ok) {
        LOG_INFO("WAF deployed for " + site_name + " by " + auth.username);
        return HttpResponse::ok(json({
            {"ok", true},
            {"message", "WAF config deployed and nginx reloaded for " + site_name}
        }).dump());
    } else {
        return HttpResponse::internal_error("WAF deployment failed for " + site_name +
            " — check daemon logs for details");
    }
}

// ============================================================================
// ============================================================================
// Site Security Management
// ============================================================================

// Helper: write security audit record
static void audit_log(const std::string& username, int site_id, const std::string& site_name,
                       const std::string& action, const std::string& detail_json,
                       const std::string& ip) {
    try {
        auto conn = DB("backdraft");
        if (!conn) return;
        auto esc = [&](const std::string& s) {
            std::string buf(s.size() * 2 + 1, '\0');
            unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
            buf.resize(len);
            return buf;
        };
        conn->execute("INSERT INTO backdraft_security_audit (username, site_id, site_name, action, detail, ip_addr) "
                      "VALUES ('" + esc(username) + "', " + std::to_string(site_id) + ", '" + esc(site_name) + "', "
                      "'" + esc(action) + "', '" + esc(detail_json) + "', '" + esc(ip) + "')");
    } catch (...) {}
}

HttpResponse ApiHandler::set_maintenance(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    int site_id = body.value("site_id", 0);
    bool active = body.value("active", false);
    int duration = body.value("duration_secs", 3600);
    std::string reason = body.value("reason", "");

    if (site_id <= 0) return HttpResponse::bad_req("site_id required");

    // Get site name
    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL_RES* res = conn->query("SELECT site_name FROM backdraft_sites WHERE id=" + std::to_string(site_id));
    if (!res) return HttpResponse::internal_error("Query failed");
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found("Site not found"); }
    std::string site_name = row[0];
    mysql_free_result(res);

    // Toggle maintenance in nginx
    if (!NginxManager::set_maintenance_mode(site_name, active)) {
        return HttpResponse::internal_error("Failed to set maintenance mode");
    }

    if (!NginxManager::test_config() || !NginxManager::reload()) {
        NginxManager::set_maintenance_mode(site_name, !active); // rollback
        return HttpResponse::internal_error("nginx config test/reload failed — rolled back");
    }

    // Update DB
    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
        buf.resize(len);
        return buf;
    };

    if (active) {
        conn->execute("UPDATE backdraft_sites SET maintenance_active=1, maintenance_started=NOW(), "
                      "maintenance_duration=" + std::to_string(duration) + ", "
                      "maintenance_reason='" + esc(reason) + "' WHERE id=" + std::to_string(site_id));
    } else {
        conn->execute("UPDATE backdraft_sites SET maintenance_active=0, maintenance_started=NULL, "
                      "maintenance_duration=0, maintenance_reason='' WHERE id=" + std::to_string(site_id));
    }

    audit_log(auth.username, site_id, site_name,
              active ? "maintenance_on" : "maintenance_off",
              "{\"duration\":" + std::to_string(duration) + ",\"reason\":\"" + reason + "\"}",
              req.remote_addr);

    LOG_INFO("Maintenance " + std::string(active ? "ON" : "OFF") + " for " + site_name + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "Maintenance " + std::string(active ? "enabled" : "disabled") + " for " + site_name}}).dump());
}

HttpResponse ApiHandler::set_security_blocks(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    int site_id = body.value("site_id", 0);
    if (site_id <= 0) return HttpResponse::bad_req("site_id required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL_RES* res = conn->query("SELECT site_name FROM backdraft_sites WHERE id=" + std::to_string(site_id));
    if (!res) return HttpResponse::internal_error("Query failed");
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }
    std::string site_name = row[0];
    mysql_free_result(res);

    NginxManager::SecurityBlockConfig cfg;
    cfg.bad_agent   = body.value("block_bad_agent", false);
    cfg.banned_ip   = body.value("block_banned_ip", false);
    cfg.bad_path    = body.value("block_bad_path", false);
    cfg.bad_payload = body.value("block_bad_payload", false);
    cfg.bad_cookie  = body.value("block_bad_cookie", false);
    cfg.bad_referer = body.value("block_bad_referer", false);
    cfg.logging     = body.value("security_log_enabled", true);

    bool any_enabled = cfg.bad_agent || cfg.banned_ip || cfg.bad_path || cfg.bad_payload || cfg.bad_cookie || cfg.bad_referer;

    if (any_enabled) {
        if (cfg.logging) NginxManager::ensure_security_log_dir(site_name);
        if (!NginxManager::write_security_snippet(site_name, cfg)) {
            return HttpResponse::internal_error("Failed to write security snippet");
        }
    } else {
        NginxManager::remove_security_snippet(site_name);
    }

    if (!NginxManager::test_config() || !NginxManager::reload()) {
        NginxManager::remove_security_snippet(site_name);
        return HttpResponse::internal_error("nginx test/reload failed — rolled back");
    }

    // Update DB
    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], s.c_str(), s.size());
        buf.resize(len); return buf;
    };
    conn->execute("UPDATE backdraft_sites SET security_blocking=" + std::to_string(any_enabled ? 1 : 0) +
                  ", block_bad_agent=" + std::to_string(cfg.bad_agent ? 1 : 0) +
                  ", block_banned_ip=" + std::to_string(cfg.banned_ip ? 1 : 0) +
                  ", block_bad_path=" + std::to_string(cfg.bad_path ? 1 : 0) +
                  ", block_bad_payload=" + std::to_string(cfg.bad_payload ? 1 : 0) +
                  ", block_bad_cookie=" + std::to_string(cfg.bad_cookie ? 1 : 0) +
                  ", block_bad_referer=" + std::to_string(cfg.bad_referer ? 1 : 0) +
                  ", security_log_enabled=" + std::to_string(cfg.logging ? 1 : 0) +
                  ", security_log_path='/var/www/" + esc(site_name) + "/logs/security'" +
                  " WHERE id=" + std::to_string(site_id));

    audit_log(auth.username, site_id, site_name, "security_blocks_update", body.dump(), req.remote_addr);

    return HttpResponse::ok(json({{"ok", true}, {"message", "Security blocks updated for " + site_name}}).dump());
}

HttpResponse ApiHandler::set_rate_limits(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    int site_id = body.value("site_id", 0);
    bool login_limit = body.value("rate_limit_login", false);

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL_RES* res = conn->query("SELECT site_name FROM backdraft_sites WHERE id=" + std::to_string(site_id));
    if (!res) return HttpResponse::internal_error("Query failed");
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }
    std::string site_name = row[0];
    mysql_free_result(res);

    if (login_limit) {
        NginxManager::write_rate_limit_snippet(site_name, login_limit);
    } else {
        NginxManager::remove_rate_limit_snippet(site_name);
    }

    NginxManager::test_config();
    NginxManager::reload();

    conn->execute("UPDATE backdraft_sites SET rate_limit_login=" + std::to_string(login_limit ? 1 : 0) +
                  " WHERE id=" + std::to_string(site_id));

    audit_log(auth.username, site_id, site_name, "rate_limit_update", body.dump(), req.remote_addr);

    return HttpResponse::ok(json({{"ok", true}, {"message", "Rate limits updated"}}).dump());
}

HttpResponse ApiHandler::sync_blacklists_now(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    bool ip_ok = NginxManager::sync_ip_blacklist();
    bool agent_ok = NginxManager::sync_agent_blacklist();

    if (ip_ok || agent_ok) {
        NginxManager::test_config();
        NginxManager::reload();
    }

    audit_log(auth.username, 0, "", "blacklist_sync", "{\"ip\":" + std::string(ip_ok ? "true" : "false") +
              ",\"agent\":" + std::string(agent_ok ? "true" : "false") + "}", req.remote_addr);

    return HttpResponse::ok(json({{"ok", true}, {"message", "Blacklists synced and nginx reloaded"},
                                   {"ip_sync", ip_ok}, {"agent_sync", agent_ok}}).dump());
}

HttpResponse ApiHandler::emergency_lockdown_handler(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::vector<std::string> sites;

    if (body.value("all", false)) {
        auto conn = DB("backdraft");
        if (!conn) return HttpResponse::internal_error("DB unavailable");
        MYSQL_RES* res = conn->query("SELECT site_name FROM backdraft_sites");
        if (res) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res))) {
                if (row[0]) sites.push_back(row[0]);
            }
            mysql_free_result(res);
        }
    } else if (body.contains("site_name")) {
        sites.push_back(body["site_name"].get<std::string>());
    } else if (body.contains("site_id")) {
        auto conn = DB("backdraft");
        if (conn) {
            MYSQL_RES* res = conn->query("SELECT site_name FROM backdraft_sites WHERE id=" + std::to_string(body.value("site_id", 0)));
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row && row[0]) sites.push_back(row[0]);
                mysql_free_result(res);
            }
        }
    }

    if (sites.empty()) return HttpResponse::bad_req("No sites specified");

    bool ok = NginxManager::emergency_lockdown(sites);

    // Update DB for all locked sites
    auto conn = DB("backdraft");
    if (conn) {
        for (auto& s : sites) {
            auto esc = [&](const std::string& str) {
                std::string buf(str.size() * 2 + 1, '\0');
                unsigned long len = mysql_real_escape_string(conn->raw(), &buf[0], str.c_str(), str.size());
                buf.resize(len); return buf;
            };
            conn->execute("UPDATE backdraft_sites SET maintenance_active=1, maintenance_started=NOW(), "
                          "maintenance_reason='Emergency lockdown by " + esc(auth.username) + "', "
                          "security_blocking=1, block_bad_agent=1, block_banned_ip=1, block_bad_path=1, "
                          "block_bad_payload=1, block_bad_cookie=1, block_bad_referer=1, "
                          "security_log_enabled=1 WHERE site_name='" + esc(s) + "'");
        }
    }

    audit_log(auth.username, 0, "", "EMERGENCY_LOCKDOWN",
              "{\"sites\":" + std::to_string(sites.size()) + "}", req.remote_addr);

    LOG_WARN("EMERGENCY LOCKDOWN by " + auth.username + " — " + std::to_string(sites.size()) + " sites");
    return HttpResponse::ok(json({{"ok", ok}, {"message", "Emergency lockdown — " + std::to_string(sites.size()) + " sites locked"},
                                   {"sites_locked", sites.size()}}).dump());
}

HttpResponse ApiHandler::get_site_security(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    int site_id = 0;
    if (req.query_params.count("site_id")) site_id = std::stoi(req.query_params.at("site_id"));
    if (site_id <= 0) return HttpResponse::bad_req("site_id required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    MYSQL_RES* res = conn->query(
        "SELECT site_name, maintenance_active, maintenance_started, maintenance_duration, maintenance_reason, "
        "security_blocking, block_bad_agent, block_banned_ip, block_bad_path, block_bad_payload, "
        "block_bad_cookie, block_bad_referer, security_log_enabled, rate_limit_login "
        "FROM backdraft_sites WHERE id=" + std::to_string(site_id));
    if (!res) return HttpResponse::internal_error("Query failed");

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }

    json data = {
        {"site_name", safe(row[0])},
        {"maintenance_active", std::stoi(safe(row[1]))},
        {"maintenance_started", safe(row[2])},
        {"maintenance_duration", std::stoi(safe(row[3]))},
        {"maintenance_reason", safe(row[4])},
        {"security_blocking", std::stoi(safe(row[5]))},
        {"block_bad_agent", std::stoi(safe(row[6]))},
        {"block_banned_ip", std::stoi(safe(row[7]))},
        {"block_bad_path", std::stoi(safe(row[8]))},
        {"block_bad_payload", std::stoi(safe(row[9]))},
        {"block_bad_cookie", std::stoi(safe(row[10]))},
        {"block_bad_referer", std::stoi(safe(row[11]))},
        {"security_log_enabled", std::stoi(safe(row[12]))},
        {"rate_limit_login", std::stoi(safe(row[13]))}
    };
    mysql_free_result(res);

    // Recent security events count
    res = conn->query("SELECT COUNT(*) FROM backdraft_security_events WHERE site_id=" + std::to_string(site_id) +
                      " AND detected_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)");
    if (res) { row = mysql_fetch_row(res); data["events_24h"] = std::stoi(safe(row[0])); mysql_free_result(res); }

    // Banned IP count
    res = conn->query("SELECT COUNT(*) FROM backdraft_ip_reputation WHERE banned=1");
    if (res) { row = mysql_fetch_row(res); data["banned_ips"] = std::stoi(safe(row[0])); mysql_free_result(res); }

    // Blocked agents count
    res = conn->query("SELECT COUNT(*) FROM backdraft_agent_signatures WHERE disposition='block' AND active=1");
    if (res) { row = mysql_fetch_row(res); data["blocked_agents"] = std::stoi(safe(row[0])); mysql_free_result(res); }

    return HttpResponse::ok(json({{"ok", true}, {"data", data}}).dump());
}

HttpResponse ApiHandler::list_security_events(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    int site_id = 0, limit = 50, offset = 0;
    std::string block_type;
    if (req.query_params.count("site_id")) site_id = std::stoi(req.query_params.at("site_id"));
    if (req.query_params.count("limit")) limit = std::min(200, std::stoi(req.query_params.at("limit")));
    if (req.query_params.count("offset")) offset = std::stoi(req.query_params.at("offset"));
    if (req.query_params.count("block_type")) block_type = req.query_params.at("block_type");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    std::string where = "1=1";
    if (site_id > 0) where += " AND site_id=" + std::to_string(site_id);
    if (!block_type.empty()) {
        auto esc = [&](const std::string& s) {
            std::string buf(s.size()*2+1,'\0');
            unsigned long len = mysql_real_escape_string(conn->raw(),&buf[0],s.c_str(),s.size());
            buf.resize(len); return buf;
        };
        where += " AND block_type='" + esc(block_type) + "'";
    }

    MYSQL_RES* res = conn->query(
        "SELECT id, site_id, detected_at, client_ip, block_type, attack_type, request_method, "
        "request_uri, user_agent, http_status, country_code FROM backdraft_security_events "
        "WHERE " + where + " ORDER BY detected_at DESC LIMIT " + std::to_string(limit) +
        " OFFSET " + std::to_string(offset));
    if (!res) return HttpResponse::internal_error("Query failed");

    json events = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        events.push_back({
            {"id", std::stoll(safe(row[0]))}, {"site_id", std::stoi(safe(row[1]))},
            {"detected_at", safe(row[2])}, {"client_ip", safe(row[3])},
            {"block_type", safe(row[4])}, {"attack_type", safe(row[5])},
            {"request_method", safe(row[6])}, {"request_uri", safe(row[7])},
            {"user_agent", safe(row[8])}, {"http_status", std::stoi(safe(row[9]))},
            {"country_code", safe(row[10])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", events}}).dump());
}

HttpResponse ApiHandler::get_security_audit(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    int site_id = 0, limit = 50;
    if (req.query_params.count("site_id")) site_id = std::stoi(req.query_params.at("site_id"));
    if (req.query_params.count("limit")) limit = std::min(200, std::stoi(req.query_params.at("limit")));

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    std::string where = site_id > 0 ? "WHERE site_id=" + std::to_string(site_id) : "";

    MYSQL_RES* res = conn->query(
        "SELECT id, username, site_name, action, category, detail, ip_addr, created_at "
        "FROM backdraft_security_audit " + where + " ORDER BY created_at DESC LIMIT " + std::to_string(limit));
    if (!res) return HttpResponse::internal_error("Query failed");

    json entries = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        entries.push_back({
            {"id", std::stoll(safe(row[0]))}, {"username", safe(row[1])},
            {"site_name", safe(row[2])}, {"action", safe(row[3])},
            {"category", safe(row[4])}, {"detail", safe(row[5])},
            {"ip_addr", safe(row[6])}, {"created_at", safe(row[7])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", entries}}).dump());
}

// Agents
// ============================================================================

HttpResponse ApiHandler::list_agents(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Columns: 0=id, 1=pattern, 2=match_type, 3=classification, 4=disposition, 5=name, 6=active
    MYSQL_RES* res = conn->query(
        "SELECT id, pattern, match_type, classification, disposition, name, active "
        "FROM backdraft_agent_signatures ORDER BY classification, name");
    if (!res) return HttpResponse::internal_error("Query failed");

    json agents = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        agents.push_back({
            {"id",              std::stoi(safe(row[0]))},
            {"pattern",         safe(row[1])},
            {"match_type",      safe(row[2])},
            {"classification",  safe(row[3])},
            {"disposition",     safe(row[4])},
            {"name",            safe(row[5])},
            {"active",          std::stoi(safe(row[6]))}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", agents}}).dump());
}

// ============================================================================
// Users
// ============================================================================

HttpResponse ApiHandler::list_users(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Columns: 0=id, 1=username, 2=role, 3=active, 4=last_login, 5=created_at
    MYSQL_RES* res = conn->query(
        "SELECT id, username, role, active, last_login, created_at "
        "FROM backdraft_users ORDER BY id");
    if (!res) return HttpResponse::internal_error("Query failed");

    json users = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        users.push_back({
            {"id",          std::stoi(safe(row[0]))},
            {"username",    safe(row[1])},
            {"role",        safe(row[2])},
            {"active",      std::stoi(safe(row[3]))},
            {"last_login",  safe(row[4])},
            {"created_at",  safe(row[5])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", users}}).dump());
}

HttpResponse ApiHandler::create_user(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string username = body.value("username", "");
    std::string password = body.value("password", "");
    std::string role = body.value("role", "user");
    std::string email = body.value("email", "");

    if (username.empty() || password.empty()) return HttpResponse::bad_req("Username and password required");
    if (role != "user" && role != "admin" && role != "superadmin") return HttpResponse::bad_req("Invalid role");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    auto esc = [](const std::string& s) {
        std::string r; for (char c : s) { if (c == '\'') r += "''"; else r += c; } return r;
    };

    std::string sql = "INSERT INTO backdraft_users (username, password_hash, role, email, active) "
                      "VALUES ('" + esc(username) + "', SHA2('" + esc(password) + "', 256), "
                      "'" + esc(role) + "', '" + esc(email) + "', 1)";
    if (!conn->execute(sql)) return HttpResponse::internal_error("User creation failed — username may already exist");

    LOG_INFO("User created: " + username + " role=" + role + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "User created"}}).dump());
}

HttpResponse ApiHandler::delete_user(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    std::string id_str = req.path.substr(req.path.rfind('/') + 1);
    int id = 0;
    try { id = std::stoi(id_str); } catch (...) {}
    if (id <= 0) return HttpResponse::bad_req("Invalid user ID");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    conn->execute("UPDATE backdraft_users SET active = 0 WHERE id = " + std::to_string(id));
    LOG_INFO("User deactivated: id=" + std::to_string(id) + " by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "User deactivated"}}).dump());
}

// ============================================================================
// Profile (self-edit)
// ============================================================================

HttpResponse ApiHandler::update_profile(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    json body;
    try { body = json::parse(req.body); } catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    auto esc = [](const std::string& s) {
        std::string r; for (char c : s) { if (c == '\'') r += "''"; else r += c; } return r;
    };

    std::string sets;
    if (body.contains("email")) {
        sets += "email='" + esc(body["email"].get<std::string>()) + "',";
    }
    if (body.contains("password") && !body["password"].get<std::string>().empty()) {
        sets += "password_hash=SHA2('" + esc(body["password"].get<std::string>()) + "',256),";
    }

    if (sets.empty()) return HttpResponse::bad_req("No fields to update");
    sets.pop_back();

    if (auth.user_id > 0) {
        conn->execute("UPDATE backdraft_users SET " + sets + " WHERE id=" + std::to_string(auth.user_id));
    } else {
        // Master admin — update by username
        conn->execute("UPDATE backdraft_users SET " + sets + " WHERE username='" + esc(auth.username) + "'");
    }

    LOG_INFO("Profile updated: " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"message", "Profile updated"}}).dump());
}

// ============================================================================
// WAF mode
// ============================================================================

HttpResponse ApiHandler::set_mode(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth)) return HttpResponse::forbidden();

    json body;
    try { body = json::parse(req.body); }
    catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string mode = body.value("mode", "");
    if (mode != "learning" && mode != "active" && mode != "disabled")
        return HttpResponse::bad_req("Mode must be: learning, active, or disabled");

    auto conn = DB("backdraft");
    if (conn) {
        conn->execute("UPDATE backdraft_config SET config_value = '" + mode +
                      "' WHERE config_key = 'waf_mode'");
    }

    LOG_INFO("WAF mode changed to '" + mode + "' by " + auth.username);
    return HttpResponse::ok(json({{"ok", true}, {"mode", mode}}).dump());
}

// ============================================================================
// Performance
// ============================================================================

HttpResponse ApiHandler::perf_metrics(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    // Single C++ daemon — no Go goroutines
    MYSQL_RES* res = conn->query(
        "SELECT recorded_at, pid, cpu_percent, mem_rss_mb, mem_vms_mb, threads, "
        "open_fds, waf_rps, waf_avg_ms, COALESCE(custom_json, '{}') "
        "FROM backdraft_perf_metrics "
        "WHERE daemon = 'backdraft' "
        "  AND recorded_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE) "
        "ORDER BY recorded_at DESC LIMIT 30");
    if (!res) return HttpResponse::internal_error("Query failed");

    json metrics = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        json m = {
            {"recorded_at", safe(row[0])},
            {"pid",         std::stoi(safe(row[1]))},
            {"cpu_percent", std::stof(safe(row[2]))},
            {"mem_rss_mb",  std::stof(safe(row[3]))},
            {"mem_vms_mb",  std::stof(safe(row[4]))},
            {"threads",     std::stoi(safe(row[5]))},
            {"open_fds",    std::stoi(safe(row[6]))},
            {"waf_rps",     std::stof(safe(row[7]))},
            {"waf_avg_ms",  std::stof(safe(row[8]))}
        };
        // Parse custom_json for WAF/task extended metrics
        try {
            m["extended"] = json::parse(safe(row[9]));
        } catch (...) {
            m["extended"] = json::object();
        }
        metrics.push_back(std::move(m));
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", metrics}}).dump());
}

// ============================================================================
// SSE Log Streaming
// ============================================================================

void ApiHandler::stream_logs(const HttpRequest& req, int fd, SSL* ssl) {
    auto auth = Auth::instance().resolve(req);
    if (!auth.authenticated) {
        std::string resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if (ssl) SSL_write(ssl, resp.c_str(), resp.size());
        else write(fd, resp.c_str(), resp.size());
        return;
    }

    std::string log_file = CFG.log.dir + "/backdraft.log";
    auto it = req.query_params.find("file");
    if (it != req.query_params.end()) {
        if (it->second == "error")  log_file = CFG.log.dir + "/error.log";
        if (it->second == "debug")  log_file = CFG.log.dir + "/debug.log";
        if (it->second == "access") log_file = CFG.log.dir + "/access.log";
    }

    std::string headers = "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/event-stream\r\n"
                          "Cache-Control: no-cache\r\n"
                          "Connection: keep-alive\r\n\r\n";
    if (ssl) SSL_write(ssl, headers.c_str(), headers.size());
    else write(fd, headers.c_str(), headers.size());

    // Send connection confirmation event
    {
        std::string connected = "event: connected\ndata: {\"file\":\"" + log_file + "\"}\n\n";
        if (ssl) SSL_write(ssl, connected.c_str(), connected.size());
        else write(fd, connected.c_str(), connected.size());
    }

    std::ifstream f(log_file);
    if (f.is_open()) {
        // Read last ~50 lines as initial tail to show immediate content
        // Seek near end and read forward
        f.seekg(0, std::ios::end);
        auto end_pos = f.tellg();
        // Seek back ~8KB to find ~50 lines
        std::streamoff seek_pos = (end_pos > (std::streamoff)8192) ? (std::streamoff)(end_pos - (std::streamoff)8192) : (std::streamoff)0;
        f.seekg(seek_pos);

        if (seek_pos > 0) {
            // Skip partial first line
            std::string skip;
            std::getline(f, skip);
        }

        std::vector<std::string> tail_lines;
        std::string line;
        while (std::getline(f, line)) {
            tail_lines.push_back(line);
            if (tail_lines.size() > 50)
                tail_lines.erase(tail_lines.begin());
        }
        f.clear();

        // Send tail lines as initial batch
        for (const auto& tl : tail_lines) {
            std::string event = "data: " + tl + "\n\n";
            int n;
            if (ssl) n = SSL_write(ssl, event.c_str(), event.size());
            else     n = write(fd, event.c_str(), event.size());
            if (n <= 0) return;
        }

        // Now positioned at EOF — new lines will stream in
    }

    while (true) {
        std::string line;
        if (f.is_open() && std::getline(f, line)) {
            std::string event = "data: " + line + "\n\n";
            int n;
            if (ssl) n = SSL_write(ssl, event.c_str(), event.size());
            else     n = write(fd, event.c_str(), event.size());
            if (n <= 0) break;
        } else {
            f.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            // Send keepalive
            std::string ka = ": keepalive\n\n";
            int n;
            if (ssl) n = SSL_write(ssl, ka.c_str(), ka.size());
            else     n = write(fd, ka.c_str(), ka.size());
            if (n <= 0) break;
        }
    }
}

// ============================================================================
// Tasks — Scheduler CRUD + Execution
// ============================================================================

HttpResponse ApiHandler::list_tasks(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    MYSQL_RES* res = conn->query(
        "SELECT id, task_id, name, description, task_type, schedule, handler, "
        "       COALESCE(params,'{}'), priority, enabled, last_run_at, next_run_at, "
        "       run_count, created_by, created_at, updated_at "
        "FROM backdraft_tasks ORDER BY FIELD(priority,'critical','high','normal','low'), name");
    if (!res) return HttpResponse::internal_error("Query failed");

    json tasks = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        tasks.push_back({
            {"id",          std::stoi(safe(row[0]))},
            {"task_id",     safe(row[1])},
            {"name",        safe(row[2])},
            {"description", safe(row[3])},
            {"task_type",   safe(row[4])},
            {"schedule",    safe(row[5])},
            {"handler",     safe(row[6])},
            {"params",      safe(row[7])},
            {"priority",    safe(row[8])},
            {"enabled",     std::stoi(safe(row[9]))},
            {"last_run_at", safe(row[10])},
            {"next_run_at", safe(row[11])},
            {"run_count",   std::stoi(safe(row[12]))},
            {"created_by",  safe(row[13])},
            {"created_at",  safe(row[14])},
            {"updated_at",  safe(row[15])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", tasks}}).dump());
}

HttpResponse ApiHandler::get_task(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    // Extract task_id from path: /api/tasks/{task_id}
    std::string path = req.path;
    auto last = path.rfind('/');
    if (last == std::string::npos) return HttpResponse::bad_req("Missing task_id");
    std::string task_id = path.substr(last + 1);

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    MYSQL* mysql = conn->raw();
    char esc[256];
    mysql_real_escape_string(mysql, esc, task_id.c_str(), task_id.size());

    std::string sql = "SELECT id, task_id, name, description, task_type, schedule, handler, "
                      "COALESCE(params,'{}'), priority, enabled, last_run_at, next_run_at, "
                      "run_count, created_by, created_at, updated_at "
                      "FROM backdraft_tasks WHERE task_id='" + std::string(esc) + "'";

    MYSQL_RES* res = conn->query(sql);
    if (!res) return HttpResponse::internal_error("Query failed");

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }

    json task = {
        {"id",          std::stoi(safe(row[0]))},
        {"task_id",     safe(row[1])},
        {"name",        safe(row[2])},
        {"description", safe(row[3])},
        {"task_type",   safe(row[4])},
        {"schedule",    safe(row[5])},
        {"handler",     safe(row[6])},
        {"params",      safe(row[7])},
        {"priority",    safe(row[8])},
        {"enabled",     std::stoi(safe(row[9]))},
        {"last_run_at", safe(row[10])},
        {"next_run_at", safe(row[11])},
        {"run_count",   std::stoi(safe(row[12]))},
        {"created_by",  safe(row[13])},
        {"created_at",  safe(row[14])},
        {"updated_at",  safe(row[15])}
    };
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", task}}).dump());
}

HttpResponse ApiHandler::save_task(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); }
    catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string task_id  = body.value("task_id", "");
    std::string name     = body.value("name", "");
    std::string handler  = body.value("handler", "");
    int existing_id      = body.value("id", 0);

    // For new tasks, task_id is required. For updates (id > 0), it's optional.
    if (existing_id <= 0 && (task_id.empty() || name.empty() || handler.empty()))
        return HttpResponse::bad_req("task_id, name, and handler required");
    if (existing_id > 0 && (name.empty() || handler.empty()))
        return HttpResponse::bad_req("name and handler required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL* mysql = conn->raw();

    auto esc = [&](const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(mysql, &buf[0], s.c_str(), s.size());
        buf.resize(len);
        return buf;
    };

    if (existing_id > 0) {
        // UPDATE existing task
        std::string sql =
            "UPDATE backdraft_tasks SET "
            "name='"        + esc(name) + "', "
            "description='" + esc(body.value("description", "")) + "', "
            "task_type='"   + esc(body.value("task_type", "custom")) + "', "
            "schedule='"    + esc(body.value("schedule", "24h")) + "', "
            "handler='"     + esc(handler) + "', "
            "params='"      + esc(body.value("params", "{}")) + "', "
            "priority='"    + esc(body.value("priority", "normal")) + "', "
            "enabled="      + std::to_string(body.value("enabled", 1)) + " "
            "WHERE id=" + std::to_string(existing_id);
        conn->execute(sql);
    } else {
        // INSERT new task
        std::string sql =
            "INSERT INTO backdraft_tasks "
            "(task_id, name, description, task_type, schedule, handler, params, priority, enabled, next_run_at, created_by) "
            "VALUES ('" + esc(task_id) + "','"
                        + esc(name) + "','"
                        + esc(body.value("description", "")) + "','"
                        + esc(body.value("task_type", "custom")) + "','"
                        + esc(body.value("schedule", "24h")) + "','"
                        + esc(handler) + "','"
                        + esc(body.value("params", "{}")) + "','"
                        + esc(body.value("priority", "normal")) + "',"
                        + std::to_string(body.value("enabled", 1)) + ","
                        + "DATE_ADD(NOW(), INTERVAL 1 HOUR),'"
                        + esc(auth.username) + "')";
        if (!conn->execute(sql)) {
            return HttpResponse::bad_req("Failed to create task — task_id may already exist");
        }
    }

    LOG_INFO("Task saved: " + task_id + " by " + auth.username);
    return HttpResponse::ok(R"({"ok":true,"message":"Task saved"})");
}

HttpResponse ApiHandler::delete_task(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    auto last = req.path.rfind('/');
    if (last == std::string::npos) return HttpResponse::bad_req("Missing task_id");
    std::string task_id = req.path.substr(last + 1);

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL* mysql = conn->raw();

    char esc[256];
    mysql_real_escape_string(mysql, esc, task_id.c_str(), task_id.size());

    conn->execute("DELETE FROM backdraft_task_runs WHERE task_id='" + std::string(esc) + "'");
    conn->execute("DELETE FROM backdraft_tasks WHERE task_id='" + std::string(esc) + "'");

    LOG_INFO("Task deleted: " + task_id + " by " + auth.username);
    return HttpResponse::ok(R"({"ok":true,"message":"Task and run history deleted"})");
}

HttpResponse ApiHandler::toggle_task(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); }
    catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string task_id = body.value("task_id", "");
    if (task_id.empty()) return HttpResponse::bad_req("task_id required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL* mysql = conn->raw();

    char esc[256];
    mysql_real_escape_string(mysql, esc, task_id.c_str(), task_id.size());

    conn->execute("UPDATE backdraft_tasks SET enabled = IF(enabled=1,0,1) "
                  "WHERE task_id='" + std::string(esc) + "'");

    LOG_INFO("Task toggled: " + task_id + " by " + auth.username);
    return HttpResponse::ok(R"({"ok":true,"message":"Task toggled"})");
}

HttpResponse ApiHandler::run_task_now(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    json body;
    try { body = json::parse(req.body); }
    catch (...) { return HttpResponse::bad_req("Invalid JSON"); }

    std::string task_id = body.value("task_id", "");
    if (task_id.empty()) return HttpResponse::bad_req("task_id required");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");
    MYSQL* mysql = conn->raw();

    char esc[256];
    mysql_real_escape_string(mysql, esc, task_id.c_str(), task_id.size());

    // Set next_run_at to NOW so scheduler picks it up within 1 second
    conn->execute("UPDATE backdraft_tasks SET next_run_at = NOW() "
                  "WHERE task_id='" + std::string(esc) + "' AND enabled = 1");

    LOG_INFO("Task run now: " + task_id + " by " + auth.username);
    return HttpResponse::ok(R"({"ok":true,"message":"Task queued for immediate execution"})");
}

HttpResponse ApiHandler::list_task_runs(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    std::string task_id;
    if (req.query_params.count("task_id")) task_id = req.query_params.at("task_id");

    int limit = 20;
    if (req.query_params.count("limit")) {
        limit = std::stoi(req.query_params.at("limit"));
        if (limit > 100) limit = 100;
    }

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    std::string sql = "SELECT id, task_id, started_at, ended_at, status, "
                      "LEFT(output_log, 2000), error_msg, "
                      "COALESCE(summary_json,'{}'), export_formats "
                      "FROM backdraft_task_runs ";

    if (!task_id.empty()) {
        MYSQL* mysql = conn->raw();
        char esc[256];
        mysql_real_escape_string(mysql, esc, task_id.c_str(), task_id.size());
        sql += "WHERE task_id='" + std::string(esc) + "' ";
    }
    sql += "ORDER BY started_at DESC LIMIT " + std::to_string(limit);

    MYSQL_RES* res = conn->query(sql);
    if (!res) return HttpResponse::internal_error("Query failed");

    json runs = json::array();
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        runs.push_back({
            {"id",             std::stoll(safe(row[0]))},
            {"task_id",        safe(row[1])},
            {"started_at",     safe(row[2])},
            {"ended_at",       safe(row[3])},
            {"status",         safe(row[4])},
            {"output_log",     safe(row[5])},
            {"error_msg",      safe(row[6])},
            {"summary_json",   safe(row[7])},
            {"export_formats", safe(row[8])}
        });
    }
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", runs}}).dump());
}

HttpResponse ApiHandler::get_task_run(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto last = req.path.rfind('/');
    if (last == std::string::npos) return HttpResponse::bad_req("Missing run_id");
    std::string run_id_str = req.path.substr(last + 1);

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    std::string sql = "SELECT id, task_id, started_at, ended_at, status, "
                      "output_log, error_msg, summary_json, export_html, export_formats "
                      "FROM backdraft_task_runs WHERE id=" + run_id_str;

    MYSQL_RES* res = conn->query(sql);
    if (!res) return HttpResponse::internal_error("Query failed");

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }

    json run = {
        {"id",             std::stoll(safe(row[0]))},
        {"task_id",        safe(row[1])},
        {"started_at",     safe(row[2])},
        {"ended_at",       safe(row[3])},
        {"status",         safe(row[4])},
        {"output_log",     safe(row[5])},
        {"error_msg",      safe(row[6])},
        {"summary_json",   safe(row[7])},
        {"export_html",    safe(row[8])},
        {"export_formats", safe(row[9])}
    };
    mysql_free_result(res);

    return HttpResponse::ok(json({{"ok", true}, {"data", run}}).dump());
}

HttpResponse ApiHandler::delete_task_run(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();
    if (!require_admin(auth))     return HttpResponse::forbidden("Admin required");

    auto last = req.path.rfind('/');
    if (last == std::string::npos) return HttpResponse::bad_req("Missing run_id");
    std::string run_id = req.path.substr(last + 1);

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    conn->execute("DELETE FROM backdraft_task_runs WHERE id=" + run_id);
    return HttpResponse::ok(R"({"ok":true,"message":"Run deleted"})");
}

HttpResponse ApiHandler::export_task_report(const HttpRequest& req) {
    AuthResult auth;
    if (!require_auth(req, auth)) return HttpResponse::unauth();

    auto last = req.path.rfind('/');
    if (last == std::string::npos) return HttpResponse::bad_req("Missing run_id");
    std::string run_id = req.path.substr(last + 1);

    std::string format = "html";
    if (req.query_params.count("format")) format = req.query_params.at("format");

    auto conn = DB("backdraft");
    if (!conn) return HttpResponse::internal_error("DB unavailable");

    std::string sql = "SELECT export_html, summary_json, task_id "
                      "FROM backdraft_task_runs WHERE id=" + run_id;
    MYSQL_RES* res = conn->query(sql);
    if (!res) return HttpResponse::internal_error("Query failed");

    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return HttpResponse::not_found(); }

    std::string html   = safe(row[0]);
    std::string json_s = safe(row[1]);
    std::string tid    = safe(row[2]);
    mysql_free_result(res);

    HttpResponse resp;
    if (format == "html") {
        resp = HttpResponse::ok(html);
        resp.headers["Content-Type"] = "text/html; charset=utf-8";
        resp.headers["Content-Disposition"] = "attachment; filename=\"" + tid + "_report.html\"";
    } else if (format == "excel") {
        // CSV export (Excel-compatible)
        resp = HttpResponse::ok(json_s);
        resp.headers["Content-Type"] = "text/csv; charset=utf-8";
        resp.headers["Content-Disposition"] = "attachment; filename=\"" + tid + "_report.csv\"";
    } else if (format == "pdf") {
        // Return HTML with print-optimized styles (client-side print-to-PDF)
        std::string pdf_html = "<!DOCTYPE html><html><head><style>"
            "@media print{body{margin:0;font-size:11pt}}"
            "body{font-family:Arial,sans-serif;max-width:900px;margin:0 auto;padding:20px}"
            "</style><script>window.onload=function(){window.print()}</script></head><body>"
            + html + "</body></html>";
        resp = HttpResponse::ok(pdf_html);
        resp.headers["Content-Type"] = "text/html; charset=utf-8";
    } else {
        resp = HttpResponse::bad_req("Unsupported format: " + format);
    }

    return resp;
}

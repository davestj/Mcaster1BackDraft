#include "router.h"
#include "http_server.h"
#include "api_handler.h"

namespace Router {

void register_routes(HttpServer& web_server, HttpServer& api_server) {
    // Public endpoints (no auth)
    api_server.route("GET", "/api/health", ApiHandler::health);
    web_server.route("GET", "/api/health", ApiHandler::health);

    // Auth endpoints
    api_server.route("POST", "/api/login",  ApiHandler::login);
    api_server.route("POST", "/api/logout", ApiHandler::logout);
    web_server.route("POST", "/api/login",  ApiHandler::login);
    web_server.route("POST", "/api/logout", ApiHandler::logout);

    // Status (API auth required)
    api_server.route("GET", "/api/status", ApiHandler::status);
    web_server.route("GET", "/api/status", ApiHandler::status);

    // Threats
    api_server.route("GET",  "/api/threats",         ApiHandler::list_threats);
    api_server.route("POST", "/api/threats/dismiss",  ApiHandler::dismiss_threat);
    web_server.route("GET",  "/api/threats",         ApiHandler::list_threats);
    web_server.route("POST", "/api/threats/dismiss",  ApiHandler::dismiss_threat);

    // IP Reputation
    api_server.route("GET",  "/api/ip-reputation",    ApiHandler::list_ip_reputation);
    api_server.route("POST", "/api/ip-reputation/ban",   ApiHandler::ban_ip);
    api_server.route("POST", "/api/ip-reputation/unban", ApiHandler::unban_ip);
    web_server.route("GET",  "/api/ip-reputation",    ApiHandler::list_ip_reputation);
    web_server.route("POST", "/api/ip-reputation/ban",   ApiHandler::ban_ip);
    web_server.route("POST", "/api/ip-reputation/unban", ApiHandler::unban_ip);

    // Rules
    api_server.route("GET",    "/api/rules",  ApiHandler::list_rules);
    api_server.route("POST",   "/api/rules",  ApiHandler::save_rule);
    api_server.route("DELETE", "/api/rules/",  ApiHandler::delete_rule);
    web_server.route("GET",    "/api/rules",  ApiHandler::list_rules);
    web_server.route("POST",   "/api/rules",  ApiHandler::save_rule);

    // Sites
    api_server.route("GET",  "/api/sites",  ApiHandler::list_sites);
    api_server.route("POST", "/api/sites",  ApiHandler::update_site);
    api_server.route("POST", "/api/sites/deploy", ApiHandler::deploy_waf);
    api_server.route("POST", "/api/sites/maintenance",       ApiHandler::set_maintenance);
    api_server.route("POST", "/api/sites/security-blocks",    ApiHandler::set_security_blocks);
    api_server.route("POST", "/api/sites/rate-limits",        ApiHandler::set_rate_limits);
    api_server.route("POST", "/api/sites/sync-blacklists",    ApiHandler::sync_blacklists_now);
    api_server.route("POST", "/api/sites/emergency-lockdown", ApiHandler::emergency_lockdown_handler);
    api_server.route("GET",  "/api/sites/security",           ApiHandler::get_site_security);
    api_server.route("GET",  "/api/security-events",          ApiHandler::list_security_events);
    api_server.route("GET",  "/api/security-audit",           ApiHandler::get_security_audit);

    web_server.route("GET",  "/api/sites",  ApiHandler::list_sites);
    web_server.route("POST", "/api/sites",  ApiHandler::update_site);
    web_server.route("POST", "/api/sites/deploy", ApiHandler::deploy_waf);
    web_server.route("POST", "/api/sites/maintenance",       ApiHandler::set_maintenance);
    web_server.route("POST", "/api/sites/security-blocks",    ApiHandler::set_security_blocks);
    web_server.route("POST", "/api/sites/rate-limits",        ApiHandler::set_rate_limits);
    web_server.route("POST", "/api/sites/sync-blacklists",    ApiHandler::sync_blacklists_now);
    web_server.route("POST", "/api/sites/emergency-lockdown", ApiHandler::emergency_lockdown_handler);
    web_server.route("GET",  "/api/sites/security",           ApiHandler::get_site_security);
    web_server.route("GET",  "/api/security-events",          ApiHandler::list_security_events);
    web_server.route("GET",  "/api/security-audit",           ApiHandler::get_security_audit);

    // Agents
    api_server.route("GET", "/api/agents", ApiHandler::list_agents);
    web_server.route("GET", "/api/agents", ApiHandler::list_agents);

    // Users (admin only)
    api_server.route("GET",    "/api/users",  ApiHandler::list_users);
    api_server.route("POST",   "/api/users",  ApiHandler::create_user);
    api_server.route("DELETE", "/api/users/",  ApiHandler::delete_user);
    web_server.route("GET",    "/api/users",  ApiHandler::list_users);

    // User CRUD on web server too
    web_server.route("POST",   "/api/users",  ApiHandler::create_user);
    web_server.route("DELETE", "/api/users/",  ApiHandler::delete_user);

    // Profile update (self-edit)
    api_server.route("POST", "/api/profile", ApiHandler::update_profile);
    web_server.route("POST", "/api/profile", ApiHandler::update_profile);

    // WAF mode
    api_server.route("POST", "/api/mode", ApiHandler::set_mode);
    web_server.route("POST", "/api/mode", ApiHandler::set_mode);

    // Rules CRUD on web server
    web_server.route("DELETE", "/api/rules/", ApiHandler::delete_rule);

    // Performance
    api_server.route("GET", "/api/perf", ApiHandler::perf_metrics);
    web_server.route("GET", "/api/perf", ApiHandler::perf_metrics);

    // Tasks
    api_server.route("GET",    "/api/tasks",      ApiHandler::list_tasks);
    api_server.route("GET",    "/api/tasks/",      ApiHandler::get_task);
    api_server.route("POST",   "/api/tasks",      ApiHandler::save_task);
    api_server.route("DELETE", "/api/tasks/",      ApiHandler::delete_task);
    api_server.route("POST",   "/api/tasks/toggle", ApiHandler::toggle_task);
    api_server.route("POST",   "/api/tasks/run",    ApiHandler::run_task_now);
    api_server.route("GET",    "/api/task-runs",    ApiHandler::list_task_runs);
    api_server.route("GET",    "/api/task-runs/",   ApiHandler::get_task_run);
    api_server.route("DELETE", "/api/task-runs/",   ApiHandler::delete_task_run);
    api_server.route("GET",    "/api/task-export/",  ApiHandler::export_task_report);

    web_server.route("GET",    "/api/tasks",      ApiHandler::list_tasks);
    web_server.route("GET",    "/api/tasks/",      ApiHandler::get_task);
    web_server.route("POST",   "/api/tasks",      ApiHandler::save_task);
    web_server.route("DELETE", "/api/tasks/",      ApiHandler::delete_task);
    web_server.route("POST",   "/api/tasks/toggle", ApiHandler::toggle_task);
    web_server.route("POST",   "/api/tasks/run",    ApiHandler::run_task_now);
    web_server.route("GET",    "/api/task-runs",    ApiHandler::list_task_runs);
    web_server.route("GET",    "/api/task-runs/",   ApiHandler::get_task_run);
    web_server.route("DELETE", "/api/task-runs/",   ApiHandler::delete_task_run);
    web_server.route("GET",    "/api/task-export/",  ApiHandler::export_task_report);

    // SSE log stream
    web_server.stream_route("GET", "/api/logs/stream", ApiHandler::stream_logs);
    api_server.stream_route("GET", "/api/logs/stream", ApiHandler::stream_logs);
}

} // namespace Router

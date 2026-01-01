#ifndef BACKDRAFT_API_HANDLER_H
#define BACKDRAFT_API_HANDLER_H

#include "http_server.h"
#include <openssl/ssl.h>

namespace ApiHandler {
    // Public
    HttpResponse health(const HttpRequest& req);

    // Auth
    HttpResponse login(const HttpRequest& req);
    HttpResponse logout(const HttpRequest& req);

    // Status
    HttpResponse status(const HttpRequest& req);

    // Threats
    HttpResponse list_threats(const HttpRequest& req);
    HttpResponse dismiss_threat(const HttpRequest& req);

    // IP Reputation
    HttpResponse ban_ip(const HttpRequest& req);
    HttpResponse unban_ip(const HttpRequest& req);
    HttpResponse list_ip_reputation(const HttpRequest& req);

    // Rules
    HttpResponse list_rules(const HttpRequest& req);
    HttpResponse save_rule(const HttpRequest& req);
    HttpResponse delete_rule(const HttpRequest& req);

    // Sites
    HttpResponse list_sites(const HttpRequest& req);
    HttpResponse update_site(const HttpRequest& req);
    HttpResponse deploy_waf(const HttpRequest& req);

    // Site Security Management
    HttpResponse set_maintenance(const HttpRequest& req);
    HttpResponse set_security_blocks(const HttpRequest& req);
    HttpResponse set_rate_limits(const HttpRequest& req);
    HttpResponse sync_blacklists_now(const HttpRequest& req);
    HttpResponse emergency_lockdown_handler(const HttpRequest& req);
    HttpResponse get_site_security(const HttpRequest& req);
    HttpResponse list_security_events(const HttpRequest& req);
    HttpResponse get_security_audit(const HttpRequest& req);

    // Agents
    HttpResponse list_agents(const HttpRequest& req);

    // Users
    HttpResponse list_users(const HttpRequest& req);
    HttpResponse create_user(const HttpRequest& req);
    HttpResponse delete_user(const HttpRequest& req);

    // Profile (self-edit)
    HttpResponse update_profile(const HttpRequest& req);

    // WAF mode
    HttpResponse set_mode(const HttpRequest& req);

    // Performance
    HttpResponse perf_metrics(const HttpRequest& req);

    // Tasks
    HttpResponse list_tasks(const HttpRequest& req);
    HttpResponse get_task(const HttpRequest& req);
    HttpResponse save_task(const HttpRequest& req);
    HttpResponse delete_task(const HttpRequest& req);
    HttpResponse toggle_task(const HttpRequest& req);
    HttpResponse run_task_now(const HttpRequest& req);
    HttpResponse list_task_runs(const HttpRequest& req);
    HttpResponse get_task_run(const HttpRequest& req);
    HttpResponse delete_task_run(const HttpRequest& req);
    HttpResponse export_task_report(const HttpRequest& req);

    // SSE log streaming
    void stream_logs(const HttpRequest& req, int fd, SSL* ssl);
}

#endif

#ifndef BACKDRAFT_WAF_HANDLER_H
#define BACKDRAFT_WAF_HANDLER_H

#include "http_server.h"
#include "botproof.h"
#include <vector>
#include <string>
#include <regex>
#include <mutex>
#include <thread>
#include <atomic>

struct WafRule {
    int id;
    std::string name;
    std::string target;   // query, path, body, agent, ip, method, header, cookie
    std::string field;
    std::string op;       // contains, regex, equals, starts_with, etc.
    std::string value;
    std::string action;   // log, flag, block
    int score;
    std::regex compiled;
    bool has_regex = false;
};

struct WafInspectResult {
    int total_score = 0;
    std::string action = "pass";
    std::vector<int> matched_rules;
};

class WafHandler {
public:
    static WafHandler& instance();

    void init();
    void stop();

    // Main WAF handler — called by the WAF port HTTP server
    HttpResponse handle_request(const HttpRequest& req);

    // Performance counters — read by PerfMonitor
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> total_threats{0};
    std::atomic<uint64_t> total_blocked{0};
    std::atomic<uint64_t> total_challenged{0};
    std::atomic<uint64_t> captcha_passed{0};
    std::atomic<uint64_t> captcha_failed{0};
    std::atomic<uint64_t> requests_1m{0};     // rolling 1-minute counter
    std::atomic<uint64_t> latency_sum_1m{0};  // sum of ms in last minute
    std::atomic<uint64_t> rules_loaded{0};

    // Snapshot counters for RPS calculation
    uint64_t prev_requests_{0};
    uint64_t prev_latency_sum_{0};

private:
    WafHandler() = default;

    void reload_rules();
    void reload_loop();
    WafInspectResult inspect(const HttpRequest& req);
    void log_request(const HttpRequest& req, const WafInspectResult& result,
                     int upstream_status, size_t response_bytes, int duration_ms);

    // Forward request to upstream PHP-FPM via FastCGI
    std::string forward_to_fcgi(const HttpRequest& req, const std::string& script_path,
                                const std::string& doc_root);

    std::mutex rules_mtx_;
    std::vector<WafRule> rules_;
    std::thread reload_thread_;
    std::atomic<bool> running_{false};
};

#endif

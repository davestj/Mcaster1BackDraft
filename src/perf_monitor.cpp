#include "perf_monitor.h"
#include "config.h"
#include "dbpool.h"
#include "logger.h"
#include "waf_handler.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <unistd.h>

namespace fs = std::filesystem;

PerfMonitor& PerfMonitor::instance() {
    static PerfMonitor inst;
    return inst;
}

void PerfMonitor::start(int interval_secs) {
    interval_secs_ = interval_secs;
    running_ = true;
    thread_ = std::thread(&PerfMonitor::run, this);
    LOG_INFO("Performance monitor started (interval=" + std::to_string(interval_secs) + "s)");
}

void PerfMonitor::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
}

/*
 * Read CPU usage from /proc/self/stat.
 * Fields 14 (utime) and 15 (stime) are in clock ticks.
 * We compute delta over the interval to get CPU %.
 */
float PerfMonitor::read_cpu_percent() {
    std::ifstream stat_file("/proc/self/stat");
    if (!stat_file.is_open()) return 0.0f;

    std::string line;
    std::getline(stat_file, line);

    // Skip past the comm field (in parens) to avoid spaces in process name
    auto close_paren = line.rfind(')');
    if (close_paren == std::string::npos) return 0.0f;

    std::istringstream ss(line.substr(close_paren + 2));
    std::string field;
    // Fields after comm: state(3), ppid(4), pgrp(5), session(6), tty_nr(7),
    // tpgid(8), flags(9), minflt(10), cminflt(11), majflt(12), cmajflt(13),
    // utime(14), stime(15)
    for (int i = 3; i <= 13; ++i) ss >> field; // skip to utime

    uint64_t utime = 0, stime = 0;
    ss >> utime >> stime;

    auto now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    float cpu_pct = 0.0f;
    if (prev_wall_ms_ > 0) {
        uint64_t wall_delta = now_ms - prev_wall_ms_;
        uint64_t cpu_delta  = (utime - prev_utime_) + (stime - prev_stime_);
        long ticks_per_sec = sysconf(_SC_CLK_TCK);
        if (ticks_per_sec <= 0) ticks_per_sec = 100;

        // Convert tick delta to milliseconds, then compute percentage
        double cpu_ms = (double)cpu_delta / (double)ticks_per_sec * 1000.0;
        if (wall_delta > 0) cpu_pct = (float)(cpu_ms / (double)wall_delta * 100.0);
    }

    prev_utime_  = utime;
    prev_stime_  = stime;
    prev_wall_ms_ = now_ms;

    return cpu_pct;
}

void PerfMonitor::run() {
    // Seed initial CPU readings
    read_cpu_percent();

    while (running_) {
        for (int i = 0; i < interval_secs_ && running_; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!running_) break;

        // ── CPU ──────────────────────────────────────────────────
        float cpu_pct = read_cpu_percent();

        // ── Memory from /proc/self/status ────────────────────────
        float rss_mb = 0, vms_mb = 0;
        {
            std::ifstream status("/proc/self/status");
            if (status.is_open()) {
                std::string line;
                while (std::getline(status, line)) {
                    if (line.find("VmRSS:") == 0) {
                        std::istringstream ss(line.substr(6));
                        float kb; ss >> kb;
                        rss_mb = kb / 1024.0f;
                    } else if (line.find("VmSize:") == 0) {
                        std::istringstream ss(line.substr(7));
                        float kb; ss >> kb;
                        vms_mb = kb / 1024.0f;
                    }
                }
            }
        }

        // ── Thread count ─────────────────────────────────────────
        int threads = 0;
        try {
            for ([[maybe_unused]] const auto& e : fs::directory_iterator("/proc/self/task"))
                threads++;
        } catch (...) {}

        // ── Open FDs ─────────────────────────────────────────────
        int fds = 0;
        try {
            for ([[maybe_unused]] const auto& e : fs::directory_iterator("/proc/self/fd"))
                fds++;
        } catch (...) {}

        // ── WAF counters (from WafHandler atomics) ───────────────
        auto& waf = WafHandler::instance();
        uint64_t cur_requests  = waf.total_requests.load();
        uint64_t cur_latency   = waf.latency_sum_1m.load();
        uint64_t cur_threats   = waf.total_threats.load();
        uint64_t cur_blocked   = waf.total_blocked.load();
        uint64_t active_rules  = waf.rules_loaded.load();

        // Compute RPS and avg latency over this interval
        uint64_t req_delta = cur_requests - waf.prev_requests_;
        uint64_t lat_delta = cur_latency  - waf.prev_latency_sum_;
        float waf_rps    = (float)req_delta / (float)interval_secs_;
        float waf_avg_ms = (req_delta > 0) ? (float)lat_delta / (float)req_delta : 0.0f;

        waf.prev_requests_    = cur_requests;
        waf.prev_latency_sum_ = cur_latency;

        // ── Task scheduler stats ─────────────────────────────────
        int task_count = 0, task_running = 0;
        {
            auto conn = DB("backdraft");
            if (conn) {
                MYSQL_RES* res = conn->query("SELECT COUNT(*) FROM backdraft_tasks WHERE enabled=1");
                if (res) {
                    MYSQL_ROW row = mysql_fetch_row(res);
                    if (row && row[0]) task_count = std::stoi(row[0]);
                    mysql_free_result(res);
                }
                res = conn->query("SELECT COUNT(*) FROM backdraft_task_runs WHERE status='running'");
                if (res) {
                    MYSQL_ROW row = mysql_fetch_row(res);
                    if (row && row[0]) task_running = std::stoi(row[0]);
                    mysql_free_result(res);
                }
            }
        }

        // ── BotProof counters ─────────────────────────────────────
        uint64_t bp_challenged = waf.total_challenged.load();
        uint64_t bp_passed     = waf.captcha_passed.load();
        uint64_t bp_failed     = waf.captcha_failed.load();

        // ── Build custom_json with extended metrics ──────────────
        std::ostringstream cjson;
        cjson << "{"
              << "\"waf_total_requests\":" << cur_requests << ","
              << "\"waf_total_threats\":" << cur_threats << ","
              << "\"waf_total_blocked\":" << cur_blocked << ","
              << "\"waf_active_rules\":" << active_rules << ","
              << "\"waf_mode\":\"" << CFG.waf.mode << "\","
              << "\"task_enabled\":" << task_count << ","
              << "\"task_running\":" << task_running << ","
              << "\"total_challenged\":" << bp_challenged << ","
              << "\"captcha_passed\":" << bp_passed << ","
              << "\"captcha_failed\":" << bp_failed
              << "}";

        // ── Write to DB ──────────────────────────────────────────
        auto conn = DB("backdraft");
        if (conn) {
            std::ostringstream sql;
            sql << "INSERT INTO backdraft_perf_metrics "
                << "(daemon, pid, cpu_percent, mem_rss_mb, mem_vms_mb, threads, "
                << "goroutines, open_fds, db_queries_1m, db_latency_p95, "
                << "log_bytes_read, log_bytes_write, waf_rps, waf_avg_ms, custom_json) VALUES ("
                << "'backdraft', " << getpid() << ", "
                << cpu_pct << ", "
                << rss_mb << ", " << vms_mb << ", "
                << threads << ", 0, " << fds << ", "
                << "0, 0, 0, 0, "
                << waf_rps << ", " << waf_avg_ms << ", "
                << "'" << cjson.str() << "')";
            conn->execute(sql.str());
        }

        // ── Prune old metrics (keep last 24 hours) ───────────────
        if (conn) {
            conn->execute("DELETE FROM backdraft_perf_metrics WHERE recorded_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        }
    }
}

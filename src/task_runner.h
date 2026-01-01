/*
 * task_runner.h — Built-in task scheduler with 1-second precision
 *
 * Reads backdraft_tasks from DB every second, evaluates next_run_at <= NOW(),
 * and dispatches PHP handler scripts via the shared ThreadPool worker pool.
 *
 * Design:
 *   - Scheduler thread wakes every 1 second
 *   - Checks backdraft_tasks WHERE enabled=1 AND next_run_at <= NOW()
 *   - Dispatches each due handler to ThreadPool (no orphan processes)
 *   - Creates backdraft_task_runs record for execution tracking
 *   - Supports schedule formats: "30s","15m","2h","24h" or fallback daily
 *   - Validates handler paths and CLI params for security
 *
 * Ported from Mcaster1YPMan task_runner.h, enhanced for BackDraft:
 *   - 1-second granularity (not per-minute)
 *   - ThreadPool dispatch (not system() &)
 *   - Execution tracking via backdraft_task_runs
 *   - Priority-aware scheduling
 */
#pragma once
#include "dbpool.h"
#include "logger.h"
#include "threadpool.h"
#include <thread>
#include <atomic>
#include <string>
#include <vector>
#include <chrono>
#include <sys/stat.h>
#include <mysql/mysql.h>
#include <unistd.h>
#include <cstdio>

class TaskRunner {
public:
    explicit TaskRunner(ThreadPool* pool,
                        const std::string& php_bin = "/usr/bin/php",
                        const std::string& handler_dir = "")
        : pool_(pool), php_bin_(php_bin), handler_dir_(handler_dir), running_(false) {}

    ~TaskRunner() { stop(); }

    void set_handler_dir(const std::string& dir) { handler_dir_ = dir; }
    void set_fallback_handler_dir(const std::string& dir) { fallback_handler_dir_ = dir; }

    void start() {
        running_ = true;
        thread_  = std::thread([this]{ loop(); });
        LOG_INFO("TaskRunner: scheduler started (1s precision, handler_dir=" +
                 handler_dir_ + ")");
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }

private:
    ThreadPool*       pool_;
    std::string       php_bin_;
    std::string       handler_dir_;
    std::string       fallback_handler_dir_;
    std::atomic<bool> running_;
    std::thread       thread_;

    /* ── Scheduler loop — 1-second precision ──────────────────── */
    void loop() {
        while (running_) {
            // Sleep 1 second, check shutdown
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!running_) break;

            check_and_dispatch();
        }
        LOG_INFO("TaskRunner: stopped");
    }

    /* ── Due task struct ──────────────────────────────────────── */
    struct DueTask {
        std::string task_id;
        std::string handler;
        std::string params;     // JSON string
        std::string priority;   // low/normal/high/critical
        std::string schedule;   // for computing next_run_at
    };

    /* ── Check DB for due tasks and dispatch ──────────────────── */
    void check_and_dispatch() {
        std::vector<DueTask> due;
        try {
            auto conn = DB("backdraft");
            MYSQL* mysql = conn->raw();

            const char* sql =
                "SELECT task_id, handler, COALESCE(params,''), "
                "       COALESCE(priority,'normal'), schedule "
                "FROM backdraft_tasks "
                "WHERE enabled = 1 "
                "  AND (next_run_at IS NULL OR next_run_at <= NOW()) "
                "ORDER BY FIELD(priority,'critical','high','normal','low'), next_run_at";

            if (mysql_query(mysql, sql) != 0) {
                LOG_WARN("TaskRunner: query error: " +
                         std::string(mysql_error(mysql)));
                return;
            }

            MYSQL_RES* res = mysql_store_result(mysql);
            if (!res) return;

            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) != nullptr) {
                unsigned long* lens = mysql_fetch_lengths(res);
                if (!row[0] || !row[1]) continue;
                DueTask t;
                t.task_id  = std::string(row[0], lens[0]);
                t.handler  = std::string(row[1], lens[1]);
                t.params   = row[2] ? std::string(row[2], lens[2]) : "";
                t.priority = row[3] ? std::string(row[3], lens[3]) : "normal";
                t.schedule = row[4] ? std::string(row[4], lens[4]) : "24h";
                due.push_back(std::move(t));
            }
            mysql_free_result(res);

            // Advance next_run_at for each due task
            for (auto& t : due) {
                int interval_secs = parse_schedule(t.schedule);
                std::string next_expr = "DATE_ADD(NOW(), INTERVAL " +
                                        std::to_string(interval_secs) + " SECOND)";

                std::string update =
                    "UPDATE backdraft_tasks "
                    "SET last_run_at = NOW(), "
                    "    next_run_at = " + next_expr + ", "
                    "    run_count   = run_count + 1 "
                    "WHERE task_id = '" + escape(mysql, t.task_id) + "'";
                mysql_query(mysql, update.c_str());
            }
        } catch (const std::exception& e) {
            LOG_WARN("TaskRunner: DB error: " + std::string(e.what()));
            return;
        }

        // Dispatch each due task to the worker pool
        for (auto& t : due) {
            dispatch(t);
        }
    }

    /* ── Parse schedule string to interval in seconds ─────────── */
    static int parse_schedule(const std::string& sched) {
        if (sched.empty()) return 86400; // default: daily

        int interval_secs = 0;
        if (sched.size() > 1) {
            char unit = sched.back();
            std::string num = sched.substr(0, sched.size() - 1);
            try {
                int val = std::stoi(num);
                if (unit == 's') interval_secs = val;
                else if (unit == 'm') interval_secs = val * 60;
                else if (unit == 'h') interval_secs = val * 3600;
                else if (unit == 'd') interval_secs = val * 86400;
            } catch (...) {}
        }

        // Minimum 10 seconds to prevent runaway tasks
        if (interval_secs < 10) interval_secs = 86400;
        return interval_secs;
    }

    /* ── MySQL string escape ──────────────────────────────────── */
    static std::string escape(MYSQL* mysql, const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(
            mysql, &buf[0], s.c_str(), (unsigned long)s.size());
        buf.resize(len);
        return buf;
    }

    /* ── Build CLI args from JSON params ──────────────────────── */
    static std::string params_to_args(const std::string& json) {
        std::string args;
        if (json.empty() || json == "null") return args;
        size_t pos = 0;
        while (pos < json.size()) {
            size_t ks = json.find('"', pos);
            if (ks == std::string::npos) break;
            size_t ke = json.find('"', ks + 1);
            if (ke == std::string::npos) break;
            std::string key = json.substr(ks + 1, ke - ks - 1);
            pos = ke + 1;

            size_t colon = json.find(':', pos);
            if (colon == std::string::npos) break;
            pos = colon + 1;
            while (pos < json.size() && json[pos] == ' ') pos++;
            if (pos >= json.size()) break;

            std::string val;
            if (json[pos] == '"') {
                size_t ve = json.find('"', pos + 1);
                if (ve == std::string::npos) break;
                val = json.substr(pos + 1, ve - pos - 1);
                pos = ve + 1;
            } else {
                size_t ve = json.find_first_of(",}", pos);
                if (ve == std::string::npos) ve = json.size();
                val = json.substr(pos, ve - pos);
                while (!val.empty() && (val.back() == ' ' || val.back() == '\n'
                                        || val.back() == '\r')) val.pop_back();
                pos = ve + 1;
            }

            // Validate key (alphanumeric + underscore + hyphen)
            bool key_ok = !key.empty();
            for (char c : key)
                if (!isalnum((unsigned char)c) && c != '_' && c != '-') { key_ok = false; break; }
            // Validate val (no shell metacharacters)
            bool val_ok = true;
            for (char c : val) {
                if (!isalnum((unsigned char)c) && c != '_' && c != '-' &&
                    c != '.' && c != '/' && c != ':' && c != '@' && c != ',') {
                    val_ok = false; break;
                }
            }
            if (key_ok && val_ok) {
                args += " --" + key + "=" + val;
            }
        }
        return args;
    }

    /* ── Dispatch task to worker pool ─────────────────────────── */
    void dispatch(const DueTask& t) {
        // Strip directory traversal from handler name
        std::string safe_handler = t.handler;
        auto slash = safe_handler.rfind('/');
        if (slash != std::string::npos)
            safe_handler = safe_handler.substr(slash + 1);

        std::string handler_path = handler_dir_ + "/" + safe_handler;

        struct stat st{};
        if (stat(handler_path.c_str(), &st) != 0) {
            if (!fallback_handler_dir_.empty()) {
                handler_path = fallback_handler_dir_ + "/" + safe_handler;
                if (stat(handler_path.c_str(), &st) != 0) {
                    LOG_WARN("TaskRunner: handler not found: " + safe_handler +
                             " (task=" + t.task_id + ")");
                    return;
                }
            } else {
                LOG_WARN("TaskRunner: handler not found: " + handler_path +
                         " (task=" + t.task_id + ")");
                return;
            }
        }

        std::string args     = params_to_args(t.params);
        std::string task_id  = t.task_id;
        std::string php_bin  = php_bin_;
        std::string priority = t.priority;

        LOG_INFO("TaskRunner: dispatching [" + task_id + "] priority=" +
                 priority + " -> " + handler_path + args);

        // Submit to worker pool — execution tracked in backdraft_task_runs
        pool_->submit([task_id, handler_path, args, php_bin]() {
            // Create run record
            long long run_id = 0;
            try {
                auto conn = DB("backdraft");
                MYSQL* mysql = conn->raw();
                std::string esc_tid = TaskRunner::escape_static(mysql, task_id);
                std::string insert =
                    "INSERT INTO backdraft_task_runs (task_id, started_at, status) "
                    "VALUES ('" + esc_tid + "', NOW(), 'running')";
                mysql_query(mysql, insert.c_str());
                run_id = (long long)mysql_insert_id(mysql);
            } catch (...) {
                LOG_WARN("TaskRunner: failed to create run record for " + task_id);
            }

            // Execute handler — capture output
            std::string logfile = "/tmp/backdraft_task_" + task_id + ".log";
            std::string cmd = php_bin + " " + handler_path + args +
                              " --run-id=" + std::to_string(run_id) +
                              " > " + logfile + " 2>&1";

            LOG_DEBUG("TaskRunner: exec: " + cmd);
            int ret = system(cmd.c_str());  // NOLINT — intentional shell dispatch
            int exit_code = WEXITSTATUS(ret);

            // Read output log (cap at 64KB for DB storage)
            std::string output;
            FILE* f = fopen(logfile.c_str(), "r");
            if (f) {
                char buf[4096];
                size_t total = 0;
                while (size_t n = fread(buf, 1, sizeof(buf), f)) {
                    if (total + n > 65536) {
                        output.append(buf, 65536 - total);
                        break;
                    }
                    output.append(buf, n);
                    total += n;
                }
                fclose(f);
            }

            // Update run record with results
            try {
                auto conn = DB("backdraft");
                MYSQL* mysql = conn->raw();

                std::string status = (exit_code == 0) ? "success" : "failed";
                std::string esc_output = TaskRunner::escape_static(mysql, output);
                std::string esc_err = (exit_code != 0)
                    ? "'" + TaskRunner::escape_static(mysql, "Exit code " + std::to_string(exit_code)) + "'"
                    : "NULL";

                std::string update =
                    "UPDATE backdraft_task_runs "
                    "SET ended_at = NOW(), "
                    "    status = '" + status + "', "
                    "    output_log = '" + esc_output + "', "
                    "    error_msg = " + esc_err + " "
                    "WHERE id = " + std::to_string(run_id);
                mysql_query(mysql, update.c_str());

                // Check if handler wrote summary_json to a sidecar file
                std::string json_path = "/tmp/backdraft_task_" + task_id + ".json";
                FILE* jf = fopen(json_path.c_str(), "r");
                if (jf) {
                    std::string json_data;
                    char jbuf[4096];
                    while (size_t n = fread(jbuf, 1, sizeof(jbuf), jf)) {
                        json_data.append(jbuf, n);
                        if (json_data.size() > 1048576) break; // 1MB cap
                    }
                    fclose(jf);

                    if (!json_data.empty()) {
                        std::string esc_json = TaskRunner::escape_static(mysql, json_data);
                        std::string jup =
                            "UPDATE backdraft_task_runs "
                            "SET summary_json = '" + esc_json + "' "
                            "WHERE id = " + std::to_string(run_id);
                        mysql_query(mysql, jup.c_str());
                    }
                }

                // Check for export_html sidecar
                std::string html_path = "/tmp/backdraft_task_" + task_id + ".html";
                FILE* hf = fopen(html_path.c_str(), "r");
                if (hf) {
                    std::string html_data;
                    char hbuf[4096];
                    while (size_t n = fread(hbuf, 1, sizeof(hbuf), hf)) {
                        html_data.append(hbuf, n);
                        if (html_data.size() > 2097152) break; // 2MB cap
                    }
                    fclose(hf);

                    if (!html_data.empty()) {
                        std::string esc_html = TaskRunner::escape_static(mysql, html_data);
                        std::string hup =
                            "UPDATE backdraft_task_runs "
                            "SET export_html = '" + esc_html + "', "
                            "    export_formats = 'html,pdf,excel' "
                            "WHERE id = " + std::to_string(run_id);
                        mysql_query(mysql, hup.c_str());
                    }
                }

            } catch (...) {
                LOG_WARN("TaskRunner: failed to update run record for " + task_id);
            }

            LOG_INFO("TaskRunner: completed [" + task_id + "] exit=" +
                     std::to_string(exit_code));
        });
    }

    /* ── Static escape for use in lambda captures ─────────────── */
    static std::string escape_static(MYSQL* mysql, const std::string& s) {
        std::string buf(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(
            mysql, &buf[0], s.c_str(), (unsigned long)s.size());
        buf.resize(len);
        return buf;
    }
};

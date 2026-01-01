#include "config.h"
#include "logger.h"
#include "dbpool.h"
#include "http_server.h"
#include "router.h"
#include "auth.h"
#include "api_handler.h"
#include "rule_engine.h"
#include "threat_scorer.h"
#include "site_discovery.h"
#include "perf_monitor.h"
#include "waf_handler.h"
#include "task_runner.h"

#include <iostream>
#include <csignal>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <unistd.h>
#include <openssl/ssl.h>

static std::atomic<bool> g_shutdown{false};
static std::mutex g_mtx;
static std::condition_variable g_cv;

static void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        g_shutdown = true;
        g_cv.notify_all();
    }
}

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "  -c <path>    Config file path (required)\n"
              << "  --daemon     Daemonize\n"
              << "  --help       Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string config_path;
    bool daemon_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "-c" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (config_path.empty()) {
        std::cerr << "Error: config file required (-c path)\n";
        print_usage(argv[0]);
        return 1;
    }

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Load configuration
    try {
        Config::instance().load(config_path);
    } catch (const std::exception& e) {
        std::cerr << "Config load failed: " << e.what() << "\n";
        return 1;
    }

    const auto& cfg = CFG;

    // Override daemon mode from CLI
    if (daemon_mode) {
        // Double fork
        if (fork() != 0) _exit(0);
        setsid();
        if (fork() != 0) _exit(0);
    }

    // Initialize logger
    Logger::instance().init(cfg.log.dir, cfg.log.level, cfg.log.max_mb, cfg.log.keep);

    LOG_INFO("========================================");
    LOG_INFO("Mcaster1BackDraft v" + cfg.version + " starting");
    LOG_INFO("========================================");
    LOG_INFO("Config: " + config_path);
    LOG_INFO("WAF mode: " + cfg.waf.mode);
    LOG_INFO("Web UI port: " + std::to_string(cfg.http.web_port));
    LOG_INFO("API port: " + std::to_string(cfg.http.api_port));
    LOG_INFO("WAF port: " + std::to_string(cfg.http.waf_port));
    LOG_INFO("WAF upstream FCGI: " + cfg.waf.upstream_fcgi);

    // Register signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe

    // Initialize database connection pools
    for (const auto& db : cfg.databases) {
        DbRegistry::instance().register_pool(
            db.name, db.host, db.port, db.username, db.password,
            db.database, db.charset, db.pool_size);
    }

    // Initialize subsystems
    RuleEngine::init();
    ThreatScorer::init();
    WafHandler::instance().init();

    // Discover nginx sites
    SiteDiscovery::discover();

    // Create HTTP servers
    HttpServer web_server(cfg.http.bind_addr, cfg.http.web_port, cfg.http.enable_https,
                          cfg.http.tls_cert, cfg.http.tls_key,
                          cfg.http.web_root, cfg.http.fcgi_socket);

    HttpServer api_server(cfg.http.bind_addr, cfg.http.api_port, cfg.http.enable_https,
                          cfg.http.tls_cert, cfg.http.tls_key,
                          cfg.http.web_root, cfg.http.fcgi_socket);

    // Create WAF server (receives proxied traffic from nginx)
    HttpServer waf_server(cfg.http.bind_addr, cfg.http.waf_port, cfg.http.enable_https,
                          cfg.http.tls_cert, cfg.http.tls_key,
                          cfg.http.web_root, cfg.waf.upstream_fcgi);

    // Register routes
    Router::register_routes(web_server, api_server);

    // WAF server routes — catch-all handler
    waf_server.route("GET",  "/health", ApiHandler::health);
    waf_server.route("*",    "/", [](const HttpRequest& req) -> HttpResponse {
        return WafHandler::instance().handle_request(req);
    });

    // Start HTTP servers
    web_server.start();
    api_server.start();
    waf_server.start();

    // Start performance monitor
    if (cfg.perf.enabled) {
        PerfMonitor::instance().start(cfg.perf.interval_secs);
    }

    // Start task scheduler with dedicated worker pool
    // Worker pool for task execution — separate from HTTP thread pools
    ThreadPool task_pool(std::max<size_t>(4, ThreadPool::recommended_size() / 4));
    TaskRunner task_runner(&task_pool, "/usr/bin/php",
                           cfg.http.web_root + "/../tasks");
    task_runner.set_fallback_handler_dir(cfg.http.web_root);
    task_runner.start();

    LOG_INFO("Mcaster1BackDraft ready — waiting for connections");

    // Write PID file — must happen after fork() so we record the daemon PID
    {
        pid_t my_pid = getpid();
        std::ofstream pf(cfg.pid_file, std::ios::trunc);
        if (pf.is_open()) {
            pf << my_pid << std::endl;
            LOG_INFO("PID file written: " + cfg.pid_file + " (pid=" + std::to_string(my_pid) + ")");
        } else {
            LOG_ERROR("Failed to write PID file: " + cfg.pid_file);
        }
    }

    // Wait for shutdown signal
    {
        std::unique_lock<std::mutex> lock(g_mtx);
        g_cv.wait(lock, []{ return g_shutdown.load(); });
    }

    LOG_INFO("Shutdown signal received — stopping services...");

    // Stop services
    task_runner.stop();
    WafHandler::instance().stop();
    PerfMonitor::instance().stop();
    waf_server.stop();
    web_server.stop();
    api_server.stop();

    // Remove PID file
    std::remove(cfg.pid_file.c_str());

    LOG_INFO("Mcaster1BackDraft stopped cleanly");
    return 0;
}

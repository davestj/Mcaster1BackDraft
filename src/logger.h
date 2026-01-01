#ifndef BACKDRAFT_LOGGER_H
#define BACKDRAFT_LOGGER_H

#include <string>
#include <mutex>
#include <fstream>

enum class LogLevel { DEBUG, INFO, WARN, ERROR, FATAL };

class Logger {
public:
    static Logger& instance();

    void init(const std::string& dir, const std::string& level_str,
              int max_mb = 50, int keep = 5);

    void log(LogLevel level, const std::string& msg);
    void access(const std::string& ip, const std::string& method,
                const std::string& path, int status, size_t bytes,
                const std::string& ua = "");

private:
    Logger() = default;
    void rotate_if_needed(std::ofstream& f, const std::string& path);
    std::string timestamp();
    std::string level_str(LogLevel l);

    std::mutex  mtx_;
    std::string dir_;
    int max_bytes_ = 50 * 1024 * 1024;
    int keep_      = 5;
    LogLevel min_level_ = LogLevel::DEBUG;

    std::ofstream f_main_;
    std::ofstream f_error_;
    std::ofstream f_debug_;
    std::ofstream f_access_;

    std::string path_main_;
    std::string path_error_;
    std::string path_debug_;
    std::string path_access_;
};

#define LOG_DEBUG(msg) Logger::instance().log(LogLevel::DEBUG, msg)
#define LOG_INFO(msg)  Logger::instance().log(LogLevel::INFO,  msg)
#define LOG_WARN(msg)  Logger::instance().log(LogLevel::WARN,  msg)
#define LOG_ERROR(msg) Logger::instance().log(LogLevel::ERROR, msg)
#define LOG_FATAL(msg) Logger::instance().log(LogLevel::FATAL, msg)
#define LOG_ACCESS(ip, method, path, status, bytes, ua) \
    Logger::instance().access(ip, method, path, status, bytes, ua)

#endif

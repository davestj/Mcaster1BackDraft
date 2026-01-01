#include "logger.h"
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::init(const std::string& dir, const std::string& level_str,
                  int max_mb, int keep) {
    std::lock_guard<std::mutex> lock(mtx_);
    dir_       = dir;
    max_bytes_ = max_mb * 1024 * 1024;
    keep_      = keep;

    std::string lv = level_str;
    std::transform(lv.begin(), lv.end(), lv.begin(), ::toupper);
    if (lv == "DEBUG")      min_level_ = LogLevel::DEBUG;
    else if (lv == "INFO")  min_level_ = LogLevel::INFO;
    else if (lv == "WARN")  min_level_ = LogLevel::WARN;
    else if (lv == "ERROR") min_level_ = LogLevel::ERROR;
    else if (lv == "FATAL") min_level_ = LogLevel::FATAL;

    fs::create_directories(dir_);

    path_main_   = dir_ + "/backdraft.log";
    path_error_  = dir_ + "/error.log";
    path_debug_  = dir_ + "/debug.log";
    path_access_ = dir_ + "/access.log";

    f_main_.open(path_main_,   std::ios::app);
    f_error_.open(path_error_,  std::ios::app);
    f_debug_.open(path_debug_,  std::ios::app);
    f_access_.open(path_access_, std::ios::app);
}

std::string Logger::timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string Logger::level_str(LogLevel l) {
    switch (l) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
    }
    return "INFO";
}

void Logger::rotate_if_needed(std::ofstream& f, const std::string& path) {
    if (!f.is_open()) return;
    auto pos = f.tellp();
    if (pos < 0 || pos < max_bytes_) return;

    f.close();
    for (int i = keep_ - 1; i >= 1; --i) {
        std::string old_name = path + "." + std::to_string(i);
        std::string new_name = path + "." + std::to_string(i + 1);
        std::rename(old_name.c_str(), new_name.c_str());
    }
    std::rename(path.c_str(), (path + ".1").c_str());
    f.open(path, std::ios::app);
}

void Logger::log(LogLevel level, const std::string& msg) {
    if (level < min_level_) return;
    std::lock_guard<std::mutex> lock(mtx_);

    std::string line = "[" + timestamp() + "] [" + level_str(level) + "] " + msg + "\n";

    if (level >= LogLevel::INFO && f_main_.is_open()) {
        f_main_ << line;
        f_main_.flush();
        rotate_if_needed(f_main_, path_main_);
    }

    if (level >= LogLevel::ERROR && f_error_.is_open()) {
        f_error_ << line;
        f_error_.flush();
        rotate_if_needed(f_error_, path_error_);
    }

    if (level == LogLevel::DEBUG && f_debug_.is_open()) {
        f_debug_ << line;
        f_debug_.flush();
        rotate_if_needed(f_debug_, path_debug_);
    }
}

void Logger::access(const std::string& ip, const std::string& method,
                    const std::string& path, int status, size_t bytes,
                    const std::string& ua) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!f_access_.is_open()) return;

    f_access_ << ip << " - - [" << timestamp() << "] \""
              << method << " " << path << " HTTP/1.1\" "
              << status << " " << bytes << " \"-\" \""
              << ua << "\"\n";
    f_access_.flush();
    rotate_if_needed(f_access_, path_access_);
}

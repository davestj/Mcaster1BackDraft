#ifndef BACKDRAFT_PERF_MONITOR_H
#define BACKDRAFT_PERF_MONITOR_H

#include <thread>
#include <atomic>
#include <cstdint>

class PerfMonitor {
public:
    static PerfMonitor& instance();
    void start(int interval_secs);
    void stop();

private:
    PerfMonitor() = default;
    void run();
    float read_cpu_percent();

    std::thread thread_;
    std::atomic<bool> running_{false};
    int interval_secs_ = 10;

    // CPU measurement state — from /proc/self/stat
    uint64_t prev_utime_  = 0;
    uint64_t prev_stime_  = 0;
    uint64_t prev_wall_ms_ = 0;
};

#endif

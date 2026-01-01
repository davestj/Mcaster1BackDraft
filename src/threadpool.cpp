#include "threadpool.h"
#include <fstream>
#include <sstream>
#include <string>

ThreadPool::ThreadPool(size_t num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPool::worker_loop, this);
    }
}

ThreadPool::~ThreadPool() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
}

void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        queue_.push(std::move(task));
    }
    cv_.notify_one();
}

size_t ThreadPool::queue_size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return queue_.size();
}

void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (stop_ && queue_.empty()) return;
            task = std::move(queue_.front());
            queue_.pop();
        }
        active_++;
        try {
            task();
        } catch (...) {
            // Swallow exceptions from individual tasks
        }
        active_--;
    }
}

size_t ThreadPool::recommended_size() {
    size_t cpus = std::thread::hardware_concurrency();
    if (cpus == 0) cpus = 4;

    // Read available memory from /proc/meminfo
    size_t mem_mb = 0;
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemAvailable:") == 0) {
                std::istringstream ss(line.substr(13));
                size_t kb;
                ss >> kb;
                mem_mb = kb / 1024;
                break;
            }
        }
    }

    // Each thread uses ~2MB stack, plus overhead
    // Cap based on memory: allow max 50% of available memory for threads
    size_t max_by_memory = (mem_mb > 0) ? (mem_mb / 2 / 2) : 256;

    // Scale: CPU * 4 for I/O-bound work (FastCGI waits), capped by memory
    size_t target = cpus * 4;
    if (target > max_by_memory) target = max_by_memory;
    if (target < 8) target = 8;
    if (target > 512) target = 512;

    return target;
}

#ifndef BACKDRAFT_THREADPOOL_H
#define BACKDRAFT_THREADPOOL_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();

    void submit(std::function<void()> task);
    size_t active_count() const { return active_.load(); }
    size_t queue_size() const;
    size_t pool_size() const { return workers_.size(); }

    // Auto-size based on system CPU and memory
    static size_t recommended_size();

private:
    void worker_loop();

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> queue_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> active_{0};
};

#endif

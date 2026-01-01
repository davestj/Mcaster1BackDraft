#include "dbpool.h"
#include "logger.h"
#include <stdexcept>

// ---------- DbPool ----------

DbPool::DbPool(const std::string& host, int port, const std::string& user,
               const std::string& pass, const std::string& db,
               const std::string& charset, int pool_size)
    : host_(host), user_(user), pass_(pass), db_(db),
      charset_(charset), port_(port) {
    for (int i = 0; i < pool_size; ++i) {
        MYSQL* conn = create_connection();
        if (conn) pool_.push(conn);
    }
    LOG_INFO("DB pool '" + db + "' initialized with " +
             std::to_string(pool_.size()) + " connections");
}

DbPool::~DbPool() {
    std::lock_guard<std::mutex> lock(mtx_);
    while (!pool_.empty()) {
        mysql_close(pool_.front());
        pool_.pop();
    }
}

MYSQL* DbPool::create_connection() {
    MYSQL* conn = mysql_init(nullptr);
    if (!conn) {
        LOG_ERROR("mysql_init failed");
        return nullptr;
    }

    mysql_options(conn, MYSQL_SET_CHARSET_NAME, charset_.c_str());

    my_bool reconnect = 1;
    mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect);

    if (!mysql_real_connect(conn, host_.c_str(), user_.c_str(), pass_.c_str(),
                            db_.c_str(), port_, nullptr, 0)) {
        LOG_ERROR("MySQL connect failed: " + std::string(mysql_error(conn)));
        mysql_close(conn);
        return nullptr;
    }
    return conn;
}

std::shared_ptr<PooledConn> DbPool::acquire() {
    std::unique_lock<std::mutex> lock(mtx_);
    cv_.wait(lock, [this]{ return !pool_.empty(); });

    MYSQL* raw = pool_.front();
    pool_.pop();

    if (mysql_ping(raw) != 0) {
        LOG_WARN("DB connection lost, reconnecting...");
        mysql_close(raw);
        raw = create_connection();
        if (!raw) return nullptr;
    }

    return std::make_shared<PooledConn>(raw);
}

void DbPool::release(std::shared_ptr<PooledConn> conn) {
    if (!conn) return;
    std::lock_guard<std::mutex> lock(mtx_);
    pool_.push(conn->raw());
    cv_.notify_one();
}

// ---------- DbRegistry ----------

DbRegistry& DbRegistry::instance() {
    static DbRegistry inst;
    return inst;
}

void DbRegistry::register_pool(const std::string& name,
                                const std::string& host, int port,
                                const std::string& user, const std::string& pass,
                                const std::string& db, const std::string& charset,
                                int pool_size) {
    std::lock_guard<std::mutex> lock(mtx_);
    pools_[name] = std::make_unique<DbPool>(host, port, user, pass, db, charset, pool_size);
}

DbConn DbRegistry::get(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = pools_.find(name);
    if (it == pools_.end()) {
        LOG_ERROR("DB pool '" + name + "' not found");
        return DbConn(nullptr, nullptr);
    }
    auto conn = it->second->acquire();
    return DbConn(conn, it->second.get());
}

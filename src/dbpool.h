#ifndef BACKDRAFT_DBPOOL_H
#define BACKDRAFT_DBPOOL_H

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <map>
#include <mysql/mysql.h>

// RAII prepared statement handle
using StmtPtr = std::unique_ptr<MYSQL_STMT, decltype(&mysql_stmt_close)>;

class PooledConn {
public:
    PooledConn(MYSQL* raw) : raw_(raw) {}
    ~PooledConn() { /* pool reclaims, not us */ }

    MYSQL* raw() { return raw_; }

    StmtPtr prepare(const std::string& sql) {
        MYSQL_STMT* s = mysql_stmt_init(raw_);
        if (s && mysql_stmt_prepare(s, sql.c_str(), sql.size()) == 0)
            return StmtPtr(s, mysql_stmt_close);
        if (s) mysql_stmt_close(s);
        return StmtPtr(nullptr, mysql_stmt_close);
    }

    bool execute(const std::string& sql) {
        return mysql_query(raw_, sql.c_str()) == 0;
    }

    MYSQL_RES* query(const std::string& sql) {
        if (mysql_query(raw_, sql.c_str()) != 0) return nullptr;
        return mysql_store_result(raw_);
    }

private:
    MYSQL* raw_;
};

class DbPool {
public:
    DbPool(const std::string& host, int port, const std::string& user,
           const std::string& pass, const std::string& db,
           const std::string& charset, int pool_size);
    ~DbPool();

    std::shared_ptr<PooledConn> acquire();
    void release(std::shared_ptr<PooledConn> conn);

private:
    MYSQL* create_connection();

    std::string host_, user_, pass_, db_, charset_;
    int port_;
    std::queue<MYSQL*> pool_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

// RAII connection handle — auto-releases on destruction
class DbConn {
public:
    DbConn(std::shared_ptr<PooledConn> conn, DbPool* pool)
        : conn_(conn), pool_(pool) {}
    ~DbConn() { if (pool_ && conn_) pool_->release(conn_); }

    PooledConn* operator->() { return conn_.get(); }
    PooledConn& operator*()  { return *conn_; }
    explicit operator bool() const { return conn_ != nullptr; }

private:
    std::shared_ptr<PooledConn> conn_;
    DbPool* pool_;
};

class DbRegistry {
public:
    static DbRegistry& instance();

    void register_pool(const std::string& name,
                       const std::string& host, int port,
                       const std::string& user, const std::string& pass,
                       const std::string& db, const std::string& charset,
                       int pool_size);

    DbConn get(const std::string& name);

private:
    DbRegistry() = default;
    std::map<std::string, std::unique_ptr<DbPool>> pools_;
    std::mutex mtx_;
};

// Convenience macro: auto conn = DB("backdraft");
#define DB(name) DbRegistry::instance().get(name)

#endif

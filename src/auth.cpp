#include "auth.h"
#include "config.h"
#include "dbpool.h"
#include "logger.h"
#include "http_server.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <cstring>

Auth& Auth::instance() {
    static Auth inst;
    return inst;
}

std::string Auth::generate_token() {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    std::ostringstream ss;
    for (int i = 0; i < 32; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    return ss.str();
}

std::string Auth::sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

AuthResult Auth::resolve(const HttpRequest& req) {
    AuthResult result;

    // Check Authorization: Bearer token
    auto it = req.headers.find("authorization");
    if (it != req.headers.end()) {
        const std::string& hdr = it->second;
        if (hdr.find("Bearer ") == 0) {
            std::string token = hdr.substr(7);

            // Check master API token
            if (token == CFG.auth.api_token) {
                result.authenticated = true;
                result.username = CFG.auth.master_username;
                result.role = "superadmin";
                return result;
            }

            // Check DB session
            auto conn = DB("backdraft");
            if (conn) {
                std::string sql = "SELECT s.user_id, u.username, u.role "
                                  "FROM backdraft_sessions s "
                                  "JOIN backdraft_users u ON u.id = s.user_id "
                                  "WHERE s.token = '" + token + "' "
                                  "AND s.expires_at > NOW() AND u.active = 1 LIMIT 1";
                MYSQL_RES* res = conn->query(sql);
                if (res) {
                    MYSQL_ROW row = mysql_fetch_row(res);
                    if (row) {
                        result.authenticated = true;
                        result.user_id  = std::stoi(row[0]);
                        result.username = row[1];
                        result.role     = row[2];
                    }
                    mysql_free_result(res);
                }
            }
        }
    }

    // Check query param ?token=
    if (!result.authenticated) {
        auto qt = req.query_params.find("token");
        if (qt != req.query_params.end() && qt->second == CFG.auth.api_token) {
            result.authenticated = true;
            result.username = CFG.auth.master_username;
            result.role = "superadmin";
        }
    }

    // Check cookie: backdraft_session=TOKEN
    if (!result.authenticated) {
        auto cookie_it = req.headers.find("cookie");
        if (cookie_it != req.headers.end()) {
            const std::string& cookies = cookie_it->second;
            std::string prefix = "backdraft_session=";
            auto pos = cookies.find(prefix);
            if (pos != std::string::npos) {
                auto end = cookies.find(';', pos);
                std::string token = cookies.substr(pos + prefix.size(),
                    end == std::string::npos ? std::string::npos : end - pos - prefix.size());

                if (token == CFG.auth.api_token) {
                    result.authenticated = true;
                    result.username = CFG.auth.master_username;
                    result.role = "superadmin";
                } else {
                    auto conn = DB("backdraft");
                    if (conn) {
                        std::string sql = "SELECT s.user_id, u.username, u.role "
                                          "FROM backdraft_sessions s "
                                          "JOIN backdraft_users u ON u.id = s.user_id "
                                          "WHERE s.token = '" + token + "' "
                                          "AND s.expires_at > NOW() AND u.active = 1 LIMIT 1";
                        MYSQL_RES* res = conn->query(sql);
                        if (res) {
                            MYSQL_ROW row = mysql_fetch_row(res);
                            if (row) {
                                result.authenticated = true;
                                result.user_id  = std::stoi(row[0]);
                                result.username = row[1];
                                result.role     = row[2];
                            }
                            mysql_free_result(res);
                        }
                    }
                }
            }
        }
    }

    return result;
}

AuthResult Auth::login(const std::string& username, const std::string& password,
                       const std::string& ip, const std::string& ua) {
    AuthResult result;

    // Check master credentials
    if (username == CFG.auth.master_username && password == CFG.auth.master_password) {
        result.authenticated = true;
        result.username = username;
        result.role = "superadmin";
        return result;
    }

    // Check DB users
    std::string hash = sha256(password);
    auto conn = DB("backdraft");
    if (!conn) return result;

    std::string sql = "SELECT id, username, role FROM backdraft_users "
                      "WHERE username = '" + username + "' "
                      "AND password_hash = '" + hash + "' "
                      "AND active = 1 LIMIT 1";
    MYSQL_RES* res = conn->query(sql);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        if (row) {
            result.authenticated = true;
            result.user_id  = std::stoi(row[0]);
            result.username = row[1];
            result.role     = row[2];
        }
        mysql_free_result(res);
    }

    return result;
}

std::string Auth::create_session(int user_id, const std::string& ip,
                                  const std::string& ua) {
    std::string token = generate_token();
    int ttl = CFG.auth.session_ttl_secs;

    auto conn = DB("backdraft");
    if (!conn) return "";

    std::string sql = "INSERT INTO backdraft_sessions (user_id, token, ip_addr, user_agent, expires_at) "
                      "VALUES (" + std::to_string(user_id) + ", '" + token + "', "
                      "'" + ip + "', '" + ua.substr(0, 512) + "', "
                      "DATE_ADD(NOW(), INTERVAL " + std::to_string(ttl) + " SECOND))";
    conn->execute(sql);
    return token;
}

bool Auth::logout(const std::string& token) {
    auto conn = DB("backdraft");
    if (!conn) return false;
    return conn->execute("DELETE FROM backdraft_sessions WHERE token = '" + token + "'");
}

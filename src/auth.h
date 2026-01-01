#ifndef BACKDRAFT_AUTH_H
#define BACKDRAFT_AUTH_H

#include <string>

struct HttpRequest;

struct AuthResult {
    bool authenticated = false;
    std::string username;
    std::string role;     // "user", "admin", "superadmin"
    int user_id = 0;
};

class Auth {
public:
    static Auth& instance();

    AuthResult resolve(const HttpRequest& req);
    AuthResult login(const std::string& username, const std::string& password,
                     const std::string& ip, const std::string& ua);
    bool logout(const std::string& token);
    std::string create_session(int user_id, const std::string& ip,
                                const std::string& ua);

private:
    Auth() = default;
    std::string generate_token();
    std::string sha256(const std::string& input);
};

#endif

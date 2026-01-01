#include "http_server.h"
#include "config.h"
#include "logger.h"
#include "auth.h"
#include "threadpool.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <openssl/err.h>

namespace fs = std::filesystem;

static constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024; // 1 MB

// ---------- HttpResponse statics ----------

HttpResponse HttpResponse::ok(const std::string& b)           { return {200, "application/json", {}, b}; }
HttpResponse HttpResponse::html(const std::string& b)         { return {200, "text/html; charset=utf-8", {}, b}; }
HttpResponse HttpResponse::bad_req(const std::string& m)      { return {400, "application/json", {}, R"({"ok":false,"error":")" + m + R"("})"}; }
HttpResponse HttpResponse::unauth()                           { return {401, "application/json", {}, R"({"ok":false,"error":"Unauthorized"})"}; }
HttpResponse HttpResponse::forbidden(const std::string& m)    { return {403, "application/json", {}, R"({"ok":false,"error":")" + m + R"("})"}; }
HttpResponse HttpResponse::not_found(const std::string& m)    { return {404, "application/json", {}, R"({"ok":false,"error":")" + m + R"("})"}; }
HttpResponse HttpResponse::internal_error(const std::string& m) { return {500, "application/json", {}, R"({"ok":false,"error":")" + m + R"("})"}; }

// ---------- HttpServer ----------

HttpServer::HttpServer(const std::string& bind_addr, int port, bool use_tls,
                       const std::string& cert_path, const std::string& key_path,
                       const std::string& web_root, const std::string& fcgi_socket)
    : bind_addr_(bind_addr), port_(port), use_tls_(use_tls),
      cert_path_(cert_path), key_path_(key_path),
      web_root_(web_root), fcgi_socket_(fcgi_socket) {}

HttpServer::~HttpServer() { stop(); }

void HttpServer::route(const std::string& method, const std::string& path, RouteHandler handler) {
    routes_.push_back({method, path, handler, nullptr, false});
}

void HttpServer::stream_route(const std::string& method, const std::string& path, StreamHandler handler) {
    routes_.push_back({method, path, nullptr, handler, true});
}

void HttpServer::start() {
    if (use_tls_) {
        ssl_ctx_ = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_num_tickets(ssl_ctx_, 0);

        if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cert_path_.c_str()) <= 0) {
            LOG_FATAL("Failed to load TLS cert: " + cert_path_);
            return;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path_.c_str(), SSL_FILETYPE_PEM) <= 0) {
            LOG_FATAL("Failed to load TLS key: " + key_path_);
            return;
        }
    }

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port_);
    addr.sin_addr.s_addr = inet_addr(bind_addr_.c_str());

    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_FATAL("Bind failed on port " + std::to_string(port_) + ": " + strerror(errno));
        return;
    }

    listen(listen_fd_, 128);
    running_ = true;

    // Create thread pool
    size_t pool_size = ThreadPool::recommended_size();
    pool_ = std::make_unique<ThreadPool>(pool_size);

    LOG_INFO("HTTP" + std::string(use_tls_ ? "S" : "") + " server listening on " +
             bind_addr_ + ":" + std::to_string(port_) +
             " (pool=" + std::to_string(pool_size) + " threads)");

    accept_thread_ = std::thread(&HttpServer::accept_loop, this);
}

void HttpServer::stop() {
    running_ = false;
    if (listen_fd_ >= 0) { close(listen_fd_); listen_fd_ = -1; }
    if (accept_thread_.joinable()) accept_thread_.join();
    if (ssl_ctx_) { SSL_CTX_free(ssl_ctx_); ssl_ctx_ = nullptr; }
}

void HttpServer::accept_loop() {
    while (running_) {
        struct sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            if (running_) LOG_DEBUG("Accept error: " + std::string(strerror(errno)));
            continue;
        }

        std::string remote_ip = inet_ntoa(client_addr.sin_addr);
        pool_->submit([this, client_fd, remote_ip]() {
            handle_client(client_fd, remote_ip);
        });
    }
}

void HttpServer::handle_client(int client_fd, const std::string& remote_ip) {
    SSL* ssl = nullptr;
    if (use_tls_ && ssl_ctx_) {
        ssl = SSL_new(ssl_ctx_);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            close(client_fd);
            return;
        }
    }

    try {
        std::string raw = read_request(client_fd, ssl);
        if (raw.empty()) {
            if (ssl) SSL_free(ssl);
            close(client_fd);
            return;
        }

        HttpRequest req = parse_request(raw);
        req.remote_addr = remote_ip;
        parse_query_params(req);

        // Check for forwarded IP
        auto it = req.headers.find("x-real-ip");
        if (it != req.headers.end()) req.remote_addr = it->second;

        // Try registered routes (specific first)
        for (const auto& r : routes_) {
            bool method_match = (r.method == "*" || r.method == req.method);
            bool path_match   = (req.path == r.path ||
                                (r.path.back() == '/' && req.path.find(r.path) == 0));

            if (method_match && path_match) {
                if (r.is_stream) {
                    r.stream_handler(req, client_fd, ssl);
                    LOG_ACCESS(req.remote_addr, req.method, req.path, 200, 0,
                               req.headers.count("user-agent") ? req.headers["user-agent"] : "");
                } else {
                    HttpResponse resp = r.handler(req);
                    std::string out = build_response(resp);
                    send_data(client_fd, ssl, out);
                    LOG_ACCESS(req.remote_addr, req.method, req.path, resp.status, resp.body.size(),
                               req.headers.count("user-agent") ? req.headers["user-agent"] : "");
                }
                if (ssl) SSL_free(ssl);
                close(client_fd);
                return;
            }
        }

        // Try PHP files via FastCGI
        if (req.path.size() > 4 && req.path.substr(req.path.size() - 4) == ".php") {
            if (serve_php(req, client_fd, ssl)) {
                if (ssl) SSL_free(ssl);
                close(client_fd);
                return;
            }
        }

        // Try static files
        if (serve_static(req, client_fd, ssl)) {
            if (ssl) SSL_free(ssl);
            close(client_fd);
            return;
        }

        // 404
        HttpResponse resp = HttpResponse::not_found("Not found: " + req.path);
        send_data(client_fd, ssl, build_response(resp));
        LOG_ACCESS(req.remote_addr, req.method, req.path, 404, 0,
                   req.headers.count("user-agent") ? req.headers["user-agent"] : "");

    } catch (const std::exception& e) {
        LOG_ERROR("handle_client exception: " + std::string(e.what()));
    }

    if (ssl) SSL_free(ssl);
    close(client_fd);
}

std::string HttpServer::read_request(int fd, SSL* ssl) {
    std::string buf;
    buf.reserve(8192);
    char chunk[4096];

    while (buf.size() < MAX_REQUEST_SIZE) {
        int n;
        if (ssl)
            n = SSL_read(ssl, chunk, sizeof(chunk));
        else
            n = read(fd, chunk, sizeof(chunk));

        if (n <= 0) break;
        buf.append(chunk, n);

        // Check if we have the full headers
        if (buf.find("\r\n\r\n") != std::string::npos) {
            // Check Content-Length for body
            auto cl_pos = buf.find("Content-Length:");
            if (cl_pos == std::string::npos) cl_pos = buf.find("content-length:");
            if (cl_pos != std::string::npos) {
                auto val_start = buf.find(':', cl_pos) + 1;
                auto val_end   = buf.find('\r', val_start);
                size_t content_len = std::stoul(buf.substr(val_start, val_end - val_start));
                auto body_start = buf.find("\r\n\r\n") + 4;
                size_t body_have = buf.size() - body_start;

                while (body_have < content_len && buf.size() < MAX_REQUEST_SIZE) {
                    n = ssl ? SSL_read(ssl, chunk, sizeof(chunk))
                            : read(fd, chunk, sizeof(chunk));
                    if (n <= 0) break;
                    buf.append(chunk, n);
                    body_have += n;
                }
            }
            break;
        }
    }
    return buf;
}

HttpRequest HttpServer::parse_request(const std::string& raw) {
    HttpRequest req;
    std::istringstream stream(raw);
    std::string line;

    // Request line
    if (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto sp1 = line.find(' ');
        auto sp2 = line.find(' ', sp1 + 1);
        if (sp1 != std::string::npos) {
            req.method = line.substr(0, sp1);
            std::string full_path = (sp2 != std::string::npos)
                ? line.substr(sp1 + 1, sp2 - sp1 - 1)
                : line.substr(sp1 + 1);

            auto qmark = full_path.find('?');
            if (qmark != std::string::npos) {
                req.path  = full_path.substr(0, qmark);
                req.query = full_path.substr(qmark + 1);
            } else {
                req.path = full_path;
            }
        }
    }

    // Headers
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;

        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            // Trim leading space
            if (!val.empty() && val[0] == ' ') val = val.substr(1);
            // Lowercase key
            for (auto& c : key) c = std::tolower(c);
            req.headers[key] = val;
        }
    }

    // Body (everything after \r\n\r\n)
    auto body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
        req.body = raw.substr(body_pos + 4);
    }

    return req;
}

void HttpServer::parse_query_params(HttpRequest& req) {
    if (req.query.empty()) return;
    std::istringstream ss(req.query);
    std::string pair;
    while (std::getline(ss, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            req.query_params[pair.substr(0, eq)] = pair.substr(eq + 1);
        } else {
            req.query_params[pair] = "";
        }
    }
}

std::string HttpServer::build_response(const HttpResponse& resp) {
    std::ostringstream out;
    out << "HTTP/1.1 " << resp.status << " OK\r\n";
    out << "Content-Type: " << resp.content_type << "\r\n";
    out << "Content-Length: " << resp.body.size() << "\r\n";
    out << "Connection: close\r\n";
    for (const auto& [k, v] : resp.headers) {
        out << k << ": " << v << "\r\n";
    }
    out << "\r\n" << resp.body;
    return out.str();
}

void HttpServer::send_data(int fd, SSL* ssl, const std::string& data) {
    send_data(fd, ssl, data.c_str(), data.size());
}

void HttpServer::send_data(int fd, SSL* ssl, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (ssl)
            n = SSL_write(ssl, buf + sent, std::min(len - sent, (size_t)32768));
        else
            n = write(fd, buf + sent, std::min(len - sent, (size_t)32768));
        if (n <= 0) break;
        sent += n;
    }
}

static bool str_ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string HttpServer::content_type_for(const std::string& path) {
    if (str_ends_with(path, ".html") || str_ends_with(path, ".htm")) return "text/html; charset=utf-8";
    if (str_ends_with(path, ".css"))  return "text/css";
    if (str_ends_with(path, ".js"))   return "application/javascript";
    if (str_ends_with(path, ".json")) return "application/json";
    if (str_ends_with(path, ".svg"))  return "image/svg+xml";
    if (str_ends_with(path, ".png"))  return "image/png";
    if (str_ends_with(path, ".ico"))  return "image/x-icon";
    if (str_ends_with(path, ".jpg") || str_ends_with(path, ".jpeg")) return "image/jpeg";
    if (str_ends_with(path, ".gif"))  return "image/gif";
    if (str_ends_with(path, ".woff2")) return "font/woff2";
    return "application/octet-stream";
}

bool HttpServer::serve_static(const HttpRequest& req, int fd, SSL* ssl) {
    std::string file_path = web_root_ + req.path;
    if (req.path == "/" || req.path.empty()) file_path = web_root_ + "/login.php";

    // Resolve to real path to prevent traversal
    char* real = realpath(file_path.c_str(), nullptr);
    if (!real) return false;
    std::string resolved(real);
    free(real);

    // Check prefix
    char* root_real = realpath(web_root_.c_str(), nullptr);
    if (!root_real) return false;
    std::string root_resolved(root_real);
    free(root_real);

    if (resolved.find(root_resolved) != 0) {
        LOG_WARN("Path traversal blocked: " + req.path);
        return false;
    }

    if (!fs::is_regular_file(resolved)) return false;

    std::ifstream f(resolved, std::ios::binary);
    if (!f.is_open()) return false;

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    HttpResponse resp;
    resp.status = 200;
    resp.content_type = content_type_for(resolved);
    resp.body = content;

    send_data(fd, ssl, build_response(resp));
    LOG_ACCESS(req.remote_addr, req.method, req.path, 200, content.size(),
               req.headers.count("user-agent") ? req.headers.at("user-agent") : "");
    return true;
}

bool HttpServer::serve_php(const HttpRequest& req, int fd, SSL* ssl) {
    // FastCGI proxy to PHP-FPM via unix socket
    // This is a simplified implementation — production should use full FCGI protocol
    // For v0.0.1a, we redirect PHP requests to the static file server
    // Full FastCGI implementation will be ported from Mcaster1YPMan in v0.0.2a

    std::string script_path = web_root_ + req.path;
    if (!fs::exists(script_path)) return false;

    // Resolve auth state for PHP header injection
    auto auth_result = Auth::instance().resolve(req);

    // Build FastCGI request to PHP-FPM socket
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("Failed to create FCGI socket");
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fcgi_socket_.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("FCGI connect failed: " + std::string(strerror(errno)));
        close(sock);
        return false;
    }

    // Build FCGI_BEGIN_REQUEST + FCGI_PARAMS + FCGI_STDIN
    // This is a minimal FastCGI implementation following the spec

    auto write_fcgi = [&](uint8_t type, uint16_t reqId, const std::string& content) {
        uint8_t header[8];
        header[0] = 1; // version
        header[1] = type;
        header[2] = (reqId >> 8) & 0xFF;
        header[3] = reqId & 0xFF;
        header[4] = (content.size() >> 8) & 0xFF;
        header[5] = content.size() & 0xFF;
        header[6] = 0; // padding
        header[7] = 0; // reserved
        ::write(sock, header, 8);
        if (!content.empty())
            ::write(sock, content.data(), content.size());
    };

    auto encode_param = [](const std::string& name, const std::string& value) -> std::string {
        std::string out;
        auto encode_len = [&](size_t len) {
            if (len < 128) {
                out += (char)len;
            } else {
                out += (char)(((len >> 24) & 0x7F) | 0x80);
                out += (char)((len >> 16) & 0xFF);
                out += (char)((len >> 8) & 0xFF);
                out += (char)(len & 0xFF);
            }
        };
        encode_len(name.size());
        encode_len(value.size());
        out += name;
        out += value;
        return out;
    };

    // FCGI_BEGIN_REQUEST (type 1)
    std::string begin_body(8, '\0');
    begin_body[0] = 0; begin_body[1] = 1; // FCGI_RESPONDER role
    write_fcgi(1, 1, begin_body);

    // Build params
    std::string params;
    params += encode_param("SCRIPT_FILENAME", script_path);
    params += encode_param("SCRIPT_NAME", req.path);
    params += encode_param("REQUEST_METHOD", req.method);
    params += encode_param("QUERY_STRING", req.query);
    params += encode_param("REQUEST_URI", req.path + (req.query.empty() ? "" : "?" + req.query));
    params += encode_param("SERVER_PROTOCOL", "HTTP/1.1");
    params += encode_param("REMOTE_ADDR", req.remote_addr);
    params += encode_param("SERVER_NAME", "localhost");
    params += encode_param("SERVER_PORT", std::to_string(port_));
    params += encode_param("DOCUMENT_ROOT", web_root_);

    // Pass original headers as HTTP_* env vars
    for (const auto& [k, v] : req.headers) {
        std::string env_key = "HTTP_" + k;
        for (auto& c : env_key) {
            c = std::toupper(c);
            if (c == '-') c = '_';
        }
        params += encode_param(env_key, v);
    }

    if (!req.body.empty()) {
        params += encode_param("CONTENT_LENGTH", std::to_string(req.body.size()));
        auto ct = req.headers.find("content-type");
        if (ct != req.headers.end())
            params += encode_param("CONTENT_TYPE", ct->second);
    }

    // Inject auth headers for PHP
    params += encode_param("HTTP_X_BACKDRAFT_AUTHENTICATED", auth_result.authenticated ? "1" : "0");
    params += encode_param("HTTP_X_BACKDRAFT_USER", auth_result.username);
    params += encode_param("HTTP_X_BACKDRAFT_ROLE", auth_result.role);

    // FCGI_PARAMS (type 4)
    write_fcgi(4, 1, params);
    write_fcgi(4, 1, ""); // empty params = end

    // FCGI_STDIN (type 5)
    if (!req.body.empty())
        write_fcgi(5, 1, req.body);
    write_fcgi(5, 1, ""); // empty stdin = end

    // Read FCGI response
    std::string fcgi_out;
    char rbuf[8192];
    while (true) {
        uint8_t hdr[8];
        int r = ::read(sock, hdr, 8);
        if (r < 8) break;

        uint16_t clen = (hdr[4] << 8) | hdr[5];
        uint8_t  plen = hdr[6];
        uint8_t  type = hdr[1];

        std::string content(clen, '\0');
        size_t got = 0;
        while (got < clen) {
            r = ::read(sock, &content[got], clen - got);
            if (r <= 0) break;
            got += r;
        }

        // Skip padding
        if (plen > 0) {
            char pad[256];
            ::read(sock, pad, plen);
        }

        if (type == 6) { // FCGI_STDOUT
            fcgi_out += content;
        } else if (type == 7) { // FCGI_STDERR
            LOG_ERROR("PHP-FPM stderr: " + content);
        } else if (type == 3) { // FCGI_END_REQUEST
            break;
        }
    }
    close(sock);

    // Parse PHP response (headers + body separated by \r\n\r\n or \n\n)
    std::string http_response;
    auto sep = fcgi_out.find("\r\n\r\n");
    if (sep == std::string::npos) sep = fcgi_out.find("\n\n");

    if (sep != std::string::npos) {
        std::string php_headers = fcgi_out.substr(0, sep);
        std::string php_body = fcgi_out.substr(sep + (fcgi_out[sep+1] == '\n' ? 2 : 4));

        // Extract status from PHP headers
        int status = 200;
        std::string ct = "text/html; charset=utf-8";
        std::istringstream hss(php_headers);
        std::string hline;
        std::string extra_headers;
        while (std::getline(hss, hline)) {
            if (!hline.empty() && hline.back() == '\r') hline.pop_back();
            if (hline.find("Status:") == 0) {
                status = std::stoi(hline.substr(8));
            } else if (hline.find("Content-Type:") == 0 || hline.find("Content-type:") == 0) {
                ct = hline.substr(hline.find(':') + 2);
            } else if (!hline.empty()) {
                extra_headers += hline + "\r\n";
            }
        }

        http_response = "HTTP/1.1 " + std::to_string(status) + " OK\r\n";
        http_response += "Content-Type: " + ct + "\r\n";
        http_response += "Content-Length: " + std::to_string(php_body.size()) + "\r\n";
        http_response += extra_headers;
        http_response += "Connection: close\r\n\r\n";
        http_response += php_body;
    } else {
        http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                        "Content-Length: " + std::to_string(fcgi_out.size()) + "\r\n"
                        "Connection: close\r\n\r\n" + fcgi_out;
    }

    send_data(fd, ssl, http_response);
    LOG_ACCESS(req.remote_addr, req.method, req.path, 200, fcgi_out.size(),
               req.headers.count("user-agent") ? req.headers.at("user-agent") : "");
    return true;
}

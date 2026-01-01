#ifndef BACKDRAFT_HTTP_SERVER_H
#define BACKDRAFT_HTTP_SERVER_H

#include <string>
#include <map>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>
#include <openssl/ssl.h>

class ThreadPool;

struct HttpRequest {
    std::string method;
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query_params;
    std::string body;
    std::string remote_addr;
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "application/json";
    std::map<std::string, std::string> headers;
    std::string body;

    static HttpResponse ok(const std::string& json_body);
    static HttpResponse html(const std::string& html_body);
    static HttpResponse bad_req(const std::string& msg);
    static HttpResponse unauth();
    static HttpResponse forbidden(const std::string& msg = "Forbidden");
    static HttpResponse not_found(const std::string& msg = "Not found");
    static HttpResponse internal_error(const std::string& msg = "Internal error");
};

using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;
using StreamHandler = std::function<void(const HttpRequest&, int fd, SSL* ssl)>;

class HttpServer {
public:
    HttpServer(const std::string& bind_addr, int port, bool use_tls,
               const std::string& cert_path, const std::string& key_path,
               const std::string& web_root, const std::string& fcgi_socket);
    ~HttpServer();

    void start();
    void stop();

    void route(const std::string& method, const std::string& path, RouteHandler handler);
    void stream_route(const std::string& method, const std::string& path, StreamHandler handler);

private:
    void accept_loop();
    void handle_client(int client_fd, const std::string& remote_ip);
    HttpRequest parse_request(const std::string& raw);
    void parse_query_params(HttpRequest& req);
    std::string build_response(const HttpResponse& resp);
    bool serve_static(const HttpRequest& req, int fd, SSL* ssl);
    bool serve_php(const HttpRequest& req, int fd, SSL* ssl);
    void send_data(int fd, SSL* ssl, const std::string& data);
    void send_data(int fd, SSL* ssl, const char* buf, size_t len);
    std::string read_request(int fd, SSL* ssl);
    std::string content_type_for(const std::string& path);

    std::string bind_addr_;
    int port_;
    bool use_tls_;
    std::string cert_path_;
    std::string key_path_;
    std::string web_root_;
    std::string fcgi_socket_;

    int listen_fd_ = -1;
    SSL_CTX* ssl_ctx_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::unique_ptr<ThreadPool> pool_;

    struct Route {
        std::string method;
        std::string path;
        RouteHandler handler;
        StreamHandler stream_handler;
        bool is_stream = false;
    };
    std::vector<Route> routes_;
};

#endif

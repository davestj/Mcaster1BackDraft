#ifndef BACKDRAFT_ROUTER_H
#define BACKDRAFT_ROUTER_H

class HttpServer;

namespace Router {
    void register_routes(HttpServer& web_server, HttpServer& api_server);
}

#endif

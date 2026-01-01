#include "waf_handler.h"
#include "botproof.h"
#include "captcha_generator.h"
#include "config.h"
#include "dbpool.h"
#include "logger.h"

// URL decode %XX sequences
static std::string url_decode(const std::string& src) {
    std::string out;
    out.reserve(src.size());
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int hi = 0, lo = 0;
            char c1 = src[i+1], c2 = src[i+2];
            if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
            else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
            else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
            else { out += src[i]; continue; }
            if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
            else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
            else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
            else { out += src[i]; continue; }
            out += (char)((hi << 4) | lo);
            i += 2;
        } else if (src[i] == '+') {
            out += ' ';
        } else {
            out += src[i];
        }
    }
    return out;
}

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <chrono>

WafHandler& WafHandler::instance() {
    static WafHandler inst;
    return inst;
}

void WafHandler::init() {
    reload_rules();
    running_ = true;
    reload_thread_ = std::thread(&WafHandler::reload_loop, this);
    LOG_INFO("WAF handler initialized — mode=" + CFG.waf.mode +
             " threshold=" + std::to_string(CFG.waf.threat_threshold));
}

void WafHandler::stop() {
    running_ = false;
    if (reload_thread_.joinable()) reload_thread_.join();
}

void WafHandler::reload_loop() {
    while (running_) {
        for (int i = 0; i < CFG.waf.rule_reload_secs && running_; ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (running_) reload_rules();
    }
}

void WafHandler::reload_rules() {
    auto conn = DB("backdraft");
    if (!conn) return;

    MYSQL_RES* res = conn->query(
        "SELECT id, name, target, field, `operator`, value, action, score "
        "FROM backdraft_rules WHERE active = 1 ORDER BY sort_order, id");
    if (!res) return;

    std::vector<WafRule> new_rules;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        WafRule r;
        r.id     = row[0] ? std::stoi(row[0]) : 0;
        r.name   = row[1] ? row[1] : "";
        r.target = row[2] ? row[2] : "";
        r.field  = row[3] ? row[3] : "";
        r.op     = row[4] ? row[4] : "";
        r.value  = row[5] ? row[5] : "";
        r.action = row[6] ? row[6] : "log";
        r.score  = row[7] ? std::stoi(row[7]) : 0;

        if (r.op == "regex") {
            try {
                // Strip (?i) prefix — std::regex uses icase flag instead
                std::string pattern = r.value;
                if (pattern.find("(?i)") == 0) pattern = pattern.substr(4);
                r.compiled = std::regex(pattern, std::regex::icase | std::regex::optimize);
                r.has_regex = true;
            } catch (const std::regex_error& e) {
                LOG_ERROR("WAF rule " + r.name + " regex error: " + e.what() + " pattern: " + r.value);
                continue;
            }
        }
        new_rules.push_back(std::move(r));
    }
    mysql_free_result(res);

    std::lock_guard<std::mutex> lock(rules_mtx_);
    rules_ = std::move(new_rules);
    rules_loaded = rules_.size();
    LOG_DEBUG("WAF rules reloaded: " + std::to_string(rules_.size()) + " active");
}

WafInspectResult WafHandler::inspect(const HttpRequest& req) {
    WafInspectResult result;

    if (CFG.waf.mode == "disabled") return result;

    std::lock_guard<std::mutex> lock(rules_mtx_);

    for (const auto& r : rules_) {
        std::string test_value;

        if (r.target == "method")     test_value = req.method;
        else if (r.target == "path")  test_value = url_decode(req.path);
        else if (r.target == "query") test_value = url_decode(req.query);
        else if (r.target == "body")  test_value = req.body.substr(0, CFG.waf.max_body_inspect);
        else if (r.target == "agent") {
            auto it = req.headers.find("user-agent");
            test_value = (it != req.headers.end()) ? it->second : "";
        } else if (r.target == "ip") {
            test_value = req.remote_addr;
        } else if (r.target == "header") {
            std::string key = r.field;
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            auto it = req.headers.find(key);
            test_value = (it != req.headers.end()) ? it->second : "";
        } else if (r.target == "cookie") {
            auto it = req.headers.find("cookie");
            test_value = (it != req.headers.end()) ? it->second : "";
        }

        bool matched = false;
        std::string tv_lower = test_value;
        std::string rv_lower = r.value;
        std::transform(tv_lower.begin(), tv_lower.end(), tv_lower.begin(), ::tolower);
        std::transform(rv_lower.begin(), rv_lower.end(), rv_lower.begin(), ::tolower);

        if (r.op == "contains")          matched = tv_lower.find(rv_lower) != std::string::npos;
        else if (r.op == "not_contains") matched = tv_lower.find(rv_lower) == std::string::npos;
        else if (r.op == "equals")       matched = tv_lower == rv_lower;
        else if (r.op == "not_equals")   matched = tv_lower != rv_lower;
        else if (r.op == "starts_with")  matched = tv_lower.find(rv_lower) == 0;
        else if (r.op == "ends_with")    matched = tv_lower.size() >= rv_lower.size() &&
                                                   tv_lower.compare(tv_lower.size()-rv_lower.size(), rv_lower.size(), rv_lower) == 0;
        else if (r.op == "regex" && r.has_regex) {
            try { matched = std::regex_search(test_value, r.compiled); } catch (...) {}
        }

        if (matched) {
            result.total_score += r.score;
            result.matched_rules.push_back(r.id);

            // Highest severity action wins
            auto pri = [](const std::string& a) -> int {
                if (a == "pass") return 0; if (a == "log") return 1;
                if (a == "flag") return 2; if (a == "challenge") return 3;
                if (a == "block") return 4;
                return 0;
            };
            if (pri(r.action) > pri(result.action)) result.action = r.action;
        }
    }

    // In learning mode, never block
    if (CFG.waf.mode == "learning" && (result.action == "block" || result.action == "challenge"))
        result.action = "flag";

    // Score-based action
    if (result.total_score > 0 && result.action == "pass")
        result.action = "log";

    return result;
}

void WafHandler::log_request(const HttpRequest& req, const WafInspectResult& result,
                              int upstream_status, size_t response_bytes, int duration_ms) {
    auto conn = DB("backdraft");
    if (!conn) return;

    std::string page_id;
    auto pit = req.headers.find("x-backdraft-page");
    if (pit != req.headers.end()) page_id = pit->second;

    auto esc = [](const std::string& s) {
        std::string r; r.reserve(s.size());
        for (char c : s) { if (c == '\'') r += "''"; else if (c == '\\') r += "\\\\"; else r += c; }
        return r;
    };

    std::string matched_str;
    for (size_t i = 0; i < result.matched_rules.size(); ++i) {
        if (i > 0) matched_str += ",";
        matched_str += std::to_string(result.matched_rules[i]);
    }

    std::string ua;
    auto ua_it = req.headers.find("user-agent");
    if (ua_it != req.headers.end()) ua = ua_it->second.substr(0, 1024);

    std::string referer;
    auto ref_it = req.headers.find("referer");
    if (ref_it != req.headers.end()) referer = ref_it->second.substr(0, 1024);

    std::string host;
    auto host_it = req.headers.find("host");
    if (host_it != req.headers.end()) host = host_it->second;

    std::string sql = "INSERT INTO backdraft_requests "
        "(client_ip, method, host, path, query_string, user_agent, referer, "
        "page_id, threat_score, action_taken, matched_rules, upstream_status, upstream_ms, response_bytes) "
        "VALUES ('" + esc(req.remote_addr) + "','" + esc(req.method) + "','" + esc(host) + "',"
        "'" + esc(req.path) + "','" + esc(req.query.substr(0, 4096)) + "',"
        "'" + esc(ua) + "','" + esc(referer) + "',"
        "'" + esc(page_id) + "'," + std::to_string(result.total_score) + ","
        "'" + result.action + "','" + matched_str + "',"
        + std::to_string(upstream_status) + "," + std::to_string(duration_ms) + ","
        + std::to_string(response_bytes) + ")";

    conn->execute(sql);

    // If threat score is elevated, log to threats table
    if (result.total_score >= CFG.waf.threat_threshold) {
        std::string severity = "low";
        if (result.total_score >= 90) severity = "critical";
        else if (result.total_score >= 75) severity = "high";
        else if (result.total_score >= 50) severity = "medium";

        conn->execute("INSERT INTO backdraft_threats "
            "(request_id, client_ip, threat_score, matched_rules, category, severity, action_taken) "
            "VALUES (LAST_INSERT_ID(), '" + esc(req.remote_addr) + "', "
            + std::to_string(result.total_score) + ", '" + matched_str + "', "
            "'custom', '" + severity + "', '" + result.action + "')");
    }

    // Update page profile (learning-mode baseline)
    if (!page_id.empty()) {
        std::string ct;
        auto ct_it = req.headers.find("content-type");
        if (ct_it != req.headers.end()) ct = ct_it->second;
        int is_threat = (result.total_score >= CFG.waf.threat_threshold) ? 1 : 0;

        // Resolve site_id from host header
        std::string host_val;
        auto h_it = req.headers.find("host");
        if (h_it != req.headers.end()) {
            host_val = h_it->second;
            auto cp = host_val.find(':');
            if (cp != std::string::npos) host_val = host_val.substr(0, cp);
        }
        int site_id = 0;
        {
            MYSQL_RES* sr = conn->query(
                "SELECT id FROM backdraft_sites WHERE site_name='" + esc(host_val) + "' LIMIT 1");
            if (sr) {
                MYSQL_ROW srow = mysql_fetch_row(sr);
                if (srow && srow[0]) site_id = std::stoi(srow[0]);
                mysql_free_result(sr);
            }
        }

        conn->execute(
            "INSERT INTO backdraft_page_profiles "
            "(site_id, page_id, display_name, total_requests, total_threats, avg_score, "
            " last_request_at, learned_methods, learned_content_types, learned_avg_size, monitoring) "
            "VALUES (" + std::to_string(site_id) + ", "
            "'" + esc(page_id) + "', '" + esc(page_id) + "', "
            "1, " + std::to_string(is_threat) + ", " + std::to_string(result.total_score) + ", "
            "NOW(), '" + esc(req.method) + "', '" + esc(ct) + "', "
            + std::to_string(response_bytes) + ", 1) "
            "ON DUPLICATE KEY UPDATE "
            "total_requests = total_requests + 1, "
            "total_threats = total_threats + " + std::to_string(is_threat) + ", "
            "avg_score = (avg_score * (total_requests - 1) + " + std::to_string(result.total_score) + ") / total_requests, "
            "last_request_at = NOW(), "
            "learned_methods = IF(FIND_IN_SET('" + esc(req.method) + "', learned_methods), "
            "  learned_methods, CONCAT_WS(',', learned_methods, '" + esc(req.method) + "')), "
            "learned_content_types = IF('" + esc(ct) + "' = '' OR FIND_IN_SET('" + esc(ct) + "', learned_content_types), "
            "  learned_content_types, CONCAT_WS(',', learned_content_types, '" + esc(ct) + "')), "
            "learned_avg_size = (learned_avg_size * (total_requests - 1) + " + std::to_string(response_bytes) + ") / total_requests"
        );
    }
}

std::string WafHandler::forward_to_fcgi(const HttpRequest& req, const std::string& script_path,
                                         const std::string& doc_root) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG_ERROR("WAF FCGI socket create failed");
        return "";
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CFG.waf.upstream_fcgi.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("WAF FCGI connect failed: " + std::string(strerror(errno)) +
                  " socket=" + CFG.waf.upstream_fcgi);
        close(sock);
        return "";
    }

    // Build FastCGI request
    auto write_fcgi = [&](uint8_t type, uint16_t reqId, const std::string& content) {
        uint8_t header[8];
        header[0] = 1; // version
        header[1] = type;
        header[2] = (reqId >> 8) & 0xFF;
        header[3] = reqId & 0xFF;
        header[4] = (content.size() >> 8) & 0xFF;
        header[5] = content.size() & 0xFF;
        header[6] = 0; header[7] = 0;
        ::write(sock, header, 8);
        if (!content.empty()) ::write(sock, content.data(), content.size());
    };

    auto encode_param = [](const std::string& name, const std::string& value) -> std::string {
        std::string out;
        auto encode_len = [&](size_t len) {
            if (len < 128) { out += (char)len; }
            else {
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

    // FCGI_BEGIN_REQUEST
    std::string begin_body(8, '\0');
    begin_body[0] = 0; begin_body[1] = 1; // FCGI_RESPONDER
    write_fcgi(1, 1, begin_body);

    // FCGI_PARAMS
    std::string params;
    params += encode_param("SCRIPT_FILENAME", script_path);
    params += encode_param("SCRIPT_NAME", req.path);
    params += encode_param("REQUEST_METHOD", req.method);
    params += encode_param("QUERY_STRING", req.query);
    params += encode_param("REQUEST_URI", req.path + (req.query.empty() ? "" : "?" + req.query));
    params += encode_param("SERVER_PROTOCOL", "HTTP/1.1");
    params += encode_param("REMOTE_ADDR", req.remote_addr);
    params += encode_param("SERVER_NAME", "localhost");
    params += encode_param("DOCUMENT_ROOT", doc_root);

    // Pass original headers
    for (const auto& [k, v] : req.headers) {
        if (k == "x-backdraft-upstream" || k == "x-backdraft-page" || k == "x-backdraft-bypass") continue;
        std::string env_key = "HTTP_" + k;
        for (auto& c : env_key) { c = std::toupper(c); if (c == '-') c = '_'; }
        params += encode_param(env_key, v);
    }

    if (!req.body.empty()) {
        params += encode_param("CONTENT_LENGTH", std::to_string(req.body.size()));
        auto ct = req.headers.find("content-type");
        if (ct != req.headers.end()) params += encode_param("CONTENT_TYPE", ct->second);
    }

    write_fcgi(4, 1, params);
    write_fcgi(4, 1, "");

    // FCGI_STDIN
    if (!req.body.empty()) write_fcgi(5, 1, req.body);
    write_fcgi(5, 1, "");

    // Read FCGI response
    std::string fcgi_out;
    while (true) {
        uint8_t hdr[8];
        int r = ::read(sock, hdr, 8);
        if (r < 8) break;

        uint16_t clen = (hdr[4] << 8) | hdr[5];
        uint8_t plen = hdr[6];
        uint8_t type = hdr[1];

        std::string content(clen, '\0');
        size_t got = 0;
        while (got < clen) {
            r = ::read(sock, &content[got], clen - got);
            if (r <= 0) break;
            got += r;
        }

        if (plen > 0) { char pad[256]; ::read(sock, pad, plen); }

        if (type == 6) fcgi_out += content;      // FCGI_STDOUT
        else if (type == 7) LOG_ERROR("WAF FCGI stderr: " + content);
        else if (type == 3) break;               // FCGI_END_REQUEST
    }
    close(sock);

    return fcgi_out;
}

// Parse application/x-www-form-urlencoded POST body
static std::map<std::string, std::string> parse_form_body(const std::string& body) {
    std::map<std::string, std::string> params;
    std::istringstream iss(body);
    std::string pair;
    while (std::getline(iss, pair, '&')) {
        auto eq = pair.find('=');
        if (eq == std::string::npos) continue;
        std::string key = pair.substr(0, eq);
        std::string val = url_decode(pair.substr(eq + 1));
        params[key] = val;
    }
    return params;
}

HttpResponse WafHandler::handle_request(const HttpRequest& req) {
    auto start = std::chrono::steady_clock::now();

    // Get real client IP from nginx headers
    HttpRequest waf_req = req;
    auto real_ip = req.headers.find("x-real-ip");
    if (real_ip != req.headers.end()) waf_req.remote_addr = real_ip->second;

    // Get BackDraft headers
    std::string page_id;
    auto pit = req.headers.find("x-backdraft-page");
    if (pit != req.headers.end()) page_id = pit->second;

    // ── BotProof/SecureLock: intercept form POSTs via _bd_action field ──
    // Forms POST back to the same WAF-proxied URL with _bd_action hidden field
    if (waf_req.method == "POST" && waf_req.body.find("_bd_action=") != std::string::npos) {
        auto form = parse_form_body(waf_req.body);
        std::string bd_action = form["_bd_action"];

        // ── BotProof CAPTCHA verify ──────────────────────────────────
        if (bd_action == "botproof_verify") {
            std::string token  = form["token"];
            std::string answer = form["answer"];

            auto vr = Botproof::verify(token, answer, waf_req.remote_addr);

            if (vr.correct) {
                auto bp_cfg = Botproof::get_config(page_id);
                int sess_mins = bp_cfg.session_mins > 0 ? bp_cfg.session_mins : 60;
                std::string sess_token = Botproof::create_session(
                    waf_req.remote_addr, vr.site_id, sess_mins);

                HttpResponse resp;
                resp.status = 302;
                resp.content_type = "text/html";
                resp.body = "<html><body>Verified. Redirecting...</body></html>";
                resp.headers["Location"] = vr.original_url.empty() ? waf_req.path : vr.original_url;
                resp.headers["Set-Cookie"] = "bd_botproof=" + sess_token +
                    "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
                    std::to_string(sess_mins * 60);

                captcha_passed++;
                total_requests++;
                return resp;
            }

            if (vr.expired) {
                auto bp_cfg = Botproof::get_config(page_id);
                std::string orig_url = waf_req.path;
                if (!waf_req.query.empty()) orig_url += "?" + waf_req.query;
                auto ch = Botproof::generate_challenge(
                    waf_req.remote_addr, page_id, orig_url,
                    bp_cfg.max_attempts > 0 ? bp_cfg.max_attempts : 3,
                    CFG.waf.botproof_challenge_ttl_secs,
                    CFG.waf.botproof_font);
                total_challenged++;
                total_requests++;
                return HttpResponse::html(ch.html);
            }

            if (vr.max_attempts) {
                captcha_failed++;
                total_requests++;
                HttpResponse resp = HttpResponse::html(
                    "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
                    "<title>Access Denied</title></head>"
                    "<body style='background:#0a0e1a;color:#ef4444;font-family:sans-serif;"
                    "display:flex;align-items:center;justify-content:center;height:100vh'>"
                    "<div style='text-align:center'>"
                    "<h1>Access Denied</h1>"
                    "<p style='color:#94a3b8'>Too many failed attempts. Please wait 10 minutes.</p>"
                    "</div></body></html>");
                resp.status = 403;
                return resp;
            }

            // Wrong answer — new challenge with error
            captcha_failed++;
            std::string orig_url = vr.original_url.empty() ? waf_req.path : vr.original_url;
            auto ch = Botproof::generate_challenge(
                waf_req.remote_addr, page_id, orig_url,
                vr.attempts_left,
                CFG.waf.botproof_challenge_ttl_secs,
                CFG.waf.botproof_font);
            total_requests++;
            return HttpResponse::html(ch.html);
        }

        // ── Turnstile verify (PoW + fingerprint) ─────────────────────
        if (bd_action == "turnstile_verify") {
            std::string token = form["token"];
            std::string nonce = form["nonce"];
            std::string fp    = form["fp"];

            auto tr = Botproof::verify_turnstile(token, nonce, fp, waf_req.remote_addr);

            if (tr.passed) {
                // Turnstile passed — create session
                auto bp_cfg = Botproof::get_config(page_id);
                int sess_mins = bp_cfg.session_mins > 0 ? bp_cfg.session_mins : 60;
                std::string sess_token = Botproof::create_session(
                    waf_req.remote_addr, tr.site_id, sess_mins);

                HttpResponse resp;
                resp.status = 302;
                resp.content_type = "text/html";
                resp.body = "<html><body>Verified. Redirecting...</body></html>";
                resp.headers["Location"] = tr.original_url.empty() ? waf_req.path : tr.original_url;
                resp.headers["Set-Cookie"] = "bd_botproof=" + sess_token +
                    "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
                    std::to_string(sess_mins * 60);

                captcha_passed++;
                total_requests++;
                LOG_INFO("BotProof: turnstile PASSED score=" + std::to_string(tr.score) +
                         " for " + waf_req.remote_addr);
                return resp;
            }

            if (tr.fallback_captcha) {
                // Turnstile failed — fall back to visual CAPTCHA
                captcha_failed++;
                auto bp_cfg = Botproof::get_config(page_id);
                std::string orig_url = tr.original_url.empty() ? waf_req.path : tr.original_url;
                auto ch = Botproof::generate_challenge(
                    waf_req.remote_addr, page_id, orig_url,
                    bp_cfg.max_attempts > 0 ? bp_cfg.max_attempts : 3,
                    CFG.waf.botproof_challenge_ttl_secs,
                    CFG.waf.botproof_font);
                total_requests++;
                LOG_INFO("BotProof: turnstile FAILED score=" + std::to_string(tr.score) +
                         " for " + waf_req.remote_addr + " — falling back to CAPTCHA");
                return HttpResponse::html(ch.html);
            }
        }

        // ── Secure Lock: send OTP ────────────────────────────────────
        if (bd_action == "secure_send_otp") {
            std::string email       = form["email"];
            std::string sl_page_id  = form["page_id"];
            std::string orig_url    = form["original_url"];

            auto bp_cfg = Botproof::get_config(sl_page_id.empty() ? page_id : sl_page_id);
            auto otp_result = Botproof::send_otp(email, waf_req.remote_addr,
                sl_page_id.empty() ? page_id : sl_page_id, orig_url,
                10, bp_cfg.allowed_emails);

            total_requests++;
            return HttpResponse::html(otp_result.html);
        }

        // ── Secure Lock: verify OTP ──────────────────────────────────
        if (bd_action == "secure_verify_otp") {
            std::string token = form["token"];
            std::string code  = form["code"];

            auto vr = Botproof::verify_otp(token, code, waf_req.remote_addr);

            if (vr.correct) {
                auto bp_cfg = Botproof::get_config(page_id);
                int sess_mins = bp_cfg.secure_session_mins > 0 ? bp_cfg.secure_session_mins : 60;
                std::string sess_token = Botproof::create_secure_session(
                    waf_req.remote_addr, vr.site_id, sess_mins);

                HttpResponse resp;
                resp.status = 302;
                resp.content_type = "text/html";
                resp.body = "<html><body>Verified. Redirecting...</body></html>";
                resp.headers["Location"] = vr.original_url.empty() ? waf_req.path : vr.original_url;
                resp.headers["Set-Cookie"] = "bd_secure=" + sess_token +
                    "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" +
                    std::to_string(sess_mins * 60);
                total_requests++;
                return resp;
            }

            if (vr.expired) {
                total_requests++;
                return HttpResponse::html(
                    Botproof::email_form_html(page_id, waf_req.path, "Code expired — please request a new one"));
            }

            if (vr.max_attempts) {
                total_requests++;
                HttpResponse resp = HttpResponse::html(
                    "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
                    "<title>Access Denied</title></head>"
                    "<body style='background:#0a0e1a;color:#ef4444;font-family:sans-serif;"
                    "display:flex;align-items:center;justify-content:center;height:100vh'>"
                    "<div style='text-align:center'>"
                    "<h1>Access Denied</h1>"
                    "<p style='color:#94a3b8'>Too many failed OTP attempts.</p>"
                    "</div></body></html>");
                resp.status = 403;
                return resp;
            }

            total_requests++;
            return HttpResponse::html(
                Botproof::email_form_html(page_id, vr.original_url.empty() ? waf_req.path : vr.original_url,
                    "Incorrect code. " + std::to_string(vr.attempts_left) + " attempt(s) remaining."));
        }
    }

    // ── Inspect request ──────────────────────────────────────────────
    WafInspectResult result = inspect(waf_req);

    // ── BotProof + Secure Lock: challenge gate ───────────────────────
    // Always check if page has BotProof/SecureLock enabled — threshold=0 means challenge everyone
    if (!page_id.empty()) {
        auto bp_cfg = Botproof::get_config(page_id);

        // Get cookies
        std::string cookie_header;
        auto cookie_it = waf_req.headers.find("cookie");
        if (cookie_it != waf_req.headers.end()) cookie_header = cookie_it->second;

        // Tier 3: Secure Lock check (if enabled) — must have valid secure session
        if (bp_cfg.secure_lock) {
            if (!Botproof::has_secure_session(waf_req.remote_addr, cookie_header)) {
                // Check if they've passed BotProof first
                if (bp_cfg.enabled && !Botproof::has_valid_session(waf_req.remote_addr, cookie_header)) {
                    // Serve turnstile (invisible PoW + fingerprint) — falls back to CAPTCHA on failure
                    std::string orig_url = waf_req.path;
                    if (!waf_req.query.empty()) orig_url += "?" + waf_req.query;

                    auto ch = Botproof::generate_turnstile(
                        waf_req.remote_addr, page_id, orig_url,
                        CFG.waf.botproof_challenge_ttl_secs, 18);

                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();
                    log_request(waf_req, result, 200, ch.html.size(), elapsed);
                    total_requests++; total_challenged++; requests_1m++;
                    latency_sum_1m += (uint64_t)elapsed;
                    return HttpResponse::html(ch.html);
                }

                // CAPTCHA passed (or not required) — show email OTP form
                std::string orig_url = waf_req.path;
                if (!waf_req.query.empty()) orig_url += "?" + waf_req.query;
                total_requests++;
                return HttpResponse::html(
                    Botproof::email_form_html(page_id, orig_url));
            }
            // Secure session valid — fall through
        }
        // Tier 2: BotProof only (no secure lock)
        else if (bp_cfg.enabled && result.total_score >= bp_cfg.threshold) {
            if (!Botproof::has_valid_session(waf_req.remote_addr, cookie_header)) {
                std::string orig_url = waf_req.path;
                if (!waf_req.query.empty()) orig_url += "?" + waf_req.query;

                // Serve turnstile (invisible) — falls back to visual CAPTCHA on failure
                auto ch = Botproof::generate_turnstile(
                    waf_req.remote_addr, page_id, orig_url,
                    CFG.waf.botproof_challenge_ttl_secs, 18);

                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                log_request(waf_req, result, 200, ch.html.size(), elapsed);
                total_requests++; total_challenged++; requests_1m++;
                latency_sum_1m += (uint64_t)elapsed;
                return HttpResponse::html(ch.html);
            }
        }
    }

    // Block if active mode and score exceeds threshold
    if (CFG.waf.mode == "active" && result.action == "block") {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        log_request(waf_req, result, 403, 0, elapsed);

        total_requests++;
        requests_1m++;
        latency_sum_1m += (uint64_t)elapsed;
        total_threats++;
        total_blocked++;

        return HttpResponse::html(
            "<html><body style='background:#0a0e1a;color:#ef4444;font-family:sans-serif;display:flex;"
            "align-items:center;justify-content:center;height:100vh;margin:0'>"
            "<div style='text-align:center'><h1>403 Blocked</h1>"
            "<p style='color:#94a3b8'>Request blocked by Mcaster1BackDraft WAF</p></div></body></html>");
    }

    // Forward to upstream PHP-FPM
    // Determine script path and doc_root from the page_id or request path
    std::string doc_root;
    std::string script_path;

    // Look up the site's doc_root from DB based on the Host header
    auto host_it = req.headers.find("host");
    std::string hostname = (host_it != req.headers.end()) ? host_it->second : "";
    // Strip port if present
    auto colon = hostname.find(':');
    if (colon != std::string::npos) hostname = hostname.substr(0, colon);

    auto conn = DB("backdraft");
    if (conn) {
        auto esc = [](const std::string& s) {
            std::string r; for (char c : s) { if (c == '\'') r += "''"; else r += c; } return r;
        };
        MYSQL_RES* res = conn->query("SELECT doc_root FROM backdraft_sites WHERE site_name = '" + esc(hostname) + "' LIMIT 1");
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) doc_root = row[0];
            mysql_free_result(res);
        }
    }

    if (doc_root.empty()) {
        // Fallback — can't determine doc_root
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        log_request(waf_req, result, 502, 0, elapsed);
        return HttpResponse::internal_error("WAF cannot determine document root for " + hostname);
    }

    script_path = doc_root + req.path;

    // Forward to PHP-FPM
    std::string fcgi_response = forward_to_fcgi(waf_req, script_path, doc_root);

    if (fcgi_response.empty()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        log_request(waf_req, result, 502, 0, elapsed);
        return HttpResponse::internal_error("WAF upstream (PHP-FPM) unavailable");
    }

    // Parse PHP-FPM response (headers + body split on \r\n\r\n)
    int status = 200;
    std::string content_type = "text/html; charset=utf-8";
    std::string body;
    std::string extra_headers;

    auto sep = fcgi_response.find("\r\n\r\n");
    if (sep == std::string::npos) sep = fcgi_response.find("\n\n");

    if (sep != std::string::npos) {
        std::string hdrs = fcgi_response.substr(0, sep);
        body = fcgi_response.substr(sep + (fcgi_response[sep+1] == '\n' ? 2 : 4));

        std::istringstream hss(hdrs);
        std::string hline;
        while (std::getline(hss, hline)) {
            if (!hline.empty() && hline.back() == '\r') hline.pop_back();
            if (hline.find("Status:") == 0) status = std::stoi(hline.substr(8));
            else if (hline.find("Content-Type:") == 0 || hline.find("Content-type:") == 0)
                content_type = hline.substr(hline.find(':') + 2);
            else if (!hline.empty()) extra_headers += hline + "\r\n";
        }
    } else {
        body = fcgi_response;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    // Log the request
    if (CFG.waf.log_all_requests || result.total_score > 0) {
        log_request(waf_req, result, status, body.size(), elapsed);
    }

    LOG_ACCESS(waf_req.remote_addr, waf_req.method, waf_req.path, status, body.size(),
               waf_req.headers.count("user-agent") ? waf_req.headers.at("user-agent") : "");

    // Update performance counters
    total_requests++;
    requests_1m++;
    latency_sum_1m += (uint64_t)elapsed;
    if (result.total_score >= CFG.waf.threat_threshold) total_threats++;
    if (result.action == "block") total_blocked++;

    HttpResponse resp;
    resp.status = status;
    resp.content_type = content_type;
    resp.body = body;
    return resp;
}

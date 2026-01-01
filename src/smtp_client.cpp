#include "smtp_client.h"
#include "config.h"
#include "logger.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <chrono>

// ── Base64 encode (for AUTH LOGIN) ───────────────────────────────────────
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64encode(const std::string& s) {
    std::string out;
    const unsigned char* d = (const unsigned char*)s.c_str();
    size_t len = s.size();
    for (size_t i = 0; i < len; i += 3) {
        unsigned b = (unsigned)d[i] << 16;
        if (i + 1 < len) b |= (unsigned)d[i + 1] << 8;
        if (i + 2 < len) b |= (unsigned)d[i + 2];
        out += B64[(b >> 18) & 0x3F];
        out += B64[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? B64[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64[b & 0x3F] : '=';
    }
    return out;
}

// ── TCP connect helper ───────────────────────────────────────────────────
static int tcp_connect(const std::string& host, int port) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);

    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    // 10 second timeout
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

// ── Read SMTP response (plain) ───────────────────────────────────────────
static std::string smtp_read(int fd) {
    char buf[2048];
    std::string resp;
    while (true) {
        int n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        resp += buf;
        // SMTP multi-line: if 4th char is space, it's the last line
        if (resp.size() >= 4 && resp[resp.size() - 2] == '\n') {
            // Find the last line
            auto last_nl = resp.rfind('\n', resp.size() - 3);
            size_t last_start = (last_nl == std::string::npos) ? 0 : last_nl + 1;
            if (resp.size() - last_start >= 4 && resp[last_start + 3] == ' ') break;
        }
        if (n < (int)sizeof(buf) - 1) break;
    }
    return resp;
}

// ── Read SMTP response (TLS) ────────────────────────────────────────────
static std::string smtp_read_ssl(SSL* ssl) {
    char buf[2048];
    std::string resp;
    while (true) {
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        resp += buf;
        if (resp.size() >= 4 && resp[resp.size() - 2] == '\n') {
            auto last_nl = resp.rfind('\n', resp.size() - 3);
            size_t last_start = (last_nl == std::string::npos) ? 0 : last_nl + 1;
            if (resp.size() - last_start >= 4 && resp[last_start + 3] == ' ') break;
        }
        if (n < (int)sizeof(buf) - 1) break;
    }
    return resp;
}

static void smtp_send_ssl(SSL* ssl, const std::string& cmd) {
    SSL_write(ssl, cmd.c_str(), cmd.size());
}

static std::string smtp_cmd_ssl(SSL* ssl, const std::string& cmd) {
    smtp_send_ssl(ssl, cmd + "\r\n");
    return smtp_read_ssl(ssl);
}

namespace SmtpClient {

std::string send(const EmailMessage& msg) {
    const auto& smtp = CFG.smtp;

    // Connect
    int fd = tcp_connect(smtp.host, smtp.port);
    if (fd < 0) return "TCP connect failed to " + smtp.host + ":" + std::to_string(smtp.port);

    // Read greeting
    std::string resp = smtp_read(fd);
    if (resp.substr(0, 3) != "220") { close(fd); return "Bad greeting: " + resp; }

    // EHLO
    std::string ehlo = "EHLO backdraft.mcaster1.com\r\n";
    ::send(fd, ehlo.c_str(), ehlo.size(), 0);
    resp = smtp_read(fd);

    // STARTTLS
    std::string starttls = "STARTTLS\r\n";
    ::send(fd, starttls.c_str(), starttls.size(), 0);
    resp = smtp_read(fd);
    if (resp.substr(0, 3) != "220") { close(fd); return "STARTTLS rejected: " + resp; }

    // Upgrade to TLS
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return "SSL_CTX_new failed"; }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "SSL handshake failed";
    }

    // EHLO again over TLS
    resp = smtp_cmd_ssl(ssl, "EHLO backdraft.mcaster1.com");

    // AUTH LOGIN
    resp = smtp_cmd_ssl(ssl, "AUTH LOGIN");
    if (resp.substr(0, 3) != "334") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "AUTH LOGIN not accepted: " + resp;
    }

    resp = smtp_cmd_ssl(ssl, b64encode(smtp.username));
    if (resp.substr(0, 3) != "334") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "AUTH username rejected: " + resp;
    }

    resp = smtp_cmd_ssl(ssl, b64encode(smtp.password));
    if (resp.substr(0, 3) != "235") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "AUTH password rejected: " + resp;
    }

    // MAIL FROM
    resp = smtp_cmd_ssl(ssl, "MAIL FROM:<" + smtp.from_addr + ">");
    if (resp.substr(0, 3) != "250") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "MAIL FROM rejected: " + resp;
    }

    // RCPT TO
    resp = smtp_cmd_ssl(ssl, "RCPT TO:<" + msg.to_addr + ">");
    if (resp.substr(0, 3) != "250") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "RCPT TO rejected: " + resp;
    }

    // DATA
    resp = smtp_cmd_ssl(ssl, "DATA");
    if (resp.substr(0, 3) != "354") {
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return "DATA rejected: " + resp;
    }

    // Build RFC 2822 message
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    char date_buf[64];
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S %z", localtime(&time_t_now));

    std::string display_to = msg.to_name.empty() ? msg.to_addr : msg.to_name + " <" + msg.to_addr + ">";

    std::ostringstream email;
    email << "From: " << smtp.from_name << " <" << smtp.from_addr << ">\r\n"
          << "To: " << display_to << "\r\n"
          << "Subject: " << msg.subject << "\r\n"
          << "Date: " << date_buf << "\r\n"
          << "MIME-Version: 1.0\r\n"
          << "Content-Type: text/html; charset=utf-8\r\n"
          << "Content-Transfer-Encoding: 8bit\r\n"
          << "\r\n"
          << msg.html_body << "\r\n"
          << ".\r\n";

    std::string data = email.str();
    smtp_send_ssl(ssl, data);
    resp = smtp_read_ssl(ssl);

    bool success = (resp.substr(0, 3) == "250");

    smtp_cmd_ssl(ssl, "QUIT");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    if (!success) return "DATA send failed: " + resp;

    LOG_INFO("SMTP: email sent to " + msg.to_addr + " subject=\"" + msg.subject + "\"");
    return "";
}

std::string send_otp(const std::string& to_email, const std::string& otp_code,
                     const std::string& page_name, int expire_mins) {
    std::string html =
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"></head>"
        "<body style=\"margin:0;padding:0;background:#0a0e1a;font-family:Arial,sans-serif\">"
        "<div style=\"max-width:500px;margin:0 auto;padding:20px\">"
        "<div style=\"background:#1e293b;border:1px solid #334155;border-radius:12px;overflow:hidden\">"
        "<div style=\"background:linear-gradient(135deg,#f59e0b,#ef4444);padding:16px 24px;text-align:center\">"
        "<span style=\"font-size:18px;font-weight:900;color:#fff\">BackDraft</span>"
        "<span style=\"font-size:11px;color:rgba(255,255,255,.7);display:block\">Secure Page Access</span>"
        "</div>"
        "<div style=\"padding:32px 24px;text-align:center;color:#e2e8f0\">"
        "<p style=\"font-size:14px;margin-bottom:24px\">Your one-time access code for <strong>" + page_name + "</strong>:</p>"
        "<div style=\"background:#111827;border:2px solid #f59e0b;border-radius:12px;padding:20px;margin:0 auto;max-width:200px\">"
        "<span style=\"font-size:36px;font-weight:900;letter-spacing:8px;color:#f59e0b;font-family:monospace\">" + otp_code + "</span>"
        "</div>"
        "<p style=\"font-size:12px;color:#94a3b8;margin-top:16px\">This code expires in " + std::to_string(expire_mins) + " minutes.</p>"
        "<p style=\"font-size:11px;color:#64748b;margin-top:8px\">If you did not request this code, ignore this email.</p>"
        "</div>"
        "<div style=\"padding:12px 24px;border-top:1px solid #334155;text-align:center;font-size:10px;color:#475569\">"
        "Mcaster1 BackDraft WAF &mdash; Secure Lock"
        "</div></div></div></body></html>";

    EmailMessage msg;
    msg.to_addr = to_email;
    msg.subject = "BackDraft Access Code: " + otp_code;
    msg.html_body = html;

    return send(msg);
}

} // namespace SmtpClient

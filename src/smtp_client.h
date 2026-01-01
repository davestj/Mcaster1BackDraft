/*
 * smtp_client.h — Lightweight SMTP client with STARTTLS for OTP delivery
 *
 * Uses OpenSSL for TLS. Reads SMTP config from AppConfig.smtp.
 * Designed for transactional emails (OTP codes, alerts) — not bulk mail.
 */
#pragma once

#include <string>

namespace SmtpClient {

struct EmailMessage {
    std::string to_addr;
    std::string to_name;
    std::string subject;
    std::string html_body;
};

// Send an email using the SMTP config from Mcaster1BackDraft.yaml
// Returns empty string on success, error message on failure.
std::string send(const EmailMessage& msg);

// Send a BackDraft-themed OTP email
std::string send_otp(const std::string& to_email, const std::string& otp_code,
                     const std::string& page_name, int expire_mins);

} // namespace SmtpClient

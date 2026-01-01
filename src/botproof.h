/*
 * botproof.h — BotProof challenge-response system
 *
 * Cloudflare-style human verification for BackDraft WAF.
 * Manages challenge tokens, session cookies, and verification flow.
 *
 * Flow:
 *   1. WAF inspect() triggers on botproof-enabled page
 *   2. Check bd_botproof cookie → has_valid_session() → pass through
 *   3. No session → generate_challenge() → serve HTML with CAPTCHA
 *   4. User POSTs answer → verify() → correct → create_session() + redirect
 */
#pragma once

#include <string>

namespace Botproof {

struct BotproofConfig {
    bool enabled          = false;
    int threshold         = 0;      // min WAF score to trigger challenge
    int session_mins      = 60;
    int max_attempts      = 3;
    // Secure Lock (email OTP)
    bool secure_lock      = false;
    int secure_session_mins = 60;
    std::string allowed_emails; // comma-separated patterns, empty = any
};

struct ChallengeResult {
    std::string token;
    std::string html;     // complete self-contained HTML page
};

struct VerifyResult {
    bool correct          = false;
    bool expired          = false;
    bool max_attempts     = false;
    int attempts_left     = 0;
    std::string original_url;
    int site_id           = 0;
};

// Check if client has a valid botproof session (parse cookie, check DB)
bool has_valid_session(const std::string& client_ip, const std::string& cookie_header);

// Generate a new challenge (creates DB record, returns HTML page)
ChallengeResult generate_challenge(const std::string& client_ip,
                                    const std::string& page_id,
                                    const std::string& original_url,
                                    int max_attempts,
                                    int ttl_secs,
                                    const std::string& font_path);

// Verify a challenge answer (checks hash, manages attempts)
VerifyResult verify(const std::string& token,
                    const std::string& answer,
                    const std::string& client_ip);

// Create a verified session (returns token for cookie)
std::string create_session(const std::string& client_ip, int site_id, int session_mins);

// Load botproof config for a page_id from DB
BotproofConfig get_config(const std::string& page_id);

// Generate invisible turnstile challenge (PoW + fingerprint + behavioral)
ChallengeResult generate_turnstile(const std::string& client_ip,
                                    const std::string& page_id,
                                    const std::string& original_url,
                                    int ttl_secs,
                                    int difficulty = 18);

// Verify turnstile proof (PoW solution + fingerprint score)
struct TurnstileResult {
    bool passed          = false;
    int score            = 0;
    bool fallback_captcha = false; // true = show visual CAPTCHA instead
    std::string original_url;
    int site_id          = 0;
};
TurnstileResult verify_turnstile(const std::string& token,
                                  const std::string& nonce,
                                  const std::string& fingerprint_json,
                                  const std::string& client_ip);

// Clean up expired challenges and sessions
void cleanup_expired();

// ── Secure Lock (Email OTP) ─────────────────────────────────────────
// Check if client has a valid secure lock session
bool has_secure_session(const std::string& client_ip, const std::string& cookie_header);

// Serve the email entry form HTML
std::string email_form_html(const std::string& page_id, const std::string& original_url,
                            const std::string& error_msg = "");

// Send OTP to email, store in DB, return token + code-entry HTML
struct OtpSendResult {
    std::string token;
    std::string html;
    std::string error;
};
OtpSendResult send_otp(const std::string& email, const std::string& client_ip,
                        const std::string& page_id, const std::string& original_url,
                        int otp_ttl_mins, const std::string& allowed_emails);

// Verify OTP code, return result
struct OtpVerifyResult {
    bool correct         = false;
    bool expired         = false;
    bool max_attempts    = false;
    int attempts_left    = 0;
    std::string original_url;
    int site_id          = 0;
};
OtpVerifyResult verify_otp(const std::string& token, const std::string& code,
                            const std::string& client_ip);

// Create a secure lock session, return token for cookie
std::string create_secure_session(const std::string& client_ip, int site_id, int session_mins);

} // namespace Botproof

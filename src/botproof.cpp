#include "botproof.h"
#include "captcha_generator.h"
#include "smtp_client.h"
#include "dbpool.h"
#include "logger.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <sstream>
#include <iomanip>

// ── Helpers ──────────────────────────────────────────────────────────────

static std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
    return ss.str();
}

static std::string random_hex(int bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), bytes);
    std::ostringstream ss;
    for (auto b : buf) ss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return ss.str();
}

static std::string to_lower(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static std::string sql_esc(MYSQL* mysql, const std::string& s) {
    std::string buf(s.size() * 2 + 1, '\0');
    unsigned long len = mysql_real_escape_string(mysql, &buf[0], s.c_str(), s.size());
    buf.resize(len);
    return buf;
}

static std::string safe(const char* s) { return s ? s : ""; }

// ── Parse bd_botproof cookie from Cookie header ──────────────────────────
static std::string parse_botproof_cookie(const std::string& cookie_header) {
    std::string prefix = "bd_botproof=";
    auto pos = cookie_header.find(prefix);
    if (pos == std::string::npos) return "";
    auto start = pos + prefix.size();
    auto end = cookie_header.find(';', start);
    return cookie_header.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// ── Challenge HTML template ──────────────────────────────────────────────
static std::string build_challenge_html(const std::string& image_data_uri,
                                         const std::string& token,
                                         const std::string& error_msg,
                                         int attempts_left) {
    std::string error_html;
    if (!error_msg.empty()) {
        error_html = "<div style=\"background:#7f1d1d;border:1px solid #ef444466;border-radius:8px;"
                     "padding:10px 16px;margin-bottom:16px;color:#fca5a5;font-size:13px\">"
                     + error_msg + "</div>";
    }

    std::string attempts_html;
    if (attempts_left < 3) {
        attempts_html = "<div style=\"font-size:12px;color:#64748b;margin-top:8px\">"
                        + std::to_string(attempts_left) + " attempt(s) remaining</div>";
    }

    return R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — BackDraft</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .box{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;
       max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
  .shield{width:56px;height:56px;margin:0 auto 20px;background:linear-gradient(135deg,#f59e0b,#ef4444);
          border-radius:14px;display:flex;align-items:center;justify-content:center}
  .shield svg{width:28px;height:28px;fill:#fff}
  h1{font-size:20px;font-weight:800;margin-bottom:6px}
  .sub{font-size:13px;color:#94a3b8;margin-bottom:24px}
  .captcha-img{border:2px solid #334155;border-radius:10px;margin:0 auto 20px;display:block;
               background:#111827;padding:4px}
  form{text-align:center}
  input[type=text]{width:100%;padding:12px 16px;background:#111827;border:2px solid #334155;
        border-radius:10px;color:#e2e8f0;font-size:16px;font-family:'SF Mono','Fira Code',monospace;
        text-align:center;letter-spacing:4px;outline:none;transition:border .2s}
  input[type=text]:focus{border-color:#f59e0b}
  input[type=text]::placeholder{letter-spacing:1px;font-size:13px;color:#64748b}
  .btn{width:100%;padding:12px;margin-top:12px;background:#f59e0b;color:#000;font-size:14px;
       font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:background .15s}
  .btn:hover{background:#d97706}
  .footer{margin-top:24px;font-size:11px;color:#475569}
  .footer a{color:#f59e0b;text-decoration:none}
</style>
</head>
<body>
<div class="box">
  <div class="shield">
    <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.13 9.04-7 10.2-3.87-1.16-7-5.53-7-10.2V6.3l7-3.12z"/><path d="M10 12l-2-2-1.41 1.41L10 14.82l7-7-1.41-1.41z"/></svg>
  </div>
  <h1>Security Check</h1>
  <div class="sub">Verify you are human to continue</div>
  )html" + error_html + R"html(
  <img class="captcha-img" src=")html" + image_data_uri + R"html(" alt="Challenge">
  <form method="POST" action="">
    <input type="hidden" name="_bd_action" value="botproof_verify">
    <input type="hidden" name="token" value=")html" + token + R"html(">
    <input type="text" name="answer" placeholder="Type your answer" autocomplete="off" autofocus required maxlength="20">
    <button type="submit" class="btn">Verify</button>
  </form>
  )html" + attempts_html + R"html(
  <div class="footer">Protected by <a href="#">Mcaster1 BackDraft</a> WAF</div>
</div>
</body>
</html>)html";
}

// ── Hard block HTML ──────────────────────────────────────────────────────
static std::string build_blocked_html(int cooldown_secs) {
    return R"html(<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Denied — BackDraft</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0e1a;color:#e2e8f0;font-family:'Inter',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh}
  .box{background:#1e293b;border:2px solid #ef444444;border-radius:16px;padding:40px;
       max-width:420px;width:100%;text-align:center}
  h1{font-size:20px;font-weight:800;color:#ef4444;margin-bottom:8px}
  .sub{font-size:13px;color:#94a3b8;margin-bottom:16px}
  .timer{font-size:32px;font-weight:800;color:#f59e0b;font-family:monospace}
  .footer{margin-top:24px;font-size:11px;color:#475569}
</style>
<script>
let secs = )html" + std::to_string(cooldown_secs) + R"html(;
function tick(){if(secs<=0){location.reload();return}
document.getElementById('t').textContent=Math.floor(secs/60)+':'+(secs%60<10?'0':'')+secs%60;secs--;setTimeout(tick,1000)}
tick();
</script>
</head><body>
<div class="box">
  <h1>Access Denied</h1>
  <div class="sub">Too many failed verification attempts</div>
  <div class="timer" id="t"></div>
  <div class="sub" style="margin-top:12px">Please wait before trying again</div>
  <div class="footer">Mcaster1 BackDraft WAF</div>
</div>
</body></html>)html";
}

// ============================================================================
// Public API
// ============================================================================

namespace Botproof {

bool has_valid_session(const std::string& client_ip, const std::string& cookie_header) {
    std::string token = parse_botproof_cookie(cookie_header);
    if (token.empty()) return false;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql = "SELECT id FROM backdraft_botproof_sessions "
                          "WHERE token='" + sql_esc(mysql, token) + "' "
                          "AND client_ip='" + sql_esc(mysql, client_ip) + "' "
                          "AND expires_at > NOW() LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (!res) return false;
        bool found = (mysql_fetch_row(res) != nullptr);
        mysql_free_result(res);
        return found;
    } catch (...) {
        return false;
    }
}

ChallengeResult generate_challenge(const std::string& client_ip,
                                    const std::string& page_id,
                                    const std::string& original_url,
                                    int max_attempts,
                                    int ttl_secs,
                                    const std::string& font_path) {
    ChallengeResult result;
    result.token = random_hex(32); // 64-char hex token

    // Generate CAPTCHA image
    auto captcha = CaptchaGen::generate(font_path);

    // Hash the answer
    std::string answer_lower = to_lower(captcha.answer);
    std::string answer_hash = sha256_hex(answer_lower);

    LOG_INFO("BotProof: challenge generated answer='" + captcha.answer +
             "' lower='" + answer_lower + "' hash=" + answer_hash.substr(0, 16) + "...");

    // Store in DB (also store plaintext answer for debug)
    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql =
            "INSERT INTO backdraft_botproof_challenges "
            "(token, answer_hash, plaintext_answer, client_ip, page_id, original_url, challenge_type, "
            " attempts_left, expires_at) VALUES ("
            "'" + sql_esc(mysql, result.token) + "', "
            "'" + sql_esc(mysql, answer_hash) + "', "
            "'" + sql_esc(mysql, captcha.answer) + "', "
            "'" + sql_esc(mysql, client_ip) + "', "
            "'" + sql_esc(mysql, page_id) + "', "
            "'" + sql_esc(mysql, original_url) + "', "
            "'text', " + std::to_string(max_attempts) + ", "
            "DATE_ADD(NOW(), INTERVAL " + std::to_string(ttl_secs) + " SECOND))";
        conn->execute(sql);
    } catch (const std::exception& e) {
        LOG_ERROR("BotProof: failed to store challenge: " + std::string(e.what()));
    }

    result.html = build_challenge_html(captcha.png_base64, result.token, "", max_attempts);

    LOG_INFO("BotProof: challenge issued to " + client_ip + " for " + page_id +
             " token=" + result.token.substr(0, 8) + "...");
    return result;
}

VerifyResult verify(const std::string& token,
                    const std::string& answer,
                    const std::string& client_ip) {
    VerifyResult result;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();

        // Fetch challenge record
        std::string sql =
            "SELECT answer_hash, client_ip, attempts_left, expires_at, original_url, page_id "
            "FROM backdraft_botproof_challenges "
            "WHERE token='" + sql_esc(mysql, token) + "' LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (!res) return result;

        MYSQL_ROW row = mysql_fetch_row(res);
        if (!row) {
            mysql_free_result(res);
            result.expired = true;
            return result;
        }

        std::string stored_hash = safe(row[0]);
        std::string stored_ip   = safe(row[1]);
        int attempts_left       = std::stoi(safe(row[2]));
        std::string expires_at  = safe(row[3]);
        result.original_url     = safe(row[4]);
        std::string page_id     = safe(row[5]);
        mysql_free_result(res);

        // Check IP match
        if (stored_ip != client_ip) {
            LOG_WARN("BotProof: IP mismatch on verify — challenge=" + stored_ip +
                     " request=" + client_ip);
            result.expired = true;
            return result;
        }

        // Check expiry (in SQL it's compared, but double check)
        MYSQL_RES* exp_res = conn->query(
            "SELECT 1 FROM backdraft_botproof_challenges "
            "WHERE token='" + sql_esc(mysql, token) + "' AND expires_at > NOW()");
        if (exp_res) {
            if (!mysql_fetch_row(exp_res)) { result.expired = true; mysql_free_result(exp_res); return result; }
            mysql_free_result(exp_res);
        }

        // Resolve site_id from page_id
        // page_id format: "hostname/path" — extract hostname
        auto slash = page_id.find('/');
        std::string hostname = (slash != std::string::npos) ? page_id.substr(0, slash) : page_id;
        MYSQL_RES* sr = conn->query(
            "SELECT id FROM backdraft_sites WHERE site_name='" + sql_esc(mysql, hostname) + "' LIMIT 1");
        if (sr) {
            MYSQL_ROW srow = mysql_fetch_row(sr);
            if (srow && srow[0]) result.site_id = std::stoi(srow[0]);
            mysql_free_result(sr);
        }

        // Check answer
        std::string user_lower = to_lower(answer);
        std::string answer_hash = sha256_hex(user_lower);
        LOG_INFO("BotProof: verify attempt — user_input='" + answer +
                 "' user_lower='" + user_lower +
                 "' user_hash=" + answer_hash.substr(0, 16) + "..." +
                 " stored_hash=" + stored_hash.substr(0, 16) + "..." +
                 " match=" + (answer_hash == stored_hash ? "YES" : "NO"));
        if (answer_hash == stored_hash) {
            result.correct = true;
            result.attempts_left = attempts_left;
            // Delete the used challenge
            conn->execute("DELETE FROM backdraft_botproof_challenges WHERE token='" +
                          sql_esc(mysql, token) + "'");
            LOG_INFO("BotProof: challenge PASSED by " + client_ip);
        } else {
            // Decrement attempts
            attempts_left--;
            result.attempts_left = attempts_left;
            if (attempts_left <= 0) {
                result.max_attempts = true;
                conn->execute("DELETE FROM backdraft_botproof_challenges WHERE token='" +
                              sql_esc(mysql, token) + "'");
                LOG_WARN("BotProof: max attempts reached for " + client_ip);
            } else {
                conn->execute("UPDATE backdraft_botproof_challenges SET attempts_left=" +
                              std::to_string(attempts_left) +
                              " WHERE token='" + sql_esc(mysql, token) + "'");
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("BotProof: verify error: " + std::string(e.what()));
    }

    return result;
}

std::string create_session(const std::string& client_ip, int site_id, int session_mins) {
    std::string token = random_hex(32);

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql =
            "INSERT INTO backdraft_botproof_sessions (token, client_ip, site_id, expires_at) "
            "VALUES ('" + sql_esc(mysql, token) + "', "
            "'" + sql_esc(mysql, client_ip) + "', "
            + std::to_string(site_id) + ", "
            "DATE_ADD(NOW(), INTERVAL " + std::to_string(session_mins) + " MINUTE))";
        conn->execute(sql);
        LOG_INFO("BotProof: session created for " + client_ip + " (expires in " +
                 std::to_string(session_mins) + "m)");
    } catch (const std::exception& e) {
        LOG_ERROR("BotProof: create_session error: " + std::string(e.what()));
    }

    return token;
}

BotproofConfig get_config(const std::string& page_id) {
    BotproofConfig cfg;
    if (page_id.empty()) return cfg;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql =
            "SELECT botproof_enabled, botproof_threshold, botproof_session_mins, botproof_max_attempts, "
            "       secure_lock_enabled, secure_lock_session_mins, COALESCE(secure_lock_allowed_emails,'') "
            "FROM backdraft_page_profiles "
            "WHERE page_id='" + sql_esc(mysql, page_id) + "' AND monitoring = 1 LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) {
                cfg.enabled            = std::stoi(safe(row[0])) == 1;
                cfg.threshold          = std::stoi(safe(row[1]));
                cfg.session_mins       = std::stoi(safe(row[2]));
                cfg.max_attempts       = std::stoi(safe(row[3]));
                cfg.secure_lock        = std::stoi(safe(row[4])) == 1;
                cfg.secure_session_mins = std::stoi(safe(row[5]));
                cfg.allowed_emails     = safe(row[6]);
            }
            mysql_free_result(res);
        }
    } catch (...) {}

    return cfg;
}

// ============================================================================
// Turnstile — Invisible PoW + Fingerprint + Behavioral Challenge
// ============================================================================

static std::string build_turnstile_html(const std::string& token, int difficulty) {
    // difficulty = number of leading zero bits required in SHA-256 hash
    return R"html(<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying — BackDraft</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',system-ui,sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.widget{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:32px 40px;
        max-width:380px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.shield{width:48px;height:48px;margin:0 auto 16px;background:linear-gradient(135deg,#14b8a6,#0891b2);
        border-radius:12px;display:flex;align-items:center;justify-content:center}
.shield svg{width:24px;height:24px;fill:#fff}
h1{font-size:16px;font-weight:700;margin-bottom:4px}
.sub{font-size:12px;color:#94a3b8;margin-bottom:20px}
.spinner{width:40px;height:40px;border:3px solid #334155;border-top-color:#14b8a6;border-radius:50%;
         animation:spin 0.8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.status{font-size:13px;color:#94a3b8;transition:all .3s}
.status.pass{color:#22c55e}
.status.fail{color:#ef4444}
.progress{background:#111827;border-radius:6px;height:6px;overflow:hidden;margin:12px 0}
.progress-bar{height:100%;background:linear-gradient(90deg,#14b8a6,#0891b2);border-radius:6px;width:0%;transition:width .3s}
.check{display:none;width:48px;height:48px;margin:0 auto 16px}
.check svg{width:48px;height:48px}
.footer{margin-top:20px;font-size:10px;color:#475569}
</style></head><body>
<div class="widget">
  <div class="shield" id="shieldIcon">
    <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
  </div>
  <div class="check" id="checkIcon">
    <svg viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
  </div>
  <h1 id="title">Verifying you are human</h1>
  <div class="sub" id="subtitle">This won't take long</div>
  <div class="spinner" id="spinner"></div>
  <div class="progress"><div class="progress-bar" id="progressBar"></div></div>
  <div class="status" id="status">Initializing security check...</div>
  <form method="POST" action="" id="proofForm" style="display:none">
    <input type="hidden" name="_bd_action" value="turnstile_verify">
    <input type="hidden" name="token" value=")html" + token + R"html(">
    <input type="hidden" name="nonce" id="fNonce">
    <input type="hidden" name="fp" id="fFingerprint">
  </form>
  <div class="footer">Protected by Mcaster1 BackDraft</div>
</div>
<script>
(function(){
const TOKEN = ')html" + token + R"html(';
const DIFFICULTY = )html" + std::to_string(difficulty) + R"html(;
const startTime = Date.now();
let mouseEntropy = 0, mousePoints = 0, touchDetected = false;

// Track mouse movement
document.addEventListener('mousemove', function(e) {
    mouseEntropy += Math.abs(e.movementX) + Math.abs(e.movementY);
    mousePoints++;
});
document.addEventListener('touchstart', function() { touchDetected = true; }, {once:true});

function setStatus(text, pct) {
    document.getElementById('status').textContent = text;
    document.getElementById('progressBar').style.width = pct + '%';
}

// Step 1: Browser fingerprint
setStatus('Collecting environment data...', 10);

async function getFingerprint() {
    const fp = {};

    // Canvas fingerprint
    try {
        const c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        const ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125,1,62,20);
        ctx.fillStyle = '#069';
        ctx.fillText('BackDraft v1', 2, 15);
        ctx.fillStyle = 'rgba(102,204,0,0.7)';
        ctx.fillText('BackDraft v1', 4, 17);
        fp.canvas = c.toDataURL().slice(-50);
    } catch(e) { fp.canvas = ''; }

    // WebGL
    try {
        const gl = document.createElement('canvas').getContext('webgl');
        if (gl) {
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            fp.webgl_vendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : '';
            fp.webgl_renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
        } else { fp.webgl_vendor = ''; fp.webgl_renderer = ''; }
    } catch(e) { fp.webgl_vendor = ''; fp.webgl_renderer = ''; }

    // Screen
    fp.screen_w = screen.width;
    fp.screen_h = screen.height;
    fp.color_depth = screen.colorDepth;
    fp.pixel_ratio = window.devicePixelRatio || 1;

    // Navigator
    fp.platform = navigator.platform || '';
    fp.language = navigator.language || '';
    fp.languages = (navigator.languages || []).join(',');
    fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    fp.hardware_concurrency = navigator.hardwareConcurrency || 0;
    fp.max_touch = navigator.maxTouchPoints || 0;

    // Timing
    fp.load_time = Date.now() - startTime;
    fp.mouse_entropy = mouseEntropy;
    fp.mouse_points = mousePoints;
    fp.touch = touchDetected;

    // DOM proof — can we manipulate the DOM?
    try {
        const d = document.createElement('div');
        d.style.cssText = 'position:absolute;left:-9999px';
        d.innerHTML = '<span>proof</span>';
        document.body.appendChild(d);
        fp.dom_proof = d.querySelector('span')?.textContent === 'proof';
        document.body.removeChild(d);
    } catch(e) { fp.dom_proof = false; }

    // Audio context fingerprint
    try {
        const ac = new (window.AudioContext || window.webkitAudioContext)();
        const osc = ac.createOscillator();
        const analyser = ac.createAnalyser();
        osc.connect(analyser);
        fp.audio = analyser.frequencyBinCount > 0;
        ac.close();
    } catch(e) { fp.audio = false; }

    return fp;
}

// Step 2: Proof of Work (SHA-256 mining)
async function solvePoW(challenge, difficulty) {
    setStatus('Solving proof of work...', 30);
    const target = difficulty; // number of leading zero bits
    let nonce = 0;
    const encoder = new TextEncoder();
    const batchSize = 5000;

    while (true) {
        for (let i = 0; i < batchSize; i++) {
            const data = encoder.encode(challenge + ':' + nonce);
            const hash = await crypto.subtle.digest('SHA-256', data);
            const view = new Uint8Array(hash);

            // Check leading zero bits
            let zeroBits = 0;
            for (let byte of view) {
                if (byte === 0) { zeroBits += 8; }
                else {
                    let b = byte;
                    while ((b & 0x80) === 0) { zeroBits++; b <<= 1; }
                    break;
                }
                if (zeroBits >= target) break;
            }

            if (zeroBits >= target) {
                return nonce.toString();
            }
            nonce++;
        }

        // Update progress (estimate based on expected iterations)
        const expected = Math.pow(2, difficulty);
        const pct = Math.min(90, 30 + (nonce / expected) * 60);
        setStatus('Solving proof of work... (' + nonce.toLocaleString() + ' hashes)', pct);

        // Yield to prevent UI freeze
        await new Promise(r => setTimeout(r, 0));
    }
}

// Step 3: Submit proof
async function run() {
    try {
        // Collect fingerprint
        const fp = await getFingerprint();
        setStatus('Analyzing environment...', 20);
        await new Promise(r => setTimeout(r, 200));

        // Solve PoW
        const nonce = await solvePoW(TOKEN, DIFFICULTY);
        setStatus('Validating...', 95);

        // Final mouse/timing data
        fp.solve_time = Date.now() - startTime;
        fp.mouse_entropy = mouseEntropy;
        fp.mouse_points = mousePoints;

        // Submit
        document.getElementById('fNonce').value = nonce;
        document.getElementById('fFingerprint').value = JSON.stringify(fp);

        // Show success animation briefly
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('shieldIcon').style.display = 'none';
        document.getElementById('checkIcon').style.display = 'block';
        document.getElementById('title').textContent = 'Verified';
        document.getElementById('subtitle').textContent = 'Redirecting...';
        document.getElementById('status').textContent = 'Human verified';
        document.getElementById('status').className = 'status pass';
        document.getElementById('progressBar').style.width = '100%';
        document.getElementById('progressBar').style.background = '#22c55e';

        await new Promise(r => setTimeout(r, 500));
        document.getElementById('proofForm').submit();

    } catch(e) {
        document.getElementById('status').textContent = 'Verification failed: ' + e.message;
        document.getElementById('status').className = 'status fail';
        // Fallback: reload for visual CAPTCHA
        setTimeout(() => location.reload(), 3000);
    }
}

// Start after brief delay (collect some mouse data first)
setTimeout(run, 800);
})();
</script>
</body></html>)html";
}

ChallengeResult generate_turnstile(const std::string& client_ip,
                                    const std::string& page_id,
                                    const std::string& original_url,
                                    int ttl_secs,
                                    int difficulty) {
    ChallengeResult result;
    result.token = random_hex(32);

    // PoW answer = the token itself (client must find nonce where SHA-256(token:nonce) has N leading zero bits)
    // We don't store an answer hash — validation is done by checking the PoW on the server side
    std::string pow_marker = "pow:" + std::to_string(difficulty);

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        conn->execute(
            "INSERT INTO backdraft_botproof_challenges "
            "(token, answer_hash, plaintext_answer, client_ip, page_id, original_url, challenge_type, "
            " attempts_left, expires_at) VALUES ("
            "'" + sql_esc(mysql, result.token) + "', "
            "'" + sql_esc(mysql, pow_marker) + "', "
            "'" + sql_esc(mysql, "turnstile:d" + std::to_string(difficulty)) + "', "
            "'" + sql_esc(mysql, client_ip) + "', "
            "'" + sql_esc(mysql, page_id) + "', "
            "'" + sql_esc(mysql, original_url) + "', "
            "'turnstile', 1, "
            "DATE_ADD(NOW(), INTERVAL " + std::to_string(ttl_secs) + " SECOND))");
    } catch (const std::exception& e) {
        LOG_ERROR("BotProof: turnstile DB error: " + std::string(e.what()));
    }

    result.html = build_turnstile_html(result.token, difficulty);

    LOG_INFO("BotProof: turnstile challenge issued to " + client_ip + " for " + page_id +
             " difficulty=" + std::to_string(difficulty));
    return result;
}

TurnstileResult verify_turnstile(const std::string& token,
                                  const std::string& nonce,
                                  const std::string& fingerprint_json,
                                  const std::string& client_ip) {
    TurnstileResult result;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();

        // Fetch challenge
        std::string sql =
            "SELECT answer_hash, client_ip, original_url, page_id "
            "FROM backdraft_botproof_challenges "
            "WHERE token='" + sql_esc(mysql, token) + "' AND expires_at > NOW() LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (!res) { result.fallback_captcha = true; return result; }

        MYSQL_ROW row = mysql_fetch_row(res);
        if (!row) { mysql_free_result(res); result.fallback_captcha = true; return result; }

        std::string stored_marker = safe(row[0]);
        std::string stored_ip    = safe(row[1]);
        result.original_url      = safe(row[2]);
        std::string page_id      = safe(row[3]);
        mysql_free_result(res);

        // IP check
        if (stored_ip != client_ip) {
            LOG_WARN("BotProof: turnstile IP mismatch");
            result.fallback_captcha = true;
            return result;
        }

        // Parse difficulty from stored marker: "pow:18"
        int difficulty = 18;
        if (stored_marker.find("pow:") == 0) {
            difficulty = std::stoi(stored_marker.substr(4));
        }

        // Resolve site_id
        auto slash = page_id.find('/');
        std::string hostname = (slash != std::string::npos) ? page_id.substr(0, slash) : page_id;
        MYSQL_RES* sr = conn->query(
            "SELECT id FROM backdraft_sites WHERE site_name='" + sql_esc(mysql, hostname) + "' LIMIT 1");
        if (sr) {
            MYSQL_ROW srow = mysql_fetch_row(sr);
            if (srow && srow[0]) result.site_id = std::stoi(srow[0]);
            mysql_free_result(sr);
        }

        // Step 1: Verify Proof of Work
        // Check that SHA-256(token + ":" + nonce) has 'difficulty' leading zero bits
        std::string pow_input = token + ":" + nonce;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(pow_input.c_str()), pow_input.size(), hash);

        int zero_bits = 0;
        for (int i = 0; i < SHA256_DIGEST_LENGTH && zero_bits < difficulty; i++) {
            if (hash[i] == 0) { zero_bits += 8; }
            else {
                uint8_t b = hash[i];
                while ((b & 0x80) == 0) { zero_bits++; b <<= 1; }
                break;
            }
        }

        bool pow_valid = (zero_bits >= difficulty);
        int score = 0;

        if (pow_valid) {
            score += 40;
            LOG_INFO("BotProof: turnstile PoW valid — " + std::to_string(zero_bits) +
                     " zero bits (required " + std::to_string(difficulty) + ")");
        } else {
            LOG_WARN("BotProof: turnstile PoW FAILED — " + std::to_string(zero_bits) +
                     " zero bits (required " + std::to_string(difficulty) + ")");
            result.fallback_captcha = true;
            conn->execute("DELETE FROM backdraft_botproof_challenges WHERE token='" +
                          sql_esc(mysql, token) + "'");
            return result;
        }

        // Step 2: Score fingerprint
        // Parse JSON fingerprint data
        // Simple JSON value extraction (no full parser needed)
        auto json_str = [&](const std::string& key) -> std::string {
            auto pos = fingerprint_json.find("\"" + key + "\"");
            if (pos == std::string::npos) return "";
            auto colon = fingerprint_json.find(':', pos);
            if (colon == std::string::npos) return "";
            auto start = fingerprint_json.find_first_not_of(" \t", colon + 1);
            if (start == std::string::npos) return "";
            if (fingerprint_json[start] == '"') {
                auto end = fingerprint_json.find('"', start + 1);
                return (end != std::string::npos) ? fingerprint_json.substr(start + 1, end - start - 1) : "";
            }
            auto end = fingerprint_json.find_first_of(",}", start);
            return (end != std::string::npos) ? fingerprint_json.substr(start, end - start) : "";
        };

        auto json_int = [&](const std::string& key) -> int {
            std::string val = json_str(key);
            try { return val.empty() ? 0 : std::stoi(val); } catch (...) { return 0; }
        };

        auto json_bool = [&](const std::string& key) -> bool {
            std::string val = json_str(key);
            return val == "true" || val == "1";
        };

        // Canvas fingerprint present
        if (!json_str("canvas").empty()) score += 10;

        // WebGL renderer present (bots rarely have GPU)
        if (!json_str("webgl_renderer").empty()) score += 10;

        // Screen dimensions (headless defaults: 800x600 or 0x0)
        int sw = json_int("screen_w"), sh = json_int("screen_h");
        if (sw > 0 && sh > 0 && !(sw == 800 && sh == 600)) score += 5;

        // Mouse movement (strong human signal)
        int mouse_entropy = json_int("mouse_entropy");
        int mouse_points = json_int("mouse_points");
        if (mouse_points > 3 && mouse_entropy > 20) score += 15;
        else if (mouse_points > 0) score += 5;

        // Timezone + language
        if (!json_str("timezone").empty() && !json_str("language").empty()) score += 5;

        // Navigator coherence
        if (!json_str("platform").empty() && json_int("hardware_concurrency") > 0) score += 5;

        // Page load timing (should take at least 800ms due to our delay)
        int solve_time = json_int("solve_time");
        if (solve_time > 500 && solve_time < 60000) score += 10;

        LOG_INFO("BotProof: turnstile score=" + std::to_string(score) + "/100 for " + client_ip +
                 " (canvas=" + (json_str("canvas").empty() ? "N" : "Y") +
                 " webgl=" + (json_str("webgl_renderer").empty() ? "N" : "Y") +
                 " screen=" + std::to_string(sw) + "x" + std::to_string(sh) +
                 " mouse=" + std::to_string(mouse_points) + "pts/" + std::to_string(mouse_entropy) + "ent" +
                 " time=" + std::to_string(solve_time) + "ms)");

        result.score = score;
        result.passed = (score >= 60);
        result.fallback_captcha = !result.passed;

        // Clean up challenge
        conn->execute("DELETE FROM backdraft_botproof_challenges WHERE token='" +
                      sql_esc(mysql, token) + "'");

    } catch (const std::exception& e) {
        LOG_ERROR("BotProof: turnstile verify error: " + std::string(e.what()));
        result.fallback_captcha = true;
    }

    return result;
}

void cleanup_expired() {
    try {
        auto conn = DB("backdraft");
        conn->execute("DELETE FROM backdraft_botproof_challenges WHERE expires_at < NOW()");
        conn->execute("DELETE FROM backdraft_botproof_sessions WHERE expires_at < NOW()");
        conn->execute("DELETE FROM backdraft_secure_otp WHERE expires_at < NOW()");
    } catch (...) {}
}

// ============================================================================
// Secure Lock (Email OTP)
// ============================================================================

static std::string parse_secure_cookie(const std::string& cookie_header) {
    std::string prefix = "bd_secure=";
    auto pos = cookie_header.find(prefix);
    if (pos == std::string::npos) return "";
    auto start = pos + prefix.size();
    auto end = cookie_header.find(';', start);
    return cookie_header.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

bool has_secure_session(const std::string& client_ip, const std::string& cookie_header) {
    std::string token = parse_secure_cookie(cookie_header);
    if (token.empty()) return false;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        // Reuse botproof_sessions table with a "secure_" prefix in token
        std::string sql = "SELECT id FROM backdraft_botproof_sessions "
                          "WHERE token='" + sql_esc(mysql, token) + "' "
                          "AND client_ip='" + sql_esc(mysql, client_ip) + "' "
                          "AND expires_at > NOW() LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (!res) return false;
        bool found = (mysql_fetch_row(res) != nullptr);
        mysql_free_result(res);
        return found;
    } catch (...) { return false; }
}

std::string email_form_html(const std::string& page_id, const std::string& original_url,
                            const std::string& error_msg) {
    std::string error_html;
    if (!error_msg.empty()) {
        error_html = "<div style=\"background:#7f1d1d;border:1px solid #ef444466;border-radius:8px;"
                     "padding:10px 16px;margin-bottom:16px;color:#fca5a5;font-size:13px\">"
                     + error_msg + "</div>";
    }

    return R"html(<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Access — BackDraft</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .box{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;
       max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
  .lock{width:56px;height:56px;margin:0 auto 20px;background:linear-gradient(135deg,#14b8a6,#0891b2);
        border-radius:14px;display:flex;align-items:center;justify-content:center}
  .lock svg{width:28px;height:28px;fill:#fff}
  h1{font-size:20px;font-weight:800;margin-bottom:6px}
  .sub{font-size:13px;color:#94a3b8;margin-bottom:24px}
  input[type=email]{width:100%;padding:12px 16px;background:#111827;border:2px solid #334155;
        border-radius:10px;color:#e2e8f0;font-size:14px;outline:none;transition:border .2s}
  input[type=email]:focus{border-color:#14b8a6}
  input[type=email]::placeholder{color:#64748b}
  .btn{width:100%;padding:12px;margin-top:12px;background:#14b8a6;color:#fff;font-size:14px;
       font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:background .15s}
  .btn:hover{background:#0d9488}
  .footer{margin-top:24px;font-size:11px;color:#475569}
</style></head><body>
<div class="box">
  <div class="lock">
    <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>
  </div>
  <h1>Secure Page Access</h1>
  <div class="sub">Enter your email to receive a one-time access code</div>
  )html" + error_html + R"html(
  <form method="POST" action="">
    <input type="hidden" name="_bd_action" value="secure_send_otp">
    <input type="hidden" name="page_id" value=")html" + page_id + R"html(">
    <input type="hidden" name="original_url" value=")html" + original_url + R"html(">
    <input type="email" name="email" placeholder="your@email.com" autocomplete="email" autofocus required>
    <button type="submit" class="btn">Send Access Code</button>
  </form>
  <div class="footer">Protected by Mcaster1 BackDraft — Secure Lock</div>
</div></body></html>)html";
}

static std::string otp_entry_html(const std::string& token, const std::string& email,
                                   const std::string& error_msg, int attempts_left) {
    std::string error_html;
    if (!error_msg.empty()) {
        error_html = "<div style=\"background:#7f1d1d;border:1px solid #ef444466;border-radius:8px;"
                     "padding:10px 16px;margin-bottom:16px;color:#fca5a5;font-size:13px\">"
                     + error_msg + "</div>";
    }
    std::string attempt_html;
    if (attempts_left < 3) {
        attempt_html = "<div style=\"font-size:12px;color:#64748b;margin-top:8px\">"
                       + std::to_string(attempts_left) + " attempt(s) remaining</div>";
    }

    // Mask email for display
    std::string masked = email;
    auto at = masked.find('@');
    if (at > 2) masked = masked.substr(0, 2) + std::string(at - 2, '*') + masked.substr(at);

    return R"html(<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enter Code — BackDraft</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0e1a;color:#e2e8f0;font-family:'Inter','Segoe UI',system-ui,sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
  .box{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:40px;
       max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}
  .lock{width:56px;height:56px;margin:0 auto 20px;background:linear-gradient(135deg,#14b8a6,#0891b2);
        border-radius:14px;display:flex;align-items:center;justify-content:center}
  .lock svg{width:28px;height:28px;fill:#fff}
  h1{font-size:20px;font-weight:800;margin-bottom:6px}
  .sub{font-size:13px;color:#94a3b8;margin-bottom:24px}
  .email-badge{background:#111827;border:1px solid #334155;border-radius:8px;padding:8px 16px;
               display:inline-block;margin-bottom:20px;font-size:13px;color:#14b8a6}
  input[type=text]{width:180px;padding:14px;background:#111827;border:2px solid #334155;
        border-radius:10px;color:#f59e0b;font-size:24px;font-family:monospace;text-align:center;
        letter-spacing:8px;outline:none;transition:border .2s}
  input[type=text]:focus{border-color:#14b8a6}
  .btn{width:100%;padding:12px;margin-top:16px;background:#14b8a6;color:#fff;font-size:14px;
       font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:background .15s}
  .btn:hover{background:#0d9488}
  .footer{margin-top:24px;font-size:11px;color:#475569}
</style></head><body>
<div class="box">
  <div class="lock">
    <svg viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>
  </div>
  <h1>Enter Access Code</h1>
  <div class="sub">A 6-digit code was sent to</div>
  <div class="email-badge">)html" + masked + R"html(</div>
  )html" + error_html + R"html(
  <form method="POST" action="">
    <input type="hidden" name="_bd_action" value="secure_verify_otp">
    <input type="hidden" name="token" value=")html" + token + R"html(">
    <input type="text" name="code" placeholder="000000" autocomplete="one-time-code" autofocus
           required maxlength="6" pattern="[0-9]{6}" inputmode="numeric">
    <button type="submit" class="btn">Verify Code</button>
  </form>
  )html" + attempt_html + R"html(
  <div class="footer">Protected by Mcaster1 BackDraft — Secure Lock</div>
</div></body></html>)html";
}

// Check if email matches allowed patterns
static bool email_allowed(const std::string& email, const std::string& allowed_csv) {
    if (allowed_csv.empty()) return true; // empty = any email allowed

    std::string lower_email = to_lower(email);
    std::istringstream iss(allowed_csv);
    std::string pattern;
    while (std::getline(iss, pattern, ',')) {
        // Trim whitespace
        while (!pattern.empty() && pattern.front() == ' ') pattern.erase(0, 1);
        while (!pattern.empty() && pattern.back() == ' ') pattern.pop_back();
        if (pattern.empty()) continue;

        std::string lower_pat = to_lower(pattern);

        // Wildcard: *@domain.com matches any email at that domain
        if (lower_pat.front() == '*') {
            std::string suffix = lower_pat.substr(1);
            if (lower_email.size() >= suffix.size() &&
                lower_email.compare(lower_email.size() - suffix.size(), suffix.size(), suffix) == 0)
                return true;
        } else if (lower_email == lower_pat) {
            return true;
        }
    }
    return false;
}

OtpSendResult send_otp(const std::string& email, const std::string& client_ip,
                        const std::string& page_id, const std::string& original_url,
                        int otp_ttl_mins, const std::string& allowed_emails) {
    OtpSendResult result;

    // Validate email format (basic)
    if (email.find('@') == std::string::npos || email.size() < 5) {
        result.error = "Invalid email address";
        result.html = email_form_html(page_id, original_url, result.error);
        return result;
    }

    // Check allowed emails
    if (!email_allowed(email, allowed_emails)) {
        result.error = "This email address is not authorized for this page";
        result.html = email_form_html(page_id, original_url, result.error);
        return result;
    }

    // Generate 6-digit OTP
    std::string otp;
    for (int i = 0; i < 6; i++) {
        unsigned char byte;
        RAND_bytes(&byte, 1);
        otp += std::to_string(byte % 10);
    }

    result.token = random_hex(32);
    std::string code_hash = sha256_hex(otp);

    // Store in DB
    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql =
            "INSERT INTO backdraft_secure_otp "
            "(token, email, code_hash, client_ip, page_id, original_url, attempts_left, expires_at) "
            "VALUES ('" + sql_esc(mysql, result.token) + "', "
            "'" + sql_esc(mysql, email) + "', "
            "'" + sql_esc(mysql, code_hash) + "', "
            "'" + sql_esc(mysql, client_ip) + "', "
            "'" + sql_esc(mysql, page_id) + "', "
            "'" + sql_esc(mysql, original_url) + "', 3, "
            "DATE_ADD(NOW(), INTERVAL " + std::to_string(otp_ttl_mins) + " MINUTE))";
        conn->execute(sql);
    } catch (const std::exception& e) {
        result.error = "Failed to store OTP";
        result.html = email_form_html(page_id, original_url, "Internal error — please try again");
        return result;
    }

    // Send email via SMTP
    std::string smtp_err = SmtpClient::send_otp(email, otp, page_id, otp_ttl_mins);
    if (!smtp_err.empty()) {
        LOG_ERROR("SecureLock: SMTP failed for " + email + ": " + smtp_err);
        result.error = smtp_err;
        result.html = email_form_html(page_id, original_url, "Failed to send email — please try again");
        return result;
    }

    LOG_INFO("SecureLock: OTP sent to " + email + " for " + page_id);
    result.html = otp_entry_html(result.token, email, "", 3);
    return result;
}

OtpVerifyResult verify_otp(const std::string& token, const std::string& code,
                            const std::string& client_ip) {
    OtpVerifyResult result;

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();

        std::string sql =
            "SELECT code_hash, client_ip, email, attempts_left, original_url, page_id "
            "FROM backdraft_secure_otp "
            "WHERE token='" + sql_esc(mysql, token) + "' AND expires_at > NOW() LIMIT 1";
        MYSQL_RES* res = conn->query(sql);
        if (!res) { result.expired = true; return result; }

        MYSQL_ROW row = mysql_fetch_row(res);
        if (!row) { mysql_free_result(res); result.expired = true; return result; }

        std::string stored_hash = safe(row[0]);
        std::string stored_ip   = safe(row[1]);
        std::string email       = safe(row[2]);
        int attempts_left       = std::stoi(safe(row[3]));
        result.original_url     = safe(row[4]);
        std::string page_id     = safe(row[5]);
        mysql_free_result(res);

        if (stored_ip != client_ip) {
            LOG_WARN("SecureLock: IP mismatch on OTP verify");
            result.expired = true;
            return result;
        }

        // Resolve site_id
        auto slash = page_id.find('/');
        std::string hostname = (slash != std::string::npos) ? page_id.substr(0, slash) : page_id;
        MYSQL_RES* sr = conn->query(
            "SELECT id FROM backdraft_sites WHERE site_name='" + sql_esc(mysql, hostname) + "' LIMIT 1");
        if (sr) {
            MYSQL_ROW srow = mysql_fetch_row(sr);
            if (srow && srow[0]) result.site_id = std::stoi(srow[0]);
            mysql_free_result(sr);
        }

        std::string code_hash = sha256_hex(code);
        if (code_hash == stored_hash) {
            result.correct = true;
            result.attempts_left = attempts_left;
            conn->execute("UPDATE backdraft_secure_otp SET verified_at=NOW() WHERE token='" +
                          sql_esc(mysql, token) + "'");
            LOG_INFO("SecureLock: OTP verified for " + email + " on " + page_id);
        } else {
            attempts_left--;
            result.attempts_left = attempts_left;
            if (attempts_left <= 0) {
                result.max_attempts = true;
                conn->execute("DELETE FROM backdraft_secure_otp WHERE token='" +
                              sql_esc(mysql, token) + "'");
            } else {
                conn->execute("UPDATE backdraft_secure_otp SET attempts_left=" +
                              std::to_string(attempts_left) +
                              " WHERE token='" + sql_esc(mysql, token) + "'");
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("SecureLock: verify_otp error: " + std::string(e.what()));
    }

    return result;
}

std::string create_secure_session(const std::string& client_ip, int site_id, int session_mins) {
    // Prefix with "sec_" to distinguish from botproof sessions
    std::string token = "sec_" + random_hex(30);

    try {
        auto conn = DB("backdraft");
        MYSQL* mysql = conn->raw();
        std::string sql =
            "INSERT INTO backdraft_botproof_sessions (token, client_ip, site_id, expires_at) "
            "VALUES ('" + sql_esc(mysql, token) + "', "
            "'" + sql_esc(mysql, client_ip) + "', "
            + std::to_string(site_id) + ", "
            "DATE_ADD(NOW(), INTERVAL " + std::to_string(session_mins) + " MINUTE))";
        conn->execute(sql);
        LOG_INFO("SecureLock: secure session created for " + client_ip +
                 " (expires in " + std::to_string(session_mins) + "m)");
    } catch (const std::exception& e) {
        LOG_ERROR("SecureLock: create_secure_session error: " + std::string(e.what()));
    }

    return token;
}

} // namespace Botproof

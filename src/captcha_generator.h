/*
 * captcha_generator.h — CAPTCHA image generation engine using libgd
 *
 * Generates distorted text or math challenge images as in-memory PNGs,
 * base64-encoded for embedding directly in HTML as data URIs.
 *
 * Anti-OCR techniques:
 *   - Per-character rotation (-15° to +15°)
 *   - Per-character size variation (24-32pt)
 *   - Per-character vertical offset
 *   - Per-character color variation (amber/gold shades)
 *   - Background noise: random dots + crossing lines
 *   - Post-render sine-wave horizontal distortion
 *   - Overlapping confuser lines in text-similar colors
 *
 * Dependencies: libgd (gdlib), FreeType, libpng
 */
#pragma once

#include <string>

namespace CaptchaGen {

struct CaptchaImage {
    std::string png_base64;   // "data:image/png;base64,..." ready for <img src="">
    std::string answer;       // plaintext answer (for hashing before DB storage)
};

// Generate a distorted text CAPTCHA (5-6 random chars)
CaptchaImage generate_text(const std::string& font_path);

// Generate a math challenge CAPTCHA (e.g. "14 + 7 = ?")
CaptchaImage generate_math(const std::string& font_path);

// Generate random challenge (50/50 text or math)
CaptchaImage generate(const std::string& font_path);

} // namespace CaptchaGen

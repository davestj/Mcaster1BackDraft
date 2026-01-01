#include "captcha_generator.h"
#include <gd.h>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <random>
#include <algorithm>
#include <chrono>

// ── Base64 encoder (lightweight, no external deps) ───────────────────────
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned b = (unsigned)data[i] << 16;
        if (i + 1 < len) b |= (unsigned)data[i + 1] << 8;
        if (i + 2 < len) b |= (unsigned)data[i + 2];
        out += B64[(b >> 18) & 0x3F];
        out += B64[(b >> 12) & 0x3F];
        out += (i + 1 < len) ? B64[(b >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? B64[b & 0x3F] : '=';
    }
    return out;
}

// ── Random helpers ───────────────────────────────────────────────────────
static std::mt19937& rng() {
    static thread_local std::mt19937 gen(
        std::random_device{}() ^ (unsigned)std::chrono::steady_clock::now().time_since_epoch().count()
    );
    return gen;
}

static int rand_int(int lo, int hi) {
    return std::uniform_int_distribution<int>(lo, hi)(rng());
}

static double rand_double(double lo, double hi) {
    return std::uniform_real_distribution<double>(lo, hi)(rng());
}

// Safe character set — no ambiguous chars (0/O, 1/I/l, 5/S)
static const char CHARSET[] = "ABCDEFGHJKLMNPQRTUVWXYZ2346789";
static const int CHARSET_LEN = sizeof(CHARSET) - 1;

// ── Draw noise (dots + lines) on image ───────────────────────────────────
static void draw_noise(gdImagePtr img, int w, int h) {
    // Random dots
    for (int i = 0; i < 120; i++) {
        int c = gdImageColorAllocate(img, rand_int(20, 80), rand_int(20, 60), rand_int(40, 100));
        gdImageSetPixel(img, rand_int(0, w - 1), rand_int(0, h - 1), c);
    }

    // Random short lines (background confusers)
    for (int i = 0; i < 15; i++) {
        int c = gdImageColorAllocate(img, rand_int(30, 90), rand_int(30, 70), rand_int(50, 110));
        gdImageSetThickness(img, rand_int(1, 2));
        int x1 = rand_int(0, w), y1 = rand_int(0, h);
        int x2 = x1 + rand_int(-60, 60), y2 = y1 + rand_int(-20, 20);
        gdImageLine(img, x1, y1, x2, y2, c);
    }
}

// ── Draw confuser lines over text (same color range as text) ─────────────
static void draw_confuser_lines(gdImagePtr img, int w, int h) {
    for (int i = 0; i < 2; i++) {
        // Amber/gold range matching text colors
        int c = gdImageColorAllocate(img, rand_int(180, 240), rand_int(130, 180), rand_int(0, 40));
        gdImageSetThickness(img, 1);
        int y1 = rand_int(15, h - 15);
        int y2 = y1 + rand_int(-15, 15);
        gdImageLine(img, 0, y1, w, y2, c);
    }
}

// ── Apply sine-wave horizontal distortion ────────────────────────────────
static gdImagePtr wave_distort(gdImagePtr src, int w, int h) {
    gdImagePtr dst = gdImageCreateTrueColor(w, h);
    int bg = gdImageColorAllocate(dst, 10, 14, 26); // #0a0e1a
    gdImageFilledRectangle(dst, 0, 0, w - 1, h - 1, bg);

    double amplitude = rand_double(2.0, 4.0);  // reduced for readability
    double period = rand_double(25.0, 45.0);
    double phase = rand_double(0.0, 2.0 * M_PI);

    for (int y = 0; y < h; y++) {
        int shift = (int)(amplitude * sin(2.0 * M_PI * y / period + phase));
        for (int x = 0; x < w; x++) {
            int sx = x - shift;
            if (sx >= 0 && sx < w) {
                int pixel = gdImageGetTrueColorPixel(src, sx, y);
                gdImageSetPixel(dst, x, y, pixel);
            }
        }
    }

    // Also apply a lighter vertical wave
    gdImagePtr dst2 = gdImageCreateTrueColor(w, h);
    gdImageFilledRectangle(dst2, 0, 0, w - 1, h - 1, bg);

    double amp2 = rand_double(1.0, 2.0);  // subtle vertical wave
    double per2 = rand_double(35.0, 55.0);
    double ph2 = rand_double(0.0, 2.0 * M_PI);

    for (int x = 0; x < w; x++) {
        int shift2 = (int)(amp2 * sin(2.0 * M_PI * x / per2 + ph2));
        for (int y = 0; y < h; y++) {
            int sy = y - shift2;
            if (sy >= 0 && sy < h) {
                int pixel = gdImageGetTrueColorPixel(dst, x, sy);
                gdImageSetPixel(dst2, x, y, pixel);
            }
        }
    }

    gdImageDestroy(dst);
    return dst2;
}

// ── Render text with per-character distortion ────────────────────────────
static void render_text(gdImagePtr img, const std::string& text, const std::string& font,
                        int start_x, int base_y) {
    int x = start_x;
    for (size_t i = 0; i < text.size(); i++) {
        char ch[2] = { text[i], '\0' };

        // Per-character variation — readable but anti-OCR
        double size = rand_double(28.0, 34.0);
        double angle = rand_double(-0.15, 0.15); // ~8 degrees (readable)
        int y_offset = rand_int(-4, 4);

        // Amber/gold color variation
        int r = rand_int(200, 255);
        int g = rand_int(140, 200);
        int b = rand_int(0, 30);
        int color = gdImageColorAllocate(img, r, g, b);

        int brect[8];
        gdImageStringFT(img, brect, color,
                         font.c_str(), size, angle,
                         x, base_y + y_offset, ch);

        // Advance x by character width + small gap
        int char_width = brect[2] - brect[0];
        x += char_width + rand_int(2, 8);
    }
}

// ── Convert gdImage to base64 data URI ───────────────────────────────────
static std::string image_to_data_uri(gdImagePtr img) {
    int size = 0;
    void* png_data = gdImagePngPtr(img, &size);
    if (!png_data || size <= 0) return "";

    std::string b64 = base64_encode((const unsigned char*)png_data, (size_t)size);
    gdFree(png_data);

    return "data:image/png;base64," + b64;
}

// ============================================================================
// Public API
// ============================================================================

namespace CaptchaGen {

CaptchaImage generate_text(const std::string& font_path) {
    CaptchaImage result;

    // Generate random text (5-6 chars)
    int len = rand_int(5, 6);
    for (int i = 0; i < len; i++) {
        result.answer += CHARSET[rand_int(0, CHARSET_LEN - 1)];
    }

    // Create image
    int w = 280, h = 80;
    gdImagePtr img = gdImageCreateTrueColor(w, h);

    // Dark background matching BackDraft theme
    int bg = gdImageColorAllocate(img, 10, 14, 26); // #0a0e1a
    gdImageFilledRectangle(img, 0, 0, w - 1, h - 1, bg);

    // Background gradient bands
    for (int i = 0; i < 3; i++) {
        int c = gdImageColorAllocate(img, rand_int(15, 30), rand_int(18, 35), rand_int(30, 50));
        int y1 = rand_int(0, h);
        gdImageFilledRectangle(img, 0, y1, w, y1 + rand_int(8, 20), c);
    }

    // Background noise
    draw_noise(img, w, h);

    // Render distorted text
    int start_x = rand_int(15, 30);
    int base_y = h / 2 + rand_int(8, 14);
    render_text(img, result.answer, font_path, start_x, base_y);

    // Confuser lines over text
    draw_confuser_lines(img, w, h);

    // Wave distortion
    gdImagePtr distorted = wave_distort(img, w, h);
    gdImageDestroy(img);

    // More noise on top of distorted image
    for (int i = 0; i < 40; i++) {
        int c = gdImageColorAllocate(distorted, rand_int(30, 100), rand_int(30, 80), rand_int(40, 100));
        gdImageSetPixel(distorted, rand_int(0, w - 1), rand_int(0, h - 1), c);
    }

    result.png_base64 = image_to_data_uri(distorted);
    gdImageDestroy(distorted);

    return result;
}

CaptchaImage generate_math(const std::string& font_path) {
    CaptchaImage result;

    int a = rand_int(1, 20);
    int b = rand_int(1, 20);
    int op_choice = rand_int(0, 2);

    std::string op_str;
    int answer;
    switch (op_choice) {
        case 0: op_str = "+"; answer = a + b; break;
        case 1: op_str = "-"; answer = a - b; if (answer < 0) { std::swap(a, b); answer = a - b; } break;
        default: op_str = "x"; a = rand_int(2, 9); b = rand_int(2, 9); answer = a * b; break;
    }

    std::string text = std::to_string(a) + " " + op_str + " " + std::to_string(b) + " = ?";
    result.answer = std::to_string(answer);

    // Create image
    int w = 280, h = 80;
    gdImagePtr img = gdImageCreateTrueColor(w, h);

    int bg = gdImageColorAllocate(img, 10, 14, 26);
    gdImageFilledRectangle(img, 0, 0, w - 1, h - 1, bg);

    // Gradient bands
    for (int i = 0; i < 3; i++) {
        int c = gdImageColorAllocate(img, rand_int(15, 30), rand_int(18, 35), rand_int(30, 50));
        int y1 = rand_int(0, h);
        gdImageFilledRectangle(img, 0, y1, w, y1 + rand_int(8, 20), c);
    }

    draw_noise(img, w, h);

    int start_x = rand_int(20, 40);
    int base_y = h / 2 + rand_int(8, 14);
    render_text(img, text, font_path, start_x, base_y);

    draw_confuser_lines(img, w, h);

    gdImagePtr distorted = wave_distort(img, w, h);
    gdImageDestroy(img);

    for (int i = 0; i < 40; i++) {
        int c = gdImageColorAllocate(distorted, rand_int(30, 100), rand_int(30, 80), rand_int(40, 100));
        gdImageSetPixel(distorted, rand_int(0, w - 1), rand_int(0, h - 1), c);
    }

    result.png_base64 = image_to_data_uri(distorted);
    gdImageDestroy(distorted);

    return result;
}

CaptchaImage generate(const std::string& font_path) {
    if (rand_int(0, 1) == 0) {
        return generate_text(font_path);
    } else {
        return generate_math(font_path);
    }
}

} // namespace CaptchaGen

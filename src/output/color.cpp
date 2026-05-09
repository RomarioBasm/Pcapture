#include "output/color.hpp"

#include <cstdlib>

#ifdef _WIN32
  #include <io.h>
  #include <stdio.h>
  #include <windows.h>
  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
    #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
#else
  #include <cstdio>
  #include <unistd.h>
#endif

namespace pcapture::format {

namespace {

// 24-bit ANSI escape sequences for the three brand colors. None are bolded:
// bold + bright-yellow tested as too loud at line rate. Plain foreground only
// — color is a hint, not a highlight, and the formatters use it sparingly so
// the eye still has somewhere to rest.
//
//   yellow  #FCB316  -> 252,179, 22
//   blue    #6DACDE  -> 109,172,222
//   green   #6D9A45  -> 109,154, 69
const Palette& kNoColor() {
    static const Palette p{"", "", "", "", "", "", "", ""};
    return p;
}

const Palette& kLogo() {
    // Brand triplet: yellow / blue / green. Address & metadata stay populated
    // so the existing compact and verbose formatters are unaffected; the new
    // table layout uses the accent/success/danger/dim slots instead.
    //
    // Red #D9534F isn't in the brand palette but semantic error signaling
    // beats palette purity — a dropped-frame counter that turns red is
    // immediately readable in a way that yellow-as-warning never is.
    //
    // Dim grey uses 256-color index 240 (~#585858). 24-bit truecolor would
    // give us exact #6B6B6B but 240 is the safer fallback for terminals that
    // claim VT but bungle 24-bit greys.
    static const Palette p{
        "\x1b[38;2;252;179;22m",   // protocol -- yellow
        "\x1b[38;2;109;172;222m",  // address  -- blue (legacy)
        "\x1b[38;2;109;154;69m",   // metadata -- green (legacy)
        "\x1b[38;2;109;172;222m",  // accent   -- blue
        "\x1b[38;2;109;154;69m",   // success  -- green
        "\x1b[38;2;217;83;79m",    // danger   -- red #D9534F
        "\x1b[38;5;240m",          // dim      -- grey
        "\x1b[0m",                 // reset
    };
    return p;
}

} // namespace

const Palette& no_color_palette() { return kNoColor(); }
const Palette& logo_palette()     { return kLogo(); }

bool resolve_enable(ColorMode mode,
                    bool sink_is_file,
                    bool is_tty,
                    bool no_color_env) {
    switch (mode) {
    case ColorMode::Always: return true;
    case ColorMode::Never:  return false;
    case ColorMode::Auto:
        if (sink_is_file)  return false;
        if (no_color_env)  return false;
        return is_tty;
    }
    return false;
}

const Palette& resolve_palette(ColorMode mode,
                               bool sink_is_file,
                               bool is_tty,
                               bool no_color_env) {
    return resolve_enable(mode, sink_is_file, is_tty, no_color_env)
        ? kLogo() : kNoColor();
}

bool enable_vt_processing_on_stdout() {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == nullptr) return false;
    DWORD mode = 0;
    // GetConsoleMode fails when stdout is a file or pipe, not a console — in
    // that case there is nothing to enable and nothing to fail; report success.
    if (!GetConsoleMode(h, &mode)) return true;
    return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    return true;
#endif
}

bool stdout_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

bool stderr_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

ConsoleUtf8Guard::ConsoleUtf8Guard() {
#ifdef _WIN32
    // GetConsoleOutputCP returns the current console output code page (or 0
    // if there's no console attached, e.g. when stdout is redirected to a
    // pipe). We unconditionally try to switch — it's a no-op for redirected
    // streams, and we'd rather succeed silently than gate on console-vs-file
    // detection that varies across cmd.exe / Windows Terminal / WSL bridges.
    previous_codepage_ = GetConsoleOutputCP();
    active_ = SetConsoleOutputCP(CP_UTF8) != 0;
#endif
}

ConsoleUtf8Guard::~ConsoleUtf8Guard() {
#ifdef _WIN32
    if (active_ && previous_codepage_ != 0) {
        SetConsoleOutputCP(previous_codepage_);
    }
#endif
}

bool no_color_env_set() {
    // https://no-color.org -- presence with non-empty value disables color.
#ifdef _WIN32
    // _dupenv_s avoids MSVC's CRT_SECURE warning on getenv. Free the buffer
    // even on miss; the API contract guarantees nullptr means "not set".
    char* v = nullptr;
    std::size_t len = 0;
    if (_dupenv_s(&v, &len, "NO_COLOR") != 0 || v == nullptr) return false;
    const bool set = v[0] != '\0';
    std::free(v);
    return set;
#else
    const char* v = std::getenv("NO_COLOR");
    return v != nullptr && v[0] != '\0';
#endif
}

} // namespace pcapture::format

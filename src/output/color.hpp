#pragma once

// Terminal color support for the human/compact formatters.
//
// Three semantic slots map to the three brand colors used in the project's
// logo. Formatters wrap output in the corresponding pre-rendered ANSI escape
// prefix and emit `reset` afterwards. When color is disabled, every prefix
// (and the reset) is the empty string, so the spans collapse into bare text
// without any conditional branching in the per-packet hot path.
//
//   protocol  yellow #FCB316  -- protocol/layer label (TCP, UDP, ipv4:, eth:)
//   address   blue   #6DACDE  -- MAC, IP literal, port number
//   metadata  green  #6D9A45  -- timestamps, flags, ttl/win/len/vlan, ethertype
//
// JSON output never carries color: it is a machine-consumable format and
// embedding ANSI sequences would make every consumer's parser deal with them.

#include <string>

namespace pcapture::format {

// Semantic color slots. The compact formatter still uses protocol/address/
// metadata directly; the new table-style human formatter and the panels use
// accent/success/danger/dim instead. When color is disabled every slot is the
// empty string so spans collapse to bare text without branching.
//
//   protocol  yellow #FCB316  -- proto badge in compact, title-strip rule
//   address   blue   #6DACDE  -- legacy, used by compact/verbose only
//   metadata  green  #6D9A45  -- legacy, used by compact/verbose only
//   accent    blue   #6DACDE  -- arrow "→", panel borders, neutral "●"
//   success   green  #6D9A45  -- "✓" icon, headline "0 drops" when zero
//   danger    red    #D9534F  -- "✗" icon, non-zero drop figures
//   dim       grey   240      -- IPv6 elision "…", separator rules, headers
struct Palette {
    std::string protocol;
    std::string address;
    std::string metadata;
    std::string accent;
    std::string success;
    std::string danger;
    std::string dim;
    std::string reset;
    bool enabled() const { return !reset.empty(); }
};

enum class ColorMode {
    Auto,    // colored on TTY, plain otherwise; honours NO_COLOR
    Always,  // colored regardless of destination
    Never,   // never colored
};

// Pre-rendered no-op palette (all four strings empty).
const Palette& no_color_palette();
// Pre-rendered logo palette (24-bit ANSI sequences for the three brand colors).
const Palette& logo_palette();

// Pure decision function: given the user's mode and three environmental facts,
// return whether color should be enabled. No I/O, no env reads — the caller
// supplies the inputs so this can be unit-tested without a TTY.
//
// `sink_is_file` short-circuits Auto mode to "no" because users almost never
// want raw escape sequences sitting in a captured-output file.
bool resolve_enable(ColorMode mode,
                    bool sink_is_file,
                    bool is_tty,
                    bool no_color_env_set);

// Convenience: resolve and return the matching pre-rendered palette by ref.
const Palette& resolve_palette(ColorMode mode,
                               bool sink_is_file,
                               bool is_tty,
                               bool no_color_env_set);

// On Windows console, enable ENABLE_VIRTUAL_TERMINAL_PROCESSING for stdout so
// ANSI escapes are interpreted instead of printed literally. On non-Windows
// platforms this is a no-op. Idempotent. Returns true on success or no-op;
// false only on Windows when the SetConsoleMode call genuinely failed on a
// real console handle.
bool enable_vt_processing_on_stdout();

// On Windows, switch the console output code page to UTF-8 (CP_UTF8 / 65001)
// for the lifetime of this object so multi-byte UTF-8 sequences in our output
// (logo glyph "▌", em-dash "—") render as glyphs instead of mojibake. Restores
// the previous code page on destruction so we don't permanently change the
// user's terminal. No-op on POSIX, where terminals are UTF-8 by default.
//
// Construct early in main() — before any text is written — so --version,
// --help, and the startup banner all benefit.
class ConsoleUtf8Guard {
public:
    ConsoleUtf8Guard();
    ~ConsoleUtf8Guard();
    ConsoleUtf8Guard(const ConsoleUtf8Guard&) = delete;
    ConsoleUtf8Guard& operator=(const ConsoleUtf8Guard&) = delete;

private:
#ifdef _WIN32
    unsigned int previous_codepage_ = 0;
    bool active_ = false;
#endif
};

// Stream-detection helpers, isolated here so application code does not need to
// touch platform headers.
bool stdout_is_tty();
bool stderr_is_tty();
bool no_color_env_set();

} // namespace pcapture::format

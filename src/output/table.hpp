#pragma once

// Table-style presentation for the human formatter and the shutdown panels.
// Pure rendering helpers — no global state, no I/O beyond the supplied
// ostream — so each function is unit-testable against a stringstream.
//
// The unit of width throughout this module is "display columns" (one per
// Unicode codepoint, ANSI escape sequences excluded) so the same writer can
// be handed pre-coloured payloads or plain text and still pad correctly.

#include "output/color.hpp"

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pcapture::format {

// Number of terminal columns occupied by `s` assuming each Unicode codepoint
// is single-cell. Skips UTF-8 continuation bytes and ANSI CSI escape
// sequences (ESC [ ... <final byte 0x40-0x7E>) so colored payloads measure
// the same as their plain equivalents. Wide CJK isn't accounted for — we
// don't emit any.
std::size_t display_width(std::string_view s);

// Right-pad `s` with spaces so its display width reaches `cols`. If `s` is
// already wider, no truncation — visible bytes are never cut, the row just
// gets pushed out of alignment.
void write_left_aligned(std::ostream& out, std::string_view s, std::size_t cols);

// Left-pad `s` with spaces so its display width reaches `cols`.
void write_right_aligned(std::ostream& out, std::string_view s, std::size_t cols);

// Repeat the U+2500 BOX DRAWINGS LIGHT HORIZONTAL glyph `count` times,
// optionally wrapped in `color_prefix`/`reset`.
void write_dashes(std::ostream& out, std::size_t count,
                  std::string_view color_prefix, std::string_view reset);

// IPv6 elision: when `addr_with_port` (e.g. "[2001:db8::1]:443") exceeds
// `max_cols`, return an elided form keeping the leading bytes and the last
// few bytes inside the brackets, joined by a U+2026 HORIZONTAL ELLIPSIS. The
// "[...]:port" structure is preserved. IPv4 is returned unchanged. The
// ellipsis itself is wrapped in `dim_color`/`reset` when supplied so it
// recedes behind the surviving address fragments.
std::string elide_address(std::string_view addr_with_port,
                          std::size_t max_cols,
                          std::string_view dim_color,
                          std::string_view reset);

// Format a byte count for the `size` column: "999 B", "1.2 KB", "3.4 MB",
// "5.6 GB". Decimal (1000-based) — matches user-facing sizes everywhere
// outside of disk usage. Always emits two display tokens separated by a
// single space.
std::string format_byte_size(std::uint64_t bytes);

// === Title strip ===
// "─── <title> ─────────...─  <suffix>"  rendered with the title-strip
// accent (brand yellow) on the rules. `suffix` is appended on the right
// without padding; pass empty to suppress. `total_cols` is the maximum width
// the strip should aim for; the rule fills whatever isn't claimed by the
// title and the suffix.
void write_title_strip(std::ostream& out, const Palette& pal,
                       std::string_view title,
                       std::string_view suffix,
                       std::size_t total_cols);

// === Stat panels ===

// Status icon mapping for a panel row.
//   Ok      -> "✓" rendered with the success color (green)
//   Neutral -> "●" rendered with the accent color (blue)
//   Danger  -> "✗" rendered with the danger color (red)
//   Plain   -> blank space (used for purely informational rows like
//              `filtered` when the count is zero)
enum class StatusKind {
    Ok,
    Neutral,
    Danger,
    Plain,
};

struct PanelRow {
    StatusKind status = StatusKind::Plain;
    std::string label;
    std::uint64_t value = 0;
    // When set, rendered as " (N.N%)" after the value. Caller decides
    // whether to populate (e.g. hide when reference is zero so the suffix
    // doesn't carry meaningless 0/0 = NaN).
    std::optional<double> percent;
};

struct Panel {
    std::string title;
    std::vector<PanelRow> rows;
};

// Render two panels side-by-side. The shorter panel pads its column with
// blank lines so the taller panel finishes drawing on its own afterward.
// Both panels' inner widths are computed independently from their content;
// the gap between them is two spaces.
void write_panels(std::ostream& out, const Palette& pal,
                  const Panel& left, const Panel& right);

// Render a single panel, full width. Used for offline replay where the
// kernel-stats panel would just be three zero rows.
void write_panel(std::ostream& out, const Palette& pal, const Panel& p);

// === Per-frame table header ===

// Width budget in display columns, exposed so the title strip and the
// table header line up. The trailing column is `size`; the leading column
// is the timestamp.
constexpr std::size_t kRowIndent       = 2;
constexpr std::size_t kColTsWidth      = 10;
constexpr std::size_t kColProtoWidth   = 6;
constexpr std::size_t kColAddrWidth    = 32;
constexpr std::size_t kColArrowWidth   = 4;   // " -> " region (3 visible cols + 1 lead)
constexpr std::size_t kColFlagsWidth   = 5;
constexpr std::size_t kColWinWidth     = 5;
constexpr std::size_t kColSizeWidth    = 7;
constexpr std::size_t kColGap          = 3;

// Total display columns across one row, indent included. Used by the title
// strip so its rule and the table line up edge-to-edge.
constexpr std::size_t kTotalRowWidth =
    kRowIndent
    + kColTsWidth     + kColGap
    + kColProtoWidth  + kColGap
    + kColAddrWidth   + kColArrowWidth
    + kColAddrWidth   + kColGap
    + kColFlagsWidth  + kColGap
    + kColWinWidth    + kColGap
    + kColSizeWidth;

// Two lines: the labels row ("Δt  proto  src  ...") and the dashed rule
// beneath. Emitted once at capture start (HumanFormatter::prologue).
void write_table_header(std::ostream& out, const Palette& pal);

} // namespace pcapture::format

#include "output/table.hpp"

#include "output/banner.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>

namespace pcapture::format {

namespace {

// UTF-8 byte sequences for the glyphs this module emits. Spelled out as raw
// bytes so the source file's execution charset does not matter.
constexpr const char* kDash      = "\xE2\x94\x80"; // U+2500 ─
constexpr const char* kVert      = "\xE2\x94\x82"; // U+2502 │
constexpr const char* kCornerTL  = "\xE2\x94\x8C"; // U+250C ┌
constexpr const char* kCornerTR  = "\xE2\x94\x90"; // U+2510 ┐
constexpr const char* kCornerBL  = "\xE2\x94\x94"; // U+2514 └
constexpr const char* kCornerBR  = "\xE2\x94\x98"; // U+2518 ┘
constexpr const char* kArrow     = "\xE2\x86\x92"; // U+2192 →
constexpr const char* kEllipsis  = "\xE2\x80\xA6"; // U+2026 …
constexpr const char* kCheck     = "\xE2\x9C\x93"; // U+2713 ✓
constexpr const char* kCircle    = "\xE2\x97\x8F"; // U+25CF ●
constexpr const char* kCross     = "\xE2\x9C\x97"; // U+2717 ✗
constexpr const char* kDeltaCap  = "\xCE\x94";     // U+0394 Δ

void write_spaces(std::ostream& out, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) out << ' ';
}

// Render the status icon for a panel row, wrapped in the appropriate color.
void write_status_icon(std::ostream& out, const Palette& pal, StatusKind k) {
    switch (k) {
    case StatusKind::Ok:      out << pal.success << kCheck  << pal.reset; break;
    case StatusKind::Neutral: out << pal.accent  << kCircle << pal.reset; break;
    case StatusKind::Danger:  out << pal.danger  << kCross  << pal.reset; break;
    case StatusKind::Plain:   out << ' '; break;
    }
}

std::size_t status_icon_width() { return 1; } // every variant is one display col

// Render a panel into a list of fully-formed lines (one per terminal row,
// without the trailing newline). The vertical box characters bracket each
// content line so panels can be combined side-by-side trivially: just zip.
std::vector<std::string> render_panel_lines(const Palette& pal, const Panel& p) {
    // Compute interior width: the longest of (title + 2 padding cols) and
    // each row's "icon label value (suffix)" footprint. Numbers come out
    // right-aligned so width(value) = max digit count.
    const std::size_t title_cols = display_width(p.title) + 2; // ─ before, space after

    // Pre-build each row's pieces so we can measure once and emit once.
    struct RenderedRow {
        StatusKind status;
        std::string label;
        std::string value;
        std::string suffix; // "(N.N%)" or empty
    };
    std::vector<RenderedRow> rows;
    rows.reserve(p.rows.size());
    std::size_t label_w = 0;
    std::size_t value_w = 0;
    std::size_t suffix_w = 0;
    for (const auto& r : p.rows) {
        RenderedRow rr;
        rr.status = r.status;
        rr.label  = r.label;
        rr.value  = std::to_string(r.value);
        if (r.percent) {
            char buf[16];
            std::snprintf(buf, sizeof buf, "(%.1f%%)", *r.percent);
            rr.suffix = buf;
        }
        label_w  = std::max(label_w,  display_width(rr.label));
        value_w  = std::max(value_w,  display_width(rr.value));
        suffix_w = std::max(suffix_w, display_width(rr.suffix));
        rows.push_back(std::move(rr));
    }

    // Inner width: 2 leading spaces + icon + space + label (padded) + 3 spaces
    //              + value (right-aligned) + 2 spaces + suffix (left-aligned)
    //              + 1 trailing space
    constexpr std::size_t kLeftPad   = 2;
    constexpr std::size_t kIconLabel = 1; // space between icon and label
    constexpr std::size_t kLabelVal  = 3; // gap between label and value
    constexpr std::size_t kValSuffix = 2; // gap before suffix
    constexpr std::size_t kRightPad  = 1;

    const std::size_t row_inner =
        kLeftPad + status_icon_width() + kIconLabel + label_w + kLabelVal
        + value_w + (suffix_w == 0 ? 0 : kValSuffix + suffix_w) + kRightPad;
    const std::size_t inner = std::max(title_cols, row_inner);

    std::vector<std::string> lines;
    lines.reserve(p.rows.size() + 2);

    // Top border: "┌─ <title> ─────────┐"
    {
        std::ostringstream s;
        s << pal.accent << kCornerTL << kDash << pal.reset
          << ' ' << p.title << ' ';
        std::size_t consumed = 1 /*corner*/ + 1 /*dash*/ + 1 /*space*/
                             + display_width(p.title) + 1 /*space*/;
        std::size_t remaining = (inner + 1 > consumed) ? (inner + 1 - consumed) : 0;
        s << pal.accent;
        for (std::size_t i = 0; i < remaining; ++i) s << kDash;
        s << kCornerTR << pal.reset;
        lines.push_back(s.str());
    }

    // Body: one line per row.
    for (const auto& rr : rows) {
        std::ostringstream s;
        s << pal.accent << kVert << pal.reset;
        write_spaces(s, kLeftPad);
        write_status_icon(s, pal, rr.status);
        write_spaces(s, kIconLabel);
        write_left_aligned(s, rr.label, label_w);
        write_spaces(s, kLabelVal);
        // Value gets danger color when the row's status is Danger so the
        // figure itself reads red, not just the icon.
        if (rr.status == StatusKind::Danger) {
            std::string padded;
            padded.reserve(value_w);
            for (std::size_t i = display_width(rr.value); i < value_w; ++i) padded += ' ';
            padded += rr.value;
            s << pal.danger << padded << pal.reset;
        } else {
            write_right_aligned(s, rr.value, value_w);
        }
        if (suffix_w > 0) {
            write_spaces(s, kValSuffix);
            write_left_aligned(s, rr.suffix, suffix_w);
        }
        // Pad to inner width.
        std::size_t row_w =
            kLeftPad + status_icon_width() + kIconLabel + label_w + kLabelVal
            + value_w + (suffix_w == 0 ? 0 : kValSuffix + suffix_w);
        write_spaces(s, (inner > row_w) ? (inner - row_w) : 0);
        s << pal.accent << kVert << pal.reset;
        lines.push_back(s.str());
    }

    // Bottom border: "└──...──┘"
    {
        std::ostringstream s;
        s << pal.accent << kCornerBL;
        for (std::size_t i = 0; i < inner; ++i) s << kDash;
        s << kCornerBR << pal.reset;
        lines.push_back(s.str());
    }

    return lines;
}

// Visible columns occupied by one rendered panel line, including the box-
// drawing borders on both sides.
std::size_t panel_line_width(std::string_view line) {
    return display_width(line);
}

} // namespace

std::size_t display_width(std::string_view s) {
    std::size_t w = 0;
    bool in_csi = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (in_csi) {
            // CSI ends at a final byte in [0x40, 0x7E].
            if (c >= 0x40 && c <= 0x7E) in_csi = false;
            continue;
        }
        if (c == 0x1B && i + 1 < s.size() && s[i + 1] == '[') {
            in_csi = true;
            ++i; // also consume the '['
            continue;
        }
        // UTF-8 continuation bytes are 10xx_xxxx — they do not start a new
        // codepoint, so they don't add a column.
        if ((c & 0xC0) == 0x80) continue;
        ++w;
    }
    return w;
}

void write_left_aligned(std::ostream& out, std::string_view s, std::size_t cols) {
    out << s;
    std::size_t w = display_width(s);
    if (w < cols) write_spaces(out, cols - w);
}

void write_right_aligned(std::ostream& out, std::string_view s, std::size_t cols) {
    std::size_t w = display_width(s);
    if (w < cols) write_spaces(out, cols - w);
    out << s;
}

void write_dashes(std::ostream& out, std::size_t count,
                  std::string_view color_prefix, std::string_view reset) {
    out << color_prefix;
    for (std::size_t i = 0; i < count; ++i) out << kDash;
    out << reset;
}

std::string elide_address(std::string_view addr_with_port,
                          std::size_t max_cols,
                          std::string_view dim_color,
                          std::string_view reset) {
    if (display_width(addr_with_port) <= max_cols) {
        return std::string{addr_with_port};
    }

    // IPv4 unaffected — never long enough to need elision and the format has
    // no closing-bracket marker to anchor on.
    const auto bracket_end = addr_with_port.rfind(']');
    if (addr_with_port.empty() || addr_with_port[0] != '[' ||
        bracket_end == std::string_view::npos) {
        return std::string{addr_with_port};
    }

    // Split into ip + ":port" so we never elide into the port number.
    const std::string_view ip_inside = addr_with_port.substr(1, bracket_end - 1);
    const std::string_view tail = addr_with_port.substr(bracket_end); // "]:port"

    const std::size_t fixed_cost = 2 /*[]*/ + display_width(tail) - 1 /*]*/ ;
    // Budget for (lead + ellipsis + trail) inside the brackets.
    if (max_cols <= fixed_cost + 3) {
        // Even at minimum (1 + 1 + 1) we don't fit; just truncate.
        std::string out{addr_with_port.substr(0, max_cols)};
        return out;
    }
    const std::size_t inner_budget = max_cols - fixed_cost - 1 /*ellipsis*/;
    // Bias slightly toward the leading bytes (network prefix is usually more
    // diagnostically useful than the suffix), but keep enough trailing bytes
    // to recognise the host portion.
    const std::size_t lead = (inner_budget * 5 + 4) / 8;  // ~62%
    const std::size_t trail = inner_budget - lead;

    std::string result;
    result.reserve(addr_with_port.size());
    result += '[';
    result.append(ip_inside.substr(0, lead));
    result.append(dim_color);
    result.append(kEllipsis);
    result.append(reset);
    result.append(ip_inside.substr(ip_inside.size() - trail));
    result.append(tail);
    return result;
}

std::string format_byte_size(std::uint64_t bytes) {
    // Decimal units (KB = 1000 B, etc.) — matches what users see in network
    // tools (Wireshark's "Length", curl's progress) and avoids the Wikipedia-
    // class binary/decimal debate at the cost of being technically imprecise
    // about "memory-style" KiB/MiB. The packet sizes we render are wire
    // bytes, so decimal is the right choice anyway.
    constexpr std::uint64_t kK = 1000;
    constexpr std::uint64_t kM = kK * 1000;
    constexpr std::uint64_t kG = kM * 1000;
    char buf[24];
    if (bytes < kK) {
        std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(bytes));
    } else if (bytes < kM) {
        std::snprintf(buf, sizeof buf, "%.1f KB",
                      static_cast<double>(bytes) / static_cast<double>(kK));
    } else if (bytes < kG) {
        std::snprintf(buf, sizeof buf, "%.1f MB",
                      static_cast<double>(bytes) / static_cast<double>(kM));
    } else {
        std::snprintf(buf, sizeof buf, "%.1f GB",
                      static_cast<double>(bytes) / static_cast<double>(kG));
    }
    return buf;
}

void write_title_strip(std::ostream& out, const Palette& pal,
                       std::string_view title,
                       std::string_view suffix,
                       std::size_t total_cols) {
    // Layout: "─── <title> ──...── [▌▌▌] ──...──  <suffix>"
    //
    //   3 lead dashes + space + title + space
    //   + left_fill dashes + space + logo (5 cols) + space + right_fill dashes
    //   + 2 spaces + suffix
    //
    // The trailing rule is split in two with the logo glyph centred between
    // the halves — the section header reads from left to right as
    // "section opens — section name — brand mark — counters". Left and right
    // dash counts are kept ≈ equal so the logo sits at the geometric middle
    // of the post-title rule, not just plopped near the suffix.
    constexpr std::size_t kLeadDashes = 3;
    constexpr std::size_t kLogoCols   = 7; // "[ ▌▌▌ ]" — see banner.cpp
    constexpr std::size_t kSuffixGap  = 2;

    const std::size_t title_w  = display_width(title);
    const std::size_t suffix_w = display_width(suffix);

    // Bytes that aren't fill: the title, the spaces flanking the title, the
    // logo region (1 space + glyph + 1 space), and the suffix region.
    const std::size_t fixed_cost =
        kLeadDashes + 1 + title_w + 1
        + 1 + kLogoCols + 1
        + (suffix_w == 0 ? 0 : kSuffixGap + suffix_w);

    // Floor of 6 so a too-narrow `total_cols` still produces a recognisable
    // strip rather than collapsing to nothing.
    const std::size_t fill = (total_cols > fixed_cost) ? (total_cols - fixed_cost) : 6;
    const std::size_t left_fill  = fill / 2;
    const std::size_t right_fill = fill - left_fill;

    write_dashes(out, kLeadDashes, pal.protocol, pal.reset);
    out << ' ' << title << ' ';
    write_dashes(out, left_fill, pal.protocol, pal.reset);
    out << ' ';
    write_logo_glyph(out, pal);
    out << ' ';
    write_dashes(out, right_fill, pal.protocol, pal.reset);
    if (suffix_w > 0) {
        write_spaces(out, kSuffixGap);
        out << suffix;
    }
    out << '\n';
}

void write_panel(std::ostream& out, const Palette& pal, const Panel& p) {
    auto lines = render_panel_lines(pal, p);
    for (const auto& line : lines) out << line << '\n';
}

void write_panels(std::ostream& out, const Palette& pal,
                  const Panel& left, const Panel& right) {
    auto l = render_panel_lines(pal, left);
    auto r = render_panel_lines(pal, right);
    const std::size_t l_w = l.empty() ? 0 : panel_line_width(l.front());
    const std::size_t rows = std::max(l.size(), r.size());
    constexpr const char* kGap = "  ";

    for (std::size_t i = 0; i < rows; ++i) {
        if (i < l.size()) {
            out << l[i];
        } else {
            // Left panel exhausted — pad spaces so the right panel still sits
            // at the same column the left one occupied.
            write_spaces(out, l_w);
        }
        if (i < r.size()) {
            out << kGap << r[i];
        }
        out << '\n';
    }
}

void write_table_header(std::ostream& out, const Palette& pal) {
    // Labels row.
    write_spaces(out, kRowIndent);
    out << pal.dim;
    // "Δt" — capital Greek delta + 't', display width 2.
    {
        std::ostringstream s;
        s << kDeltaCap << 't';
        write_left_aligned(out, s.str(), kColTsWidth);
    }
    write_spaces(out, kColGap);
    write_left_aligned(out, "proto", kColProtoWidth);
    write_spaces(out, kColGap);
    write_left_aligned(out, "src",   kColAddrWidth);
    write_spaces(out, kColArrowWidth);
    write_left_aligned(out, "dst",   kColAddrWidth);
    write_spaces(out, kColGap);
    write_left_aligned(out, "flags", kColFlagsWidth);
    write_spaces(out, kColGap);
    write_left_aligned(out, "win",   kColWinWidth);
    write_spaces(out, kColGap);
    write_left_aligned(out, "size",  kColSizeWidth);
    out << pal.reset << '\n';

    // Dashed rule beneath the labels. The arrow column stays blank — the
    // rule under the arrow would imply alignment that doesn't exist.
    write_spaces(out, kRowIndent);
    write_dashes(out, kColTsWidth,    pal.dim, pal.reset);
    write_spaces(out, kColGap);
    write_dashes(out, kColProtoWidth, pal.dim, pal.reset);
    write_spaces(out, kColGap);
    write_dashes(out, kColAddrWidth,  pal.dim, pal.reset);
    write_spaces(out, kColArrowWidth);
    write_dashes(out, kColAddrWidth,  pal.dim, pal.reset);
    write_spaces(out, kColGap);
    write_dashes(out, kColFlagsWidth, pal.dim, pal.reset);
    write_spaces(out, kColGap);
    write_dashes(out, kColWinWidth,   pal.dim, pal.reset);
    write_spaces(out, kColGap);
    write_dashes(out, kColSizeWidth,  pal.dim, pal.reset);
    out << '\n';
}

} // namespace pcapture::format

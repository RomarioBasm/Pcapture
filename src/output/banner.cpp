#include "output/banner.hpp"

#include <ostream>

namespace pcapture::format {
namespace {

constexpr const char* kProgramName    = "pcapture";
constexpr const char* kProgramVersion = "0.1.0";

// UTF-8 encoding of U+258C ▌ (LEFT HALF BLOCK). Each glyph paints the left
// half of its cell, so three of them in a row leave a half-cell of dead
// space on the right side. write_logo_glyph compensates by padding the
// inside of the brackets with a single space on each side ("[ ▌▌▌ ]") so
// the painted cluster sits visually centred between "[" and "]".
// Spelled out as raw bytes so the source file stays portable across
// compilers that disagree about the default execution character set.
constexpr const char* kBar = "\xE2\x96\x8C";

} // namespace

void write_logo_glyph(std::ostream& out, const Palette& pal) {
    // "[ ▌▌▌ ]" — the leading and trailing spaces compensate for the half-
    // cell of dead space the third LEFT HALF BLOCK leaves on the right of
    // its cell. Without them the three bars cluster visually against the
    // opening bracket. Total visible width: 7 columns.
    out << "[ ";
    out << pal.protocol << kBar << pal.reset;
    out << pal.address  << kBar << pal.reset;
    out << pal.metadata << kBar << pal.reset;
    out << " ]";
}

void write_program_banner(std::ostream& out, const Palette& pal) {
    write_logo_glyph(out, pal);
    out << ' ' << kProgramName << ' ' << kProgramVersion << '\n';
}

const char* program_name()    { return kProgramName; }
const char* program_version() { return kProgramVersion; }

} // namespace pcapture::format

#pragma once

// Logo-themed terminal output: the project's "[▌▌▌]" mark — bracket frame
// around three vertical bars in the brand colors — rendered via ANSI escape
// sequences when the supplied palette is enabled, plain when not. Used as a
// startup banner, version line, and section marker in the shutdown summary
// so every entry point shares one recognisable visual identity.

#include "output/color.hpp"

#include <iosfwd>

namespace pcapture::format {

// Renders "[▌▌▌]" with the three logo colors. When `pal` has no escape codes
// the bars are still emitted as plain glyphs so the motif is recognisable in
// uncolored output. The Unicode ▌ (U+258C, LEFT HALF BLOCK) renders cleanly
// in any VT-capable terminal — which we already require for color anyway.
void write_logo_glyph(std::ostream& out, const Palette& pal);

// One-liner: logo glyph + program name + version, ending in '\n'. Used at
// startup, on --version, and as a header decoration for the shutdown summary.
void write_program_banner(std::ostream& out, const Palette& pal);

// Centralised version constants. Other call sites (cxxopts help text, the
// version-string formatter) read them from here so the logo banner and the
// rest of the program never drift.
const char* program_name();
const char* program_version();

} // namespace pcapture::format

#include "output/hex_formatter.hpp"

#include <algorithm>
#include <cstdio>
#include <ostream>

namespace pcapture::util {

void hexdump(const std::uint8_t* data, std::size_t len, std::ostream& out) {
    constexpr std::size_t kBytesPerLine = 16;
    char line[80];

    for (std::size_t off = 0; off < len; off += kBytesPerLine) {
        const std::size_t row = std::min(kBytesPerLine, len - off);

        // Offset (8 hex digits)
        std::snprintf(line, sizeof line, "    %08zx  ", off);
        out << line;

        // Hex columns, two groups of 8 separated by an extra space.
        for (std::size_t i = 0; i < kBytesPerLine; ++i) {
            if (i < row) {
                std::snprintf(line, sizeof line, "%02x ", data[off + i]);
                out << line;
            } else {
                out << "   ";
            }
            if (i == 7) out << " ";
        }

        out << " |";
        for (std::size_t i = 0; i < row; ++i) {
            const auto c = data[off + i];
            out << static_cast<char>((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        out << "|\n";
    }
}

} // namespace pcapture::util

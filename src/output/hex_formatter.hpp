#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>

namespace pcapture::util {

// Verbose-mode aid: emit a canonical hex dump (offset / 16 bytes / ASCII).
void hexdump(const std::uint8_t* data, std::size_t len, std::ostream& out);

} // namespace pcapture::util

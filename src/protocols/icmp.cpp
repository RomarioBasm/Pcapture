#include "protocols/icmp.hpp"

namespace pcapture::decode::icmp {

constexpr std::size_t kMinSize = 4; // type:8 code:8 checksum:16

ParseError parse(const std::uint8_t* data, std::size_t len, Icmp& out, std::size_t& consumed, bool v6) {
    consumed = 0;
    if (len < kMinSize) return ParseError::TooShort;
    out.type = data[0];
    out.code = data[1];
    out.v6   = v6;
    consumed = kMinSize;
    return ParseError::Ok;
}

} // namespace pcapture::decode::icmp

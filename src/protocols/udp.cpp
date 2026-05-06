#include "protocols/udp.hpp"
#include "common/byte_reader.hpp"

namespace pcapture::decode::udp {

constexpr std::size_t kHeaderSize = 8;

ParseError parse(const std::uint8_t* data, std::size_t len, Udp& out, std::size_t& consumed) {
    consumed = 0;
    if (len < kHeaderSize) return ParseError::TooShort;

    out.sport  = read_be16(data + 0);
    out.dport  = read_be16(data + 2);
    out.length = read_be16(data + 4);
    // checksum at +6 (not modeled in v1)

    if (out.length < kHeaderSize) return ParseError::Malformed;

    consumed = kHeaderSize;
    return ParseError::Ok;
}

} // namespace pcapture::decode::udp

#include "protocols/ipv4.hpp"
#include "common/byte_reader.hpp"

#include <cstring>

namespace pcapture::decode::ipv4 {

ParseError parse(const std::uint8_t* data, std::size_t len, Ipv4& out, std::size_t& consumed) {
    consumed = 0;
    if (len < 20) return ParseError::TooShort;

    const std::uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) return ParseError::Malformed;

    const std::uint8_t ihl_words = data[0] & 0x0F;
    if (ihl_words < 5) return ParseError::Malformed; // header < 20 bytes

    const std::size_t header_bytes = static_cast<std::size_t>(ihl_words) * 4u;
    if (len < header_bytes) return ParseError::TooShort;

    out.ihl = ihl_words;
    out.total_length = read_be16(data + 2);
    const std::uint16_t flags_frag = read_be16(data + 6);
    out.flags = static_cast<std::uint8_t>((flags_frag >> 13) & 0x07);
    out.frag_offset = static_cast<std::uint16_t>(flags_frag & 0x1FFF);
    out.ttl = data[8];
    out.proto = data[9];
    std::memcpy(&out.src, data + 12, 4); // network byte order, kept as-is
    std::memcpy(&out.dst, data + 16, 4);
    out.src = ntohl(out.src);
    out.dst = ntohl(out.dst);

    consumed = header_bytes;
    return ParseError::Ok;
}

} // namespace pcapture::decode::ipv4

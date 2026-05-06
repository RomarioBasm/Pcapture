#include "protocols/ipv6.hpp"
#include "common/byte_reader.hpp"

#include <cstring>

namespace pcapture::decode::ipv6 {

constexpr std::size_t kHeaderSize = 40;

// IPv6 extension header type numbers we recognize and walk past. RFC 8200.
constexpr std::uint8_t kHopByHop  = 0;
constexpr std::uint8_t kRouting   = 43;
constexpr std::uint8_t kFragment  = 44;
constexpr std::uint8_t kDstOpts   = 60;
constexpr std::uint8_t kNoNext    = 59;

namespace {
bool is_extension(std::uint8_t nh) {
    return nh == kHopByHop || nh == kRouting || nh == kDstOpts || nh == kFragment;
}
} // namespace

ParseError parse(const std::uint8_t* data, std::size_t len, Ipv6& out, std::size_t& consumed) {
    consumed = 0;
    if (len < kHeaderSize) return ParseError::TooShort;

    const std::uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 6) return ParseError::Malformed;

    out.payload_length = read_be16(data + 4);
    out.next_header = data[6];
    out.hop_limit = data[7];
    std::memcpy(out.src.data(), data + 8, 16);
    std::memcpy(out.dst.data(), data + 24, 16);

    // Walk extension headers. RFC 8200: HBH/Routing/Dst use the format
    //   [next:8][hdr-ext-len:8][... 6 + hdr-ext-len*8 bytes total ...]
    // Fragment is always 8 bytes regardless of hdr-ext-len encoding.
    std::uint8_t nh = out.next_header;
    std::size_t off = kHeaderSize;
    std::uint16_t walked = 0;
    constexpr int kMaxExtHeaders = 16; // guard against pathological packets

    for (int i = 0; i < kMaxExtHeaders && is_extension(nh); ++i) {
        if (off + 2 > len) {
            // truncated; keep what we have, transport_proto stays at current nh
            out.transport_proto = nh;
            out.ext_header_bytes = walked;
            consumed = off > len ? len : off;
            return ParseError::Ok;
        }
        std::uint8_t next = data[off];
        std::size_t hdr_bytes;
        if (nh == kFragment) {
            hdr_bytes = 8;
            out.fragmented = true;
        } else {
            std::uint8_t hdr_ext_len = data[off + 1];
            hdr_bytes = static_cast<std::size_t>(hdr_ext_len + 1) * 8u;
        }
        if (off + hdr_bytes > len) {
            out.transport_proto = nh;
            out.ext_header_bytes = walked;
            consumed = len;
            return ParseError::Ok;
        }
        off += hdr_bytes;
        walked = static_cast<std::uint16_t>(walked + hdr_bytes);
        nh = next;
    }

    out.transport_proto = nh;
    out.ext_header_bytes = walked;
    consumed = off;
    if (nh == kNoNext) {
        // Indicate "no upper-layer protocol" by leaving consumed at end of
        // walked headers; caller will see len-consumed == 0 or skip L4.
    }
    return ParseError::Ok;
}

} // namespace pcapture::decode::ipv6

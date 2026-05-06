#include "protocols/vlan.hpp"
#include "common/byte_reader.hpp"

namespace pcapture::decode::vlan {

// 802.1Q tag is 4 bytes laid over the EtherType slot of an Ethernet frame:
//   [TPID:16][PCP:3][DEI:1][VID:12][next-EtherType-or-TPID:16]
// Caller already consumed the first 16-bit field as `tpid`; we receive the
// 4-byte TCI+nextType chunk starting at the byte after `tpid`. To keep the
// interface uniform with other parsers we accept the *full* 4-byte tag here:
// data[0..1] = TCI, data[2..3] = inner EtherType (returned to caller via the
// frame walk).

constexpr std::size_t kTagSize = 4;

ParseError parse(const std::uint8_t* data, std::size_t len, VlanTag& out, std::size_t& consumed) {
    consumed = 0;
    if (len < kTagSize) return ParseError::TooShort;
    const std::uint16_t tci = read_be16(data);
    out.pcp = static_cast<std::uint8_t>((tci >> 13) & 0x07);
    out.dei = ((tci >> 12) & 0x01) != 0;
    out.vid = static_cast<std::uint16_t>(tci & 0x0FFF);
    // tpid is filled in by the caller (it was the 16-bit field that selected
    // this parser); inner ethertype lives at data[2..3] and the caller reads
    // it from the next dispatch step. We only consume the 2 TCI bytes.
    consumed = 2;
    return ParseError::Ok;
}

} // namespace pcapture::decode::vlan

#include "protocols/arp.hpp"
#include "common/byte_reader.hpp"

#include <cstring>

namespace pcapture::decode::arp {

// ARP for IPv4 over Ethernet: 28 bytes total.
//   htype:16 ptype:16 hlen:8 plen:8 op:16
//   sha:6 spa:4 tha:6 tpa:4
constexpr std::size_t kEthIpSize = 28;

ParseError parse(const std::uint8_t* data, std::size_t len, Arp& out, std::size_t& consumed) {
    consumed = 0;
    if (len < kEthIpSize) return ParseError::TooShort;

    const std::uint16_t htype = read_be16(data + 0);
    const std::uint16_t ptype = read_be16(data + 2);
    const std::uint8_t hlen = data[4];
    const std::uint8_t plen = data[5];
    if (htype != 0x0001 || ptype != 0x0800 || hlen != 6 || plen != 4) {
        return ParseError::Unsupported; // only Ethernet/IPv4 ARP for v1
    }

    out.op = read_be16(data + 6);
    std::memcpy(out.sha.data(), data + 8, 6);
    std::memcpy(&out.spa, data + 14, 4);
    out.spa = ntohl(out.spa);
    std::memcpy(out.tha.data(), data + 18, 6);
    std::memcpy(&out.tpa, data + 24, 4);
    out.tpa = ntohl(out.tpa);

    consumed = kEthIpSize;
    return ParseError::Ok;
}

} // namespace pcapture::decode::arp

#include "common/checksum.hpp"

namespace pcapture::decode::checksum {
namespace {

// Sum bytes as 16-bit big-endian words, with a trailing zero pad for an odd
// length. Returns the unfolded 32-bit accumulator so callers can chain pseudo
// headers and the segment without losing carries — folding too early would
// drop high bits and produce wrong totals on long segments.
std::uint32_t sum_bytes(const std::uint8_t* data, std::size_t len) {
    std::uint32_t acc = 0;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        acc += (static_cast<std::uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (i < len) {
        acc += static_cast<std::uint32_t>(data[i]) << 8;
    }
    return acc;
}

// Add a 32-bit value (e.g. an IPv4 address in network order, viewed as bytes)
// into the running accumulator.
std::uint32_t add_be32(std::uint32_t acc, std::uint32_t v_be) {
    const std::uint8_t bytes[4] = {
        static_cast<std::uint8_t>((v_be >> 24) & 0xFFu),
        static_cast<std::uint8_t>((v_be >> 16) & 0xFFu),
        static_cast<std::uint8_t>((v_be >> 8)  & 0xFFu),
        static_cast<std::uint8_t>( v_be        & 0xFFu),
    };
    acc += (static_cast<std::uint32_t>(bytes[0]) << 8) | bytes[1];
    acc += (static_cast<std::uint32_t>(bytes[2]) << 8) | bytes[3];
    return acc;
}

std::uint16_t fold(std::uint32_t acc) {
    while (acc >> 16) {
        acc = (acc & 0xFFFFu) + (acc >> 16);
    }
    return static_cast<std::uint16_t>(acc);
}

bool finalize_ok(std::uint32_t acc) {
    // RFC 1071 verification trick: when you sum the full buffer (including
    // the original checksum field as-is, not zeroed), the folded result is
    // 0xFFFF iff nothing changed since the sender computed the checksum.
    // Lets us validate without recomputing-and-comparing.
    return fold(acc) == 0xFFFFu;
}

} // namespace

std::uint16_t internet_sum(const std::uint8_t* data, std::size_t len) {
    return fold(sum_bytes(data, len));
}

std::uint16_t fold_combine(std::uint32_t partial) {
    return fold(partial);
}

bool ipv4_header_ok(const std::uint8_t* hdr, std::size_t header_bytes) {
    if (header_bytes < 20) return false;
    return finalize_ok(sum_bytes(hdr, header_bytes));
}

namespace {

// IPv4 pseudo-header sum: src(4) + dst(4) + zero(1) + proto(1) + length(2).
// The pseudo-header is what binds an L4 checksum to its L3 envelope: it
// catches packets that have been mis-routed or whose addresses were
// rewritten without the checksum being updated, even if the L4 bytes
// themselves are intact. RFC 793 sec. 3.1 (TCP), RFC 768 (UDP).
std::uint32_t pseudo_v4(std::uint32_t src_be, std::uint32_t dst_be,
                        std::uint8_t proto, std::uint16_t l4_len) {
    std::uint32_t acc = 0;
    acc = add_be32(acc, src_be);
    acc = add_be32(acc, dst_be);
    acc += static_cast<std::uint32_t>(proto);   // zero(1) + proto(1)
    acc += l4_len;
    return acc;
}

std::uint32_t pseudo_v6(const std::array<std::uint8_t, 16>& src,
                        const std::array<std::uint8_t, 16>& dst,
                        std::uint8_t next_header,
                        std::uint32_t l4_len) {
    std::uint32_t acc = 0;
    acc += sum_bytes(src.data(), 16);
    acc += sum_bytes(dst.data(), 16);
    // RFC 8200 sec. 8.1: 32-bit upper-layer length, then 24 zero bits, then NH.
    acc += static_cast<std::uint16_t>((l4_len >> 16) & 0xFFFFu);
    acc += static_cast<std::uint16_t>( l4_len        & 0xFFFFu);
    acc += static_cast<std::uint32_t>(next_header);
    return acc;
}

bool tcp_ok_common(std::uint32_t pseudo, const std::uint8_t* l4, std::size_t l4_len) {
    return finalize_ok(pseudo + sum_bytes(l4, l4_len));
}

bool udp_ok_common(std::uint32_t pseudo, const std::uint8_t* l4, std::size_t l4_len,
                   bool checksum_optional) {
    if (l4_len < 8) return false;
    // UDP/IPv4 lets the sender skip the checksum entirely (RFC 768) by
    // writing 0 in the field. Treat that as "not validated" rather than
    // "bad", otherwise we'd flag legitimate DNS / DHCP / lots-of-old-traffic
    // as broken. UDP/IPv6 forbids this — caller passes optional=false there.
    const std::uint16_t cks = (static_cast<std::uint16_t>(l4[6]) << 8) | l4[7];
    if (cks == 0 && checksum_optional) return true;
    return finalize_ok(pseudo + sum_bytes(l4, l4_len));
}

} // namespace

bool tcp_v4_ok(const std::uint8_t* l4, std::size_t l4_len,
               std::uint32_t src_be, std::uint32_t dst_be) {
    if (l4_len < 20) return false;
    return tcp_ok_common(pseudo_v4(src_be, dst_be, 6,
                                   static_cast<std::uint16_t>(l4_len)),
                         l4, l4_len);
}

bool udp_v4_ok(const std::uint8_t* l4, std::size_t l4_len,
               std::uint32_t src_be, std::uint32_t dst_be) {
    if (l4_len < 8) return false;
    return udp_ok_common(pseudo_v4(src_be, dst_be, 17,
                                   static_cast<std::uint16_t>(l4_len)),
                         l4, l4_len, /*checksum_optional=*/true);
}

bool icmp_v4_ok(const std::uint8_t* l4, std::size_t l4_len) {
    if (l4_len < 4) return false;
    // No pseudo-header for ICMPv4: the protocol predates the address-binding
    // convention TCP/UDP adopted, and addresses aren't part of its checksum.
    // ICMPv6 reversed this — see icmp_v6_ok.
    return finalize_ok(sum_bytes(l4, l4_len));
}

bool tcp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
               const std::array<std::uint8_t, 16>& src,
               const std::array<std::uint8_t, 16>& dst) {
    if (l4_len < 20) return false;
    return tcp_ok_common(pseudo_v6(src, dst, 6, static_cast<std::uint32_t>(l4_len)),
                         l4, l4_len);
}

bool udp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
               const std::array<std::uint8_t, 16>& src,
               const std::array<std::uint8_t, 16>& dst) {
    if (l4_len < 8) return false;
    // IPv6 UDP checksum is mandatory (no zero-means-unset convention).
    return udp_ok_common(pseudo_v6(src, dst, 17, static_cast<std::uint32_t>(l4_len)),
                         l4, l4_len, /*checksum_optional=*/false);
}

bool icmp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
                const std::array<std::uint8_t, 16>& src,
                const std::array<std::uint8_t, 16>& dst) {
    if (l4_len < 4) return false;
    return finalize_ok(pseudo_v6(src, dst, 58, static_cast<std::uint32_t>(l4_len)) +
                       sum_bytes(l4, l4_len));
}

} // namespace pcapture::decode::checksum

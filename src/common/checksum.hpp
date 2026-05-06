#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Internet checksum (RFC 1071) + IPv4/IPv6 pseudo-header helpers.
// Used by the decoder when --check-checksums is enabled to surface bad
// checksums as DecodedPacket notes. Validation is opt-in because TX
// checksum offload routinely produces "wrong" checksums for
// locally-originated traffic on capture hosts.

namespace pcapture::decode::checksum {

// Folded 16-bit one's-complement sum over a byte buffer. Exposed for tests
// and for callers that need to combine sums across discontiguous regions
// (e.g. pseudo-header + segment) without re-walking the bytes.
std::uint16_t internet_sum(const std::uint8_t* data, std::size_t len);

// Combine two folded one's-complement sums. Useful when a caller has already
// summed part of a buffer and wants to fold in another partial.
std::uint16_t fold_combine(std::uint32_t partial);

// IPv4 header: returns true when the on-wire checksum field validates.
// IPv4 is the only L3 with a header-only checksum (IPv6 deliberately
// dropped this in favour of relying on L4 + link-layer integrity).
bool ipv4_header_ok(const std::uint8_t* hdr, std::size_t header_bytes);

// TCP / UDP / ICMP checksums require the whole L4 segment. `l4` points at
// the start of the L4 header; `l4_len` is the length of the L4 segment as
// reported by the L3 header (clamped to whatever was actually captured).
//
// For IPv4 transports, the pseudo-header consumes (src, dst, proto, length).
// For IPv6 transports, the pseudo-header consumes (src[16], dst[16], length, nh).
//
// Returns true on validate, false on mismatch.
bool tcp_v4_ok(const std::uint8_t* l4, std::size_t l4_len,
               std::uint32_t src_be, std::uint32_t dst_be);
bool udp_v4_ok(const std::uint8_t* l4, std::size_t l4_len,
               std::uint32_t src_be, std::uint32_t dst_be);
bool icmp_v4_ok(const std::uint8_t* l4, std::size_t l4_len);

bool tcp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
               const std::array<std::uint8_t, 16>& src,
               const std::array<std::uint8_t, 16>& dst);
bool udp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
               const std::array<std::uint8_t, 16>& src,
               const std::array<std::uint8_t, 16>& dst);
bool icmp_v6_ok(const std::uint8_t* l4, std::size_t l4_len,
                const std::array<std::uint8_t, 16>& src,
                const std::array<std::uint8_t, 16>& dst);

} // namespace pcapture::decode::checksum

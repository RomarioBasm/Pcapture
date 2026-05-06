#pragma once

#include "model/protocol_model.hpp"

#include <array>
#include <cstdint>
#include <cstddef>

namespace pcapture::decode {

struct DecodeOptions; // forward decl, defined in decoder.hpp

// ParseContext is the per-frame scratch space carried through the decoder
// chain. It exists because some L4 decisions (transport-layer checksum
// validation) require context the L3 decoder produced — without a typed
// carrier the parser would need an out-of-band side-channel.
//
// The parse context carries "cursor, remaining bytes, current layer hint"
// as the minimum content; the rest of the fields are inter-layer hints set
// by upstream decoders and read by downstream ones (never by the parser).
struct ParseContext {
    DecodedPacket* pkt = nullptr;
    const DecodeOptions* opts = nullptr;
    // Absolute offset of `data` within the original RawFrame. Used when
    // recording ParseErrorRecord / UnknownLayer so consumers can correlate
    // errors with hex dumps.
    std::size_t base_offset = 0;
    // Layer that pointed at the current decoder. Recorded on UnknownLayer
    // entries when a (parent, next_id) lookup misses.
    LayerId parent_layer = LayerId::Unknown;
    // The protocol identifier the parent advertised (ethertype, IP proto).
    // Decoders that need to surface their own dispatch tag — VLAN's TPID is
    // the textbook example — read it from here rather than re-reading bytes.
    std::uint32_t incoming_id = 0;

    // L3-side hints consumed by L4 decoders for transport-checksum validation.
    // Disabled by default; the IPv4/IPv6 decoders flip them on after they've
    // populated src/dst/segment-length.
    bool l4_checksum_enabled = false;
    bool ipv6 = false;
    std::uint32_t v4_src = 0;
    std::uint32_t v4_dst = 0;
    std::array<std::uint8_t, 16> v6_src{};
    std::array<std::uint8_t, 16> v6_dst{};
    std::size_t l4_segment_len = 0;
};

} // namespace pcapture::decode

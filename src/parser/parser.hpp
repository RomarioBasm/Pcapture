#pragma once

#include "model/raw_packet.hpp"
#include "model/protocol_model.hpp"

#include <memory>

namespace pcapture::decode {

class DecoderRegistry;

// Per-call decoder knobs. Kept as a struct (rather than free parameters) so
// new options can be added without breaking call sites or flipping arguments.
struct DecodeOptions {
    // Validate IPv4/TCP/UDP/ICMP/ICMPv6 checksums. Off by default because TX
    // checksum offload commonly produces "wrong" checksums for locally-
    // originated traffic, which would spam DecodedPacket::notes.
    bool check_checksums = false;
};

// Top-level entry point. Drives the registry-based decoder chain over a
// single raw frame. The default registry covers Ethernet/VLAN/IPv4/IPv6/
// ARP/TCP/UDP/ICMP/ICMPv6 and is built lazily on first call.
DecodedPacket decode(const capture::RawFrame& frame,
                     const DecodeOptions& opts = {});

// Same as above but lets the caller supply a custom registry — useful for
// tests that want to inject mock decoders or for future modes that disable
// some protocols.
DecodedPacket decode(const capture::RawFrame& frame,
                     const DecoderRegistry& registry,
                     const DecodeOptions& opts);

} // namespace pcapture::decode

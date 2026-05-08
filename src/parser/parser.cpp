#include "parser/parser.hpp"

#include "parser/decoder_registry.hpp"
#include "parser/parse_context.hpp"

#include <cstdio>
#include <memory>

namespace pcapture::decode {
namespace {

// One-time-built default registry. Built lazily so the cost is paid only by
// callers that go through the convenience overload.
const DecoderRegistry& default_registry() {
    static const std::shared_ptr<DecoderRegistry> kRegistry = build_default_registry();
    return *kRegistry;
}

// Cap on how deeply the parser will recurse through stacked protocols. Today
// only VLAN can recurse into itself (Q-in-Q); cap at 8 so a malicious packet
// can't drag the worker thread into pathological work.
constexpr int kMaxDecodeDepth = 8;

void record_unknown_layer(DecodedPacket& pkt, LayerId parent,
                          std::uint32_t next_id, std::size_t offset,
                          std::size_t length) {
    UnknownLayer u;
    u.parent = parent;
    u.next_id = next_id;
    u.byte_offset = static_cast<std::uint32_t>(offset);
    u.byte_length = static_cast<std::uint32_t>(length);
    pkt.unknown_layers.push_back(u);

    char buf[64];
    if (parent == LayerId::Ipv4 || parent == LayerId::Ipv6) {
        std::snprintf(buf, sizeof buf, "unknown L4 protocol %u%s",
                      static_cast<unsigned>(next_id),
                      parent == LayerId::Ipv6 ? " (v6)" : "");
    } else {
        std::snprintf(buf, sizeof buf, "unknown EtherType 0x%04x",
                      static_cast<unsigned>(next_id));
    }
    pkt.notes.emplace_back(buf);
}

void record_parse_error(DecodedPacket& pkt, LayerId layer, ParseError kind,
                        std::size_t offset, const char* fallback_message) {
    ParseErrorRecord rec;
    rec.layer = layer;
    rec.kind = kind;
    rec.offset = offset;
    rec.message = fallback_message;
    pkt.errors.push_back(rec);
    pkt.notes.emplace_back(rec.message);
}

const char* default_error_message(LayerId layer, ParseError kind) {
    switch (layer) {
    case LayerId::Ethernet: return "truncated Ethernet";
    case LayerId::Vlan:     return kind == ParseError::Malformed
                                   ? "malformed VLAN tag"
                                   : "truncated VLAN tag";
    case LayerId::Ipv4:     return "truncated/malformed IPv4";
    case LayerId::Ipv6:     return "truncated/malformed IPv6";
    case LayerId::Arp:      return kind == ParseError::Unsupported
                                   ? "unsupported ARP variant"
                                   : "truncated ARP";
    case LayerId::Tcp:      return "truncated/malformed TCP";
    case LayerId::Udp:      return "truncated/malformed UDP";
    case LayerId::Icmp:     return "truncated ICMP";
    case LayerId::Icmpv6:   return "truncated ICMPv6";
    default:                return "decode failed";
    }
}

} // namespace

DecodedPacket decode(const capture::RawFrame& frame, const DecodeOptions& opts) {
    return decode(frame, default_registry(), opts);
}

DecodedPacket decode(const capture::RawFrame& frame,
                     const DecoderRegistry& registry,
                     const DecodeOptions& opts) {
    DecodedPacket pkt;
    pkt.timestamp = frame.timestamp;
    pkt.seq = frame.seq;
    pkt.captured_len = frame.captured_len;
    pkt.original_len = frame.original_len;

    if (frame.bytes.empty()) return pkt;

    ProtocolDecoder* current = initial_decoder_for(frame.linktype, registry);
    if (!current) {
        // No decoder for this linktype. Surface as an unknown layer attached
        // to the frame; the caller can render a hex dump if it wants.
        record_unknown_layer(pkt, LayerId::Unknown,
                             static_cast<std::uint32_t>(frame.linktype),
                             0, frame.bytes.size());
        return pkt;
    }

    const std::uint8_t* const frame_base = frame.bytes.data();
    const std::uint8_t* data = frame_base;
    std::size_t remaining = frame.bytes.size();

    ParseContext ctx;
    ctx.pkt = &pkt;
    ctx.opts = &opts;
    ctx.parent_layer = LayerId::Unknown;

    int depth = 0;
    LayerId previous = LayerId::Unknown;
    std::uint32_t incoming_id = static_cast<std::uint32_t>(frame.linktype);
    while (current && depth < kMaxDecodeDepth) {
        ctx.base_offset = static_cast<std::size_t>(data - frame_base);
        ctx.parent_layer = previous;
        ctx.incoming_id = incoming_id;
        const LayerId this_layer = current->layer_id();

        DecodeResult r = current->decode(data, remaining, ctx);
        if (r.error != ParseError::Ok) {
            record_parse_error(pkt, this_layer, r.error, ctx.base_offset,
                               default_error_message(this_layer, r.error));
            return pkt;
        }

        // Advance cursor past the consumed bytes.
        if (r.consumed > remaining) r.consumed = remaining; // defensive
        data += r.consumed;
        remaining -= r.consumed;

        if (!r.has_next) {
            // Terminal layer (ARP, TCP/UDP/ICMP after which is application
            // payload). Done.
            return pkt;
        }

        ProtocolDecoder* next = registry.find(r.decoded_as, r.next_id);
        if (!next) {
            // Doc §8: unknown is information, not an error.
            record_unknown_layer(pkt, r.decoded_as, r.next_id,
                                 static_cast<std::size_t>(data - frame_base),
                                 remaining);
            return pkt;
        }
        previous = r.decoded_as;
        incoming_id = r.next_id;
        current = next;
        ++depth;
    }

    // Recursion-cap exit.
    if (depth >= kMaxDecodeDepth) {
        record_parse_error(pkt, LayerId::Unknown, ParseError::Unsupported,
                           static_cast<std::size_t>(data - frame_base),
                           "decode depth exceeded");
    }
    return pkt;
}

} // namespace pcapture::decode

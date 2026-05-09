#pragma once

// Decoded packet model. See the architecture notes for the full rationale.
//
// Two design rules drive the shape of this file:
//   1. Layers are tagged unions (variants), never null pointers — a frame
//      that stops at L2 is a valid DecodedPacket, not a half-built error.
//   2. Per-packet errors and unknown-layer markers are first-class data, not
//      log lines. The formatter renders them; nothing is silently dropped.

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace pcapture::decode {

// LayerId names every protocol the parser knows about, plus a sentinel for
// layers we couldn't identify. Used as the key in DecoderRegistry, in the
// per-packet `errors`/`unknown_layers` records, and (eventually) in the
// filter language. Adding a new protocol means adding a value here and
// registering a decoder against it.
enum class LayerId : std::uint16_t {
    Unknown = 0,
    Ethernet,
    Vlan,
    Ipv4,
    Ipv6,
    Arp,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
};

const char* to_string(LayerId);

using Mac = std::array<std::uint8_t, 6>;

struct Ethernet {
    Mac src{};
    Mac dst{};
    std::uint16_t ethertype = 0;
};

struct VlanTag {
    std::uint16_t tpid = 0;
    std::uint8_t pcp = 0;
    bool dei = false;
    std::uint16_t vid = 0;
    // EtherType immediately following this tag on the wire. For the innermost
    // tag this is the L3 protocol (e.g. 0x0800); for an outer tag in Q-in-Q
    // it is the next tag's TPID (0x8100 / 0x88A8). Recorded so formatters
    // can show what the tag actually points at without re-walking the chain.
    std::uint16_t inner_ethertype = 0;
};

struct Ipv4 {
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    std::uint8_t proto = 0;
    std::uint8_t ttl = 0;
    std::uint16_t total_length = 0;
    std::uint8_t flags = 0;
    std::uint16_t frag_offset = 0;
    std::uint8_t ihl = 0;
};

struct Ipv6 {
    std::array<std::uint8_t, 16> src{};
    std::array<std::uint8_t, 16> dst{};
    std::uint8_t next_header = 0;        // first header in the chain (raw)
    std::uint8_t transport_proto = 0;    // protocol after walking ext headers
    std::uint8_t hop_limit = 0;
    std::uint16_t payload_length = 0;
    std::uint16_t ext_header_bytes = 0;  // total length of ext headers walked
    bool fragmented = false;             // saw a Fragment header
};

struct Arp {
    std::uint16_t op = 0;
    Mac sha{};
    std::uint32_t spa = 0;
    Mac tha{};
    std::uint32_t tpa = 0;
};

struct Tcp {
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
};

struct Udp {
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint16_t length = 0;
};

struct Icmp {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    bool v6 = false;
};

using L3 = std::variant<std::monostate, Ipv4, Ipv6, Arp>;
using L4 = std::variant<std::monostate, Tcp, Udp, Icmp>;

struct PayloadSummary {
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
};

enum class ParseError {
    Ok,
    TooShort,
    Malformed,
    Unsupported,
};

const char* to_string(ParseError);

// One non-fatal decode failure attached to a packet. The run continues,
// the packet is still emitted, and consumers (formatters,
// filters) can render or branch on `kind`/`layer`. The `offset` is the byte
// position inside the captured frame where decoding gave up — useful for
// post-mortems with hex dumps.
struct ParseErrorRecord {
    LayerId layer = LayerId::Unknown;
    ParseError kind = ParseError::Ok;
    std::size_t offset = 0;
    std::string message;
};

// One layer the parser saw but had no decoder for. NOT an error — just data.
// `parent` is the layer that pointed at us; `next_id` is the protocol number
// the parent advertised (ethertype, IP protocol, etc.); `byte_offset`+
// `byte_length` describe where the unknown payload sits in the frame.
struct UnknownLayer {
    LayerId parent = LayerId::Unknown;
    std::uint32_t next_id = 0;
    std::uint32_t byte_offset = 0;
    std::uint32_t byte_length = 0;
};

struct DecodedPacket {
    std::chrono::system_clock::time_point timestamp;
    std::uint64_t seq = 0;          // mirrored from RawFrame::seq for output
    std::uint32_t captured_len = 0;
    std::uint32_t original_len = 0;

    std::optional<Ethernet> ethernet;
    std::vector<VlanTag> vlan_tags;
    L3 l3;
    L4 l4;
    PayloadSummary payload;

    // Typed per-packet errors. Tier 2 of the parse contract: parse always
    // returns a packet; trouble is reported here.
    std::vector<ParseErrorRecord> errors;
    // Layers we saw but couldn't decode (unknown ethertype/proto). Per the
    // doc, "unknown is not an error; it's information."
    std::vector<UnknownLayer> unknown_layers;

    // Free-text notes, kept for the human formatter and for things that are
    // neither parse errors nor unknown layers (e.g. "ipv6 fragmented").
    std::vector<std::string> notes;
};

} // namespace pcapture::decode

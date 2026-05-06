#pragma once

#include "parser/parse_context.hpp"
#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>

namespace pcapture::decode {

// Outcome of a single decoder call. The parser consumes `consumed` bytes,
// then looks up `(decoded_as, next_id)` in the registry to find the next
// decoder. `has_next == false` ends the chain (e.g. TCP is terminal — the
// rest is application payload).
struct DecodeResult {
    std::size_t consumed = 0;
    LayerId decoded_as = LayerId::Unknown;
    std::uint32_t next_id = 0;
    bool has_next = false;
    ParseError error = ParseError::Ok;
};

// One protocol header. Concrete implementations adapt the free-function
// decoders (ethernet::parse, ipv4::parse, ...) into a polymorphic shape so
// the parser can treat every layer uniformly.
//
// Decoder contract: "A decoder reads its bytes, validates
// them, populates its layer-specific struct, and tells the parser what to
// dispatch next. Decoders do not call each other directly, do not perform
// I/O, and do not know about output formatting."
class ProtocolDecoder {
public:
    virtual ~ProtocolDecoder() = default;
    virtual LayerId layer_id() const = 0;
    virtual DecodeResult decode(const std::uint8_t* data, std::size_t len,
                                ParseContext& ctx) = 0;
};

// Maps (parent_layer, next_protocol_id) to the decoder that handles that
// transition. The parser owns one of these; nothing else needs to know how
// dispatch is implemented.
//
// Adding a new protocol: write a ProtocolDecoder, register it under all
// (parent, id) pairs that should dispatch to it. The parser is untouched.
class DecoderRegistry {
public:
    void register_decoder(LayerId parent, std::uint32_t next_id,
                          std::shared_ptr<ProtocolDecoder> decoder);
    // nullptr if no decoder is registered for the (parent, next_id) tuple.
    ProtocolDecoder* find(LayerId parent, std::uint32_t next_id) const;

    // Per-linktype starting decoder. Set via register_initial; queried via
    // find_initial. Today only DLT_EN10MB is wired; non-Ethernet datalinks
    // are surfaced as fatal errors at open-time, so this is intentionally
    // sparse.
    void register_initial(int linktype, std::shared_ptr<ProtocolDecoder> decoder);
    ProtocolDecoder* find_initial(int linktype) const;

private:
    std::map<std::pair<LayerId, std::uint32_t>, std::shared_ptr<ProtocolDecoder>> map_;
    std::map<int, std::shared_ptr<ProtocolDecoder>> initial_;
};

// Build a DecoderRegistry pre-loaded with every protocol the project
// currently supports. Callers typically build it once and reuse.
std::shared_ptr<DecoderRegistry> build_default_registry();

// The starting decoder for a given linktype. For DLT_EN10MB this is the
// Ethernet decoder; other linktypes return nullptr (caller should record an
// error).
ProtocolDecoder* initial_decoder_for(int linktype, const DecoderRegistry&);

} // namespace pcapture::decode

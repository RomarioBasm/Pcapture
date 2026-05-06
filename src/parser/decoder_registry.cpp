#include "parser/decoder_registry.hpp"

#include "protocols/arp.hpp"
#include "common/byte_reader.hpp"
#include "common/checksum.hpp"
#include "parser/parser.hpp"
#include "protocols/ethernet.hpp"
#include "protocols/icmp.hpp"
#include "protocols/ipv4.hpp"
#include "protocols/ipv6.hpp"
#include "protocols/tcp.hpp"
#include "protocols/udp.hpp"
#include "protocols/vlan.hpp"

namespace pcapture::decode {

void DecoderRegistry::register_decoder(LayerId parent, std::uint32_t next_id,
                                       std::shared_ptr<ProtocolDecoder> decoder) {
    map_[{parent, next_id}] = std::move(decoder);
}

ProtocolDecoder* DecoderRegistry::find(LayerId parent, std::uint32_t next_id) const {
    const auto it = map_.find({parent, next_id});
    return it == map_.end() ? nullptr : it->second.get();
}

void DecoderRegistry::register_initial(int linktype,
                                       std::shared_ptr<ProtocolDecoder> decoder) {
    initial_[linktype] = std::move(decoder);
}

ProtocolDecoder* DecoderRegistry::find_initial(int linktype) const {
    const auto it = initial_.find(linktype);
    return it == initial_.end() ? nullptr : it->second.get();
}

namespace {

// libpcap DLT_EN10MB. Hardcoded so this header doesn't have to drag <pcap.h>
// into the model layer (architecture rule: protocols/decoders/model never
// include OS or capture-library headers).
constexpr int kDltEn10Mb = 1;

// Each adapter is a small class that calls the existing free-function
// parser, populates the right field on DecodedPacket, and tells the parser
// what comes next. Keeping the wire-format logic in the free functions
// means the existing unit tests in test_decoders.cpp still target a stable
// API; the registry is purely an orchestration layer on top.

class EthernetDecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Ethernet; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Ethernet;
        Ethernet eth{};
        std::size_t used = 0;
        if (ethernet::parse(data, len, eth, used) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->ethernet = eth;
        r.consumed = used;
        r.next_id = eth.ethertype;
        r.has_next = true;
        return r;
    }
};

class VlanDecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Vlan; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Vlan;
        if (len < 4) {
            r.error = ParseError::TooShort;
            return r;
        }
        VlanTag tag;
        std::size_t tci_used = 0;
        if (vlan::parse(data, len, tag, tci_used) != ParseError::Ok) {
            r.error = ParseError::Malformed;
            return r;
        }
        // The free parser only consumes 2 bytes of TCI; the next 2 bytes are
        // the inner ethertype. Promote the parent's id (the ethertype that
        // dispatched us — 0x8100 or 0x88a8) onto the tag so formatters can
        // distinguish C-VLAN from S-VLAN in Q-in-Q.
        tag.tpid = static_cast<std::uint16_t>(ctx.incoming_id);
        ctx.pkt->vlan_tags.push_back(tag);
        const std::uint16_t inner_ethertype = read_be16(data + 2);
        r.consumed = 4;
        r.next_id = inner_ethertype;
        r.has_next = true;
        return r;
    }
};

class Ipv4DecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Ipv4; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Ipv4;
        Ipv4 v4;
        std::size_t used = 0;
        if (ipv4::parse(data, len, v4, used) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->l3 = v4;
        const std::size_t hdr_bytes = static_cast<std::size_t>(v4.ihl) * 4u;
        if (ctx.opts && ctx.opts->check_checksums && hdr_bytes <= len) {
            if (!checksum::ipv4_header_ok(data, hdr_bytes)) {
                ParseErrorRecord rec;
                rec.layer = LayerId::Ipv4;
                rec.kind = ParseError::Malformed;
                rec.offset = ctx.base_offset;
                rec.message = "bad ipv4 header checksum";
                ctx.pkt->errors.push_back(rec);
                ctx.pkt->notes.emplace_back(rec.message);
            }
        }
        // L4 segment length per the IPv4 header, clamped to captured bytes.
        std::size_t l4_len = 0;
        if (v4.total_length > hdr_bytes) {
            l4_len = static_cast<std::size_t>(v4.total_length) - hdr_bytes;
        }
        const std::size_t avail = (len > used) ? (len - used) : 0;
        if (l4_len > avail) l4_len = avail;

        const bool more_frags = (v4.flags & 0x1) != 0;
        const bool not_first  = v4.frag_offset != 0;

        ctx.l4_checksum_enabled = (ctx.opts && ctx.opts->check_checksums) && !more_frags && !not_first;
        ctx.ipv6 = false;
        ctx.v4_src = v4.src;
        ctx.v4_dst = v4.dst;
        ctx.l4_segment_len = l4_len;

        r.consumed = used;
        r.next_id = v4.proto;
        r.has_next = true;
        return r;
    }
};

class Ipv6DecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Ipv6; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Ipv6;
        Ipv6 v6;
        std::size_t used = 0;
        if (ipv6::parse(data, len, v6, used) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->l3 = v6;
        if (v6.fragmented) ctx.pkt->notes.emplace_back("ipv6 fragmented (non-first or first frag)");
        if (v6.ext_header_bytes > 0) {
            char b[64];
            std::snprintf(b, sizeof b, "ipv6 ext-headers=%u bytes",
                          static_cast<unsigned>(v6.ext_header_bytes));
            ctx.pkt->notes.emplace_back(b);
        }
        std::size_t l4_len = 0;
        if (v6.payload_length > v6.ext_header_bytes) {
            l4_len = static_cast<std::size_t>(v6.payload_length) - v6.ext_header_bytes;
        }
        const std::size_t avail = (len > used) ? (len - used) : 0;
        if (l4_len > avail) l4_len = avail;

        ctx.l4_checksum_enabled = (ctx.opts && ctx.opts->check_checksums) && !v6.fragmented;
        ctx.ipv6 = true;
        ctx.v6_src = v6.src;
        ctx.v6_dst = v6.dst;
        ctx.l4_segment_len = l4_len;

        r.consumed = used;
        r.next_id = v6.transport_proto;
        r.has_next = true;
        return r;
    }
};

class ArpDecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Arp; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Arp;
        Arp a;
        std::size_t used = 0;
        const auto rc = arp::parse(data, len, a, used);
        if (rc == ParseError::Ok) {
            ctx.pkt->l3 = a;
            r.consumed = used;
            return r; // ARP is terminal
        }
        r.error = rc;
        return r;
    }
};

class TcpDecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Tcp; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Tcp;
        Tcp t;
        std::size_t used = 0;
        if (tcp::parse(data, len, t, used) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->l4 = t;
        if (ctx.l4_checksum_enabled && ctx.l4_segment_len > 0 && ctx.l4_segment_len <= len) {
            const bool ok = ctx.ipv6
                ? checksum::tcp_v6_ok(data, ctx.l4_segment_len, ctx.v6_src, ctx.v6_dst)
                : checksum::tcp_v4_ok(data, ctx.l4_segment_len, ctx.v4_src, ctx.v4_dst);
            if (!ok) {
                ParseErrorRecord rec;
                rec.layer = LayerId::Tcp;
                rec.kind = ParseError::Malformed;
                rec.offset = ctx.base_offset;
                rec.message = "bad tcp checksum";
                ctx.pkt->errors.push_back(rec);
                ctx.pkt->notes.emplace_back(rec.message);
            }
        }
        ctx.pkt->payload = {static_cast<std::uint32_t>(used),
                            static_cast<std::uint32_t>(len > used ? len - used : 0)};
        r.consumed = used;
        return r;
    }
};

class UdpDecoderImpl final : public ProtocolDecoder {
public:
    LayerId layer_id() const override { return LayerId::Udp; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = LayerId::Udp;
        Udp u;
        std::size_t used = 0;
        if (udp::parse(data, len, u, used) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->l4 = u;
        if (ctx.l4_checksum_enabled && ctx.l4_segment_len > 0 && ctx.l4_segment_len <= len) {
            const bool ok = ctx.ipv6
                ? checksum::udp_v6_ok(data, ctx.l4_segment_len, ctx.v6_src, ctx.v6_dst)
                : checksum::udp_v4_ok(data, ctx.l4_segment_len, ctx.v4_src, ctx.v4_dst);
            if (!ok) {
                ParseErrorRecord rec;
                rec.layer = LayerId::Udp;
                rec.kind = ParseError::Malformed;
                rec.offset = ctx.base_offset;
                rec.message = "bad udp checksum";
                ctx.pkt->errors.push_back(rec);
                ctx.pkt->notes.emplace_back(rec.message);
            }
        }
        ctx.pkt->payload = {static_cast<std::uint32_t>(used),
                            static_cast<std::uint32_t>(len > used ? len - used : 0)};
        r.consumed = used;
        return r;
    }
};

class IcmpDecoderImpl final : public ProtocolDecoder {
public:
    explicit IcmpDecoderImpl(bool v6) : v6_(v6) {}
    LayerId layer_id() const override { return v6_ ? LayerId::Icmpv6 : LayerId::Icmp; }
    DecodeResult decode(const std::uint8_t* data, std::size_t len,
                        ParseContext& ctx) override {
        DecodeResult r;
        r.decoded_as = layer_id();
        Icmp ic;
        std::size_t used = 0;
        if (icmp::parse(data, len, ic, used, v6_) != ParseError::Ok) {
            r.error = ParseError::TooShort;
            return r;
        }
        ctx.pkt->l4 = ic;
        if (ctx.l4_checksum_enabled && ctx.l4_segment_len > 0 && ctx.l4_segment_len <= len) {
            const bool ok = v6_
                ? checksum::icmp_v6_ok(data, ctx.l4_segment_len, ctx.v6_src, ctx.v6_dst)
                : checksum::icmp_v4_ok(data, ctx.l4_segment_len);
            if (!ok) {
                ParseErrorRecord rec;
                rec.layer = layer_id();
                rec.kind = ParseError::Malformed;
                rec.offset = ctx.base_offset;
                rec.message = v6_ ? "bad icmpv6 checksum" : "bad icmp checksum";
                ctx.pkt->errors.push_back(rec);
                ctx.pkt->notes.emplace_back(rec.message);
            }
        }
        ctx.pkt->payload = {static_cast<std::uint32_t>(used),
                            static_cast<std::uint32_t>(len > used ? len - used : 0)};
        r.consumed = used;
        return r;
    }
private:
    bool v6_;
};

} // namespace

std::shared_ptr<DecoderRegistry> build_default_registry() {
    auto reg = std::make_shared<DecoderRegistry>();

    auto eth   = std::make_shared<EthernetDecoderImpl>();
    auto vlan  = std::make_shared<VlanDecoderImpl>();
    auto ipv4  = std::make_shared<Ipv4DecoderImpl>();
    auto ipv6  = std::make_shared<Ipv6DecoderImpl>();
    auto arp   = std::make_shared<ArpDecoderImpl>();
    auto tcp_  = std::make_shared<TcpDecoderImpl>();
    auto udp_  = std::make_shared<UdpDecoderImpl>();
    auto icmp_ = std::make_shared<IcmpDecoderImpl>(false);
    auto icmp6 = std::make_shared<IcmpDecoderImpl>(true);

    // Ethernet → ...
    reg->register_decoder(LayerId::Ethernet, 0x0800, ipv4);
    reg->register_decoder(LayerId::Ethernet, 0x86DD, ipv6);
    reg->register_decoder(LayerId::Ethernet, 0x0806, arp);
    reg->register_decoder(LayerId::Ethernet, 0x8100, vlan);
    reg->register_decoder(LayerId::Ethernet, 0x88A8, vlan);

    // VLAN → ... (same set; the parser caps Q-in-Q recursion depth)
    reg->register_decoder(LayerId::Vlan, 0x0800, ipv4);
    reg->register_decoder(LayerId::Vlan, 0x86DD, ipv6);
    reg->register_decoder(LayerId::Vlan, 0x0806, arp);
    reg->register_decoder(LayerId::Vlan, 0x8100, vlan);
    reg->register_decoder(LayerId::Vlan, 0x88A8, vlan);

    // L4 dispatch from IPv4 / IPv6
    reg->register_decoder(LayerId::Ipv4, 6,  tcp_);
    reg->register_decoder(LayerId::Ipv4, 17, udp_);
    reg->register_decoder(LayerId::Ipv4, 1,  icmp_);
    reg->register_decoder(LayerId::Ipv6, 6,  tcp_);
    reg->register_decoder(LayerId::Ipv6, 17, udp_);
    reg->register_decoder(LayerId::Ipv6, 58, icmp6);

    reg->register_initial(kDltEn10Mb, eth);
    return reg;
}

ProtocolDecoder* initial_decoder_for(int linktype, const DecoderRegistry& reg) {
    // 0 is what tests/in-process synthesis pass when they don't bother to set
    // a linktype on the RawFrame. Treat it as Ethernet — the project's
    // default — rather than failing every synthetic frame.
    const int effective = (linktype == 0) ? kDltEn10Mb : linktype;
    return reg.find_initial(effective);
}

} // namespace pcapture::decode

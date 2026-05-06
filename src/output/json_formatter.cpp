#include "output/formatter.hpp"

#include <chrono>
#include <cstdio>
#include <ostream>
#include <variant>

namespace pcapture::format {
namespace {

using namespace pcapture::decode;

void json_string(std::ostream& out, const std::string& s) {
    out << '"';
    for (char c : s) {
        switch (c) {
        case '"':  out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n";  break;
        case '\r': out << "\\r";  break;
        case '\t': out << "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char esc[8];
                std::snprintf(esc, sizeof esc, "\\u%04x", static_cast<unsigned>(c));
                out << esc;
            } else {
                out << c;
            }
        }
    }
    out << '"';
}

class JsonFormatter final : public Formatter {
public:
    void format(const DecodedPacket& pkt, std::ostream& out) override {
        const auto sec = std::chrono::duration_cast<std::chrono::microseconds>(
            pkt.timestamp.time_since_epoch()).count();

        out << "{\"ts_us\":" << sec
            << ",\"seq\":" << pkt.seq
            << ",\"caplen\":" << pkt.captured_len
            << ",\"len\":" << pkt.original_len;

        if (pkt.ethernet) {
            out << ",\"eth\":{\"src\":";
            json_string(out, format_mac(pkt.ethernet->src));
            out << ",\"dst\":";
            json_string(out, format_mac(pkt.ethernet->dst));
            out << ",\"ethertype\":" << pkt.ethernet->ethertype << "}";
        }

        if (!pkt.vlan_tags.empty()) {
            out << ",\"vlans\":[";
            bool first = true;
            for (const auto& v : pkt.vlan_tags) {
                if (!first) out << ",";
                first = false;
                out << "{\"vid\":" << v.vid
                    << ",\"pcp\":" << static_cast<int>(v.pcp)
                    << ",\"dei\":" << (v.dei ? "true" : "false") << "}";
            }
            out << "]";
        }

        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                out << ",\"ipv4\":{\"src\":";
                json_string(out, format_ipv4(l3.src));
                out << ",\"dst\":";
                json_string(out, format_ipv4(l3.dst));
                out << ",\"proto\":" << static_cast<int>(l3.proto)
                    << ",\"ttl\":" << static_cast<int>(l3.ttl)
                    << ",\"total_length\":" << l3.total_length << "}";
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                out << ",\"ipv6\":{\"src\":";
                json_string(out, format_ipv6(l3.src));
                out << ",\"dst\":";
                json_string(out, format_ipv6(l3.dst));
                out << ",\"next_header\":" << static_cast<int>(l3.next_header)
                    << ",\"hop_limit\":" << static_cast<int>(l3.hop_limit)
                    << ",\"payload_length\":" << l3.payload_length << "}";
            } else if constexpr (std::is_same_v<T, Arp>) {
                out << ",\"arp\":{\"op\":" << l3.op
                    << ",\"spa\":";  json_string(out, format_ipv4(l3.spa));
                out << ",\"tpa\":";  json_string(out, format_ipv4(l3.tpa));
                out << "}";
            }
        }, pkt.l3);

        std::visit([&](const auto& l4) {
            using T = std::decay_t<decltype(l4)>;
            if constexpr (std::is_same_v<T, Tcp>) {
                out << ",\"tcp\":{\"sport\":" << l4.sport
                    << ",\"dport\":" << l4.dport
                    << ",\"seq\":" << l4.seq
                    << ",\"ack\":" << l4.ack
                    << ",\"flags\":" << static_cast<int>(l4.flags)
                    << ",\"window\":" << l4.window << "}";
            } else if constexpr (std::is_same_v<T, Udp>) {
                out << ",\"udp\":{\"sport\":" << l4.sport
                    << ",\"dport\":" << l4.dport
                    << ",\"length\":" << l4.length << "}";
            } else if constexpr (std::is_same_v<T, Icmp>) {
                out << (l4.v6 ? ",\"icmpv6\":{" : ",\"icmp\":{")
                    << "\"type\":" << static_cast<int>(l4.type)
                    << ",\"code\":" << static_cast<int>(l4.code) << "}";
            }
        }, pkt.l4);

        if (!pkt.errors.empty()) {
            out << ",\"errors\":[";
            bool first = true;
            for (const auto& e : pkt.errors) {
                if (!first) out << ",";
                first = false;
                out << "{\"layer\":";
                json_string(out, to_string(e.layer));
                out << ",\"kind\":";
                json_string(out, to_string(e.kind));
                out << ",\"offset\":" << e.offset
                    << ",\"message\":";
                json_string(out, e.message);
                out << "}";
            }
            out << "]";
        }

        if (!pkt.unknown_layers.empty()) {
            out << ",\"unknown_layers\":[";
            bool first = true;
            for (const auto& u : pkt.unknown_layers) {
                if (!first) out << ",";
                first = false;
                out << "{\"parent\":";
                json_string(out, to_string(u.parent));
                out << ",\"next_id\":" << u.next_id
                    << ",\"offset\":" << u.byte_offset
                    << ",\"length\":" << u.byte_length << "}";
            }
            out << "]";
        }

        if (!pkt.notes.empty()) {
            out << ",\"notes\":[";
            bool first = true;
            for (const auto& n : pkt.notes) {
                if (!first) out << ",";
                first = false;
                json_string(out, n);
            }
            out << "]";
        }

        out << "}\n";
    }
};

} // namespace

std::unique_ptr<Formatter> make_json_formatter() {
    return std::make_unique<JsonFormatter>();
}

} // namespace pcapture::format

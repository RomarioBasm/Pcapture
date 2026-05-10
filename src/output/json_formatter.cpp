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

        // "v" is the schema version. Bump only on breaking field-shape changes
        // (renames, type changes, removals); additive changes do not bump it.
        out << "{\"v\":1,\"ts_us\":" << sec
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

        if (auto* v4 = std::get_if<Ipv4>(&pkt.l3)) {
            out << ",\"ipv4\":{\"src\":";
            json_string(out, format_ipv4(v4->src));
            out << ",\"dst\":";
            json_string(out, format_ipv4(v4->dst));
            out << ",\"proto\":" << static_cast<int>(v4->proto)
                << ",\"ttl\":" << static_cast<int>(v4->ttl)
                << ",\"total_length\":" << v4->total_length << "}";
        } else if (auto* v6 = std::get_if<Ipv6>(&pkt.l3)) {
            out << ",\"ipv6\":{\"src\":";
            json_string(out, format_ipv6(v6->src));
            out << ",\"dst\":";
            json_string(out, format_ipv6(v6->dst));
            out << ",\"next_header\":" << static_cast<int>(v6->next_header)
                << ",\"hop_limit\":" << static_cast<int>(v6->hop_limit)
                << ",\"payload_length\":" << v6->payload_length << "}";
        } else if (auto* ar = std::get_if<Arp>(&pkt.l3)) {
            out << ",\"arp\":{\"op\":" << ar->op
                << ",\"spa\":";  json_string(out, format_ipv4(ar->spa));
            out << ",\"tpa\":";  json_string(out, format_ipv4(ar->tpa));
            out << "}";
        }

        if (auto* t = std::get_if<Tcp>(&pkt.l4)) {
            out << ",\"tcp\":{\"sport\":" << t->sport
                << ",\"dport\":" << t->dport
                << ",\"seq\":" << t->seq
                << ",\"ack\":" << t->ack
                << ",\"flags\":" << static_cast<int>(t->flags)
                << ",\"window\":" << t->window << "}";
        } else if (auto* u = std::get_if<Udp>(&pkt.l4)) {
            out << ",\"udp\":{\"sport\":" << u->sport
                << ",\"dport\":" << u->dport
                << ",\"length\":" << u->length << "}";
        } else if (auto* c = std::get_if<Icmp>(&pkt.l4)) {
            out << (c->v6 ? ",\"icmpv6\":{" : ",\"icmp\":{")
                << "\"type\":" << static_cast<int>(c->type)
                << ",\"code\":" << static_cast<int>(c->code) << "}";
        }

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

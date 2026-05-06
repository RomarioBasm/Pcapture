#include "output/formatter.hpp"

#include <cstdio>
#include <ostream>
#include <variant>

namespace pcapture::format {
namespace {

using namespace pcapture::decode;

const char* tcp_flags_str(std::uint8_t f, char* buf, std::size_t cap) {
    // Order: CWR ECE URG ACK PSH RST SYN FIN
    std::snprintf(buf, cap, "%s%s%s%s%s%s%s%s",
        (f & 0x80) ? "C" : "",
        (f & 0x40) ? "E" : "",
        (f & 0x20) ? "U" : "",
        (f & 0x10) ? "A" : "",
        (f & 0x08) ? "P" : "",
        (f & 0x04) ? "R" : "",
        (f & 0x02) ? "S" : "",
        (f & 0x01) ? "F" : "");
    if (buf[0] == '\0') {
        std::snprintf(buf, cap, ".");
    }
    return buf;
}

// Render a one-line summary. Verbose mode then appends details.
void render_one_line(const DecodedPacket& pkt, std::ostream& out) {
    if (!pkt.ethernet) {
        out << "raw len=" << pkt.captured_len;
        return;
    }
    const auto& e = *pkt.ethernet;
    out << format_mac(e.src) << " > " << format_mac(e.dst);

    for (const auto& v : pkt.vlan_tags) {
        out << " vlan=" << v.vid;
    }

    std::visit([&](const auto& l3) {
        using T = std::decay_t<decltype(l3)>;
        if constexpr (std::is_same_v<T, Ipv4>) {
            out << " " << format_ipv4(l3.src) << " > " << format_ipv4(l3.dst);
            out << " ttl=" << static_cast<int>(l3.ttl);
        } else if constexpr (std::is_same_v<T, Ipv6>) {
            out << " " << format_ipv6(l3.src) << " > " << format_ipv6(l3.dst);
            out << " hlim=" << static_cast<int>(l3.hop_limit);
        } else if constexpr (std::is_same_v<T, Arp>) {
            out << " ARP " << (l3.op == 1 ? "request" : l3.op == 2 ? "reply" : "op?")
                << " who-has " << format_ipv4(l3.tpa)
                << " tell " << format_ipv4(l3.spa);
        }
    }, pkt.l3);

    std::visit([&](const auto& l4) {
        using T = std::decay_t<decltype(l4)>;
        if constexpr (std::is_same_v<T, Tcp>) {
            char fbuf[16];
            tcp_flags_str(l4.flags, fbuf, sizeof fbuf);
            out << " TCP " << l4.sport << " > " << l4.dport
                << " [" << fbuf << "] win=" << l4.window;
        } else if constexpr (std::is_same_v<T, Udp>) {
            out << " UDP " << l4.sport << " > " << l4.dport
                << " len=" << l4.length;
        } else if constexpr (std::is_same_v<T, Icmp>) {
            out << (l4.v6 ? " ICMPv6" : " ICMP")
                << " type=" << static_cast<int>(l4.type)
                << " code=" << static_cast<int>(l4.code);
        }
    }, pkt.l4);

    out << " caplen=" << pkt.captured_len;
    if (pkt.captured_len != pkt.original_len) {
        out << "/" << pkt.original_len;
    }
}

class HumanFormatter final : public Formatter {
public:
    explicit HumanFormatter(int verbosity) : verbosity_(verbosity) {}
    void format(const DecodedPacket& pkt, std::ostream& out) override {
        render_one_line(pkt, out);
        out << "\n";
        if (verbosity_ < 1) return;

        if (pkt.ethernet) {
            out << "    eth: src=" << format_mac(pkt.ethernet->src)
                << " dst=" << format_mac(pkt.ethernet->dst)
                << " ethertype=0x"
                << std::hex << pkt.ethernet->ethertype << std::dec << "\n";
        }
        for (const auto& v : pkt.vlan_tags) {
            out << "    vlan: vid=" << v.vid << " pcp=" << static_cast<int>(v.pcp)
                << " dei=" << (v.dei ? 1 : 0) << "\n";
        }
        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                out << "    ipv4: " << format_ipv4(l3.src) << " -> " << format_ipv4(l3.dst)
                    << " proto=" << static_cast<int>(l3.proto)
                    << " ttl=" << static_cast<int>(l3.ttl)
                    << " total=" << l3.total_length << "\n";
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                out << "    ipv6: " << format_ipv6(l3.src) << " -> " << format_ipv6(l3.dst)
                    << " next=" << static_cast<int>(l3.next_header)
                    << " hlim=" << static_cast<int>(l3.hop_limit)
                    << " plen=" << l3.payload_length << "\n";
            } else if constexpr (std::is_same_v<T, Arp>) {
                out << "    arp: op=" << l3.op
                    << " sha=" << format_mac(l3.sha) << " spa=" << format_ipv4(l3.spa)
                    << " tha=" << format_mac(l3.tha) << " tpa=" << format_ipv4(l3.tpa)
                    << "\n";
            }
        }, pkt.l3);
        std::visit([&](const auto& l4) {
            using T = std::decay_t<decltype(l4)>;
            if constexpr (std::is_same_v<T, Tcp>) {
                char fbuf[16];
                tcp_flags_str(l4.flags, fbuf, sizeof fbuf);
                out << "    tcp: " << l4.sport << " -> " << l4.dport
                    << " seq=" << l4.seq << " ack=" << l4.ack
                    << " flags=" << fbuf << " win=" << l4.window << "\n";
            } else if constexpr (std::is_same_v<T, Udp>) {
                out << "    udp: " << l4.sport << " -> " << l4.dport
                    << " len=" << l4.length << "\n";
            } else if constexpr (std::is_same_v<T, Icmp>) {
                out << (l4.v6 ? "    icmpv6: " : "    icmp: ")
                    << "type=" << static_cast<int>(l4.type)
                    << " code=" << static_cast<int>(l4.code) << "\n";
            }
        }, pkt.l4);
        for (const auto& n : pkt.notes) {
            out << "    note: " << n << "\n";
        }
    }
private:
    int verbosity_;
};

} // namespace

std::unique_ptr<Formatter> make_human_formatter(int verbosity) {
    return std::make_unique<HumanFormatter>(verbosity);
}

} // namespace pcapture::format

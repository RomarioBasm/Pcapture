#include "output/formatter.hpp"

#include <ostream>
#include <variant>

namespace pcapture::format {
namespace {

using namespace pcapture::decode;

class CompactFormatter final : public Formatter {
public:
    void format(const DecodedPacket& pkt, std::ostream& out) override {
        // protocol src dst caplen
        const char* proto = "?";
        std::string src, dst;
        std::uint16_t sport = 0, dport = 0;
        bool has_ports = false;

        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                src = format_ipv4(l3.src);
                dst = format_ipv4(l3.dst);
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                src = format_ipv6(l3.src);
                dst = format_ipv6(l3.dst);
            } else if constexpr (std::is_same_v<T, Arp>) {
                src = format_ipv4(l3.spa);
                dst = format_ipv4(l3.tpa);
                proto = "ARP";
            }
        }, pkt.l3);

        std::visit([&](const auto& l4) {
            using T = std::decay_t<decltype(l4)>;
            if constexpr (std::is_same_v<T, Tcp>) {
                proto = "TCP"; sport = l4.sport; dport = l4.dport; has_ports = true;
            } else if constexpr (std::is_same_v<T, Udp>) {
                proto = "UDP"; sport = l4.sport; dport = l4.dport; has_ports = true;
            } else if constexpr (std::is_same_v<T, Icmp>) {
                proto = l4.v6 ? "ICMPv6" : "ICMP";
            }
        }, pkt.l4);

        if (src.empty() && pkt.ethernet) {
            src = format_mac(pkt.ethernet->src);
            dst = format_mac(pkt.ethernet->dst);
            if (proto[0] == '?') proto = "ETH";
        }

        out << proto << " " << src;
        if (has_ports) out << ":" << sport;
        out << " " << dst;
        if (has_ports) out << ":" << dport;
        out << " " << pkt.captured_len << "\n";
    }
};

} // namespace

std::unique_ptr<Formatter> make_compact_formatter() {
    return std::make_unique<CompactFormatter>();
}

} // namespace pcapture::format

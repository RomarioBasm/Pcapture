#include "output/formatter.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <ostream>
#include <variant>

namespace pcapture::format {
namespace {

using namespace pcapture::decode;

class CompactFormatter final : public Formatter {
public:
    CompactFormatter(TimeFormat tf, const Palette& palette)
        : tf_(tf), pal_(palette) {}

    void format(const DecodedPacket& pkt, std::ostream& out) override {
        if (tf_ != TimeFormat::None) {
            out << pal_.metadata;
            write_timestamp(out, pkt, tf_, first_ts_);
            out << pal_.reset;
        }

        // Resolve protocol label and the address pair used in the header line.
        // Falls back to MAC src/dst when no L3 was decoded so an Ethernet-only
        // frame still shows useful identity rather than a bare "?".
        const char* proto = "?";
        std::string src, dst;
        std::uint16_t sport = 0, dport = 0;
        bool has_ports = false;
        bool is_ipv6 = false;

        if (auto* v4 = std::get_if<Ipv4>(&pkt.l3)) {
            src = format_ipv4(v4->src);
            dst = format_ipv4(v4->dst);
        } else if (auto* v6 = std::get_if<Ipv6>(&pkt.l3)) {
            src = format_ipv6(v6->src);
            dst = format_ipv6(v6->dst);
            is_ipv6 = true;
        } else if (auto* ar = std::get_if<Arp>(&pkt.l3)) {
            src = format_ipv4(ar->spa);
            dst = format_ipv4(ar->tpa);
            proto = "ARP";
        }

        const Tcp* tcp_ptr = nullptr;
        if (auto* t = std::get_if<Tcp>(&pkt.l4)) {
            proto = "TCP"; sport = t->sport; dport = t->dport; has_ports = true;
            tcp_ptr = t;
        } else if (auto* u = std::get_if<Udp>(&pkt.l4)) {
            proto = "UDP"; sport = u->sport; dport = u->dport; has_ports = true;
        } else if (auto* c = std::get_if<Icmp>(&pkt.l4)) {
            proto = c->v6 ? "ICMPv6" : "ICMP";
        }

        if (src.empty() && pkt.ethernet) {
            src = format_mac(pkt.ethernet->src);
            dst = format_mac(pkt.ethernet->dst);
            if (proto[0] == '?') proto = "ETH";
        }

        // Pad the protocol label to width 6 (matches the longest, "ICMPv6") so
        // adjacent rows align under one another for at-a-glance scanning. The
        // colour is picked by OSI layer (L2 yellow / L3 blue / L4 green) so
        // adjacent rows of mixed protocols are scannable on color alone.
        char proto_field[8];
        std::snprintf(proto_field, sizeof proto_field, "%-6s", proto);
        out << color_for_proto(pal_, proto) << proto_field << pal_.reset << ' ';

        // URL-style brackets around IPv6 keep the trailing port from visually
        // fusing with the address's last (zero-compressed) segment.
        const char* lb = is_ipv6 ? "[" : "";
        const char* rb = is_ipv6 ? "]" : "";

        out << pal_.address << lb << src << rb;
        if (has_ports) out << ':' << sport;
        out << pal_.reset << " > " << pal_.address << lb << dst << rb;
        if (has_ports) out << ':' << dport;
        out << pal_.reset;

        if (tcp_ptr) {
            char fbuf[16];
            tcp_flags_str(tcp_ptr->flags, fbuf, sizeof fbuf);
            out << ' ' << pal_.metadata << '[' << fbuf << ']' << pal_.reset;
        }
        out << ' ' << pal_.metadata << "len=" << pkt.captured_len << pal_.reset << '\n';
    }

private:
    TimeFormat tf_;
    const Palette& pal_;
    std::optional<std::chrono::system_clock::time_point> first_ts_;
};

} // namespace

std::unique_ptr<Formatter> make_compact_formatter(TimeFormat tf, const Palette& palette) {
    return std::make_unique<CompactFormatter>(tf, palette);
}

} // namespace pcapture::format

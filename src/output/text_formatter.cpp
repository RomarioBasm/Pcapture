#include "output/formatter.hpp"
#include "output/table.hpp"

#include <chrono>
#include <cstdio>
#include <optional>
#include <ostream>
#include <sstream>
#include <string_view>
#include <variant>

namespace pcapture::format {
namespace {

using namespace pcapture::decode;

// Layer-label column width. Pad short labels ("eth:", "tcp:") so values line
// up across consecutive lines no matter which layers are present. 8 fits the
// longest label ("icmpv6:") plus a trailing space.
constexpr int kLabelWidth = 8;

void write_label(std::ostream& out, const Palette& pal, const char* label) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%-*s", kLabelWidth, label);
    // Layer label colour mirrors the table-row proto cell: L2 (eth/vlan/arp)
    // -> yellow, L3 (ipv4/ipv6/icmp/icmpv6) -> blue, L4 (tcp/udp) -> green.
    // Anything that doesn't match (e.g. "note:") falls back to yellow.
    out << "    " << color_for_proto(pal, label) << buf << pal.reset;
}

// === Per-frame table row ============================================
// Builds an "endpoint" string of the form "<addr>:<port>" or "[<addr>]:<port>"
// for IPv6, then runs IPv6 elision so the column-aligned table caps at a
// reasonable max width without truncating the host portion outright.
std::string build_endpoint(const std::string& addr, bool is_ipv6,
                           bool has_port, std::uint16_t port) {
    std::string s;
    s.reserve(addr.size() + 8);
    if (is_ipv6) s += '[';
    s += addr;
    if (is_ipv6) s += ']';
    if (has_port) {
        s += ':';
        s += std::to_string(port);
    }
    return s;
}

// Emit a TCP-flag bracket like "[A]" or "[FA]". Empty flag set renders as
// "[.]" so the column never collapses to nothing.
std::string format_flags_bracketed(std::uint8_t flags) {
    char buf[16];
    tcp_flags_str(flags, buf, sizeof buf);
    std::string s;
    s.reserve(8);
    s += '[';
    s += buf;
    s += ']';
    return s;
}

// Render one row of the per-frame table. The `palette` controls coloring;
// when it's empty the function emits identical bytes minus the ANSI codes,
// so width-correct alignment depends only on display_width.
void render_table_row(const DecodedPacket& pkt,
                      const std::string& ts_field,
                      const Palette& pal,
                      std::ostream& out) {
    write_left_aligned(out, "", kRowIndent); // 2-space indent

    write_left_aligned(out, ts_field, kColTsWidth);
    write_left_aligned(out, "", kColGap);

    // Resolve protocol label: L4 wins over L3 ("TCP" rather than "IPv4")
    // because it's the more diagnostic identity at a glance.
    const char* proto = "ETH";
    bool is_arp = false;
    bool is_l2_only = std::holds_alternative<std::monostate>(pkt.l3);
    if      (std::holds_alternative<Ipv4>(pkt.l3)) proto = "IPv4";
    else if (std::holds_alternative<Ipv6>(pkt.l3)) proto = "IPv6";
    else if (std::holds_alternative<Arp>(pkt.l3))  { proto = "ARP"; is_arp = true; }
    if      (std::holds_alternative<Tcp>(pkt.l4)) proto = "TCP";
    else if (std::holds_alternative<Udp>(pkt.l4)) proto = "UDP";
    else if (auto* c = std::get_if<Icmp>(&pkt.l4)) proto = c->v6 ? "ICMPv6" : "ICMP";

    // Protocol cell — coloured by OSI layer (L2 yellow, L3 blue, L4 green)
    // and left-aligned. The column width covers "ICMPv6" exactly; shorter
    // labels right-pad with spaces.
    {
        std::ostringstream s;
        s << color_for_proto(pal, proto) << proto << pal.reset;
        write_left_aligned(out, s.str(), kColProtoWidth);
    }
    write_left_aligned(out, "", kColGap);

    // Endpoints. ARP shows IP-only. L2-only frames show MACs.
    std::string src_ep, dst_ep;
    bool is_ipv6 = false;
    std::uint16_t sport = 0, dport = 0;
    bool has_ports = false;
    std::uint8_t tcp_flags = 0;
    bool has_tcp_flags = false;
    std::optional<std::uint16_t> tcp_window;

    if (auto* t = std::get_if<Tcp>(&pkt.l4)) {
        sport = t->sport; dport = t->dport; has_ports = true;
        tcp_flags = t->flags; has_tcp_flags = true;
        tcp_window = t->window;
    } else if (auto* u = std::get_if<Udp>(&pkt.l4)) {
        sport = u->sport; dport = u->dport; has_ports = true;
    }

    if (is_arp) {
        const auto& a = std::get<Arp>(pkt.l3);
        src_ep = format_ipv4(a.spa);
        dst_ep = format_ipv4(a.tpa);
    } else if (is_l2_only && pkt.ethernet) {
        src_ep = format_mac(pkt.ethernet->src);
        dst_ep = format_mac(pkt.ethernet->dst);
    } else {
        std::string l3_src, l3_dst;
        if (auto* v4 = std::get_if<Ipv4>(&pkt.l3)) {
            l3_src = format_ipv4(v4->src);
            l3_dst = format_ipv4(v4->dst);
        } else if (auto* v6 = std::get_if<Ipv6>(&pkt.l3)) {
            l3_src = format_ipv6(v6->src);
            l3_dst = format_ipv6(v6->dst);
            is_ipv6 = true;
        }
        src_ep = build_endpoint(l3_src, is_ipv6, has_ports, sport);
        dst_ep = build_endpoint(l3_dst, is_ipv6, has_ports, dport);
    }

    // IPv6 elision down to the column width. IPv4 / MAC / ARP returned
    // unchanged.
    src_ep = elide_address(src_ep, kColAddrWidth, pal.dim, pal.reset);
    dst_ep = elide_address(dst_ep, kColAddrWidth, pal.dim, pal.reset);

    write_left_aligned(out, src_ep, kColAddrWidth);

    // Arrow region: " → " (1 leading space + arrow + 2 trailing spaces).
    out << ' ' << pal.accent << "\xE2\x86\x92" << pal.reset << "  ";

    write_left_aligned(out, dst_ep, kColAddrWidth);
    write_left_aligned(out, "", kColGap);

    // Flags. Empty when not TCP / not applicable.
    if (has_tcp_flags) {
        write_left_aligned(out, format_flags_bracketed(tcp_flags), kColFlagsWidth);
    } else {
        write_left_aligned(out, "", kColFlagsWidth);
    }
    write_left_aligned(out, "", kColGap);

    // Win — TCP only, right-aligned. Blank otherwise.
    if (tcp_window) {
        write_right_aligned(out, std::to_string(*tcp_window), kColWinWidth);
    } else {
        write_left_aligned(out, "", kColWinWidth);
    }
    write_left_aligned(out, "", kColGap);

    // Size — right-aligned, formatted with unit suffix.
    write_right_aligned(out, format_byte_size(pkt.captured_len), kColSizeWidth);
    out << '\n';
}

class HumanFormatter final : public Formatter {
public:
    HumanFormatter(int verbosity, TimeFormat tf, const Palette& palette)
        : verbosity_(verbosity), tf_(tf), pal_(palette) {}

    void prologue(std::ostream& out) override {
        // Table header only at default verbosity. -v / -vv use the layered
        // breakdown (one block per packet) where a fixed table header would
        // not align with the per-layer rows beneath each frame.
        if (verbosity_ == 0) {
            write_table_header(out, pal_);
        }
    }

    void format(const DecodedPacket& pkt, std::ostream& out) override {
        // Build the timestamp string up front so the row writer can pad it
        // like any other column. None mode renders as empty so the column
        // is just whitespace.
        std::string ts_field;
        if (tf_ != TimeFormat::None) {
            std::ostringstream s;
            write_timestamp(s, pkt, tf_, first_ts_);
            ts_field = s.str();
            // write_timestamp appends a trailing space; strip it for the
            // table column which provides its own padding.
            if (!ts_field.empty() && ts_field.back() == ' ') ts_field.pop_back();
        }

        if (verbosity_ == 0) {
            render_table_row(pkt, ts_field, pal_, out);
            return;
        }

        // Verbose modes: keep the previous human one-liner + per-layer
        // breakdown. Users opt into them precisely when the table density
        // isn't enough.
        if (!ts_field.empty()) out << ts_field << ' ';
        render_one_line_legacy(pkt, pal_, out);
        out << '\n';
        if (verbosity_ < 1) return;

        if (pkt.ethernet) {
            char etbuf[8];
            std::snprintf(etbuf, sizeof etbuf, "0x%04x",
                          static_cast<unsigned>(pkt.ethernet->ethertype));
            write_label(out, pal_, "eth:");
            out << "src=" << pal_.address << format_mac(pkt.ethernet->src) << pal_.reset
                << " dst=" << pal_.address << format_mac(pkt.ethernet->dst) << pal_.reset
                << " ethertype=" << etbuf;
            // The Ethernet ethertype field carries the VLAN TPID (0x8100 /
            // 0x88a8) when the frame is tagged. Annotate so the reader does
            // not mistake it for an L3 protocol number; the per-VLAN line
            // below carries the inner ethertype that actually identifies L3.
            if (!pkt.vlan_tags.empty()) {
                out << " (VLAN tag — see vlan: lines)";
            }
            out << '\n';
        }
        for (const auto& v : pkt.vlan_tags) {
            char tpbuf[8];
            char inbuf[8];
            std::snprintf(tpbuf, sizeof tpbuf, "0x%04x", static_cast<unsigned>(v.tpid));
            std::snprintf(inbuf, sizeof inbuf, "0x%04x",
                          static_cast<unsigned>(v.inner_ethertype));
            write_label(out, pal_, "vlan:");
            out << "tpid=" << tpbuf
                << " vid=" << v.vid
                << " pcp=" << static_cast<int>(v.pcp)
                << " dei=" << (v.dei ? 1 : 0)
                << " inner_ethertype=" << inbuf << '\n';
        }
        if (auto* v4 = std::get_if<Ipv4>(&pkt.l3)) {
            write_label(out, pal_, "ipv4:");
            out << pal_.address << format_ipv4(v4->src) << pal_.reset
                << " -> "
                << pal_.address << format_ipv4(v4->dst) << pal_.reset
                << " proto=" << static_cast<int>(v4->proto)
                << " ttl=" << static_cast<int>(v4->ttl)
                << " total=" << v4->total_length << '\n';
        } else if (auto* v6 = std::get_if<Ipv6>(&pkt.l3)) {
            write_label(out, pal_, "ipv6:");
            out << pal_.address << format_ipv6(v6->src) << pal_.reset
                << " -> "
                << pal_.address << format_ipv6(v6->dst) << pal_.reset
                << " next=" << static_cast<int>(v6->next_header)
                << " hlim=" << static_cast<int>(v6->hop_limit)
                << " plen=" << v6->payload_length << '\n';
        } else if (auto* ar = std::get_if<Arp>(&pkt.l3)) {
            write_label(out, pal_, "arp:");
            out << "op=" << ar->op
                << " sha=" << pal_.address << format_mac(ar->sha) << pal_.reset
                << " spa=" << pal_.address << format_ipv4(ar->spa) << pal_.reset
                << " tha=" << pal_.address << format_mac(ar->tha) << pal_.reset
                << " tpa=" << pal_.address << format_ipv4(ar->tpa) << pal_.reset
                << '\n';
        }
        if (auto* t = std::get_if<Tcp>(&pkt.l4)) {
            char fbuf[16];
            tcp_flags_str(t->flags, fbuf, sizeof fbuf);
            write_label(out, pal_, "tcp:");
            out << pal_.address << t->sport << pal_.reset << " -> "
                << pal_.address << t->dport << pal_.reset
                << " seq=" << t->seq << " ack=" << t->ack
                << " flags=" << pal_.metadata << fbuf << pal_.reset
                << " win=" << t->window << '\n';
        } else if (auto* u = std::get_if<Udp>(&pkt.l4)) {
            write_label(out, pal_, "udp:");
            out << pal_.address << u->sport << pal_.reset << " -> "
                << pal_.address << u->dport << pal_.reset
                << " len=" << u->length << '\n';
        } else if (auto* c = std::get_if<Icmp>(&pkt.l4)) {
            write_label(out, pal_, c->v6 ? "icmpv6:" : "icmp:");
            out << "type=" << static_cast<int>(c->type)
                << " code=" << static_cast<int>(c->code) << '\n';
        }
        for (const auto& n : pkt.notes) {
            write_label(out, pal_, "note:");
            out << n << '\n';
        }
    }

private:
    // Legacy one-liner kept as the lead-in for verbose mode where the row-
    // table format would compete with the per-layer breakdown beneath it.
    static void render_one_line_legacy(const DecodedPacket& pkt, const Palette& pal,
                                       std::ostream& out) {
        if (!pkt.ethernet) {
            out << "raw  " << pkt.captured_len << 'B';
            return;
        }
        const auto& e = *pkt.ethernet;
        out << pal.address << format_mac(e.src) << pal.reset
            << " > " << pal.address << format_mac(e.dst) << pal.reset;
        if (auto* v4 = std::get_if<Ipv4>(&pkt.l3)) {
            out << " " << pal.address << format_ipv4(v4->src) << pal.reset
                << " > " << pal.address << format_ipv4(v4->dst) << pal.reset
                << " ttl=" << static_cast<int>(v4->ttl);
        } else if (auto* v6 = std::get_if<Ipv6>(&pkt.l3)) {
            out << " " << pal.address << format_ipv6(v6->src) << pal.reset
                << " > " << pal.address << format_ipv6(v6->dst) << pal.reset
                << " hlim=" << static_cast<int>(v6->hop_limit);
        } else if (auto* ar = std::get_if<Arp>(&pkt.l3)) {
            out << " ARP "
                << (ar->op == 1 ? "request" : ar->op == 2 ? "reply" : "op?")
                << " who-has " << pal.address << format_ipv4(ar->tpa) << pal.reset
                << " tell "    << pal.address << format_ipv4(ar->spa) << pal.reset;
        }
        if (auto* t = std::get_if<Tcp>(&pkt.l4)) {
            char fbuf[16];
            tcp_flags_str(t->flags, fbuf, sizeof fbuf);
            out << " TCP " << t->sport << " > " << t->dport
                << " [" << fbuf << "] win=" << t->window;
        } else if (auto* u = std::get_if<Udp>(&pkt.l4)) {
            out << " UDP " << u->sport << " > " << u->dport
                << " len=" << u->length;
        } else if (auto* c = std::get_if<Icmp>(&pkt.l4)) {
            out << (c->v6 ? " ICMPv6" : " ICMP")
                << " type=" << static_cast<int>(c->type)
                << " code=" << static_cast<int>(c->code);
        }
        out << " caplen=" << pkt.captured_len;
        if (pkt.captured_len != pkt.original_len) {
            out << "/" << pkt.original_len;
        }
    }

    int verbosity_;
    TimeFormat tf_;
    const Palette& pal_;
    std::optional<std::chrono::system_clock::time_point> first_ts_;
};

} // namespace

std::unique_ptr<Formatter> make_human_formatter(int verbosity, TimeFormat tf,
                                                const Palette& palette) {
    return std::make_unique<HumanFormatter>(verbosity, tf, palette);
}

} // namespace pcapture::format

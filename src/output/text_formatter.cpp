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
    std::visit([&](const auto& l3) {
        using T = std::decay_t<decltype(l3)>;
        if constexpr (std::is_same_v<T, Ipv4>) proto = "IPv4";
        else if constexpr (std::is_same_v<T, Ipv6>) proto = "IPv6";
        else if constexpr (std::is_same_v<T, Arp>)  { proto = "ARP"; is_arp = true; }
    }, pkt.l3);
    std::visit([&](const auto& l4) {
        using T = std::decay_t<decltype(l4)>;
        if constexpr (std::is_same_v<T, Tcp>)  proto = "TCP";
        else if constexpr (std::is_same_v<T, Udp>)  proto = "UDP";
        else if constexpr (std::is_same_v<T, Icmp>) proto = l4.v6 ? "ICMPv6" : "ICMP";
    }, pkt.l4);

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

    std::visit([&](const auto& l4) {
        using T = std::decay_t<decltype(l4)>;
        if constexpr (std::is_same_v<T, Tcp>) {
            sport = l4.sport; dport = l4.dport; has_ports = true;
            tcp_flags = l4.flags; has_tcp_flags = true;
            tcp_window = l4.window;
        } else if constexpr (std::is_same_v<T, Udp>) {
            sport = l4.sport; dport = l4.dport; has_ports = true;
        }
    }, pkt.l4);

    if (is_arp) {
        const auto& a = std::get<Arp>(pkt.l3);
        src_ep = format_ipv4(a.spa);
        dst_ep = format_ipv4(a.tpa);
    } else if (is_l2_only && pkt.ethernet) {
        src_ep = format_mac(pkt.ethernet->src);
        dst_ep = format_mac(pkt.ethernet->dst);
    } else {
        std::string l3_src, l3_dst;
        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                l3_src = format_ipv4(l3.src);
                l3_dst = format_ipv4(l3.dst);
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                l3_src = format_ipv6(l3.src);
                l3_dst = format_ipv6(l3.dst);
                is_ipv6 = true;
            }
        }, pkt.l3);
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
        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                write_label(out, pal_, "ipv4:");
                out << pal_.address << format_ipv4(l3.src) << pal_.reset
                    << " -> "
                    << pal_.address << format_ipv4(l3.dst) << pal_.reset
                    << " proto=" << static_cast<int>(l3.proto)
                    << " ttl=" << static_cast<int>(l3.ttl)
                    << " total=" << l3.total_length << '\n';
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                write_label(out, pal_, "ipv6:");
                out << pal_.address << format_ipv6(l3.src) << pal_.reset
                    << " -> "
                    << pal_.address << format_ipv6(l3.dst) << pal_.reset
                    << " next=" << static_cast<int>(l3.next_header)
                    << " hlim=" << static_cast<int>(l3.hop_limit)
                    << " plen=" << l3.payload_length << '\n';
            } else if constexpr (std::is_same_v<T, Arp>) {
                write_label(out, pal_, "arp:");
                out << "op=" << l3.op
                    << " sha=" << pal_.address << format_mac(l3.sha) << pal_.reset
                    << " spa=" << pal_.address << format_ipv4(l3.spa) << pal_.reset
                    << " tha=" << pal_.address << format_mac(l3.tha) << pal_.reset
                    << " tpa=" << pal_.address << format_ipv4(l3.tpa) << pal_.reset
                    << '\n';
            }
        }, pkt.l3);
        std::visit([&](const auto& l4) {
            using T = std::decay_t<decltype(l4)>;
            if constexpr (std::is_same_v<T, Tcp>) {
                char fbuf[16];
                tcp_flags_str(l4.flags, fbuf, sizeof fbuf);
                write_label(out, pal_, "tcp:");
                out << pal_.address << l4.sport << pal_.reset << " -> "
                    << pal_.address << l4.dport << pal_.reset
                    << " seq=" << l4.seq << " ack=" << l4.ack
                    << " flags=" << pal_.metadata << fbuf << pal_.reset
                    << " win=" << l4.window << '\n';
            } else if constexpr (std::is_same_v<T, Udp>) {
                write_label(out, pal_, "udp:");
                out << pal_.address << l4.sport << pal_.reset << " -> "
                    << pal_.address << l4.dport << pal_.reset
                    << " len=" << l4.length << '\n';
            } else if constexpr (std::is_same_v<T, Icmp>) {
                write_label(out, pal_, l4.v6 ? "icmpv6:" : "icmp:");
                out << "type=" << static_cast<int>(l4.type)
                    << " code=" << static_cast<int>(l4.code) << '\n';
            }
        }, pkt.l4);
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
        std::visit([&](const auto& l3) {
            using T = std::decay_t<decltype(l3)>;
            if constexpr (std::is_same_v<T, Ipv4>) {
                out << " " << pal.address << format_ipv4(l3.src) << pal.reset
                    << " > " << pal.address << format_ipv4(l3.dst) << pal.reset
                    << " ttl=" << static_cast<int>(l3.ttl);
            } else if constexpr (std::is_same_v<T, Ipv6>) {
                out << " " << pal.address << format_ipv6(l3.src) << pal.reset
                    << " > " << pal.address << format_ipv6(l3.dst) << pal.reset
                    << " hlim=" << static_cast<int>(l3.hop_limit);
            } else if constexpr (std::is_same_v<T, Arp>) {
                out << " ARP "
                    << (l3.op == 1 ? "request" : l3.op == 2 ? "reply" : "op?")
                    << " who-has " << pal.address << format_ipv4(l3.tpa) << pal.reset
                    << " tell "    << pal.address << format_ipv4(l3.spa) << pal.reset;
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

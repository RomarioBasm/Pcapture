#include "output/formatter.hpp"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <ostream>
#include <string>
#include <string_view>

namespace pcapture::format {

std::string format_mac(const decode::Mac& mac) {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string format_ipv4(std::uint32_t addr_host_order) {
    in_addr a;
    a.s_addr = htonl(addr_host_order);
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof buf);
    return buf;
}

std::string format_ipv6(const std::array<std::uint8_t, 16>& addr) {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, addr.data(), buf, sizeof buf);
    return buf;
}

namespace {

// Case-insensitive prefix match — accepts "eth:" / "ETH" alike. We only need
// ASCII because every label this matches against is ASCII.
bool starts_with_ci(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const char a = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
        const char b = static_cast<char>(std::tolower(static_cast<unsigned char>(prefix[i])));
        if (a != b) return false;
    }
    return true;
}

} // namespace

const std::string& color_for_proto(const Palette& pal, std::string_view proto) {
    // L4 transport: TCP / UDP.
    if (starts_with_ci(proto, "tcp") || starts_with_ci(proto, "udp")) {
        return pal.success;
    }
    // L3 network: IPv4 / IPv6 / ARP / ICMP / ICMPv6.
    //
    // ARP is grouped with L3 to match this project's data model (Arp lives in
    // the L3 std::variant in protocol_model.hpp) and CLAUDE.md §3. A strict
    // OSI reading would put ARP at L2 since it has its own EtherType, but the
    // codebase has consistently classified it as L3 — colour follows the
    // model so the table reads the same as the parser sees the world.
    //
    // Order matters: match "icmp" before any future "ip" prefix.
    if (starts_with_ci(proto, "arp")  ||
        starts_with_ci(proto, "icmp") ||
        starts_with_ci(proto, "ipv4") ||
        starts_with_ci(proto, "ipv6") ||
        starts_with_ci(proto, "ip")) {
        return pal.accent;
    }
    // L2 link-layer (and the catch-all): ETH / VLAN / unknown.
    return pal.protocol;
}

const char* tcp_flags_str(std::uint8_t f, char* buf, std::size_t cap) {
    // Order: CWR ECE URG ACK PSH RST SYN FIN. tcpdump-like single-letter form.
    std::snprintf(buf, cap, "%s%s%s%s%s%s%s%s",
        (f & 0x80) ? "C" : "",
        (f & 0x40) ? "E" : "",
        (f & 0x20) ? "U" : "",
        (f & 0x10) ? "A" : "",
        (f & 0x08) ? "P" : "",
        (f & 0x04) ? "R" : "",
        (f & 0x02) ? "S" : "",
        (f & 0x01) ? "F" : "");
    if (buf[0] == '\0' && cap >= 2) {
        buf[0] = '.';
        buf[1] = '\0';
    }
    return buf;
}

namespace {

// Microseconds since unix epoch. Centralizes the conversion so each mode does
// not redo the duration_cast.
long long pkt_epoch_us(const decode::DecodedPacket& pkt) {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        pkt.timestamp.time_since_epoch()).count();
}

void write_relative(std::ostream& out,
                    const decode::DecodedPacket& pkt,
                    std::optional<std::chrono::system_clock::time_point>& first_ts) {
    if (!first_ts) first_ts = pkt.timestamp;
    const auto delta_us = std::chrono::duration_cast<std::chrono::microseconds>(
        pkt.timestamp - *first_ts).count();
    // Out-of-order frames (rare even in replay) would otherwise print an
    // ambiguous "+-N..." prefix. Splitting the sign keeps the format parseable.
    const char* sign = delta_us < 0 ? "-" : "+";
    const long long abs_us = delta_us < 0 ? -delta_us : delta_us;
    char buf[32];
    std::snprintf(buf, sizeof buf, "%s%lld.%06lld",
                  sign, abs_us / 1000000, abs_us % 1000000);
    out << buf;
}

void write_absolute_utc(std::ostream& out, const decode::DecodedPacket& pkt) {
    const auto us = pkt_epoch_us(pkt);
    const std::time_t secs = static_cast<std::time_t>(us / 1000000);
    const long long frac = us % 1000000;
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &secs);
#else
    gmtime_r(&secs, &tm_utc);
#endif
    char hms[16];
    std::strftime(hms, sizeof hms, "%H:%M:%S", &tm_utc);
    char full[32];
    std::snprintf(full, sizeof full, "%s.%06lld", hms, frac);
    out << full;
}

void write_epoch(std::ostream& out, const decode::DecodedPacket& pkt) {
    const auto us = pkt_epoch_us(pkt);
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld.%06lld", us / 1000000, us % 1000000);
    out << buf;
}

} // namespace

void write_timestamp(std::ostream& out,
                     const decode::DecodedPacket& pkt,
                     TimeFormat tf,
                     std::optional<std::chrono::system_clock::time_point>& first_ts) {
    switch (tf) {
    case TimeFormat::None:
        return;
    case TimeFormat::Relative: write_relative(out, pkt, first_ts); break;
    case TimeFormat::Absolute: write_absolute_utc(out, pkt); break;
    case TimeFormat::Epoch:    write_epoch(out, pkt); break;
    }
    out << ' ';
}

} // namespace pcapture::format

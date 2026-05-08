#pragma once

#include "model/protocol_model.hpp"
#include "output/color.hpp"

#include <chrono>
#include <iosfwd>
#include <memory>
#include <optional>

namespace pcapture::format {

// Selects how a packet's timestamp is printed by the human/compact formatters.
// JSON output is unaffected — it always emits epoch microseconds.
enum class TimeFormat {
    None,      // suppress the timestamp column entirely
    Relative,  // "+S.uuuuuu" since the first packet seen by this formatter
    Absolute,  // "HH:MM:SS.uuuuuu" in UTC (deterministic for golden tests)
    Epoch,     // seconds.microseconds since the Unix epoch
};

class Formatter {
public:
    virtual ~Formatter() = default;
    virtual void format(const decode::DecodedPacket& pkt, std::ostream& out) = 0; //pure virtual
    virtual void prologue(std::ostream& /*out*/) {}
    virtual void epilogue(std::ostream& /*out*/) {}
};

// verbosity: 0 = one-line, 1 = multi-line, 2 = multi-line + hex dump (the hex
// dump itself is emitted by the application loop, not the formatter, since it
// needs the raw frame bytes which the decoded model deliberately omits).
//
// `palette` is borrowed for the formatter's lifetime. Pass `no_color_palette()`
// for plain output, `logo_palette()` for ANSI-colored output, or whatever the
// application layer resolved from the user's --color choice. The default keeps
// existing call sites (notably tests) plain.
std::unique_ptr<Formatter> make_human_formatter(int verbosity,
                                                TimeFormat tf = TimeFormat::Relative,
                                                const Palette& palette = no_color_palette());
std::unique_ptr<Formatter> make_compact_formatter(TimeFormat tf = TimeFormat::Relative,
                                                  const Palette& palette = no_color_palette());
std::unique_ptr<Formatter> make_json_formatter();

// Helpers reused by formatters and tests.
std::string format_mac(const decode::Mac& mac);
std::string format_ipv4(std::uint32_t addr_host_order);
std::string format_ipv6(const std::array<std::uint8_t, 16>& addr);

// Write TCP flag letters (CWR ECE URG ACK PSH RST SYN FIN, in that order) into
// `buf`. An empty flag set renders as ".". Returns `buf` for chaining.
const char* tcp_flags_str(std::uint8_t flags, char* buf, std::size_t cap);

// Pick the palette slot used to colour a protocol or layer label, based on
// where the protocol sits in the OSI stack:
//
//   L2 (yellow)  ETH, VLAN  -- pal.protocol
//   L3 (blue)    IPv4, IPv6, ARP, ICMP, ICMPv6  -- pal.accent
//   L4 (green)   TCP, UDP  -- pal.success
//
// ARP follows the data model (Arp is part of the L3 variant in
// protocol_model.hpp) rather than the strict OSI reading. ICMP rides inside
// IP and is grouped with L3.
//
// Lookup is case-insensitive on the leading characters so verbose-mode
// labels ("eth:", "ipv4:", "tcp:") and table proto cells ("ETH", "IPv4",
// "TCP") share the same dispatch.
const std::string& color_for_proto(const Palette& pal, std::string_view proto);

// Render `pkt.timestamp` per `tf`, followed by a single trailing space. No-op
// when `tf == TimeFormat::None`. `first_ts` carries Relative-mode state across
// calls within one Formatter instance; it is set on the first invocation and
// read on subsequent ones.
void write_timestamp(std::ostream& out,
                     const decode::DecodedPacket& pkt,
                     TimeFormat tf,
                     std::optional<std::chrono::system_clock::time_point>& first_ts);

} // namespace pcapture::format

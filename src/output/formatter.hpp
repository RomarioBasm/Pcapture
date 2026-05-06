#pragma once

#include "model/protocol_model.hpp"

#include <iosfwd>
#include <memory>

namespace pcapture::format {

class Formatter {
public:
    virtual ~Formatter() = default;
    virtual void format(const decode::DecodedPacket& pkt, std::ostream& out) = 0;
    virtual void prologue(std::ostream& /*out*/) {}
    virtual void epilogue(std::ostream& /*out*/) {}
};

// verbosity: 0 = one-line, 1 = multi-line, 2 = multi-line + hex dump.
std::unique_ptr<Formatter> make_human_formatter(int verbosity);
std::unique_ptr<Formatter> make_compact_formatter();
std::unique_ptr<Formatter> make_json_formatter();

// Helpers reused by formatters and tests.
std::string format_mac(const decode::Mac& mac);
std::string format_ipv4(std::uint32_t addr_host_order);
std::string format_ipv6(const std::array<std::uint8_t, 16>& addr);

} // namespace pcapture::format

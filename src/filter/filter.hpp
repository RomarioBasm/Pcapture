#pragma once

#include "model/protocol_model.hpp"

#include <memory>
#include <string>
#include <vector>

namespace pcapture::filter {

class Filter {
public:
    virtual ~Filter() = default;
    virtual bool accept(const decode::DecodedPacket& pkt) const = 0;
};

// Compile a list of "key=value" predicates into an AND'd Filter. Returns
// nullptr and populates `error` on the first invalid token.
//
// Supported keys (all values are case-insensitive where it matters):
//   vlan=<vid>           any VLAN tag with the given vid
//   proto=tcp|udp|icmp|icmpv6|arp
//   ip=<v4 or v6>        matches L3 src or dst
//   src=<v4 or v6>
//   dst=<v4 or v6>
//   port=<n>             matches L4 sport or dport
//   sport=<n>
//   dport=<n>
//
// Predicates are AND'd. An empty list compiles to a pass-through.
std::unique_ptr<Filter> compile(const std::vector<std::string>& exprs, std::string& error);

// Pass-through filter, useful as a no-op default.
std::unique_ptr<Filter> pass_through();

} // namespace pcapture::filter

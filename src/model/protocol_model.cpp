#include "model/protocol_model.hpp"

namespace pcapture::decode {

const char* to_string(LayerId id) {
    switch (id) {
    case LayerId::Unknown:  return "unknown";
    case LayerId::Ethernet: return "ethernet";
    case LayerId::Vlan:     return "vlan";
    case LayerId::Ipv4:     return "ipv4";
    case LayerId::Ipv6:     return "ipv6";
    case LayerId::Arp:      return "arp";
    case LayerId::Tcp:      return "tcp";
    case LayerId::Udp:      return "udp";
    case LayerId::Icmp:     return "icmp";
    case LayerId::Icmpv6:   return "icmpv6";
    }
    return "?";
}

const char* to_string(ParseError e) {
    switch (e) {
    case ParseError::Ok:          return "ok";
    case ParseError::TooShort:    return "too-short";
    case ParseError::Malformed:   return "malformed";
    case ParseError::Unsupported: return "unsupported";
    }
    return "?";
}

} // namespace pcapture::decode

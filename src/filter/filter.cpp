#include "filter/filter.hpp"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <variant>

namespace pcapture::filter {
namespace {

using namespace pcapture::decode;

using Predicate = std::function<bool(const DecodedPacket&)>;

class Compound final : public Filter {
public:
    explicit Compound(std::vector<Predicate> ps) : preds_(std::move(ps)) {}
    bool accept(const DecodedPacket& pkt) const override {
        for (const auto& p : preds_) {
            if (!p(pkt)) return false;
        }
        return true;
    }
private:
    std::vector<Predicate> preds_;
};

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

bool parse_uint(const std::string& s, std::uint64_t& out) {
    if (s.empty()) return false;
    char* end = nullptr;
    auto v = std::strtoull(s.c_str(), &end, 10);
    if (!end || *end != '\0') return false;
    out = v;
    return true;
}

bool parse_v4(const std::string& s, std::uint32_t& out_host) {
    in_addr a;
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    out_host = ntohl(a.s_addr);
    return true;
}

bool parse_v6(const std::string& s, std::array<std::uint8_t, 16>& out) {
    in6_addr a;
    if (inet_pton(AF_INET6, s.c_str(), &a) != 1) return false;
    std::memcpy(out.data(), &a, 16);
    return true;
}

// Helpers to extract address/port views from the packet's L3/L4 variants.
bool l3_v4(const DecodedPacket& pkt, std::uint32_t& src, std::uint32_t& dst) {
    if (auto* v = std::get_if<Ipv4>(&pkt.l3)) { src = v->src; dst = v->dst; return true; }
    return false;
}
bool l3_v6(const DecodedPacket& pkt,
           std::array<std::uint8_t, 16>& src,
           std::array<std::uint8_t, 16>& dst) {
    if (auto* v = std::get_if<Ipv6>(&pkt.l3)) { src = v->src; dst = v->dst; return true; }
    return false;
}
bool l4_ports(const DecodedPacket& pkt, std::uint16_t& sport, std::uint16_t& dport) {
    if (auto* t = std::get_if<Tcp>(&pkt.l4)) { sport = t->sport; dport = t->dport; return true; }
    if (auto* u = std::get_if<Udp>(&pkt.l4)) { sport = u->sport; dport = u->dport; return true; }
    return false;
}

Predicate make_proto(const std::string& v, std::string& error) {
    auto vv = lower(v);
    if (vv == "tcp")    return [](const DecodedPacket& p){ return std::holds_alternative<Tcp>(p.l4); };
    if (vv == "udp")    return [](const DecodedPacket& p){ return std::holds_alternative<Udp>(p.l4); };
    if (vv == "icmp")   return [](const DecodedPacket& p){
        if (auto* i = std::get_if<Icmp>(&p.l4)) return !i->v6;
        return false;
    };
    if (vv == "icmpv6") return [](const DecodedPacket& p){
        if (auto* i = std::get_if<Icmp>(&p.l4)) return i->v6;
        return false;
    };
    if (vv == "arp")    return [](const DecodedPacket& p){ return std::holds_alternative<Arp>(p.l3); };
    error = "unknown proto '" + v + "' (expected tcp|udp|icmp|icmpv6|arp)";
    return {};
}

Predicate make_addr(const std::string& v, bool match_src, bool match_dst, std::string& error) {
    std::uint32_t want4 = 0;
    std::array<std::uint8_t, 16> want6{};
    bool is_v6 = false;
    if (parse_v4(v, want4)) {
        is_v6 = false;
    } else if (parse_v6(v, want6)) {
        is_v6 = true;
    } else {
        error = "not a valid IP address: " + v;
        return {};
    }
    if (is_v6) {
        return [want6, match_src, match_dst](const DecodedPacket& p) {
            std::array<std::uint8_t, 16> s{}, d{};
            if (!l3_v6(p, s, d)) return false;
            return (match_src && s == want6) || (match_dst && d == want6);
        };
    }
    return [want4, match_src, match_dst](const DecodedPacket& p) {
        // Try IPv4 in L3, and ARP spa/tpa.
        std::uint32_t s = 0, d = 0;
        if (l3_v4(p, s, d)) {
            return (match_src && s == want4) || (match_dst && d == want4);
        }
        if (auto* a = std::get_if<Arp>(&p.l3)) {
            return (match_src && a->spa == want4) || (match_dst && a->tpa == want4);
        }
        return false;
    };
}

Predicate make_port(const std::string& v, bool match_src, bool match_dst, std::string& error) {
    std::uint64_t n = 0;
    if (!parse_uint(v, n) || n > 0xFFFFu) {
        error = "port must be 0..65535: " + v;
        return {};
    }
    auto want = static_cast<std::uint16_t>(n);
    return [want, match_src, match_dst](const DecodedPacket& p) {
        std::uint16_t s = 0, d = 0;
        if (!l4_ports(p, s, d)) return false;
        return (match_src && s == want) || (match_dst && d == want);
    };
}

Predicate make_vlan(const std::string& v, std::string& error) {
    std::uint64_t n = 0;
    if (!parse_uint(v, n) || n > 4095) {
        error = "vlan must be 0..4095: " + v;
        return {};
    }
    auto want = static_cast<std::uint16_t>(n);
    return [want](const DecodedPacket& p) {
        for (const auto& t : p.vlan_tags) if (t.vid == want) return true;
        return false;
    };
}

} // namespace

std::unique_ptr<Filter> pass_through() {//no filter operation
    return std::make_unique<Compound>(std::vector<Predicate>{});
}

std::unique_ptr<Filter> compile(const std::vector<std::string>& exprs, std::string& error) {
    std::vector<Predicate> preds;
    preds.reserve(exprs.size());
    for (const auto& e : exprs) {
        const auto eq = e.find('=');
        if (eq == std::string::npos) {
            error = "expected key=value, got: " + e;
            return nullptr;
        }
        const auto key = lower(e.substr(0, eq));
        const auto val = e.substr(eq + 1);

        Predicate p;
        if      (key == "proto") p = make_proto(val, error);
        else if (key == "ip")    p = make_addr(val, true, true, error);
        else if (key == "src")   p = make_addr(val, true, false, error);
        else if (key == "dst")   p = make_addr(val, false, true, error);
        else if (key == "port")  p = make_port(val, true, true, error);
        else if (key == "sport") p = make_port(val, true, false, error);
        else if (key == "dport") p = make_port(val, false, true, error);
        else if (key == "vlan")  p = make_vlan(val, error);
        else {
            error = "unknown key '" + key + "'";
            return nullptr;
        }
        if (!p) return nullptr; // make_* set `error`
        preds.push_back(std::move(p));
    }
    return std::make_unique<Compound>(std::move(preds));
}

} // namespace pcapture::filter

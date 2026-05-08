#include "filter/filter.hpp"
#include "model/protocol_model.hpp"

#include <gtest/gtest.h>

using namespace pcapture::decode;
using namespace pcapture::filter;

namespace {

DecodedPacket tcp_packet(std::uint32_t src, std::uint32_t dst,
                         std::uint16_t sport, std::uint16_t dport) {
    DecodedPacket p;
    Ipv4 ip{}; ip.src = src; ip.dst = dst; ip.proto = 6; ip.ttl = 64;
    p.l3 = ip;
    Tcp t{}; t.sport = sport; t.dport = dport; t.flags = 0x02;
    p.l4 = t;
    Ethernet e{}; e.ethertype = 0x0800;
    p.ethernet = e;
    return p;
}

DecodedPacket udp_packet(std::uint16_t sport, std::uint16_t dport) {
    DecodedPacket p;
    Ipv4 ip{}; ip.src = 0x01010101; ip.dst = 0x02020202; ip.proto = 17;
    p.l3 = ip;
    Udp u{}; u.sport = sport; u.dport = dport; u.length = 8;
    p.l4 = u;
    Ethernet e{}; e.ethertype = 0x0800;
    p.ethernet = e;
    return p;
}

} // namespace

TEST(Filter, EmptyAcceptsAll) {
    std::string err;
    auto f = compile({}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(tcp_packet(0,0,0,0)));
}

TEST(Filter, ProtoTcp) {
    std::string err;
    auto f = compile({"proto=tcp"}, err);
    ASSERT_NE(f, nullptr) << err;
    EXPECT_TRUE(f->accept(tcp_packet(0,0,0,80)));
    EXPECT_FALSE(f->accept(udp_packet(53, 53)));
}

TEST(Filter, PortMatchesEitherSide) {
    std::string err;
    auto f = compile({"port=443"}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(tcp_packet(0,0,1234,443)));
    EXPECT_TRUE(f->accept(tcp_packet(0,0,443,1234)));
    EXPECT_FALSE(f->accept(tcp_packet(0,0,80,8080)));
}

TEST(Filter, DportOnly) {
    std::string err;
    auto f = compile({"dport=443"}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(tcp_packet(0,0,1234,443)));
    EXPECT_FALSE(f->accept(tcp_packet(0,0,443,1234)));
}

TEST(Filter, IpMatchesSrcOrDst) {
    std::string err;
    auto f = compile({"ip=10.0.0.1"}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(tcp_packet(0x0A000001, 0x08080808, 0, 0)));
    EXPECT_TRUE(f->accept(tcp_packet(0x08080808, 0x0A000001, 0, 0)));
    EXPECT_FALSE(f->accept(tcp_packet(0x08080808, 0x08080808, 0, 0)));
}

TEST(Filter, AndCombination) {
    std::string err;
    auto f = compile({"proto=tcp", "dport=443"}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(tcp_packet(0,0,1234,443)));
    EXPECT_FALSE(f->accept(tcp_packet(0,0,1234,80)));
    EXPECT_FALSE(f->accept(udp_packet(0, 443)));
}

TEST(Filter, RejectsBadKey) {
    std::string err;
    auto f = compile({"flavor=mint"}, err);
    EXPECT_EQ(f, nullptr);
    EXPECT_FALSE(err.empty());
}

TEST(Filter, RejectsBadIp) {
    std::string err;
    auto f = compile({"ip=not.an.address"}, err);
    EXPECT_EQ(f, nullptr);
}

TEST(Filter, RejectsPortOutOfRange) {
    std::string err;
    auto f = compile({"port=70000"}, err);
    EXPECT_EQ(f, nullptr);
}

TEST(Filter, VlanMatch) {
    DecodedPacket p;
    VlanTag t{}; t.vid = 10;
    p.vlan_tags.push_back(t);
    std::string err;
    auto f = compile({"vlan=10"}, err);
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->accept(p));
    auto g = compile({"vlan=20"}, err);
    EXPECT_FALSE(g->accept(p));
}

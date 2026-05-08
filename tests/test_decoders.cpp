#include "protocols/arp.hpp"
#include "parser/parser.hpp"
#include "protocols/ethernet.hpp"
#include "protocols/icmp.hpp"
#include "protocols/ipv4.hpp"
#include "protocols/ipv6.hpp"
#include "protocols/tcp.hpp"
#include "protocols/udp.hpp"
#include "protocols/vlan.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <vector>

using namespace pcapture::decode;

namespace {
std::vector<std::uint8_t> hex(std::initializer_list<int> bytes) {
    std::vector<std::uint8_t> v;
    v.reserve(bytes.size());
    for (int b : bytes) v.push_back(static_cast<std::uint8_t>(b));
    return v;
}
} // namespace

// -------- Ethernet ----------------------------------------------------------

TEST(Ethernet, MinimumValid) {
    auto f = hex({
        0x11,0x22,0x33,0x44,0x55,0x66, // dst
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, // src
        0x08,0x00                      // ethertype IPv4
    });
    Ethernet e;
    std::size_t used = 0;
    EXPECT_EQ(ethernet::parse(f.data(), f.size(), e, used), ParseError::Ok);
    EXPECT_EQ(used, 14u);
    EXPECT_EQ(e.ethertype, 0x0800);
    EXPECT_EQ(e.dst[0], 0x11);
    EXPECT_EQ(e.src[5], 0xFF);
}

TEST(Ethernet, TruncatedTooShort) {
    auto f = hex({0x11,0x22,0x33,0x44,0x55,0x66, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08});
    Ethernet e;
    std::size_t used = 0;
    EXPECT_EQ(ethernet::parse(f.data(), f.size(), e, used), ParseError::TooShort);
    EXPECT_EQ(used, 0u);
}

// -------- VLAN --------------------------------------------------------------

TEST(Vlan, ParsesTciAndConsumesTwoBytes) {
    // TCI = 1010_0000_0000_1010 -> PCP=5, DEI=0, VID=10
    // followed by inner ethertype 0x0800
    auto f = hex({0xA0,0x0A, 0x08,0x00});
    VlanTag t;
    std::size_t used = 0;
    EXPECT_EQ(vlan::parse(f.data(), f.size(), t, used), ParseError::Ok);
    EXPECT_EQ(used, 2u);
    EXPECT_EQ(t.pcp, 5);
    EXPECT_FALSE(t.dei);
    EXPECT_EQ(t.vid, 10);
}

TEST(Vlan, TruncatedTooShort) {
    auto f = hex({0xA0});
    VlanTag t;
    std::size_t used = 0;
    EXPECT_EQ(vlan::parse(f.data(), f.size(), t, used), ParseError::TooShort);
}

// -------- IPv4 --------------------------------------------------------------

TEST(Ipv4, MinimumValid) {
    auto f = hex({
        0x45, 0x00,            // ver=4, ihl=5, dscp=0
        0x00, 0x28,            // total length = 40
        0xab, 0xcd,            // id
        0x40, 0x00,            // flags=DF, frag=0
        0x40,                  // ttl
        0x06,                  // proto=TCP
        0x00, 0x00,            // checksum (ignored)
        0x0A, 0x00, 0x00, 0x01,// src
        0x0A, 0x00, 0x00, 0x02 // dst
    });
    Ipv4 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv4::parse(f.data(), f.size(), ip, used), ParseError::Ok);
    EXPECT_EQ(used, 20u);
    EXPECT_EQ(ip.ihl, 5);
    EXPECT_EQ(ip.proto, 6);
    EXPECT_EQ(ip.ttl, 0x40);
    EXPECT_EQ(ip.total_length, 40);
    EXPECT_EQ(ip.flags, 0x2); // DF set
    EXPECT_EQ(ip.src, 0x0A000001u);
    EXPECT_EQ(ip.dst, 0x0A000002u);
}

TEST(Ipv4, TruncatedHeader) {
    auto f = hex({0x45,0x00,0x00,0x28,0xab,0xcd,0x40,0x00,0x40,0x06,0x00,0x00});
    Ipv4 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv4::parse(f.data(), f.size(), ip, used), ParseError::TooShort);
}

TEST(Ipv4, BadVersionRejected) {
    auto f = hex({
        0x55, 0x00, 0x00, 0x14, 0,0,0,0, 0x40, 0x06, 0,0, 0,0,0,0, 0,0,0,0
    });
    Ipv4 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv4::parse(f.data(), f.size(), ip, used), ParseError::Malformed);
}

TEST(Ipv4, IhlTooSmallRejected) {
    auto f = hex({
        0x44, 0x00, 0x00, 0x14, 0,0,0,0, 0x40, 0x06, 0,0, 0,0,0,0, 0,0,0,0
    });
    Ipv4 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv4::parse(f.data(), f.size(), ip, used), ParseError::Malformed);
}

// -------- IPv6 --------------------------------------------------------------

TEST(Ipv6, MinimumValid) {
    auto f = hex({
        0x60, 0x00, 0x00, 0x00, // version=6, traffic class/flow label=0
        0x00, 0x10,             // payload length = 16
        0x06,                   // next header = TCP
        0x40,                   // hop limit
        0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01, // src
        0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x02  // dst
    });
    Ipv6 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv6::parse(f.data(), f.size(), ip, used), ParseError::Ok);
    EXPECT_EQ(used, 40u);
    EXPECT_EQ(ip.next_header, 6);
    EXPECT_EQ(ip.hop_limit, 0x40);
    EXPECT_EQ(ip.payload_length, 16);
}

TEST(Ipv6, TruncatedHeader) {
    auto f = hex({0x60,0x00,0x00,0x00,0x00,0x10,0x06,0x40});
    Ipv6 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv6::parse(f.data(), f.size(), ip, used), ParseError::TooShort);
}

TEST(Ipv6, ExtHeaderHbhWalksToTcp) {
    auto f = hex({
        0x60, 0,0,0, 0x00,0x18, 0x00, 0x40,           // next=HBH(0), payload=24
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
        // HBH ext header: next=TCP(6), hdr-ext-len=0 -> total 8 bytes
        0x06, 0x00, 0,0,0,0,0,0,
        // (transport bytes follow but we don't need them for this assertion)
        0x12,0x34, 0x00,0x50, 0,0,0,1, 0,0,0,0, 0x50,0x02, 0,0, 0,0, 0,0
    });
    Ipv6 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv6::parse(f.data(), f.size(), ip, used), ParseError::Ok);
    EXPECT_EQ(ip.next_header, 0);          // raw first hop = HBH
    EXPECT_EQ(ip.transport_proto, 6);      // walked to TCP
    EXPECT_EQ(ip.ext_header_bytes, 8);
    EXPECT_EQ(used, 48u);
}

TEST(Ipv6, ExtHeaderFragmentRecorded) {
    auto f = hex({
        0x60, 0,0,0, 0x00,0x10, 0x2C, 0x40,           // next=Fragment(44)
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,
        // Fragment header: next=UDP(17), reserved, frag_offset+M=0, id=0
        0x11, 0x00, 0x00, 0x00, 0,0,0,0
    });
    Ipv6 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv6::parse(f.data(), f.size(), ip, used), ParseError::Ok);
    EXPECT_TRUE(ip.fragmented);
    EXPECT_EQ(ip.transport_proto, 17);
    EXPECT_EQ(ip.ext_header_bytes, 8);
}

TEST(Ipv6, BadVersionRejected) {
    auto f = hex({
        0x70, 0,0,0, 0,0x10, 0x06, 0x40,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    });
    Ipv6 ip;
    std::size_t used = 0;
    EXPECT_EQ(ipv6::parse(f.data(), f.size(), ip, used), ParseError::Malformed);
}

// -------- ARP ---------------------------------------------------------------

TEST(Arp, RequestEthernetIpv4) {
    auto f = hex({
        0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x01, // who-has request
        0x00,0x11,0x22,0x33,0x44,0x55, 0x0A,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00, 0x0A,0x00,0x00,0x02
    });
    Arp a;
    std::size_t used = 0;
    EXPECT_EQ(arp::parse(f.data(), f.size(), a, used), ParseError::Ok);
    EXPECT_EQ(a.op, 1);
    EXPECT_EQ(a.spa, 0x0A000001u);
    EXPECT_EQ(a.tpa, 0x0A000002u);
}

TEST(Arp, Truncated) {
    auto f = hex({0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01});
    Arp a;
    std::size_t used = 0;
    EXPECT_EQ(arp::parse(f.data(), f.size(), a, used), ParseError::TooShort);
}

TEST(Arp, NonEthernetIpv4Unsupported) {
    auto f = hex({
        0x00,0x06, 0x08,0x00, 0x06, 0x04, 0x00,0x01,
        0,0,0,0,0,0, 0,0,0,0, 0,0,0,0,0,0, 0,0,0,0
    });
    Arp a;
    std::size_t used = 0;
    EXPECT_EQ(arp::parse(f.data(), f.size(), a, used), ParseError::Unsupported);
}

// -------- TCP ---------------------------------------------------------------

TEST(Tcp, SynPacket) {
    auto f = hex({
        0x12, 0x34, 0x00, 0x50,        // sport=0x1234, dport=80
        0x00, 0x00, 0x00, 0x01,        // seq
        0x00, 0x00, 0x00, 0x00,        // ack
        0x50, 0x02, 0xff, 0xff,        // data offset=5, flags=SYN, window
        0x00, 0x00, 0x00, 0x00         // checksum + urgent
    });
    Tcp t;
    std::size_t used = 0;
    EXPECT_EQ(tcp::parse(f.data(), f.size(), t, used), ParseError::Ok);
    EXPECT_EQ(used, 20u);
    EXPECT_EQ(t.sport, 0x1234);
    EXPECT_EQ(t.dport, 80);
    EXPECT_EQ(t.flags, 0x02); // SYN
    EXPECT_EQ(t.seq, 1u);
}

TEST(Tcp, TruncatedHeader) {
    auto f = hex({0x12,0x34,0x00,0x50, 0,0,0,1, 0,0,0,0, 0x50,0x02});
    Tcp t;
    std::size_t used = 0;
    EXPECT_EQ(tcp::parse(f.data(), f.size(), t, used), ParseError::TooShort);
}

TEST(Tcp, BadDataOffsetRejected) {
    auto f = hex({
        0x12,0x34,0x00,0x50, 0,0,0,1, 0,0,0,0,
        0x40,0x02, 0xff,0xff, 0,0,0,0
    });
    Tcp t;
    std::size_t used = 0;
    EXPECT_EQ(tcp::parse(f.data(), f.size(), t, used), ParseError::Malformed);
}

// -------- UDP ---------------------------------------------------------------

TEST(Udp, MinimumValid) {
    auto f = hex({0x00, 0x35, 0x12, 0x34, 0x00, 0x08, 0x00, 0x00});
    Udp u;
    std::size_t used = 0;
    EXPECT_EQ(udp::parse(f.data(), f.size(), u, used), ParseError::Ok);
    EXPECT_EQ(used, 8u);
    EXPECT_EQ(u.sport, 53);
    EXPECT_EQ(u.dport, 0x1234);
    EXPECT_EQ(u.length, 8);
}

TEST(Udp, Truncated) {
    auto f = hex({0x00, 0x35, 0x12, 0x34, 0x00, 0x08});
    Udp u;
    std::size_t used = 0;
    EXPECT_EQ(udp::parse(f.data(), f.size(), u, used), ParseError::TooShort);
}

TEST(Udp, LengthShorterThanHeaderRejected) {
    auto f = hex({0x00, 0x35, 0x12, 0x34, 0x00, 0x04, 0x00, 0x00});
    Udp u;
    std::size_t used = 0;
    EXPECT_EQ(udp::parse(f.data(), f.size(), u, used), ParseError::Malformed);
}

// -------- ICMP --------------------------------------------------------------

TEST(Icmp, EchoRequest) {
    auto f = hex({0x08, 0x00, 0xab, 0xcd});
    Icmp i;
    std::size_t used = 0;
    EXPECT_EQ(icmp::parse(f.data(), f.size(), i, used, false), ParseError::Ok);
    EXPECT_EQ(i.type, 8);
    EXPECT_EQ(i.code, 0);
    EXPECT_FALSE(i.v6);
}

TEST(Icmp, V6Flag) {
    auto f = hex({0x80, 0x00, 0x00, 0x00});
    Icmp i;
    std::size_t used = 0;
    EXPECT_EQ(icmp::parse(f.data(), f.size(), i, used, true), ParseError::Ok);
    EXPECT_TRUE(i.v6);
}

TEST(Icmp, Truncated) {
    auto f = hex({0x08});
    Icmp i;
    std::size_t used = 0;
    EXPECT_EQ(icmp::parse(f.data(), f.size(), i, used, false), ParseError::TooShort);
}

// -------- End-to-end decoder dispatch ---------------------------------------

namespace {
pcapture::capture::RawFrame make_frame(std::initializer_list<int> bytes) {
    pcapture::capture::RawFrame f;
    for (int b : bytes) f.bytes.push_back(static_cast<std::uint8_t>(b));
    f.captured_len = static_cast<std::uint32_t>(f.bytes.size());
    f.original_len = f.captured_len;
    return f;
}
} // namespace

TEST(DecodeDispatch, EthernetIpv4Tcp) {
    auto f = make_frame({
        // Ethernet
        0x11,0x22,0x33,0x44,0x55,0x66, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08,0x00,
        // IPv4 (20 bytes, proto=TCP)
        0x45,0x00, 0x00,0x28, 0,0, 0x40,0x00, 0x40, 0x06, 0,0,
        0x0A,0,0,0x01, 0x0A,0,0,0x02,
        // TCP (20 bytes, SYN)
        0x12,0x34, 0x00,0x50, 0,0,0,1, 0,0,0,0, 0x50,0x02, 0xff,0xff, 0,0, 0,0
    });
    auto pkt = decode(f);
    ASSERT_TRUE(pkt.ethernet.has_value());
    EXPECT_EQ(pkt.ethernet->ethertype, 0x0800);
    ASSERT_TRUE(std::holds_alternative<Ipv4>(pkt.l3));
    EXPECT_EQ(std::get<Ipv4>(pkt.l3).proto, 6);
    ASSERT_TRUE(std::holds_alternative<Tcp>(pkt.l4));
    EXPECT_EQ(std::get<Tcp>(pkt.l4).dport, 80);
}

TEST(DecodeDispatch, VlanTaggedIpv4) {
    auto f = make_frame({
        0x11,0x22,0x33,0x44,0x55,0x66, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x81,0x00,             // VLAN TPID
        0x00,0x0A,             // TCI: VID=10
        0x08,0x00,             // inner ethertype = IPv4
        0x45,0x00, 0x00,0x14, 0,0, 0x00,0x00, 0x40, 0xff, 0,0,
        0x0A,0,0,0x01, 0x0A,0,0,0x02
    });
    auto pkt = decode(f);
    ASSERT_EQ(pkt.vlan_tags.size(), 1u);
    EXPECT_EQ(pkt.vlan_tags[0].vid, 10);
    ASSERT_TRUE(std::holds_alternative<Ipv4>(pkt.l3));
}

TEST(DecodeDispatch, ArpRequest) {
    auto f = make_frame({
        0xff,0xff,0xff,0xff,0xff,0xff, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x08,0x06,
        0x00,0x01, 0x08,0x00, 0x06, 0x04, 0x00,0x01,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF, 0x0A,0x00,0x00,0x01,
        0,0,0,0,0,0,                   0x0A,0x00,0x00,0x02
    });
    auto pkt = decode(f);
    ASSERT_TRUE(std::holds_alternative<Arp>(pkt.l3));
    EXPECT_EQ(std::get<Arp>(pkt.l3).op, 1);
}

TEST(DecodeDispatch, RandomBytesDoesNotCrash) {
    pcapture::capture::RawFrame f;
    f.bytes = {0xde, 0xad, 0xbe, 0xef, 0x12};
    f.captured_len = 5;
    f.original_len = 5;
    // Should not throw or assert; partially decoded packet is fine.
    EXPECT_NO_THROW(decode(f));
}

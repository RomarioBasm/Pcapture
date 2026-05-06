#pragma once

#include "model/raw_packet.hpp"
#include "cli/config.hpp"

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace pcapture::capture {

struct InterfaceAddress {
    std::string family;  // "ipv4", "ipv6", "link", "other"
    std::string address; // textual representation
};

struct InterfaceInfo {
    std::string name;
    std::string description;
    bool loopback = false;
    bool up = false;
    bool running = false;
    std::vector<InterfaceAddress> addresses;
};

// Enumerate interfaces via libpcap. Returns 0 on success, non-zero on error
// (and writes an error message to `err`).
int enumerate_interfaces(std::vector<InterfaceInfo>& out, std::ostream& err);

// Render an interface list to `out` in the requested format.
void render_interfaces(const std::vector<InterfaceInfo>& ifs,
                       cli::OutputFormat format,
                       std::ostream& out);

// Top-level entry point used by main().
int list_interfaces(cli::OutputFormat format, std::ostream& out, std::ostream& err);

struct CaptureStats {
    std::uint64_t received = 0;       // packets handed to our callback
    std::uint32_t kernel_received = 0; // pcap_stats: ps_recv
    std::uint32_t kernel_dropped = 0;  // pcap_stats: ps_drop
    std::uint32_t iface_dropped = 0;   // pcap_stats: ps_ifdrop
};

// Phase 3 vertical slice: open the configured interface and print "len=N"
// per packet until count/duration is reached or the user signals stop.
// Phase 6 will replace this with a threaded pipeline.
int run_synchronous(const cli::Config& cfg, std::ostream& out, std::ostream& err);

} // namespace pcapture::capture

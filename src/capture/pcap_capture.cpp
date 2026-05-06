#include "capture/pcap_capture.hpp"

#include "capture/pcap_handle.hpp"
#include "parser/parser.hpp"
#include "output/formatter.hpp"
#include "output/hex_formatter.hpp"
#include "capture/platform/signals.hpp"

#include <pcap.h>

#ifdef PCAPTURE_WINDOWS
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ostream>
#include <string>

namespace pcapture::capture {

namespace {

std::string sockaddr_text(const sockaddr* sa, std::string& family) {
    if (!sa) {
        family = "other";
        return {};
    }
    char buf[INET6_ADDRSTRLEN] = {0};
    switch (sa->sa_family) {
    case AF_INET: {
        family = "ipv4";
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        if (inet_ntop(AF_INET, &in->sin_addr, buf, sizeof buf)) return buf;
        return {};
    }
    case AF_INET6: {
        family = "ipv6";
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
        if (inet_ntop(AF_INET6, &in6->sin6_addr, buf, sizeof buf)) return buf;
        return {};
    }
    default:
        family = "other";
        return {};
    }
}

void escape_json(const std::string& s, std::ostream& out) {
    out << '"';
    for (char c : s) {
        switch (c) {
        case '"':  out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n";  break;
        case '\r': out << "\\r";  break;
        case '\t': out << "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char esc[8];
                std::snprintf(esc, sizeof esc, "\\u%04x", static_cast<unsigned>(c));
                out << esc;
            } else {
                out << c;
            }
        }
    }
    out << '"';
}

} // namespace

int enumerate_interfaces(std::vector<InterfaceInfo>& out, std::ostream& err) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* devs = nullptr;
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        err << "pcap_findalldevs: " << errbuf << "\n";
        return 1;
    }

    for (auto* d = devs; d != nullptr; d = d->next) {
        InterfaceInfo info;
        info.name = d->name ? d->name : "";
        info.description = d->description ? d->description : "";
#ifdef PCAP_IF_LOOPBACK
        info.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
#endif
#ifdef PCAP_IF_UP
        info.up = (d->flags & PCAP_IF_UP) != 0;
#endif
#ifdef PCAP_IF_RUNNING
        info.running = (d->flags & PCAP_IF_RUNNING) != 0;
#endif
        for (auto* a = d->addresses; a != nullptr; a = a->next) {
            InterfaceAddress ia;
            ia.address = sockaddr_text(a->addr, ia.family);
            if (!ia.address.empty()) info.addresses.push_back(std::move(ia));
        }
        out.push_back(std::move(info));
    }

    pcap_freealldevs(devs);
    return 0;
}

void render_interfaces(const std::vector<InterfaceInfo>& ifs,
                       cli::OutputFormat format,
                       std::ostream& out) {
    if (format == cli::OutputFormat::Json) {
        out << "[";
        bool first = true;
        for (const auto& i : ifs) {
            if (!first) out << ",";
            first = false;
            out << "{";
            out << "\"name\":";         escape_json(i.name, out);
            out << ",\"description\":"; escape_json(i.description, out);
            out << ",\"loopback\":"    << (i.loopback ? "true" : "false");
            out << ",\"up\":"          << (i.up ? "true" : "false");
            out << ",\"running\":"     << (i.running ? "true" : "false");
            out << ",\"addresses\":[";
            bool firsta = true;
            for (const auto& a : i.addresses) {
                if (!firsta) out << ",";
                firsta = false;
                out << "{\"family\":";  escape_json(a.family, out);
                out << ",\"address\":"; escape_json(a.address, out);
                out << "}";
            }
            out << "]}";
        }
        out << "]\n";
        return;
    }

    // Human / compact share a simple table.
    for (const auto& i : ifs) {
        out << i.name;
        std::string flags;
        if (i.loopback) flags += "loopback ";
        if (i.up)       flags += "up ";
        if (i.running)  flags += "running ";
        if (!flags.empty()) {
            if (flags.back() == ' ') flags.pop_back();
            out << "  [" << flags << "]";
        }
        out << "\n";
        if (!i.description.empty()) {
            out << "    description: " << i.description << "\n";
        }
        for (const auto& a : i.addresses) {
            out << "    " << a.family << ": " << a.address << "\n";
        }
    }
    if (ifs.empty()) {
        out << "(no capture-capable interfaces found; on Linux try with sudo "
               "or CAP_NET_RAW)\n";
    }
}

int list_interfaces(cli::OutputFormat format, std::ostream& out, std::ostream& err) {
    std::vector<InterfaceInfo> ifs;
    if (int rc = enumerate_interfaces(ifs, err); rc != 0) return rc;
    render_interfaces(ifs, format, out);
    return 0;
}


namespace {

struct LoopState {
    std::ostream* out;
    format::Formatter* fmt;
    CaptureStats stats;
    std::uint64_t count_limit; // 0 = unlimited
    pcap_t* handle;            // for pcap_breakloop on count exhaustion
    bool dump_hex;
    bool check_checksums;
};

void on_packet(u_char* user, const struct pcap_pkthdr* hdr, const u_char* bytes) {//Calls once for every captured frame
    auto* s = reinterpret_cast<LoopState*>(user);
    s->stats.received++;

    capture::RawFrame frame;
    frame.timestamp = std::chrono::system_clock::time_point{
        std::chrono::seconds{hdr->ts.tv_sec} +
        std::chrono::microseconds{hdr->ts.tv_usec}};
    frame.captured_len = hdr->caplen;
    frame.original_len = hdr->len;
    frame.bytes.assign(bytes, bytes + hdr->caplen);

    decode::DecodeOptions opts;
    opts.check_checksums = s->check_checksums;
    auto pkt = decode::decode(frame, opts);
    s->fmt->format(pkt, *s->out);
    if (s->dump_hex && !frame.bytes.empty()) {
        util::hexdump(frame.bytes.data(), frame.bytes.size(), *s->out);
    }

    if (s->count_limit && s->stats.received >= s->count_limit) {
        pcap_breakloop(s->handle);
    }
}

} // namespace

int run_synchronous(const cli::Config& cfg, std::ostream& out, std::ostream& err) {
    auto open_result = open_source(cfg, err);
    if (!open_result) {// Error already logged by open_source.
        return 2;
    }
    auto& opened = open_result.value();
    const bool offline = opened.offline;

    util::install_signal_handlers(); //registers the SIGINT(POSIX) or  console control (Windows) 
    util::set_active_pcap(opened.handle.get()); //publishes the live pcap_t* to the global atomic so the signal handler can call 

    std::unique_ptr<format::Formatter> fmt;
    switch (cfg.format) {
        case cli::OutputFormat::Human:   fmt = format::make_human_formatter(cfg.verbosity); break;
        case cli::OutputFormat::Compact: fmt = format::make_compact_formatter(); break;
        case cli::OutputFormat::Json:    fmt = format::make_json_formatter(); break;
    }
    fmt->prologue(out);

    const bool dump_hex = (cfg.format == cli::OutputFormat::Human) && cfg.verbosity >= 2;
    LoopState state{&out, fmt.get(), {}, cfg.count, opened.handle.get(), dump_hex, cfg.check_checksums};

    const auto start = std::chrono::steady_clock::now();
    int rc = 0;

    while (!util::stop_flag().load(std::memory_order_acquire)) {
        // pcap_dispatch returns after the read timeout; we re-check stop_flag
        // and the duration cap each tick so Ctrl-C and -d both stay responsive.
        const int n = pcap_dispatch(opened.handle.get(), -1, on_packet,
                                    reinterpret_cast<u_char*>(&state));
        if (n == -1) {
            err << "pcap_dispatch: " << pcap_geterr(opened.handle.get()) << "\n";
            rc = 1;
            break;
        }
        if (n == -2) {
            // pcap_breakloop was called (signal or count limit).
            break;
        }
        if (offline && n == 0) break; // EOF for file replay
        if (cfg.count && state.stats.received >= cfg.count) break;
        if (cfg.duration_s > 0) {
            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed >= std::chrono::seconds(cfg.duration_s)) break;
        }
    }

    // Final pcap_stats before closing the handle (live only; not valid offline).
    if (!offline) {
        pcap_stat ps{};
        if (pcap_stats(opened.handle.get(), &ps) == 0) {
            state.stats.kernel_received = ps.ps_recv; //frames the kernel passed to libpcap (after BPF filtering).
            state.stats.kernel_dropped = ps.ps_drop;  //frames the kernel had to drop because we weren't draining fast enough.
            state.stats.iface_dropped = ps.ps_ifdrop; //frames the NIC driver dropped before the kernel ring saw them.
        }
    }

    util::set_active_pcap(nullptr);
    fmt->epilogue(out);

    err << "\npcapture: shutdown summary\n"
        << "  packets displayed : " << state.stats.received << "\n"
        << "  kernel received   : " << state.stats.kernel_received << "\n"
        << "  kernel dropped    : " << state.stats.kernel_dropped << "\n"
        << "  iface dropped     : " << state.stats.iface_dropped << "\n";

    return rc;
}

} // namespace pcapture::capture

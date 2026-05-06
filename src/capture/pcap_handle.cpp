#include "capture/pcap_handle.hpp"

#include <pcap.h>

#include <optional>
#include <ostream>
#include <utility>

namespace pcapture::capture {

PcapHandle::~PcapHandle() { 
    reset();
}

PcapHandle::PcapHandle(PcapHandle&& other) noexcept //move constructor: take ownership of the other handle and null it out.
    : handle_(std::exchange(other.handle_, nullptr)) {} //exchange: Reads other.handle_, writes nullptr into it, returns the old value. 

PcapHandle& PcapHandle::operator=(PcapHandle&& other) noexcept {
    if (this != &other) {
        reset(std::exchange(other.handle_, nullptr));
    }
    return *this;
}

void PcapHandle::reset(pcap_t* p) noexcept { //destroy the old handle, (defaulting to null).
    if (handle_) { //if it's not null, close it.
        pcap_close(handle_);
    }
    handle_ = p;
}

namespace { //privete helper functions

// Shared post-open handling: datalink check + BPF filter compile/install.
// Centralized so live and offline paths can't drift in their safety checks —
// every opened handle is validated identically before it leaves this file.
//
// Returns nullopt on success and populates `out`; on failure it closes the
// handle, writes a diagnostic, and returns the classified OpenError.
std::optional<OpenError> finish_open(pcap_t* p, const cli::Config& cfg,
                                     OpenSuccess& out, const char* what,
                                     std::ostream& err) {
    out.datalink = pcap_datalink(p);
    if (out.datalink != DLT_EN10MB) {
        if (cfg.allow_non_ethernet) {
            err << "pcapture: warning: " << what << " datalink is " << out.datalink
                << " (expected DLT_EN10MB=" << DLT_EN10MB
                << "); --allow-non-ethernet set, decoding may misparse\n";
        } else {
            err << "pcapture: error: " << what << " datalink is " << out.datalink
                << " (expected DLT_EN10MB=" << DLT_EN10MB
                << "); pass --allow-non-ethernet to override\n";
            pcap_close(p);
            return OpenError{OpenErrorKind::NonEthernet, "non-Ethernet datalink"};
        }
    }

    if (cfg.bpf_filter && !cfg.bpf_filter->empty()) {
        if (!apply_filter(p, *cfg.bpf_filter, err)) {
            pcap_close(p);
            return OpenError{OpenErrorKind::BpfFailed, "failed to apply BPF filter"};
        }
    }

    out.handle.reset(p);
    return std::nullopt;
}

} // namespace

OpenResult open_live(const cli::Config& cfg, std::ostream& err) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    pcap_t* p = pcap_open_live(cfg.interface.c_str(),
                               cfg.snaplen,
                               cfg.promiscuous ? 1 : 0,
                               cfg.read_timeout_ms,
                               errbuf);
    if (!p) {
        err << "pcap_open_live(" << cfg.interface << "): " << errbuf << "\n";
        return OpenResult::err({OpenErrorKind::DeviceOpenFailed, errbuf});
    }

    if (errbuf[0] != '\0') {
        // libpcap may return a warning even on success.
        err << "pcap warning: " << errbuf << "\n";
    }

    OpenSuccess ok;
    ok.offline = false;
    if (auto e = finish_open(p, cfg, ok, "interface", err)) {
        return OpenResult::err(std::move(*e));
    }
    return OpenResult::ok(std::move(ok));
}

OpenResult open_offline(const cli::Config& cfg, std::ostream& err) {
    if (!cfg.read_path || cfg.read_path->empty()) {
        err << "pcapture: open_offline called without --read\n";
        return OpenResult::err({OpenErrorKind::BadConfig, "no read path configured"});
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* p = pcap_open_offline(cfg.read_path->c_str(), errbuf);
    if (!p) {
        err << "pcap_open_offline(" << *cfg.read_path << "): " << errbuf << "\n";
        return OpenResult::err({OpenErrorKind::DeviceOpenFailed, errbuf});
    }

    OpenSuccess ok;
    ok.offline = true;
    // Detect timestamp precision before finish_open: if finish_open rejects
    // the datalink, `p` is closed and we can't query it afterward.
#ifdef PCAP_TSTAMP_PRECISION_NANO
    ok.nanosecond_timestamps =
        (pcap_get_tstamp_precision(p) == PCAP_TSTAMP_PRECISION_NANO);
#endif
    if (auto e = finish_open(p, cfg, ok, "file", err)) {
        return OpenResult::err(std::move(*e));
    }
    return OpenResult::ok(std::move(ok));
}

// Thin dispatcher: keeps the live-vs-offline decision in one place so the
// pipeline and the legacy synchronous runner stay in sync.
OpenResult open_source(const cli::Config& cfg, std::ostream& err) {
    if (cfg.read_path && !cfg.read_path->empty()) {
        return open_offline(cfg, err);
    }
    return open_live(cfg, err);
}

bool apply_filter(pcap_t* handle, const std::string& expression, std::ostream& err) {
    bpf_program program{};
    // netmask 0 is fine for non-broadcast filters; libpcap docs OK this.
    if (pcap_compile(handle, &program, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        err << "pcap_compile: " << pcap_geterr(handle) << "\n";
        return false;
    }
    if (pcap_setfilter(handle, &program) != 0) {
        err << "pcap_setfilter: " << pcap_geterr(handle) << "\n";
        pcap_freecode(&program);
        return false;
    }
    pcap_freecode(&program);
    return true;
}

} // namespace pcapture::capture

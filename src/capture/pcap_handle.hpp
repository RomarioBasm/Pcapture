#pragma once

#include "cli/config.hpp"
#include "common/result.hpp"

#include <iosfwd>
#include <string>
#include <utility>

// Forward declaration to keep <pcap.h> out of the public header.
struct pcap;
using pcap_t = pcap;

namespace pcapture::capture {

// RAII wrapper around pcap_t*.
class PcapHandle {
public:
    PcapHandle() = default;
    ~PcapHandle(); //destructor: close the handle if it's open.

    PcapHandle(const PcapHandle&) = delete;
    PcapHandle& operator=(const PcapHandle&) = delete; 
    PcapHandle(PcapHandle&& other) noexcept; //move constructor: take ownership of the other handle and null it out.
    PcapHandle& operator=(PcapHandle&& other) noexcept; //assignment operator: if not self-assignment, close the current handle and take ownership of the other handle, nulling it out.

    pcap_t* get() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr; }

    void reset(pcap_t* p = nullptr) noexcept;

private:
    pcap_t* handle_ = nullptr;
};

// Success payload for an opened capture source. Intentionally light on
// behavior — it's plain data the pipeline reads on every frame.
struct OpenSuccess {
    PcapHandle handle;
    int datalink = 0;       // DLT_*
    bool offline = false;   // true if opened from a file
    // pcap files come in two timestamp flavours: microsecond (magic 0xa1b2c3d4)
    // and nanosecond (magic 0xa1b23c4d). libpcap reports the precision per
    // handle; surfacing it here lets the pipeline build correct timestamps
    // without re-querying libpcap.
    bool nanosecond_timestamps = false;
};

// Failure tier of architecture, here, so callers
// don't have to grep error strings to decide what to print.
enum class OpenErrorKind {
    Unknown,
    BadConfig,        // caller bug (no read path, etc.)
    DeviceOpenFailed, // pcap_open_live / pcap_open_offline rejected
    NonEthernet,      // datalink isn't EN10MB and --allow-non-ethernet absent
    BpfFailed,        // pcap_compile / pcap_setfilter failed
};

struct OpenError {
    OpenErrorKind kind = OpenErrorKind::Unknown;
    std::string message;
};

// Result<OpenSuccess, OpenError>: architecture boundary contract.
// Callers decide via `is_ok()`; success carries the handle, failure the
// classified error. Diagnostics have already been written to `err` by the
// time the function returns either way — this is for the caller's exit-code
// decision, not for re-printing.
using OpenResult = common::Result<OpenSuccess, OpenError>;

OpenResult open_live(const cli::Config& cfg, std::ostream& err);

// Honours `cfg.read_path`, `cfg.bpf_filter`, `cfg.allow_non_ethernet`.
// Snaplen / promiscuous / read-timeout do not apply offline and are ignored.
OpenResult open_offline(const cli::Config& cfg, std::ostream& err);

// Single entry point so callers (pipeline, CLI runner) don't branch on
// "live vs file" themselves; the rest of the system treats both sources
// uniformly via `OpenSuccess::offline`.
OpenResult open_source(const cli::Config& cfg, std::ostream& err);

// Apply a kernel BPF filter to an opened handle. Returns true on success.
bool apply_filter(pcap_t* handle, const std::string& expression, std::ostream& err);

} // namespace pcapture::capture

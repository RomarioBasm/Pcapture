#pragma once

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <vector>

namespace pcapture::capture {

struct RawFrame {
    std::chrono::system_clock::time_point timestamp;
    // Monotonic per-process sequence number assigned by the capture layer the
    // moment the frame is pulled out of libpcap. This is what users diagnose
    // drops with: a gap in `seq` between two emitted packets means the queue
    // overflowed (or a filter rejected one); it lets the worker's output be
    // correlated with the capture-side counters even when output is paginated
    // or piped through `head`.
    std::uint64_t seq = 0;
    std::uint32_t captured_len = 0;
    std::uint32_t original_len = 0;
    // Link-layer type, surfaced from libpcap (DLT_*). Today the project rejects
    // anything other than DLT_EN10MB unless --allow-non-ethernet is set, but
    // carrying the value per-frame lets formatters/filters do the right thing
    // when a non-Ethernet datalink is opted into.
    int linktype = 0;
    std::vector<std::uint8_t> bytes;
};

} // namespace pcapture::capture

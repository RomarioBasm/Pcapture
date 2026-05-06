#pragma once

#include "cli/config.hpp"
#include "output/formatter.hpp"
#include "output/sink.hpp"

#include <cstdint>
#include <iosfwd>
#include <memory>

namespace pcapture::pipeline {

struct PipelineStats {
    std::uint64_t captured = 0;     // packets pulled off the wire
    std::uint64_t decoded  = 0;     // packets handed to the formatter
    std::uint64_t printed  = 0;     // packets actually written
    std::uint64_t dropped_queue = 0; // queue overflow drops (our policy)
    std::uint64_t kernel_received = 0;
    std::uint64_t kernel_dropped  = 0;
    std::uint64_t iface_dropped   = 0;
    std::uint64_t filtered_out    = 0;
};

// Capture thread -> bounded queue -> decode/format thread -> output sink.
// Replaces capture::run_synchronous when you want to stop tying capture to
// printing speed. Honors cfg.queue_capacity and cfg.back_pressure.
//
// Primary entry point: takes a Sink so callers can supply file/stdout/syslog
// targets without the pipeline itself caring about resource lifetime.
int run_threaded(const cli::Config& cfg, format::Sink& sink, std::ostream& err);

// Convenience overload kept for callers (and tests) that already have an
// ostream — wraps it in a non-owning StreamSink internally.
int run_threaded(const cli::Config& cfg, std::ostream& out, std::ostream& err);

} // namespace pcapture::pipeline

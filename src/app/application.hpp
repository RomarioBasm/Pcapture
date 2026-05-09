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

// Render the shutdown summary block to `err`. The section headers carry the
// project's logo glyph; when `palette` is enabled the three bars are colored,
// otherwise they fall back to plain glyphs. `include_kernel` controls whether
// the kernel section is emitted — pcap_stats is meaningless for offline
// replay so the caller passes false in that case to avoid printing four zero
// rows that imply something was lost.
//
// `unicode_ok` selects the rendering style: true uses the box-drawing panels
// and brand glyphs, suitable for an interactive terminal. false drops back to
// plain-ASCII text — needed when the destination stream is being captured by
// a host that re-encodes bytes (notably PowerShell's UTF-16 redirect, which
// otherwise turns every "─" "▌" "·" into mojibake).
//
// `comment_prefix` only takes effect when `unicode_ok` is false. When true,
// every emitted line is prefixed with "# " so the summary can sit on stdout
// alongside compact packet lines without confusing line-oriented consumers
// (awk/grep/cut all skip "^#"-prefixed records by convention).
void write_shutdown_summary(std::ostream& err,
                            const PipelineStats& stats,
                            bool include_kernel,
                            const format::Palette& palette,
                            bool unicode_ok,
                            bool comment_prefix = false);

// Capture thread -> bounded queue -> decode/format thread -> output sink.
// Replaces capture::run_synchronous when you want to stop tying capture to
// printing speed. Honors cfg.queue_capacity and cfg.back_pressure.
//
// Primary entry point: takes a Sink so callers can supply file/stdout/syslog
// targets without the pipeline itself caring about resource lifetime. The
// palette is resolved by the caller (main.cpp) — the pipeline doesn't probe
// TTY/NO_COLOR/etc itself, so tests stay deterministic by default.
//
// `stderr_is_tty` lets the caller declare whether the diagnostic stream is
// connected to an interactive terminal. When false for compact/json formats,
// the shutdown summary is rerouted to stdout with a "# " comment prefix so
// PowerShell 5.1 cannot wrap the first stderr write in a NativeCommandError
// envelope. Defaults to true (no reroute) for tests and other callers that
// pass synthetic streams.
int run_threaded(const cli::Config& cfg,
                 format::Sink& sink,
                 const format::Palette& palette,
                 std::ostream& err,
                 bool stderr_is_tty = true);

// Convenience overload kept for callers (and tests) that already have an
// ostream — wraps it in a non-owning StreamSink internally and uses the
// no-color palette so captured-string assertions don't see ANSI escapes.
int run_threaded(const cli::Config& cfg, std::ostream& out, std::ostream& err);

} // namespace pcapture::pipeline

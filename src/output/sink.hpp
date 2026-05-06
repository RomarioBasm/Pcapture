#pragma once

// Sink: owns the resource that rendered output is written to. The output
// layer splits into Formatter (renders bytes) and Sink
// (writes them somewhere). Concrete sinks keep platform/lifecycle concerns
// (file handles, stdout buffering) out of the formatters and out of the
// pipeline orchestration code.
//
// Implementations expose the underlying ostream so that streaming formatters
// can keep writing piece-by-piece — the alternative (every formatter
// builds a string) would force per-packet allocations on the hot path. The
// `write(string)` overload is provided for byte-pure consumers that may
// arrive later (syslog, network sinks).

#include <iosfwd>
#include <memory>
#include <string>

namespace pcapture::format {

class Sink {
public:
    virtual ~Sink() = default;
    virtual std::ostream& stream() = 0;
    virtual void write(const std::string& bytes) {
        // Default: route through stream(). Override for sinks that prefer
        // record-oriented writes (e.g. syslog).
        stream() << bytes;
    }
    virtual void flush() = 0;
};

// stdout/stderr/etc — does NOT own the stream lifetime.
std::unique_ptr<Sink> make_stdout_sink();
// Wraps any caller-supplied ostream, again without ownership. Useful for
// tests that want to capture into an ostringstream and for the pipeline's
// existing `std::ostream& out` parameter.
std::unique_ptr<Sink> make_stream_sink(std::ostream& out);
// Owns an std::ofstream opened at the supplied path. On open failure, the
// returned pointer is non-null but `good() == false`.
std::unique_ptr<Sink> make_file_sink(const std::string& path);

// Probe whether a sink finished construction successfully (relevant only for
// FileSink — the others are infallible).
bool sink_good(const Sink& sink);

} // namespace pcapture::format

#include "output/sink.hpp"

#include <fstream>
#include <iostream>
#include <ostream>
#include <utility>

namespace pcapture::format {
namespace {

// Wraps a caller-owned ostream. Used by StdoutSink (cout) and by tests via
// make_stream_sink(ostringstream).
class StreamSink final : public Sink {
public:
    explicit StreamSink(std::ostream& out) : out_(&out) {}
    std::ostream& stream() override { return *out_; }
    void flush() override { out_->flush(); }
private:
    std::ostream* out_;
};

// Owns an ofstream at a configured path. flush() forwards to the underlying
// file; the dtor closes it (RAII). If construction fails the file_.is_open()
// will be false — sink_good() lets the caller surface a clean error.
class FileSink final : public Sink {
public:
    explicit FileSink(const std::string& path) : file_(path) {}
    std::ostream& stream() override { return file_; }
    void flush() override { file_.flush(); }
    bool good() const { return file_.is_open() && file_.good(); }
private:
    std::ofstream file_;
};

} // namespace

std::unique_ptr<Sink> make_stdout_sink() {
    return std::make_unique<StreamSink>(std::cout);
}

std::unique_ptr<Sink> make_stream_sink(std::ostream& out) {
    return std::make_unique<StreamSink>(out);
}

std::unique_ptr<Sink> make_file_sink(const std::string& path) {
    return std::make_unique<FileSink>(path);
}

bool sink_good(const Sink& sink) {
    // Only FileSink can fail at construction. Probe via dynamic_cast; the
    // alternative is to put a `bool ok()` on the base, which would force a
    // meaningless override on every infallible sink.
    if (auto* fs = dynamic_cast<const FileSink*>(&sink)) {
        return fs->good();
    }
    return true;
}

} // namespace pcapture::format

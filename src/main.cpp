#include "capture/pcap_capture.hpp"
#include "cli/config.hpp"
#include "output/sink.hpp"
#include "app/application.hpp"

#include <iostream>
#include <memory>

int main(int argc, char** argv) {
    auto result = pcapture::cli::parse(argc, argv, std::cout, std::cerr);
    if (result.exit_code) return *result.exit_code;

    const auto& cfg = result.config;

    // The sink owns whatever resource output ends up writing to. Lifecycle
    // stays here in main() so the pipeline doesn't need to know about file
    // ownership; it just calls sink.stream() and sink.flush().
    std::unique_ptr<pcapture::format::Sink> sink;
    if (cfg.output_path) {
        sink = pcapture::format::make_file_sink(*cfg.output_path);
        if (!pcapture::format::sink_good(*sink)) {
            std::cerr << "pcapture: cannot open output file: " << *cfg.output_path << "\n";
            return 2;
        }
    } else {
        sink = pcapture::format::make_stdout_sink();
    }

    if (cfg.list_interfaces) {
        return pcapture::capture::list_interfaces(cfg.format, sink->stream(), std::cerr);
    }

    return pcapture::pipeline::run_threaded(cfg, *sink, std::cerr);
}

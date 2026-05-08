#include "capture/pcap_capture.hpp"
#include "cli/config.hpp"
#include "output/color.hpp"
#include "output/sink.hpp"
#include "app/application.hpp"

#include <iostream>
#include <memory>

namespace {

pcapture::format::ColorMode to_format_color_mode(pcapture::cli::ColorMode m) {
    using FM = pcapture::format::ColorMode;
    switch (m) {
    case pcapture::cli::ColorMode::Auto:   return FM::Auto;
    case pcapture::cli::ColorMode::Always: return FM::Always;
    case pcapture::cli::ColorMode::Never:  return FM::Never;
    }
    return FM::Auto;
}

} // namespace

int main(int argc, char** argv) {
    // Switch the Windows console to UTF-8 for our process lifetime so the
    // logo glyph and em-dash in our banners render as characters rather than
    // mojibake. Constructed first so even --version (which exits inside
    // parse()) runs with the swap in effect; restored automatically when
    // main() returns. No-op on non-Windows.
    pcapture::format::ConsoleUtf8Guard utf8_guard;

    auto result = pcapture::cli::parse(argc, argv, std::cout, std::cerr);
    if (result.exit_code) return *result.exit_code;

    const auto& cfg = result.config;

    // The sink owns whatever resource output ends up writing to. Lifecycle
    // stays here in main() so the pipeline doesn't need to know about file
    // ownership; it just calls sink.stream() and sink.flush().
    std::unique_ptr<pcapture::format::Sink> sink;
    const bool sink_is_file = cfg.output_path.has_value();
    if (sink_is_file) {
        sink = pcapture::format::make_file_sink(*cfg.output_path);
        if (!pcapture::format::sink_good(*sink)) {
            std::cerr << "pcapture: cannot open output file: " << *cfg.output_path << "\n";
            return 2;
        }
    } else {
        sink = pcapture::format::make_stdout_sink();
    }

    // Resolve the color palette here, in main() — the only place that knows
    // the destination of stdout, the user's --color choice, and the process
    // environment all at once. Enable Windows VT processing eagerly so the
    // ANSI escapes are interpreted instead of printed literally; this is a
    // no-op when stdout isn't a real console or on non-Windows platforms.
    const auto color_mode = to_format_color_mode(cfg.color_mode);
    const bool tty = pcapture::format::stdout_is_tty();
    const bool no_color = pcapture::format::no_color_env_set();
    const auto& palette = pcapture::format::resolve_palette(
        color_mode, sink_is_file, tty, no_color);
    if (palette.enabled()) {
        pcapture::format::enable_vt_processing_on_stdout();
    }

    if (cfg.list_interfaces) {
        return pcapture::capture::list_interfaces(cfg.format, sink->stream(), std::cerr);
    }

    return pcapture::pipeline::run_threaded(
        cfg, *sink, palette, std::cerr,
        /*stderr_is_tty=*/pcapture::format::stderr_is_tty());
}

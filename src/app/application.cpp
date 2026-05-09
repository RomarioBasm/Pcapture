#include "app/application.hpp"

#include "capture/pcap_capture.hpp"
#include "capture/pcap_handle.hpp"
#include "model/raw_packet.hpp"
#include "parser/parser.hpp"
#include "filter/filter.hpp"
#include "app/packet_queue.hpp"
#include "output/banner.hpp"
#include "output/color.hpp"
#include "output/hex_formatter.hpp"
#include "output/table.hpp"
#include "capture/platform/signals.hpp"

#include <pcap.h>

#include <chrono>
#include <cstdio>
#include <ostream>
#include <sstream>
#include <string>
#include <thread>

namespace pcapture::pipeline {
namespace {

// Pick the status icon for a row. Drop-style metrics turn red when non-zero;
// "should match" rows compare against a reference and are green only when
// equal; pure observations (received) stay neutral; informational rows
// without a clear pass/fail get the plain space.
format::PanelRow row_drop(const char* label, std::uint64_t value) {
    format::PanelRow r;
    r.status = (value == 0) ? format::StatusKind::Ok : format::StatusKind::Danger;
    r.label  = label;
    r.value  = value;
    return r;
}

format::PanelRow row_match(const char* label, std::uint64_t value,
                           std::uint64_t expected) {
    format::PanelRow r;
    r.status = (value == expected) ? format::StatusKind::Ok : format::StatusKind::Danger;
    r.label  = label;
    r.value  = value;
    return r;
}

format::PanelRow row_neutral(const char* label, std::uint64_t value) {
    format::PanelRow r;
    r.status = format::StatusKind::Neutral;
    r.label  = label;
    r.value  = value;
    return r;
}

format::PanelRow row_info_pct(const char* label, std::uint64_t value,
                              std::uint64_t reference) {
    // Informational row (filtered/dropped) — no pass/fail icon, just a
    // percentage when the reference is non-zero so the user can read at a
    // glance how much was lost / filtered relative to the input.
    format::PanelRow r;
    r.status = format::StatusKind::Plain;
    r.label  = label;
    r.value  = value;
    if (reference > 0) {
        r.percent = 100.0 * static_cast<double>(value) / static_cast<double>(reference);
    }
    return r;
}

format::PanelRow row_drop_pct(const char* label, std::uint64_t value,
                              std::uint64_t reference) {
    auto r = row_drop(label, value);
    if (reference > 0) {
        r.percent = 100.0 * static_cast<double>(value) / static_cast<double>(reference);
    }
    return r;
}

format::PanelRow row_match_pct(const char* label, std::uint64_t value,
                               std::uint64_t expected,
                               std::uint64_t reference) {
    auto r = row_match(label, value, expected);
    if (reference > 0) {
        r.percent = 100.0 * static_cast<double>(value) / static_cast<double>(reference);
    }
    return r;
}

// ASCII-only summary used when the chrome stream is being captured by a host
// that mangles UTF-8 (Windows PowerShell `>` reinterprets bytes through the
// active legacy code page before re-encoding to UTF-16, so "─" "▌" "·" all
// emerge as mojibake). Stays parseable with shell tools and survives any
// reasonable redirection chain.
//
// Built in a stringstream and emitted in a single `<<` so the underlying
// stream sees one contiguous write. Matters for PowerShell 5.1: it wraps the
// first native-stderr write in a NativeCommandError envelope (~7 lines of
// "At line:1 char:1" / CategoryInfo noise around the content). One write =
// one envelope for the whole summary instead of one per line.
void write_plain_summary(std::ostream& out,
                         const PipelineStats& stats,
                         bool include_kernel,
                         bool comment_prefix) {
    auto pct_suffix = [](std::uint64_t value, std::uint64_t reference) {
        if (reference == 0) return std::string{};
        char buf[16];
        std::snprintf(buf, sizeof buf, " (%.1f%%)",
                      100.0 * static_cast<double>(value) / static_cast<double>(reference));
        return std::string(buf);
    };

    const std::uint64_t total_drops =
        stats.dropped_queue + stats.kernel_dropped + stats.iface_dropped;

    const char* p = comment_prefix ? "# " : "";

    std::ostringstream s;
    // When this summary is going to stderr (comment_prefix == false), lead
    // with a sacrificial blank line. PowerShell 5.1 wraps the first line of
    // any first native-stderr write in a NativeCommandError envelope; an
    // empty first line means the envelope wraps nothing useful and the real
    // summary appears cleanly below it. When the summary is going to stdout
    // alongside packet lines (comment_prefix == true), the leading blank is
    // skipped — stdout has no envelope to absorb and an extra newline would
    // just be noise in the captured packet stream.
    if (!comment_prefix) {
        s << "\n";
    }
    s << p << "-- capture -- " << stats.printed
      << " frame" << (stats.printed == 1 ? "" : "s")
      << ", " << total_drops << " drop" << (total_drops == 1 ? "" : "s")
      << "\n";
    s << p << "pcapture: captured=" << stats.captured
      << " decoded="                << stats.decoded
      << " filtered="               << stats.filtered_out
      << pct_suffix(stats.filtered_out, stats.decoded)
      << " displayed="              << stats.printed
      << pct_suffix(stats.printed, stats.captured)
      << " queue_drops="            << stats.dropped_queue
      << "\n";
    if (include_kernel) {
        s << p << "kernel:   received=" << stats.kernel_received
          << " dropped="                 << stats.kernel_dropped
          << pct_suffix(stats.kernel_dropped, stats.kernel_received)
          << " iface_dropped="           << stats.iface_dropped
          << "\n";
    }
    out << s.str();
}

DropPolicy to_drop_policy(cli::BackPressure b) {
    switch (b) {
    case cli::BackPressure::DropNewest: return DropPolicy::DropNewest;
    case cli::BackPressure::DropOldest: return DropPolicy::DropOldest;
    case cli::BackPressure::Block:      return DropPolicy::Block;
    }
    return DropPolicy::DropNewest;
}

// Per-thread counters. Threads update only their own struct, then the values
// are folded into PipelineStats after every thread joins. Avoids atomics on
// the hot path and keeps the summary's reduction logic in one place.
struct CaptureCounters {
    std::uint64_t captured = 0;
    std::uint64_t dropped_q1 = 0;
    std::uint64_t kernel_received = 0;
    std::uint64_t kernel_dropped = 0;
    std::uint64_t iface_dropped = 0;
};
struct DecoderCounters {
    std::uint64_t decoded = 0;
    std::uint64_t filtered_out = 0;
    std::uint64_t dropped_q2 = 0;
};
struct FormatterCounters {
    std::uint64_t printed = 0;
};

// Item carried on Q2 (decoder -> formatter). The decoded model already mirrors
// timestamp/seq/lengths from the raw frame, so only the byte buffer needs to
// be carried — and only when the formatter actually needs it (verbosity 2 hex
// dump). Empty `hex_bytes` is the common case and costs nothing to move.
struct DecodedItem {
    decode::DecodedPacket pkt;
    std::vector<std::uint8_t> hex_bytes;
};

struct CaptureState {
    BoundedQueue<capture::RawFrame>* queue;
    CaptureCounters* counters;
    pcap_t* handle;
    std::uint64_t count_limit;
    int linktype = 0;
    std::uint64_t next_seq = 0;
    // Replay-only fields. Live captures leave these at their defaults; offline
    // captures use them to honour wall-clock spacing across packets.
    bool nanosecond_timestamps = false;
    bool pace_replay = false;
    double replay_speed_factor = 1.0;
    std::chrono::steady_clock::time_point pace_start{};
    std::chrono::system_clock::time_point first_pkt_ts{};
    bool pace_initialized = false;
};

void on_packet(u_char* user, const struct pcap_pkthdr* hdr, const u_char* bytes) {
    auto* s = reinterpret_cast<CaptureState*>(user);
    s->counters->captured++;

    capture::RawFrame frame;
    // tv_usec carries nanoseconds when libpcap was told the file is ns-precision;
    // otherwise it's microseconds. Treating ns as us would scale time by 1000x.
    const auto subseconds = s->nanosecond_timestamps
        ? std::chrono::duration_cast<std::chrono::system_clock::duration>(
              std::chrono::nanoseconds{hdr->ts.tv_usec})
        : std::chrono::duration_cast<std::chrono::system_clock::duration>(
              std::chrono::microseconds{hdr->ts.tv_usec});
    frame.timestamp = std::chrono::system_clock::time_point{
        std::chrono::seconds{hdr->ts.tv_sec} + subseconds};
    frame.seq = ++s->next_seq;
    frame.linktype = s->linktype;
    frame.captured_len = hdr->caplen;
    frame.original_len = hdr->len;
    frame.bytes.assign(bytes, bytes + hdr->caplen);

    if (s->pace_replay) {
        // Sleep until our steady-clock offset catches up with the packet's
        // offset from the first packet, scaled by the speed factor. Anchoring
        // on the first packet (rather than per-packet deltas) keeps cumulative
        // drift bounded — slow consumers don't compound timing error.
        if (!s->pace_initialized) {
            s->first_pkt_ts = frame.timestamp;
            s->pace_start = std::chrono::steady_clock::now();
            s->pace_initialized = true;
        } else {
            using DoubleNs = std::chrono::duration<double, std::nano>;
            const auto pkt_offset = std::chrono::duration_cast<DoubleNs>(
                frame.timestamp - s->first_pkt_ts);
            const DoubleNs scaled_ns(pkt_offset.count() / s->replay_speed_factor);
            const auto scaled = std::chrono::duration_cast<std::chrono::nanoseconds>(scaled_ns);
            const auto target = s->pace_start + scaled;
            const auto now = std::chrono::steady_clock::now();
            if (target > now) {
                std::this_thread::sleep_until(target);
            }
        }
    }

    auto rc = s->queue->push(std::move(frame));
    if (rc == PushResult::Dropped) {
        s->counters->dropped_q1++;
    }

    if (s->count_limit && s->counters->captured >= s->count_limit) {
        pcap_breakloop(s->handle);
    }
}

} // namespace

int run_threaded(const cli::Config& cfg, std::ostream& out, std::ostream& err) {
    // Wrap the supplied ostream in a non-owning StreamSink so the body of
    // run_threaded only knows about Sinks. Keeps test call sites — which
    // pass `std::ostringstream` — working without introducing a Sink wrapper
    // at every test. No color: tests assert on plain text.
    auto sink = format::make_stream_sink(out);
    return run_threaded(cfg, *sink, format::no_color_palette(), err);
}

int run_threaded(const cli::Config& cfg,
                 format::Sink& sink,
                 const format::Palette& palette,
                 std::ostream& err,
                 bool stderr_is_tty) {
    std::ostream& out = sink.stream();
    auto open_result = capture::open_source(cfg, err);
    if (!open_result) return 2; // diagnostics already on `err`
    auto& opened = open_result.value();
    const bool offline = opened.offline;

    // Logo-themed startup line on stderr. Tells the user instantly which
    // version is running and which mode they're in, so a long-running session
    // is unambiguous when it eventually scrolls back into view. Skipped
    // entirely when stderr isn't a TTY: in that case stderr is being captured
    // (typically by PowerShell, which wraps the first native-stderr write in a
    // NativeCommandError envelope), and a captured log is better off without
    // a banner that the user can already infer from their own command line.
    if (stderr_is_tty) {
        format::write_logo_glyph(err, palette);
        err << ' ' << format::program_name() << ' ' << format::program_version()
            << " \xE2\x80\x94 ";  // U+2014 EM DASH
        if (offline) {
            err << "replaying " << (cfg.read_path ? *cfg.read_path : std::string{"<file>"});
        } else {
            err << "capturing on " << cfg.interface;
        }
        err << '\n';
    }

    util::install_signal_handlers();
    util::set_active_pcap(opened.handle.get());

    const auto tf = [&] {
        switch (cfg.time_format) {
        case cli::TimeFormat::None:     return format::TimeFormat::None;
        case cli::TimeFormat::Relative: return format::TimeFormat::Relative;
        case cli::TimeFormat::Absolute: return format::TimeFormat::Absolute;
        case cli::TimeFormat::Epoch:    return format::TimeFormat::Epoch;
        }
        return format::TimeFormat::Relative;
    }();
    std::unique_ptr<format::Formatter> fmt;
    switch (cfg.format) {
    case cli::OutputFormat::Human:   fmt = format::make_human_formatter(cfg.verbosity, tf, palette); break;
    case cli::OutputFormat::Compact: fmt = format::make_compact_formatter(tf, palette); break;
    case cli::OutputFormat::Json:    fmt = format::make_json_formatter(); break;
    }
    fmt->prologue(out);

    std::string filter_err;
    auto filter = filter::compile(cfg.match_predicates, filter_err);
    if (!filter) {
        err << "pcapture: bad --match: " << filter_err << "\n";
        return 2;
    }

    PipelineStats stats;
    const auto drop_policy = to_drop_policy(cfg.back_pressure);
    BoundedQueue<capture::RawFrame> q1(cfg.queue_capacity, drop_policy);
    BoundedQueue<DecodedItem>       q2(cfg.queue_capacity, drop_policy);

    // The capture thread sets `capture_rc` before exiting; main reads it after
    // joining all three threads. Plain int is fine because the only writer is
    // the capture thread and we always join before reading.
    int capture_rc = 0;

    // Per-thread counters; reduced into `stats` after all threads join.
    CaptureCounters   cap_ctrs;
    DecoderCounters   dec_ctrs;
    FormatterCounters fmt_ctrs;

    // Build decode options once, outside the hot loop. Cheap today, matters
    // at line rate.
    decode::DecodeOptions decode_opts;
    decode_opts.check_checksums = cfg.check_checksums;
    const bool dump_hex = (cfg.format == cli::OutputFormat::Human) && cfg.verbosity >= 2;

    // -- Formatter thread --------------------------------------------------
    // Sole writer to `out` between prologue() and epilogue(). Drains Q2 and
    // exits when the decoder closes it.
    std::thread formatter_thread([&] {
        while (auto item = q2.pop()) {
            fmt->format(item->pkt, out);
            if (!item->hex_bytes.empty()) {
                util::hexdump(item->hex_bytes.data(), item->hex_bytes.size(), out);
            }
            fmt_ctrs.printed++;
        }
    });

    // -- Decoder thread ----------------------------------------------------
    // Pulls raw frames off Q1, runs the decoder + filter, hands DecodedItems
    // to Q2. Closes Q2 once Q1 has been drained so the formatter can finish.
    std::thread decoder_thread([&] {
        while (auto frame = q1.pop()) {
            dec_ctrs.decoded++;
            auto pkt = decode::decode(*frame, decode_opts);
            if (!filter->accept(pkt)) {
                dec_ctrs.filtered_out++;
                continue;
            }
            DecodedItem item;
            item.pkt = std::move(pkt);
            // Move the byte buffer through Q2 only when the formatter is
            // going to dump it; otherwise let it die with the RawFrame to
            // avoid the per-packet allocation churn on Q2.
            if (dump_hex && !frame->bytes.empty()) {
                item.hex_bytes = std::move(frame->bytes);
            }
            const auto rc = q2.push(std::move(item));
            if (rc == PushResult::Dropped) {
                dec_ctrs.dropped_q2++;
            }
        }
        q2.close();
    });

    // -- Capture thread ----------------------------------------------------
    // Owns the pcap_dispatch loop. Pushes RawFrames into Q1 via the on_packet
    // callback; closes Q1 on exit so the decoder can drain and shut down.
    std::thread capture_thread([&] {
        CaptureState cs{};
        cs.queue = &q1;
        cs.counters = &cap_ctrs;
        cs.handle = opened.handle.get();
        cs.count_limit = cfg.count;
        cs.nanosecond_timestamps = opened.nanosecond_timestamps;
        cs.linktype = opened.datalink;
        cs.pace_replay = offline && cfg.replay_speed_mode == cli::ReplaySpeed::Multiplier;
        cs.replay_speed_factor = cfg.replay_speed_factor;

        const auto start = std::chrono::steady_clock::now();
        while (!util::stop_flag().load(std::memory_order_acquire)) {
            const int n = pcap_dispatch(opened.handle.get(), -1, on_packet,
                                        reinterpret_cast<u_char*>(&cs));
            if (n == -1) {
                err << "pcap_dispatch: " << pcap_geterr(opened.handle.get()) << "\n";
                capture_rc = 1;
                break;
            }
            if (n == -2) break; // pcap_breakloop fired
            // pcap_dispatch == 0 is overloaded: live mode = "no packets in
            // this timeout window, keep polling"; offline mode = "EOF". Only
            // break the loop in the offline case so live captures don't exit
            // on idle.
            if (offline && n == 0) break;
            if (cfg.count && cap_ctrs.captured >= cfg.count) break;
            if (cfg.duration_s > 0) {
                const auto elapsed = std::chrono::steady_clock::now() - start;
                if (elapsed >= std::chrono::seconds(cfg.duration_s)) break;
            }
        }

        // pcap_stats is undefined on offline handles (libpcap returns an
        // error), and the numbers wouldn't be meaningful anyway since there's
        // no kernel ring behind a saved file. Skip and leave the counters at
        // zero.
        if (!offline) {
            pcap_stat ps{};
            if (pcap_stats(opened.handle.get(), &ps) == 0) {
                cap_ctrs.kernel_received = ps.ps_recv;
                cap_ctrs.kernel_dropped  = ps.ps_drop;
                cap_ctrs.iface_dropped   = ps.ps_ifdrop;
            }
        }
        q1.close();
    });

    // Wait in pipeline order: capture finishes -> Q1 closes -> decoder drains
    // and closes Q2 -> formatter drains. Joining the formatter last guarantees
    // every accepted packet has reached `out` before we touch the sink.
    capture_thread.join();
    decoder_thread.join();
    formatter_thread.join();

    util::set_active_pcap(nullptr);

    // Reduce per-thread counters into the summary struct. Q1 and Q2 drops
    // both feed the single "queue drops" row — the user reads it as "how
    // much did the pipeline shed because something downstream was slow",
    // which is true regardless of which queue overflowed.
    stats.captured        = cap_ctrs.captured;
    stats.decoded         = dec_ctrs.decoded;
    stats.filtered_out    = dec_ctrs.filtered_out;
    stats.printed         = fmt_ctrs.printed;
    stats.dropped_queue   = cap_ctrs.dropped_q1 + dec_ctrs.dropped_q2;
    stats.kernel_received = cap_ctrs.kernel_received;
    stats.kernel_dropped  = cap_ctrs.kernel_dropped;
    stats.iface_dropped   = cap_ctrs.iface_dropped;

    int rc = capture_rc;
    fmt->epilogue(out);
    sink.flush();

    // Human format prints a coloured table on stdout — its summary panels
    // belong on the same stream so the report reads as one block. Compact
    // and JSON normally keep the summary on stderr so machine consumers
    // piping stdout don't have to filter it out — but when stderr is
    // captured (e.g. PowerShell `2> file`), any first stderr write triggers
    // PS 5.1's NativeCommandError envelope and dumps ~7 lines of "At line:1
    // char:1" / CategoryInfo noise into the captured file. There's no flag
    // we can set in the child process to disable that wrap.
    //
    // So when stderr is not a TTY for compact/json, we route the summary to
    // stdout instead, prefixed with "# " so awk/grep/cut consumers can skip
    // it the same way they'd skip shell-style comments. Result: stderr stays
    // empty (no PS envelope possible), and `pcapture ... > file.txt` lands
    // packets + summary in one clean ASCII file.
    const bool reroute_to_stdout =
        cfg.format != cli::OutputFormat::Human && !stderr_is_tty;
    std::ostream& chrome = (cfg.format == cli::OutputFormat::Human || reroute_to_stdout)
        ? out : err;
    // Pick rendering style by whether the chrome destination is a real TTY.
    // For human, palette.enabled() is the proxy — colors only resolve on
    // when stdout is a TTY (or `--color always` was forced, in which case
    // the user opted into fancy output). For compact/json on stderr the
    // chrome destination is stderr itself; on the rerouted-to-stdout path
    // we always want plain ASCII (a captured stdout file may be machine-
    // parsed, and unicode chrome would be mojibake'd by PS's UTF-16 anyway).
    const bool unicode_ok = (cfg.format == cli::OutputFormat::Human)
        ? palette.enabled()
        : (stderr_is_tty && !reroute_to_stdout);
    write_shutdown_summary(chrome, stats, /*include_kernel=*/!offline,
                           palette, unicode_ok, /*comment_prefix=*/reroute_to_stdout);
    sink.flush();
    return rc;
}

void write_shutdown_summary(std::ostream& err,
                            const PipelineStats& stats,
                            bool include_kernel,
                            const format::Palette& palette,
                            bool unicode_ok,
                            bool comment_prefix) {
    if (!unicode_ok) {
        write_plain_summary(err, stats, include_kernel, comment_prefix);
        return;
    }
    // Title strip first — its right-side suffix gives the at-a-glance result
    // (frame count + drop count). The "0 drops" reads green when truly zero,
    // red otherwise, so the user can read the run's outcome without scanning
    // the panel rows.
    const std::uint64_t total_drops =
        stats.dropped_queue + stats.kernel_dropped + stats.iface_dropped;
    std::ostringstream suffix;
    suffix << stats.printed << " frame" << (stats.printed == 1 ? "" : "s") << " \xC2\xB7 ";
    if (total_drops == 0) {
        suffix << palette.success << "0 drops" << palette.reset;
    } else {
        suffix << palette.danger << total_drops << " drops" << palette.reset;
    }
    err << '\n';
    format::write_title_strip(err, palette, "capture", suffix.str(),
                              format::kTotalRowWidth);
    err << '\n';

    // pcapture panel: process-side counters. captured -> decoded should be
    // exact; displayed reflects what survived the filter.
    format::Panel pcap_panel;
    pcap_panel.title = "pcapture";
    pcap_panel.rows.push_back(row_match("captured",  stats.captured, stats.decoded));
    pcap_panel.rows.push_back(row_match("decoded",   stats.decoded,  stats.captured));
    pcap_panel.rows.push_back(row_info_pct("filtered", stats.filtered_out, stats.decoded));
    pcap_panel.rows.push_back(row_match_pct("displayed",
        stats.printed, stats.decoded - stats.filtered_out, stats.captured));
    pcap_panel.rows.push_back(row_drop("queue drops", stats.dropped_queue));

    if (include_kernel) {
        format::Panel kernel_panel;
        kernel_panel.title = "kernel";
        kernel_panel.rows.push_back(row_neutral("received",      stats.kernel_received));
        kernel_panel.rows.push_back(row_drop_pct("dropped",
            stats.kernel_dropped, stats.kernel_received));
        kernel_panel.rows.push_back(row_drop("iface dropped", stats.iface_dropped));
        format::write_panels(err, palette, pcap_panel, kernel_panel);
    } else {
        format::write_panel(err, palette, pcap_panel);
    }
    err << '\n';
}

} // namespace pcapture::pipeline

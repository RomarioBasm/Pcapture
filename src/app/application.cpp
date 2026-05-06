#include "app/application.hpp"

#include "capture/pcap_capture.hpp"
#include "capture/pcap_handle.hpp"
#include "model/raw_packet.hpp"
#include "parser/parser.hpp"
#include "filter/filter.hpp"
#include "app/packet_queue.hpp"
#include "output/hex_formatter.hpp"
#include "capture/platform/signals.hpp"

#include <pcap.h>

#include <atomic>
#include <chrono>
#include <ostream>
#include <thread>

namespace pcapture::pipeline {
namespace {

DropPolicy to_drop_policy(cli::BackPressure b) {
    switch (b) {
    case cli::BackPressure::DropNewest: return DropPolicy::DropNewest;
    case cli::BackPressure::DropOldest: return DropPolicy::DropOldest;
    case cli::BackPressure::Block:      return DropPolicy::Block;
    }
    return DropPolicy::DropNewest;
}

struct CaptureState {
    BoundedQueue<capture::RawFrame>* queue;
    PipelineStats* stats;
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
    s->stats->captured++;

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
        s->stats->dropped_queue++;
    }

    if (s->count_limit && s->stats->captured >= s->count_limit) {
        pcap_breakloop(s->handle);
    }
}

} // namespace

int run_threaded(const cli::Config& cfg, std::ostream& out, std::ostream& err) {
    // Wrap the supplied ostream in a non-owning StreamSink so the body of
    // run_threaded only knows about Sinks. Keeps test call sites — which
    // pass `std::ostringstream` — working without introducing a Sink wrapper
    // at every test.
    auto sink = format::make_stream_sink(out);
    return run_threaded(cfg, *sink, err);
}

int run_threaded(const cli::Config& cfg, format::Sink& sink, std::ostream& err) {
    std::ostream& out = sink.stream();
    auto open_result = capture::open_source(cfg, err);
    if (!open_result) return 2; // diagnostics already on `err`
    auto& opened = open_result.value();
    const bool offline = opened.offline;

    util::install_signal_handlers();
    util::set_active_pcap(opened.handle.get());

    std::unique_ptr<format::Formatter> fmt;
    switch (cfg.format) {
    case cli::OutputFormat::Human:   fmt = format::make_human_formatter(cfg.verbosity); break;
    case cli::OutputFormat::Compact: fmt = format::make_compact_formatter(); break;
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
    BoundedQueue<capture::RawFrame> queue(cfg.queue_capacity, to_drop_policy(cfg.back_pressure));

    std::atomic<bool> consumer_running{true};

    // Consumer: decode + format. Blocks on queue.pop(). Returns when queue is
    // closed AND drained.
    const bool dump_hex = (cfg.format == cli::OutputFormat::Human) && cfg.verbosity >= 2;
    // Build options once, outside the hot loop, so each frame doesn't pay
    // for option assembly. Cheap now, would matter at line rate.
    decode::DecodeOptions decode_opts;
    decode_opts.check_checksums = cfg.check_checksums;
    std::thread consumer([&] {
        while (auto frame = queue.pop()) {
            stats.decoded++;
            auto pkt = decode::decode(*frame, decode_opts);
            if (!filter->accept(pkt)) {
                stats.filtered_out++;
                continue;
            }
            fmt->format(pkt, out);
            if (dump_hex && !frame->bytes.empty()) {
                util::hexdump(frame->bytes.data(), frame->bytes.size(), out);
            }
            stats.printed++;
        }
        consumer_running = false;
    });

    CaptureState cs{};
    cs.queue = &queue;
    cs.stats = &stats;
    cs.handle = opened.handle.get();
    cs.count_limit = cfg.count;
    cs.nanosecond_timestamps = opened.nanosecond_timestamps;
    cs.linktype = opened.datalink;
    cs.pace_replay = offline && cfg.replay_speed_mode == cli::ReplaySpeed::Multiplier;
    cs.replay_speed_factor = cfg.replay_speed_factor;

    const auto start = std::chrono::steady_clock::now();
    int rc = 0;
    while (!util::stop_flag().load(std::memory_order_acquire)) {
        const int n = pcap_dispatch(opened.handle.get(), -1, on_packet,
                                    reinterpret_cast<u_char*>(&cs));
        if (n == -1) {
            err << "pcap_dispatch: " << pcap_geterr(opened.handle.get()) << "\n";
            rc = 1;
            break;
        }
        if (n == -2) break; // pcap_breakloop fired
        // pcap_dispatch == 0 is overloaded: live mode = "no packets in this
        // timeout window, keep polling"; offline mode = "EOF". We only break
        // the loop in the offline case so live captures don't exit on idle.
        if (offline && n == 0) break;
        if (cfg.count && stats.captured >= cfg.count) break;
        if (cfg.duration_s > 0) {
            const auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed >= std::chrono::seconds(cfg.duration_s)) break;
        }
    }

    // pcap_stats is undefined on offline handles (libpcap returns an error),
    // and the numbers wouldn't be meaningful anyway since there's no kernel
    // ring behind a saved file. Skip and leave the counters at zero.
    if (!offline) {
        pcap_stat ps{};
        if (pcap_stats(opened.handle.get(), &ps) == 0) {
            stats.kernel_received = ps.ps_recv;
            stats.kernel_dropped  = ps.ps_drop;
            stats.iface_dropped   = ps.ps_ifdrop;
        }
    }
    util::set_active_pcap(nullptr);

    // Drain: tell consumer no more frames are coming and wait.
    queue.close();
    if (consumer.joinable()) consumer.join();
    fmt->epilogue(out);
    sink.flush();

    err << "\npcapture: shutdown summary\n"
        << "  packets captured  : " << stats.captured << "\n"
        << "  packets decoded   : " << stats.decoded << "\n"
        << "  packets filtered  : " << stats.filtered_out << "\n"
        << "  packets printed   : " << stats.printed << "\n"
        << "  queue drops       : " << stats.dropped_queue << "\n"
        << "  kernel received   : " << stats.kernel_received << "\n"
        << "  kernel dropped    : " << stats.kernel_dropped << "\n"
        << "  iface dropped     : " << stats.iface_dropped << "\n";

    return rc;
}

} // namespace pcapture::pipeline

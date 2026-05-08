#include "cli/config.hpp"

#include "output/banner.hpp"

#include <cxxopts.hpp>

#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace pcapture::cli {

std::optional<OutputFormat> parse_format(const std::string& s) {
    if (s == "human")   return OutputFormat::Human;
    if (s == "compact") return OutputFormat::Compact;
    if (s == "json")    return OutputFormat::Json;
    return std::nullopt;
}

std::optional<BackPressure> parse_back_pressure(const std::string& s) {
    if (s == "drop-newest") return BackPressure::DropNewest;
    if (s == "drop-oldest") return BackPressure::DropOldest;
    if (s == "block")       return BackPressure::Block;
    return std::nullopt;
}

std::optional<TimeFormat> parse_time_format(const std::string& s) {
    if (s == "none")     return TimeFormat::None;
    if (s == "relative") return TimeFormat::Relative;
    if (s == "absolute") return TimeFormat::Absolute;
    if (s == "epoch")    return TimeFormat::Epoch;
    return std::nullopt;
}

std::optional<ColorMode> parse_color_mode(const std::string& s) {
    if (s == "auto")   return ColorMode::Auto;
    if (s == "always") return ColorMode::Always;
    if (s == "never")  return ColorMode::Never;
    return std::nullopt;
}

std::optional<std::pair<ReplaySpeed, double>> parse_replay_speed(const std::string& s) {
    if (s.empty()) return std::nullopt;
    if (s == "asfast" || s == "as-fast" || s == "max") {
        return std::make_pair(ReplaySpeed::AsFast, 1.0);
    }
    double factor = 0.0;
    try {
        std::size_t end = 0;
        factor = std::stod(s, &end);
        if (end != s.size()) return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!(factor > 0.0) || factor > 1000.0) return std::nullopt;
    return std::make_pair(ReplaySpeed::Multiplier, factor);
}

const char* to_string(OutputFormat f) {
    switch (f) {
    case OutputFormat::Human:   return "human";
    case OutputFormat::Compact: return "compact";
    case OutputFormat::Json:    return "json";
    }
    return "?";
}

const char* to_string(BackPressure b) {
    switch (b) {
    case BackPressure::DropNewest: return "drop-newest";
    case BackPressure::DropOldest: return "drop-oldest";
    case BackPressure::Block:      return "block";
    }
    return "?";
}

const char* to_string(TimeFormat t) {
    switch (t) {
    case TimeFormat::None:     return "none";
    case TimeFormat::Relative: return "relative";
    case TimeFormat::Absolute: return "absolute";
    case TimeFormat::Epoch:    return "epoch";
    }
    return "?";
}

const char* to_string(ColorMode c) {
    switch (c) {
    case ColorMode::Auto:   return "auto";
    case ColorMode::Always: return "always";
    case ColorMode::Never:  return "never";
    }
    return "?";
}

bool validate(const Config& cfg, std::vector<std::string>& errors) {
    const std::size_t before = errors.size();

    // Exactly one capture source must be selected. Mutual exclusion catches
    // the ambiguous "both -i and -r" case at parse time rather than letting
    // the pipeline silently prefer one.
    const bool has_iface = !cfg.interface.empty();
    const bool has_read  = cfg.read_path.has_value() && !cfg.read_path->empty();
    if (!cfg.list_interfaces && !has_iface && !has_read) {
        errors.emplace_back("one of --list-interfaces, --interface <name>, or --read <file> is required");
    }
    if (has_iface && has_read) {
        errors.emplace_back("--interface and --read are mutually exclusive");
    }
    // --list-interfaces operates on live devices only; combining with --read
    // is almost certainly a mistake the user wants to know about.
    if (cfg.list_interfaces && has_read) {
        errors.emplace_back("--list-interfaces and --read are mutually exclusive");
    }
    // Replay pacing is meaningless on live captures (kernel decides timing).
    if (cfg.replay_speed_mode == ReplaySpeed::Multiplier && !has_read) {
        errors.emplace_back("--replay-speed requires --read");
    }
    if (cfg.replay_speed_mode == ReplaySpeed::Multiplier &&
        !(cfg.replay_speed_factor > 0.0 && cfg.replay_speed_factor <= 1000.0)) {
        errors.emplace_back("--replay-speed factor must be in (0, 1000]");
    }
    if (cfg.snaplen < 64 || cfg.snaplen > 262144) {
        errors.emplace_back("--snaplen must be in [64, 262144]");
    }
    if (cfg.read_timeout_ms < 0 || cfg.read_timeout_ms > 60000) {
        errors.emplace_back("--read-timeout-ms must be in [0, 60000]");
    }
    if (cfg.queue_capacity == 0) {
        errors.emplace_back("--queue-capacity must be > 0");
    }
    if (cfg.output_path && cfg.output_path->empty()) {
        errors.emplace_back("--output cannot be empty");
    }

    return errors.size() == before;
}

namespace {

constexpr const char* kProgram = "pcapture";

cxxopts::Options build_spec() {
    cxxopts::Options o(kProgram, "Cross-platform C++17 packet sniffer");
    o.add_options()
        ("h,help", "Show this help and exit")
        ("V,version", "Print version and exit")
        ("L,list-interfaces", "List capture-capable interfaces and exit")
        ("i,interface", "Interface name to capture from (live)",
            cxxopts::value<std::string>())
        ("r,read", "Read packets from a saved pcap file (offline)",
            cxxopts::value<std::string>())
        ("f,filter", "BPF filter expression (kernel-side)",
            cxxopts::value<std::string>())
        ("allow-non-ethernet", "Allow non-DLT_EN10MB datalinks (decoder may misparse)",
            cxxopts::value<bool>()->default_value("false"))
        ("check-checksums", "Validate IPv4/TCP/UDP/ICMP/ICMPv6 checksums; bad ones recorded as notes",
            cxxopts::value<bool>()->default_value("false"))
        ("s,snaplen", "Bytes to capture per packet [64..262144]",
            cxxopts::value<int>()->default_value("65535"))
        ("p,promiscuous", "Enable promiscuous mode (default: on); use --no-promiscuous to disable",
            cxxopts::value<bool>()->default_value("true"))
        ("read-timeout-ms", "libpcap read timeout in ms [0..60000]",
            cxxopts::value<int>()->default_value("100"))
        ("F,format", "Output format: human | compact | json",
            cxxopts::value<std::string>()->default_value("human"))
        ("time", "Timestamp column for human/compact: none | relative | absolute | epoch",
            cxxopts::value<std::string>()->default_value("relative"))
        ("color", "Colorize human/compact output: auto | always | never (NO_COLOR honoured in auto)",
            cxxopts::value<std::string>()->default_value("auto"))
        ("v,verbose", "Verbose multi-line output (repeat: -vv adds hex dump)",
            cxxopts::value<int>()->default_value("0")->implicit_value("1"))
        ("m,match", "Decoded-side filter predicate (key=value, repeatable). "
                    "Keys: proto, vlan, ip, src, dst, port, sport, dport.",
            cxxopts::value<std::vector<std::string>>())
        ("o,output", "Write output to file instead of stdout",
            cxxopts::value<std::string>())
        ("c,count", "Stop after N packets (0 = unlimited)",
            cxxopts::value<std::uint64_t>()->default_value("0"))
        ("d,duration", "Stop after N seconds (0 = unlimited)",
            cxxopts::value<std::uint64_t>()->default_value("0"))
        ("queue-capacity", "Bounded queue capacity (frames)",
            cxxopts::value<std::size_t>()->default_value("8192"))
        ("back-pressure", "Queue overflow policy: drop-newest | drop-oldest | block",
            cxxopts::value<std::string>()->default_value("drop-newest"))
        ("replay-speed", "Offline replay pacing: 'asfast' (default) or numeric factor (1.0 = wall-clock, 2.0 = 2x); requires --read",
            cxxopts::value<std::string>()->default_value("asfast"))
    ;
    return o;
}

} // namespace

ParseResult parse(int argc, char** argv, std::ostream& out, std::ostream& err) {
    ParseResult result;

    auto spec = build_spec();
    cxxopts::ParseResult parsed;
    try {
        parsed = spec.parse(argc, argv);
    } catch (const cxxopts::exceptions::exception& e) {
        err << kProgram << ": " << e.what() << "\n";
        result.exit_code = 2;
        result.errors.emplace_back(e.what());
        return result;
    }

    if (parsed.count("help")) {
        format::write_program_banner(out, format::no_color_palette());
        out << spec.help() << "\n";
        result.exit_code = 0;
        return result;
    }
    if (parsed.count("version")) {
        // Logo banner doubles as the version line — colour is off here because
        // --version is commonly piped into shell glue (`pcapture --version`).
        // Users who want the colored banner can run `--color=always`-aware
        // entry points like the startup banner emitted by run_threaded.
        format::write_program_banner(out, format::no_color_palette());
        result.exit_code = 0;
        return result;
    }

    Config& cfg = result.config;
    cfg.list_interfaces = parsed["list-interfaces"].as<bool>();
    if (parsed.count("interface")) cfg.interface = parsed["interface"].as<std::string>();
    if (parsed.count("read"))      cfg.read_path = parsed["read"].as<std::string>();
    if (parsed.count("filter"))    cfg.bpf_filter = parsed["filter"].as<std::string>();
    if (parsed.count("output"))    cfg.output_path = parsed["output"].as<std::string>();

    cfg.allow_non_ethernet = parsed["allow-non-ethernet"].as<bool>();
    cfg.check_checksums    = parsed["check-checksums"].as<bool>();

    cfg.snaplen        = parsed["snaplen"].as<int>();
    cfg.promiscuous    = parsed["promiscuous"].as<bool>();
    cfg.read_timeout_ms = parsed["read-timeout-ms"].as<int>();
    cfg.verbosity      = parsed["verbose"].as<int>();
    cfg.verbose        = cfg.verbosity > 0;
    cfg.count          = parsed["count"].as<std::uint64_t>();
    cfg.duration_s     = parsed["duration"].as<std::uint64_t>();
    cfg.queue_capacity = parsed["queue-capacity"].as<std::size_t>();

    if (parsed.count("match")) {
        cfg.match_predicates = parsed["match"].as<std::vector<std::string>>();
    }

    const auto fmt_str = parsed["format"].as<std::string>();
    if (auto f = parse_format(fmt_str)) {
        cfg.format = *f;
    } else {
        err << kProgram << ": invalid --format '" << fmt_str
            << "' (expected human|compact|json)\n";
        result.exit_code = 2;
        result.errors.emplace_back("invalid --format: " + fmt_str);
        return result;
    }

    const auto time_str = parsed["time"].as<std::string>();
    if (auto t = parse_time_format(time_str)) {
        cfg.time_format = *t;
    } else {
        err << kProgram << ": invalid --time '" << time_str
            << "' (expected none|relative|absolute|epoch)\n";
        result.exit_code = 2;
        result.errors.emplace_back("invalid --time: " + time_str);
        return result;
    }

    const auto color_str = parsed["color"].as<std::string>();
    if (auto c = parse_color_mode(color_str)) {
        cfg.color_mode = *c;
    } else {
        err << kProgram << ": invalid --color '" << color_str
            << "' (expected auto|always|never)\n";
        result.exit_code = 2;
        result.errors.emplace_back("invalid --color: " + color_str);
        return result;
    }

    const auto bp_str = parsed["back-pressure"].as<std::string>();
    if (auto bp = parse_back_pressure(bp_str)) {
        cfg.back_pressure = *bp;
    } else {
        err << kProgram << ": invalid --back-pressure '" << bp_str
            << "' (expected drop-newest|drop-oldest|block)\n";
        result.exit_code = 2;
        result.errors.emplace_back("invalid --back-pressure: " + bp_str);
        return result;
    }

    const auto rs_str = parsed["replay-speed"].as<std::string>();
    if (auto rs = parse_replay_speed(rs_str)) {
        cfg.replay_speed_mode = rs->first;
        cfg.replay_speed_factor = rs->second;
    } else {
        err << kProgram << ": invalid --replay-speed '" << rs_str
            << "' (expected 'asfast' or a positive number <= 1000)\n";
        result.exit_code = 2;
        result.errors.emplace_back("invalid --replay-speed: " + rs_str);
        return result;
    }

    if (!validate(cfg, result.errors)) {
        for (const auto& m : result.errors) {
            err << kProgram << ": " << m << "\n";
        }
        result.exit_code = 2;
        return result;
    }

    return result;
}

} // namespace pcapture::cli

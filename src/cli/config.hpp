#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace pcapture::cli {

enum class OutputFormat {
    Human,
    Compact,
    Json,
};

enum class BackPressure {
    DropNewest,
    DropOldest,
    Block,
};

// Pacing mode for offline replay. AsFast bypasses inter-packet sleeps so
// integration tests are deterministic; Multiplier honours wall-clock spacing
// (scaled by `replay_speed_factor`) so a saved capture replays "naturally".
enum class ReplaySpeed {
    AsFast,
    Multiplier,
};

struct Config {
    bool list_interfaces = false;
    std::string interface;
    // Offline replay path. Lets users feed saved captures through the same
    // pipeline as live traffic — essential for reproducible debugging and
    // for running the tool on hosts that lack capture privileges.
    std::optional<std::string> read_path;
    std::optional<std::string> bpf_filter;
    std::optional<std::string> output_path;

    // Refuse non-Ethernet datalinks by default — the decoder assumes
    // DLT_EN10MB and will misparse Linux "any", raw IP, etc. The flag is
    // an explicit acknowledgement that output may be wrong.
    bool allow_non_ethernet = false;
    // Off by default: NIC TX checksum offload routinely produces "wrong"
    // checksums for locally-originated frames, so blanket validation would
    // spam notes. Useful when inspecting captures from another host.
    bool check_checksums = false;

    int snaplen = 65535;
    bool promiscuous = true;
    int read_timeout_ms = 100;

    OutputFormat format = OutputFormat::Human;
    bool verbose = false; // legacy single-flag mirror of (verbosity >= 1)

    std::uint64_t count = 0;     // 0 = unlimited
    std::uint64_t duration_s = 0; // 0 = unlimited

    std::size_t queue_capacity = 8192;
    BackPressure back_pressure = BackPressure::DropNewest;

    // Decoded-side filter predicates ("vlan=10", "proto=tcp", "port=443"...).
    // AND'd. See filter::compile() for the grammar.
    std::vector<std::string> match_predicates;

    // Verbosity: 0 = compact lines only, 1 = -v multi-line, 2 = -vv adds hexdump.
    int verbosity = 0;

    // Offline replay pacing. Default AsFast keeps tests deterministic; users
    // who want wall-clock fidelity pass `--replay-speed 1.0` (or any factor).
    ReplaySpeed replay_speed_mode = ReplaySpeed::AsFast;
    double replay_speed_factor = 1.0;
};

// Outcome of CLI parsing.
//   exit_code == std::nullopt -> caller should run with `config`.
//   exit_code != std::nullopt -> caller should exit with that code (help / version / error).
// `messages` are pre-rendered and already written to the appropriate stream
// (stdout for help, stderr for errors) when produced via `parse(argc, argv)`.
struct ParseResult {
    std::optional<int> exit_code;
    Config config;
    std::vector<std::string> errors;
};

// Build the cxxopts spec and parse argv. Writes help to `out` and errors to `err`.
ParseResult parse(int argc, char** argv, std::ostream& out, std::ostream& err);

// Pure validator over an already-populated Config. Used by tests and by
// `parse` after argv handling. Appends human-readable messages to `errors`.
// Returns true iff config is valid.
bool validate(const Config& cfg, std::vector<std::string>& errors);

// Helpers exposed for testing.
std::optional<OutputFormat> parse_format(const std::string& s);
std::optional<BackPressure> parse_back_pressure(const std::string& s);
// Parses "asfast" -> {AsFast, 1.0}, or a positive numeric factor in (0, 1000]
// -> {Multiplier, factor}. Empty or out-of-range returns nullopt.
std::optional<std::pair<ReplaySpeed, double>> parse_replay_speed(const std::string& s);
const char* to_string(OutputFormat);
const char* to_string(BackPressure);

} // namespace pcapture::cli

#include "cli/config.hpp"

#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace pcapture::cli;

// Small helper: build a mutable argv vector that cxxopts can chew on.
struct ArgvHolder {
    std::vector<std::string> storage;
    std::vector<char*> ptrs;
    explicit ArgvHolder(std::initializer_list<const char*> args) {
        for (auto* a : args) storage.emplace_back(a);
        ptrs.reserve(storage.size());
        for (auto& s : storage) ptrs.push_back(s.data());
    }
    int argc() const { return static_cast<int>(ptrs.size()); }
    char** argv() { return ptrs.data(); }
};

ParseResult run(std::initializer_list<const char*> args) {
    ArgvHolder h(args);
    std::ostringstream out, err;
    return parse(h.argc(), h.argv(), out, err);
}

} // namespace

TEST(ConfigParser, HelpExitsZero) {
    auto r = run({"pcapture", "--help"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 0);
}

TEST(ConfigParser, MissingInterfaceIsError) {
    auto r = run({"pcapture"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
    bool found = false;
    for (const auto& m : r.errors) {
        if (m.find("--list-interfaces") != std::string::npos &&
            m.find("--interface") != std::string::npos) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "expected message about required interface flag";
}

TEST(ConfigParser, ListInterfacesAlone) {
    auto r = run({"pcapture", "--list-interfaces"});
    ASSERT_FALSE(r.exit_code.has_value()) << "should run, not exit early";
    EXPECT_TRUE(r.config.list_interfaces);
    EXPECT_EQ(r.config.format, OutputFormat::Human);
}

TEST(ConfigParser, InterfaceShortFlag) {
    auto r = run({"pcapture", "-i", "eth0"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.interface, "eth0");
}

TEST(ConfigParser, FormatWhitelistAccepts) {
    for (const char* fmt : {"human", "compact", "json"}) {
        auto r = run({"pcapture", "-i", "eth0", "--format", fmt});
        ASSERT_FALSE(r.exit_code.has_value()) << "format=" << fmt;
        EXPECT_NE(parse_format(fmt), std::nullopt);
    }
}

TEST(ConfigParser, FormatWhitelistRejectsUnknown) {
    auto r = run({"pcapture", "-i", "eth0", "--format", "yaml"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
}

TEST(ConfigParser, BackPressureWhitelist) {
    auto good = run({"pcapture", "-i", "eth0", "--back-pressure", "block"});
    ASSERT_FALSE(good.exit_code.has_value());
    EXPECT_EQ(good.config.back_pressure, BackPressure::Block);

    auto bad = run({"pcapture", "-i", "eth0", "--back-pressure", "panic"});
    ASSERT_TRUE(bad.exit_code.has_value());
    EXPECT_EQ(*bad.exit_code, 2);
}

TEST(ConfigParser, SnaplenBoundsReject) {
    auto low = run({"pcapture", "-i", "eth0", "--snaplen", "10"});
    ASSERT_TRUE(low.exit_code.has_value());
    EXPECT_EQ(*low.exit_code, 2);

    auto high = run({"pcapture", "-i", "eth0", "--snaplen", "999999"});
    ASSERT_TRUE(high.exit_code.has_value());
    EXPECT_EQ(*high.exit_code, 2);
}

TEST(ConfigParser, CountAndDurationParsed) {
    auto r = run({"pcapture", "-i", "eth0", "--count", "100", "--duration", "5"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.count, 100u);
    EXPECT_EQ(r.config.duration_s, 5u);
}

TEST(ConfigValidator, EmptyOutputRejected) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.output_path = std::string{};
    std::vector<std::string> errs;
    EXPECT_FALSE(validate(cfg, errs));
    EXPECT_FALSE(errs.empty());
}

TEST(ConfigValidator, QueueCapacityZeroRejected) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.queue_capacity = 0;
    std::vector<std::string> errs;
    EXPECT_FALSE(validate(cfg, errs));
}

TEST(ConfigValidator, MinimalValid) {
    Config cfg;
    cfg.interface = "eth0";
    std::vector<std::string> errs;
    EXPECT_TRUE(validate(cfg, errs));
    EXPECT_TRUE(errs.empty());
}

TEST(ConfigParser, ReplaySpeedAsFastDefault) {
    auto r = run({"pcapture", "-r", "fixture.pcap"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.replay_speed_mode, ReplaySpeed::AsFast);
}

TEST(ConfigParser, ReplaySpeedNumericFactor) {
    auto r = run({"pcapture", "-r", "fixture.pcap", "--replay-speed", "2.5"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.replay_speed_mode, ReplaySpeed::Multiplier);
    EXPECT_DOUBLE_EQ(r.config.replay_speed_factor, 2.5);
}

TEST(ConfigParser, ReplaySpeedRejectsGarbage) {
    auto r = run({"pcapture", "-r", "fixture.pcap", "--replay-speed", "fast"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
}

TEST(ConfigParser, ReplaySpeedRejectsNonPositive) {
    auto r = run({"pcapture", "-r", "fixture.pcap", "--replay-speed", "0"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
}

TEST(ConfigValidator, ReplaySpeedRequiresRead) {
    Config cfg;
    cfg.interface = "eth0";
    cfg.replay_speed_mode = ReplaySpeed::Multiplier;
    cfg.replay_speed_factor = 1.0;
    std::vector<std::string> errs;
    EXPECT_FALSE(validate(cfg, errs));
}

TEST(ConfigValidator, ListInterfacesAndReadMutuallyExclusive) {
    Config cfg;
    cfg.list_interfaces = true;
    cfg.read_path = std::string{"fixture.pcap"};
    std::vector<std::string> errs;
    EXPECT_FALSE(validate(cfg, errs));
}

TEST(ConfigParser, TimeFormatDefaultRelative) {
    auto r = run({"pcapture", "-i", "eth0"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.time_format, TimeFormat::Relative);
}

TEST(ConfigParser, TimeFormatWhitelistAccepts) {
    for (const char* t : {"none", "relative", "absolute", "epoch"}) {
        auto r = run({"pcapture", "-i", "eth0", "--time", t});
        ASSERT_FALSE(r.exit_code.has_value()) << "time=" << t;
        ASSERT_TRUE(parse_time_format(t).has_value()) << t;
        EXPECT_EQ(r.config.time_format, *parse_time_format(t));
    }
}

TEST(ConfigParser, TimeFormatRejectsUnknown) {
    auto r = run({"pcapture", "-i", "eth0", "--time", "iso8601"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
}

TEST(ConfigParser, ColorDefaultAuto) {
    auto r = run({"pcapture", "-i", "eth0"});
    ASSERT_FALSE(r.exit_code.has_value());
    EXPECT_EQ(r.config.color_mode, ColorMode::Auto);
}

TEST(ConfigParser, ColorWhitelistAccepts) {
    for (const char* c : {"auto", "always", "never"}) {
        auto r = run({"pcapture", "-i", "eth0", "--color", c});
        ASSERT_FALSE(r.exit_code.has_value()) << "color=" << c;
        ASSERT_TRUE(parse_color_mode(c).has_value()) << c;
        EXPECT_EQ(r.config.color_mode, *parse_color_mode(c));
    }
}

TEST(ConfigParser, ColorRejectsUnknown) {
    auto r = run({"pcapture", "-i", "eth0", "--color", "rainbow"});
    ASSERT_TRUE(r.exit_code.has_value());
    EXPECT_EQ(*r.exit_code, 2);
}

TEST(ParseReplaySpeedHelper, KnownAliases) {
    auto a = parse_replay_speed("asfast");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->first, ReplaySpeed::AsFast);

    auto b = parse_replay_speed("1.0");
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->first, ReplaySpeed::Multiplier);
    EXPECT_DOUBLE_EQ(b->second, 1.0);

    EXPECT_FALSE(parse_replay_speed("").has_value());
    EXPECT_FALSE(parse_replay_speed("-1").has_value());
    EXPECT_FALSE(parse_replay_speed("2x").has_value());
    EXPECT_FALSE(parse_replay_speed("1001").has_value());
}

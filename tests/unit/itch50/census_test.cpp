#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#include "proto/itch50/census.h"
#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

template <class M>
std::vector<std::byte> bytes_of(const M& m) {
  std::vector<std::byte> b(M::kLen);
  EXPECT_EQ(encode(b, m), M::kLen);
  return b;
}

constexpr std::uint64_t kMs = 1'000'000;
constexpr std::uint64_t kHour = 3'600'000ull * kMs;

std::string report_of(const Census& c) {
  std::FILE* f = std::tmpfile();
  c.print_report(f);
  c.print_coverage(f);
  std::rewind(f);
  std::string s;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
  std::fclose(f);
  return s;
}

TEST(Census, CountsBurstsAndReportFormat) {
  Census c;
  auto sys = [](std::uint64_t ts, EventCode e) {
    return SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = ts, .event_code = e};
  };
  c.add(bytes_of(sys(3 * kHour, EventCode::StartOfMessages)));
  c.add(bytes_of(sys(4 * kHour, EventCode::StartOfSystemHours)));
  // 5 adds in one millisecond at 09:30:00.001, 3 in the next second.
  for (int i = 0; i < 5; ++i) {
    AddOrder a{.stock_locate = 7, .tracking_number = 0, .timestamp = 34'200'001'000'000 + std::uint64_t(i),
               .order_ref = std::uint64_t(i), .side = Side::Buy, .shares = 1, .stock = Symbol8("AAPL"), .price = 1};
    c.add(bytes_of(a));
  }
  for (int i = 0; i < 3; ++i) {
    OrderDelete d{.stock_locate = 7, .tracking_number = 0, .timestamp = 34'201'000'000'000 + std::uint64_t(i) * kMs,
                  .order_ref = std::uint64_t(i)};
    c.add(bytes_of(d));
  }
  AddOrderMpid f{.stock_locate = 7, .tracking_number = 0, .timestamp = 34'202'000'000'000, .order_ref = 9,
                 .side = Side::Sell, .shares = 1, .stock = Symbol8("AAPL"), .price = 1, .attribution = Mpid4("GSCO")};
  c.add(bytes_of(f));
  c.add({});  // zero-length record
  std::vector<std::byte> bad = bytes_of(f);
  bad.pop_back();
  c.add(bad);  // length mismatch: counted per type, no timestamp
  std::vector<std::byte> unknown(5, std::byte{'G'});
  c.add(unknown);

  EXPECT_EQ(c.messages(), 14u);
  EXPECT_EQ(c.zero_length(), 1u);
  EXPECT_EQ(c.bad_length(), 1u);
  EXPECT_EQ(c.unknown_type(), 1u);
  EXPECT_EQ(c.count('A'), 5u);
  EXPECT_EQ(c.count('F'), 2u);
  EXPECT_EQ(c.count('S'), 2u);
  EXPECT_EQ(c.locate_zero('S'), 2u);
  EXPECT_EQ(c.max_in_1ms(), 5u);
  EXPECT_EQ(c.max_in_1s(), 5u);
  EXPECT_EQ(c.timestamp_decreases(), 0u);
  EXPECT_EQ(c.first_timestamp(), 3 * kHour);
  EXPECT_EQ(c.enum_values("S.event").size(), 2u);
  EXPECT_EQ(c.enum_values("F.attribution_top").at("GSCO"), 1u);

  const std::string r = report_of(c);
  EXPECT_NE(r.find("zero_len 1 unknown_type 1 bad_len 1\n"), std::string::npos) << r;
  EXPECT_NE(r.find("  A            5  35.714% len=36 mism=0 loc0=0\n"), std::string::npos) << r;
  EXPECT_NE(r.find("  F            2  14.286% len=40 mism=1 loc0=0\n"), std::string::npos) << r;
  EXPECT_NE(r.find("  G            1   7.143% len=-1 mism=0 loc0=0\n"), std::string::npos) << r;
  EXPECT_NE(r.find("SYSTEM EVENTS: O@03:00:00.000000000 S@04:00:00.000000000\n"), std::string::npos) << r;
  EXPECT_NE(r.find("BURSTS max_msgs_in_1ms 5 at 09:30:00.001000000 ; max_in_100ms 5 ; max_in_1s 5 at second 34200 "
                   "(09:30:00)\n"),
            std::string::npos)
      << r;
  EXPECT_NE(r.find("HOURLY: 03:1 04:1 09:9\n"), std::string::npos) << r;
  EXPECT_NE(r.find("  S.event (2 distinct): 'S'=1 'O'=1\n"), std::string::npos) << r;
  EXPECT_NE(r.find("  spec-only: R H Y L V W K J h E C X U P Q B I N O\n"), std::string::npos) << r;
}

}  // namespace
}  // namespace lle::itch50

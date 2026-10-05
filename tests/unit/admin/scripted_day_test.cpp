// The T03 scripted days (05 §11: "scripted halt/IPO days reproduce the real
// ITCH message shapes"): apps/scripted_day/days/{halt,ipo}_day.txt run through
// the sequencer into the engine; the ITCH stream must carry the NASDAQ halt
// and IPO message sequences in order, pass the strict validator, and be
// identical across runs.
#include <gtest/gtest.h>

#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

#include "admin/day_runner.h"
#include "common/endian.h"

namespace lle::admin {
namespace {

std::string read(const std::string& name) {
  std::ifstream f(std::string(LLE_SOURCE_DIR) + "/apps/scripted_day/days/" + name);
  return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

std::string trim8(const std::byte* p) {
  std::string s(reinterpret_cast<const char*>(p), 8);
  while (!s.empty() && s.back() == ' ') s.pop_back();
  return s;
}

// The halt/auction events of one symbol as compact strings.
std::vector<std::string> events(const DayResult& r, const std::string& symbol) {
  std::map<std::uint16_t, std::string> names;
  std::vector<std::string> out;
  for (const auto& m : r.itch) {
    const char t = static_cast<char>(m[0]);
    const std::uint16_t loc = load_be16(m.data() + 1);
    if (t == 'R') names[loc] = trim8(m.data() + 11);
    if (t == 'K' && trim8(m.data() + 11) == symbol) out.push_back("K");
    if (names[loc] != symbol) continue;
    switch (t) {
      case 'H': {
        std::string reason(reinterpret_cast<const char*>(m.data() + 21), 4);
        while (!reason.empty() && reason.back() == ' ') reason.pop_back();
        out.push_back(std::string("H:") + static_cast<char>(m[19]) + ":" + reason);
        break;
      }
      case 'J':
        out.push_back("J:" + std::to_string(load_be32(m.data() + 31)) + ":" + std::to_string(load_be32(m.data() + 23)) +
                      ":" + std::to_string(load_be32(m.data() + 27)));
        break;
      case 'I': out.push_back(std::string("I:") + static_cast<char>(m[48])); break;
      case 'Q':
        out.push_back(std::string("Q:") + static_cast<char>(m[39]) + ":" + std::to_string(load_be64(m.data() + 11)) +
                      ":" + std::to_string(load_be32(m.data() + 27)));
        break;
      default: break;
    }
  }
  return out;
}

// `want` occurs in `got` as a subsequence.
::testing::AssertionResult in_order(const std::vector<std::string>& got, const std::vector<std::string>& want) {
  std::size_t k = 0;
  for (const auto& e : got)
    if (k < want.size() && e == want[k]) ++k;
  if (k == want.size()) return ::testing::AssertionSuccess();
  std::string s;
  for (const auto& e : got)
    if (e[0] != 'I') s += e + " ";
  return ::testing::AssertionFailure() << "missing \"" << want[k] << "\" (step " << k << "); events (NOII omitted): "
                                       << s;
}

TEST(ScriptedDay, HaltDayShapes) {
  const auto r = run_day(read("halt_day.txt"));
  ASSERT_TRUE(r.has_value()) << r.error();
  EXPECT_EQ(r->invalid_itch, 0u);
  // News halt: H T1, quotation-only H Q T3 with collars 55/45, NOII 'H' every
  // second, extension 1 to 60/40, the halt cross (200 at 56.00), H T.
  EXPECT_TRUE(in_order(events(*r, "HALT"), {"H:H:T1", "H:Q:T3", "J:0:550000:450000", "I:H", "J:1:600000:400000",
                                            "I:H", "Q:H:200:560000", "H:T:"}));
  // LULD pause: H P LUDP with collars 38.85 / 31.00, NOII, the pause cross, H T.
  EXPECT_TRUE(in_order(events(*r, "FLAT"), {"H:P:LUDP", "J:0:388500:310000", "I:H", "Q:H:100:370000", "H:T:"}));
  EXPECT_EQ(r->liquidity.at('K'), 4u);  // halt-cross executions: two pairs
  const auto again = run_day(read("halt_day.txt"));
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(again->itch, r->itch);
  EXPECT_EQ(again->state_hash, r->state_hash);
}

TEST(ScriptedDay, IpoDayShapes) {
  const auto r = run_day(read("ipo_day.txt"));
  ASSERT_TRUE(r.has_value()) << r.error();
  EXPECT_EQ(r->invalid_itch, 0u);
  // IPO: H H IPO1, K, H Q IPOQ, NOII 'H', the IPO cross (500 at 25.00), H T.
  EXPECT_TRUE(in_order(events(*r, "NEWCO"), {"H:H:IPO1", "K", "H:Q:IPOQ", "I:H", "Q:H:500:250000", "H:T:"}));
  EXPECT_EQ(r->liquidity.at('H'), 4u);  // IPO-cross executions carry liquidity 'H'
  // AAPL opened with the opening cross ('Q' type 'O') and traded.
  EXPECT_TRUE(in_order(events(*r, "AAPL"), {"Q:O:0:0"}));
  const auto again = run_day(read("ipo_day.txt"));
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(again->itch, r->itch);
  EXPECT_EQ(again->state_hash, r->state_hash);
}

// NOII cadence (05 §11 T03 "NOII cadence check exact"; R2 D2.1, D2.6): per
// symbol, EOII every 10 s 09:25:00-09:27:50 and 15:50:00-15:54:50, NOII every
// second 09:28:00-09:29:59 and 15:55:00-15:59:59, at those times (within the
// nanoseconds the sequencer adds to keep stamps strictly increasing).
TEST(ScriptedDay, NoiiCadenceIsExact) {
  const auto r = run_day(
      "day 20261001\n"
      "symbol AAPL prior=100.00\nsymbol MSFT prior=20.00\n"
      "account 100 FIRM\nsession 1 account=100 flags=market\n"
      "04:00:00.5 login 1\n"
      "09:00:00 enter 1 1 B 100 AAPL MKT cross=O\n"
      "09:00:01 enter 1 2 B 100 MSFT MKT cross=C\n"
      "16:00:10 run\n");
  ASSERT_TRUE(r.has_value()) << r.error();
  EXPECT_EQ(r->invalid_itch, 0u);
  for (const std::uint16_t loc : {std::uint16_t{1}, std::uint16_t{2}}) {
    std::vector<std::uint64_t> open_e, open_n, close_e, close_n;
    for (const auto& m : r->itch) {
      if (static_cast<char>(m[0]) != 'I' || load_be16(m.data() + 1) != loc) continue;
      const std::uint64_t ts = load_be48(m.data() + 5);
      const char cross = static_cast<char>(m[48]);
      const std::uint64_t cut = (cross == 'O' ? 9 * 3600 + 28 * 60 : 15 * 3600 + 55 * 60) * std::uint64_t{1'000'000'000};
      const bool eoii = ts < cut;
      if (eoii) {  // EOII: Far = Near = 0, PVI blank
        EXPECT_EQ(load_be32(m.data() + 36), 0u);
        EXPECT_EQ(load_be32(m.data() + 40), 0u);
        EXPECT_EQ(static_cast<char>(m[49]), ' ');
      }
      if (cross == 'O') (eoii ? open_e : open_n).push_back(ts);
      if (cross == 'C') (eoii ? close_e : close_n).push_back(ts);
    }
    auto check = [&](const std::vector<std::uint64_t>& v, std::size_t n, std::uint64_t first_s, std::uint64_t step_s) {
      ASSERT_EQ(v.size(), n) << "locate " << loc << " first " << first_s;
      for (std::size_t i = 0; i < v.size(); ++i) {
        const std::uint64_t want = (first_s + i * step_s) * 1'000'000'000u;
        EXPECT_GE(v[i], want);
        EXPECT_LT(v[i], want + 1'000) << "locate " << loc << " tick " << i;
      }
    };
    check(open_e, 18, 9 * 3600 + 25 * 60, 10);
    check(open_n, 120, 9 * 3600 + 28 * 60, 1);
    check(close_e, 30, 15 * 3600 + 50 * 60, 10);
    check(close_n, 300, 15 * 3600 + 55 * 60, 1);
  }
}

TEST(ScriptedDay, ScriptErrorsAreReported) {
  EXPECT_FALSE(run_day("day 20261001\n").has_value());  // no tables
  const auto r = run_day(
      "symbol AAPL\naccount 1 FIRM\nsession 1 account=1\n10:00:00 enter 1 1 X 100 AAPL 1.00\n");
  ASSERT_FALSE(r.has_value());
  EXPECT_NE(r.error().find("line 4"), std::string::npos) << r.error();
}

}  // namespace
}  // namespace lle::admin

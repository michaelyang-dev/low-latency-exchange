#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "sim/oracles/determinism.h"
#include "sim/oracles/prefix_checker.h"
#include "sim/oracles/registry.h"
#include "sim/oracles/seq_checker.h"

namespace lle::sim {
namespace {

std::vector<std::byte> b(std::string_view s) {
  std::vector<std::byte> v(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) v[i] = static_cast<std::byte>(s[i]);
  return v;
}

TEST(OracleRegistry, PreDeclaresPlanOraclesAsPlaceholders) {
  OracleRegistry r;
  for (const std::string_view id : {kOSeq, kOReplay, kOPrefix, kONoLostFill, kOExactlyOnce, kOOutputCommit,
                                    kOOnePrimary, kOLine, kOArb, kOBook, kOConserve, kORisk, kOLive, kODeterminism}) {
    const OracleId h = r.find(id);
    ASSERT_NE(h, OracleRegistry::kNone) << id;
    EXPECT_EQ(r.list()[h].state, OracleState::Placeholder);
  }
  EXPECT_EQ(r.list().size(), 14u);
  const OracleId seq = r.activate(kOSeq);
  EXPECT_EQ(r.list()[seq].state, OracleState::Active);
  EXPECT_EQ(r.activate("O-NEW", "custom"), 14u);
}

TEST(OracleRegistry, FirstFailureBecomesTheSignature) {
  OracleRegistry r;
  std::uint64_t event = 41;
  r.set_event_index_source(&event);
  const OracleId a = r.activate("O-A");
  const OracleId c = r.activate("O-C");
  r.check(a, true, "fine");
  EXPECT_FALSE(r.failed());
  event = 42;
  r.fail(a, "boom");
  event = 50;
  r.fail(c, "later");
  ASSERT_TRUE(r.failed());
  EXPECT_EQ(r.first_failure().oracle, "O-A");
  EXPECT_EQ(r.first_failure().event_index, 42u);
  EXPECT_EQ(r.first_failure().message, "boom");
  EXPECT_EQ(r.list()[a].checks, 2u);
  EXPECT_EQ(r.list()[a].failures, 1u);
  const std::string sig = r.first_failure().str();
  EXPECT_EQ(sig.substr(0, 7), "O-A:42:");
  EXPECT_EQ(sig.size(), 7u + 18u);
}

TEST(OracleRegistry, FinalChecksStopAtFirstFailure) {
  OracleRegistry r;
  const OracleId a = r.activate("O-A");
  int ran = 0;
  r.add_final_check(a, [&] {
    ++ran;
    r.fail(a, "x");
  });
  r.add_final_check(a, [&] { ++ran; });
  r.run_final_checks();
  EXPECT_EQ(ran, 1);
}

TEST(SeqChecker, StrictContiguity) {
  SeqContiguityChecker c(1);
  EXPECT_EQ(c.observe(1), SeqVerdict::Ok);
  EXPECT_EQ(c.observe(2), SeqVerdict::Ok);
  EXPECT_EQ(c.observe(2), SeqVerdict::Duplicate);
  EXPECT_EQ(c.observe(4), SeqVerdict::Gap);
  EXPECT_EQ(c.next(), 3u);
  EXPECT_EQ(c.accepted(), 2u);
  EXPECT_EQ(c.duplicates(), 1u);
  EXPECT_EQ(c.gaps(), 1u);
}

TEST(SeqChecker, RangesLikeMoldUdp64Packets) {
  SeqContiguityChecker c(1);
  EXPECT_EQ(c.observe_range(1, 3), SeqVerdict::Ok);   // 1..3
  EXPECT_EQ(c.observe_range(2, 4), SeqVerdict::Ok);   // overlap, extends to 5
  EXPECT_EQ(c.next(), 6u);
  EXPECT_EQ(c.observe_range(1, 2), SeqVerdict::Duplicate);
  EXPECT_EQ(c.observe_range(7, 1), SeqVerdict::Gap);
  EXPECT_EQ(c.observe_range(6, 0), SeqVerdict::Ok);  // heartbeat
  KeyedSeqChecker k(1);
  EXPECT_EQ(k.observe(10, 1), SeqVerdict::Ok);
  EXPECT_EQ(k.observe(20, 1), SeqVerdict::Ok);
  EXPECT_EQ(k.observe(10, 3), SeqVerdict::Gap);
  EXPECT_EQ(k.size(), 2u);
}

TEST(PrefixChecker, CanonicalAheadObservedAheadAndInterleaved) {
  PrefixChecker p;
  EXPECT_TRUE(p.append_canonical(b("hello ")));
  EXPECT_TRUE(p.append_observed(b("hel")));
  EXPECT_TRUE(p.is_prefix());
  EXPECT_TRUE(p.append_observed(b("lo wo")));  // observed now ahead by "wo"
  EXPECT_FALSE(p.is_prefix());
  EXPECT_TRUE(p.append_canonical(b("world")));
  EXPECT_TRUE(p.is_prefix());
  EXPECT_EQ(p.matched(), 8u);
  EXPECT_FALSE(p.append_observed(b("rlX")));
  EXPECT_TRUE(p.diverged());
  EXPECT_EQ(p.divergence_offset(), 10u);
  EXPECT_FALSE(p.is_prefix());
  EXPECT_FALSE(p.append_canonical(b("more")));
}

TEST(PrefixChecker, DivergenceDetectedWhenCanonicalCatchesUp) {
  PrefixChecker p;
  EXPECT_TRUE(p.append_observed(b("abcXef")));
  EXPECT_FALSE(p.append_canonical(b("abcdef")));
  EXPECT_EQ(p.divergence_offset(), 3u);
}

TEST(PrefixChecker, LongStreamsKeepOnlyTheLag) {
  PrefixChecker p;
  std::vector<std::byte> chunk(1000);
  for (int i = 0; i < 2000; ++i) {
    for (std::size_t k = 0; k < chunk.size(); ++k) chunk[k] = static_cast<std::byte>((i * 7 + static_cast<int>(k)) & 0xFF);
    ASSERT_TRUE(p.append_canonical(chunk));
    ASSERT_TRUE(p.append_observed(chunk));
  }
  EXPECT_TRUE(p.is_prefix());
  EXPECT_EQ(p.observed_size(), 2'000'000u);
}

TEST(Determinism, HelperComparesEventsAndHash) {
  int calls = 0;
  const DeterminismResult same = check_determinism([&] {
    RunResult r;
    r.events = 10;
    r.trace_hash = 0xABC;
    ++calls;
    return r;
  });
  EXPECT_TRUE(same.ok);
  EXPECT_EQ(calls, 2);
  const DeterminismResult diff = check_determinism([&] {
    RunResult r;
    r.events = 10;
    r.trace_hash = static_cast<std::uint64_t>(++calls);
    return r;
  });
  EXPECT_FALSE(diff.ok);
  OracleRegistry reg;
  record_determinism(reg, diff);
  EXPECT_TRUE(reg.failed());
  EXPECT_EQ(reg.first_failure().oracle, "O-DETERMINISM");
}

}  // namespace
}  // namespace lle::sim

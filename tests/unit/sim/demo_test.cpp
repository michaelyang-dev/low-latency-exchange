// End-to-end tests over the demonstration worlds: determinism (09 §9), every
// fault class firing (T22), ablation independence, canary detection, and
// record/replay of the fault schedule (shrinking input).
#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "sim/worlds/worlds.h"
#include "sim/fault/injector.h"
#include "sim/fault/swarm.h"

namespace lle::sim {
namespace {

using worlds::WorldKind;

#if defined(__has_feature)
#if __has_feature(memory_sanitizer) || __has_feature(thread_sanitizer)
constexpr bool kSlowSanitizer = true;
#else
constexpr bool kSlowSanitizer = false;
#endif
#elif defined(__SANITIZE_THREAD__)
constexpr bool kSlowSanitizer = true;
#else
constexpr bool kSlowSanitizer = false;
#endif

// The worlds of this build, except `ha`: it has its own seeded test
// (tests/integration/repl) and generates its own fault schedule; and except
// exchange_ha_split, which runs the exchange_ha world again in split mode and has its own
// determinism test (sim_determinism_exchange_ha_split_8x2). Under MSan (a Debug build)
// and TSan also except the exchange worlds: a day with a deep book takes minutes there,
// the simulation runs on one thread (TSan finds nothing in it), and the MSan job runs
// them through exsim.
std::vector<WorldKind> test_worlds() {
  std::vector<WorldKind> v;
  for (const WorldKind w : worlds::built_worlds()) {
    if (w == WorldKind::Ha || w == WorldKind::ExchangeHaSplit) continue;
    if (kSlowSanitizer && (w == WorldKind::Exchange || w == WorldKind::ExchangeHa)) continue;
    v.push_back(w);
  }
  return v;
}

worlds::Report run(WorldKind w, std::uint64_t seed, Mode mode = Mode::Swarm, std::uint32_t disabled = 0,
                 bool canary = false) {
  worlds::Options o;
  o.seed = seed;
  o.faults = draw_fault_config(seed, mode, disabled);
  o.canary = canary;
  o.plan = worlds::default_plan();
  return worlds::run_world(w, o);
}

TEST(Demo, SameSeedSameTraceHashDifferentSeedsDiffer) {
  for (const WorldKind w : test_worlds()) {
    std::set<std::uint64_t> hashes;
    for (std::uint64_t seed = 1; seed <= 16; ++seed) {
      const worlds::Report a = run(w, seed);
      const worlds::Report b = run(w, seed);
      ASSERT_FALSE(a.run.failed) << worlds::world_name(w) << " seed " << seed << ": " << a.run.failure.str() << " "
                                 << a.run.failure.message;
      ASSERT_EQ(a.run.events, b.run.events) << worlds::world_name(w) << " seed " << seed;
      ASSERT_EQ(a.run.trace_hash, b.run.trace_hash) << worlds::world_name(w) << " seed " << seed;
      hashes.insert(a.run.trace_hash);
    }
    EXPECT_EQ(hashes.size(), 16u) << worlds::world_name(w);
  }
}

// The PR cadence of 09 §9 is 128 seeds, each run twice (also registered as
// the exsim ctest `sim_determinism_128x2`); unoptimized builds run a subset.
#if defined(NDEBUG)
constexpr std::uint64_t kSweepSeeds = 128;
#else
constexpr std::uint64_t kSweepSeeds = 32;
#endif

TEST(Demo, DeterminismSweepSeedsTwice) {
  int mismatches = 0;
  int failures = 0;
  for (std::uint64_t seed = 1000; seed < 1000 + kSweepSeeds; ++seed) {
    for (const WorldKind w : test_worlds()) {
      const worlds::Report a = run(w, seed);
      const worlds::Report b = run(w, seed);
      if (a.run.trace_hash != b.run.trace_hash || a.run.events != b.run.events) ++mismatches;
      if (a.run.failed) ++failures;
    }
  }
  EXPECT_EQ(mismatches, 0);
  EXPECT_EQ(failures, 0);
}

TEST(Demo, EveryFaultClassFiresAcrossASeedSweep) {
  FaultStats s;
  std::uint64_t probes_ooo = 0;
  for (std::uint64_t seed = 1; seed <= 48; ++seed) {
    for (const WorldKind w : test_worlds()) {
      const worlds::Report r = run(w, seed);
      ASSERT_FALSE(r.run.failed) << worlds::world_name(w) << " seed " << seed << ": " << r.run.failure.message;
      s += r.stats;
      probes_ooo += r.probes.hits("disk.ooo_persist_at_crash");
    }
  }
  EXPECT_GT(s.net_loss, 0u);
  EXPECT_GT(s.net_dup, 0u);
  EXPECT_GT(s.net_reorder, 0u);
  EXPECT_GT(s.net_spike, 0u);
  EXPECT_GT(s.partitions, 0u);
  EXPECT_GT(s.stream_short_segments, 0u);
  EXPECT_GT(s.stream_resets, 0u);
  EXPECT_GT(s.crashes_process, 0u);
  EXPECT_GT(s.crashes_host, 0u);
  EXPECT_GT(s.restarts, 0u);
  EXPECT_GT(s.pauses, 0u);
  EXPECT_GT(s.disk_stalls, 0u);
  EXPECT_GT(s.disk_eio, 0u);
  EXPECT_GT(s.disk_lost_unsynced + s.disk_torn, 0u);
  EXPECT_GT(s.clock_steps, 0u);
  EXPECT_GT(s.clock_drift_nodes, 0u);
  EXPECT_EQ(probes_ooo, s.disk_ooo_persist);
#if defined(LLE_SIM) && LLE_SIM
  EXPECT_GT(s.buggify_fired, 0u);
#else
  EXPECT_EQ(s.buggify_fired, 0u);  // SIM_BUGGIFY compiled out
#endif
}

// The journal's must-hit probes are observed by the journal world's device
// and harness; a short sweep reaches the non-rare ones.
TEST(Demo, JournalWorldHitsTheJournalProbes) {
  if (!worlds::world_built(WorldKind::Journal)) GTEST_SKIP() << "journal world not in this build";
  std::uint64_t between = 0, stall = 0, ooo = 0, disk_ooo = 0;
  for (std::uint64_t seed = 1; seed <= 64; ++seed) {
    const worlds::Report r = run(WorldKind::Journal, seed);
    ASSERT_FALSE(r.run.failed) << "seed " << seed << ": " << r.run.failure.message;
    between += r.probes.hits("journal.crash_between_write_and_fsync");
    stall += r.probes.hits("journal.stall_longer_than_heartbeat");
    ooo += r.probes.hits("journal.ooo_persist_inflight_at_crash");
    disk_ooo += r.stats.disk_ooo_persist;
  }
  EXPECT_GT(between, 0u);
  EXPECT_GT(stall, 0u);
  EXPECT_LE(ooo, disk_ooo);  // one hit per restart after an out-of-order crash
}

TEST(Demo, NoFaultsModeInjectsNothing) {
  FaultStats s;
  for (std::uint64_t seed = 1; seed <= 8; ++seed) {
    for (const WorldKind w : test_worlds()) s += run(w, seed, Mode::NoFaults).stats;
  }
  EXPECT_EQ(s.net_loss + s.net_dup + s.net_reorder + s.partitions + s.crashes_process + s.crashes_host + s.pauses +
                s.disk_stalls + s.disk_eio + s.clock_steps + s.buggify_fired,
            0u);
  EXPECT_GT(s.net_delivered, 0u);
}

TEST(Demo, DisablingAClassSilencesItAndKeepsOtherFaultsIdentical) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    worlds::Options o;
    o.seed = seed;
    o.plan = worlds::default_plan();
    FaultSchedule all;
    FaultSchedule no_net;
    o.faults = draw_fault_config(seed, Mode::Swarm, 0);
    o.record = &all;
    worlds::run_world(WorldKind::PingPong, o);
    o.faults = draw_fault_config(seed, Mode::Swarm, class_bit(FaultClass::Net));
    o.record = &no_net;
    const worlds::Report r = worlds::run_world(WorldKind::PingPong, o);
    EXPECT_EQ(r.stats.net_loss + r.stats.net_dup + r.stats.partitions, 0u);
    std::vector<FaultEvent> a;
    std::vector<FaultEvent> b;
    for (const FaultEvent& e : all.events) {
      if (e.kind != FaultKind::Partition) a.push_back(e);
    }
    for (const FaultEvent& e : no_net.events) b.push_back(e);
    EXPECT_EQ(a, b) << "seed " << seed;
  }
}

TEST(Demo, CanaryIsCaughtByTheIntendedOracle) {
  struct Expect {
    WorldKind w;
    std::string oracle;
  };
  for (const Expect& e : {Expect{WorldKind::PingPong, "O-EXACTLY-ONCE"}, Expect{WorldKind::Wal, "O-WAL-DURABLE"},
                          Expect{WorldKind::Stream, "O-PREFIX"}, Expect{WorldKind::Soupbin, "O-SOUP-SEQ"}}) {
    if (!worlds::world_built(e.w)) continue;
    int caught = 0;
    for (std::uint64_t seed = 1; seed <= 60 && caught == 0; ++seed) {
      const worlds::Report r = run(e.w, seed, Mode::Swarm, 0, /*canary=*/true);
      if (r.run.failed) {
        EXPECT_EQ(r.run.failure.oracle, e.oracle);
        ++caught;
      }
    }
    EXPECT_GT(caught, 0) << worlds::world_name(e.w);
  }
}

TEST(Demo, RecordedScheduleReplaysToTheSameTrace) {
  for (const WorldKind w : test_worlds()) {
    worlds::Options o;
    o.seed = 77;
    o.faults = draw_fault_config(77, Mode::Swarm, 0);
    o.plan = worlds::default_plan();
    FaultSchedule rec;
    o.record = &rec;
    const worlds::Report a = worlds::run_world(w, o);
    FaultSchedule parsed;
    ASSERT_TRUE(parsed.parse(rec.format("x"), "x"));
    o.record = nullptr;
    o.replay = &parsed;
    const worlds::Report b = worlds::run_world(w, o);
    EXPECT_EQ(a.run.trace_hash, b.run.trace_hash) << worlds::world_name(w);
    FaultSchedule empty;
    o.replay = &empty;
    const worlds::Report c = worlds::run_world(w, o);
    EXPECT_EQ(c.faults_fired, 0u);
    EXPECT_FALSE(c.run.failed);
  }
}

TEST(Demo, TicksMaxTruncatesTheRun) {
  worlds::Options o;
  o.seed = 5;
  o.faults = draw_fault_config(5, Mode::Swarm, 0);
  o.plan = worlds::default_plan();
  o.plan.ticks_max = 1000;
  const worlds::Report r = worlds::run_world(WorldKind::PingPong, o);
  EXPECT_TRUE(r.run.truncated);
  EXPECT_EQ(r.run.events, 1000u);
  EXPECT_FALSE(r.run.failed);
}

}  // namespace
}  // namespace lle::sim

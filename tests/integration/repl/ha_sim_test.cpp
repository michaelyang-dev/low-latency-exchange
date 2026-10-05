// The `ha` simulation world as a test: seeded swarm runs must pass every oracle and
// converge, and a re-run with the same seed must reproduce the same trace hash.
// Larger campaigns run through exsim_ha (docs/design/replication.md).
#include <gtest/gtest.h>

#include <cstdint>

#include "sim/fault/swarm.h"
#include "common/prng.h"
#include "sim/ha/ha_world.h"

namespace lle::sim::ha {
namespace {

Report run_seed(std::uint64_t seed, Mode mode) {
  Options o;
  o.seed = seed;
  o.faults = draw_fault_config(seed, mode, 0);
  o.plan = default_plan();
  o.plan.safety_ns = 400'000'000;
  return run(o);
}

TEST(ReplHaSim, NoFaultsConverges) {
  for (std::uint64_t seed = 1; seed <= 4; ++seed) {
    const Report r = run_seed(seed, Mode::NoFaults);
    EXPECT_FALSE(r.run.failed) << "seed " << seed << ": " << r.run.failure.str() << " " << r.run.failure.message;
    EXPECT_TRUE(r.run.converged) << "seed " << seed << " " << r.summary;
    EXPECT_GT(r.orders_acked, 0u);
  }
}

TEST(ReplHaSim, SwarmSeedsPassEveryOracle) {
  for (std::uint64_t seed = 100; seed < 116; ++seed) {
    const Report r = run_seed(seed, Mode::Swarm);
    EXPECT_FALSE(r.run.failed) << "seed " << seed << ": " << r.run.failure.str() << " " << r.run.failure.message;
    EXPECT_TRUE(r.run.converged) << "seed " << seed << " " << r.summary;
  }
}

TEST(ReplHaSim, SameSeedSameTraceHash) {
  for (std::uint64_t seed : {7ull, 31ull, 0x1234ull}) {
    const Report a = run_seed(seed, Mode::Swarm);
    const Report b = run_seed(seed, Mode::Swarm);
    EXPECT_EQ(a.run.trace_hash, b.run.trace_hash) << "seed " << seed;
    EXPECT_EQ(a.run.events, b.run.events) << "seed " << seed;
  }
}

}  // namespace
}  // namespace lle::sim::ha

#include "common/hash.h"
#include "journal/record.h"
#include "sim/ha/toy_engine.h"

namespace lle::sim::ha {
namespace {

std::vector<std::vector<std::byte>> toy_journal(std::uint64_t seed, int n) {
  const journal::Sealer canonical;
  journal::RecordBuilder b(canonical, journal::ChainState{});
  b.set_epoch(1);
  Prng rng(seed);
  std::vector<std::vector<std::byte>> out;
  std::vector<std::byte> buf(256);
  std::uint32_t urn[4] = {0, 0, 0, 0};
  for (int i = 0; i < n; ++i) {
    std::span<std::byte> r;
    const auto acct = static_cast<std::uint32_t>(rng.below(4));
    if (rng.below(8) == 0) {
      r = b.append(std::span<std::byte>(buf), i + 1,
                   journal::SessionEvent{acct + 1, static_cast<std::uint16_t>(rng.below(3)),
                                         journal::SessionEventKind::Login, 1});
    } else {
      ToyOrder o;
      o.urn = rng.below(5) == 0 ? urn[acct] : ++urn[acct];  // some duplicates
      o.side = rng.below(2) == 0 ? 'B' : 'S';
      o.px = 100 + static_cast<std::uint32_t>(rng.below(4));
      o.qty = 1 + static_cast<std::uint32_t>(rng.below(9));
      const auto msg = encode_order(o);
      r = b.append(std::span<std::byte>(buf), i + 1, journal::OuchInbound{acct + 1, acct + 1, 1, msg});
    }
    out.emplace_back(r.begin(), r.end());
  }
  return out;
}

TEST(ReplHaToyEngine, SnapshotRestoreContinuesIdentically) {
  for (std::uint64_t seed = 1; seed <= 20; ++seed) {
    const auto j = toy_journal(seed, 300);
    ToyEngine full;
    ToyEngine head;
    for (std::size_t i = 0; i < j.size(); ++i) {
      ASSERT_TRUE(full.apply(journal::RecordView{std::span<const std::byte>(j[i])}));
      if (i < 150) ASSERT_TRUE(head.apply(journal::RecordView{std::span<const std::byte>(j[i])}));
    }
    const auto img = head.snapshot_image(1);
    ASSERT_FALSE(img.empty());
    ToyEngine restored;
    ASSERT_TRUE(restored.restore(img)) << "seed " << seed;
    EXPECT_EQ(restored.applied(), 150u);
    EXPECT_EQ(restored.hash(), head.hash());
    for (std::size_t i = 150; i < j.size(); ++i) ASSERT_TRUE(restored.apply(journal::RecordView{std::span<const std::byte>(j[i])}));
    EXPECT_EQ(restored.hash(), full.hash()) << "seed " << seed;
    EXPECT_GT(full.executions(), 0u);
    EXPECT_GT(full.duplicates(), 0u);
  }
}

}  // namespace
}  // namespace lle::sim::ha

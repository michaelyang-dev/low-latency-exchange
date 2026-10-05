#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "common/int128.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/rng.h"
#include "sim/scheduler.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

struct Recorder {
  std::vector<std::uint64_t> seen;
  std::vector<Nanos> times;
  static Dispatch on(void* ctx, const Event& ev) {
    auto* r = static_cast<Recorder*>(ctx);
    r->seen.push_back(ev.a);
    r->times.push_back(ev.at);
    return {ev.b == 0, ev.a};  // b != 0 marks a stale event
  }
};

TEST(World, EventsPopInTimeThenInsertionOrder) {
  World w(1, base_fault_config());
  Recorder r;
  const HandlerId h = w.register_handler(&r, &Recorder::on, "rec");
  w.schedule(300, h, 0, kNoNode, 1);
  w.schedule(100, h, 0, kNoNode, 2);
  w.schedule(200, h, 0, kNoNode, 3);
  w.schedule(100, h, 0, kNoNode, 4);  // tie: after 2 (inserted later)
  w.schedule(100, h, 0, kNoNode, 5);
  while (w.step()) {
  }
  EXPECT_EQ(r.seen, (std::vector<std::uint64_t>{2, 4, 5, 3, 1}));
  EXPECT_EQ(r.times, (std::vector<Nanos>{100, 100, 100, 200, 300}));
  EXPECT_EQ(w.now(), 300);
  EXPECT_EQ(w.events(), 5u);
}

TEST(World, StaleEventsAreNotCountedOrHashed) {
  World a(1, base_fault_config());
  World b(1, base_fault_config());
  Recorder ra;
  Recorder rb;
  const HandlerId ha = a.register_handler(&ra, &Recorder::on, "rec");
  const HandlerId hb = b.register_handler(&rb, &Recorder::on, "rec");
  a.schedule(10, ha, 0, kNoNode, 7);
  b.schedule(5, hb, 0, kNoNode, 99, /*stale=*/1);
  b.schedule(10, hb, 0, kNoNode, 7);
  while (a.step()) {
  }
  while (b.step()) {
  }
  EXPECT_EQ(a.events(), 1u);
  EXPECT_EQ(b.events(), 1u);
  EXPECT_EQ(a.trace_hash(), b.trace_hash());
}

TEST(World, TraceHashCoversTypeNodeTimeAndDigest) {
  auto hash_of = [](Nanos at, NodeId node, std::uint16_t kind, std::uint64_t digest) {
    World w(1, base_fault_config());
    Recorder r;
    const HandlerId h = w.register_handler(&r, &Recorder::on, "rec");
    w.schedule(at, h, kind, node, 1, 0, digest);
    w.step();
    return w.trace_hash();
  };
  const std::uint64_t base = hash_of(10, 0, 0, 0);
  EXPECT_EQ(base, hash_of(10, 0, 0, 0));
  EXPECT_NE(base, hash_of(11, 0, 0, 0));
  EXPECT_NE(base, hash_of(10, 1, 0, 0));
  EXPECT_NE(base, hash_of(10, 0, 1, 0));
  EXPECT_NE(base, hash_of(10, 0, 0, 1));
}

TEST(World, StreamsAreIndependentPureFunctions) {
  std::set<std::uint64_t> seeds;
  for (std::uint64_t s = 1; s <= static_cast<std::uint64_t>(Stream::Swarm); ++s) {
    seeds.insert(derive_seed(42, static_cast<Stream>(s)));
    seeds.insert(derive_seed(42, static_cast<Stream>(s), 1));
  }
  EXPECT_EQ(seeds.size(), 16u);
  EXPECT_EQ(derive_seed(42, Stream::Network, 7), derive_seed(42, Stream::Network, 7));
  EXPECT_NE(derive_seed(42, Stream::Network, 7), derive_seed(43, Stream::Network, 7));
  // Creating one stream never perturbs another: no shared state.
  World w(42, base_fault_config());
  Rng a = w.stream(Stream::Disk);
  Rng x = w.stream(Stream::Clock);
  (void)x.next_u64();
  Rng b = w.stream(Stream::Disk);
  EXPECT_EQ(a.next_u64(), b.next_u64());
}

TEST(Dist, IntegerExponentialHasTheRequestedMean) {
  EXPECT_NEAR(static_cast<double>(neg_ln_q16(std::uint64_t{1} << 63)), 45426.0, 4.0);  // -ln(1/2)
  EXPECT_NEAR(static_cast<double>(neg_ln_q16(std::uint64_t{1} << 62)), 90852.0, 8.0);  // -ln(1/4)
  Prng r(7);
  const Nanos mean = 1'000'000;
  i128 sum = 0;
  const int n = 200'000;
  for (int i = 0; i < n; ++i) sum += exp_ns(r, mean);
  const auto avg = static_cast<double>(sum / n);
  EXPECT_NEAR(avg, 1e6, 1e6 * 0.02);
}

TEST(Dist, DrawCountDoesNotDependOnParameters) {
  Prng a(9);
  Prng b(9);
  (void)chance_ppm(a, 0);
  (void)chance_ppm(b, kPpm);
  (void)exp_ns(a, 0);
  (void)exp_ns(b, 5000);
  (void)uniform(a, 5, 5);
  (void)uniform(b, 0, 100);
  EXPECT_EQ(a.next_u64(), b.next_u64());
  Prng c(3);
  for (int i = 0; i < 10'000; ++i) {
    const std::int64_t v = log_uniform(c, 1000, 5'000'000);
    ASSERT_GE(v, 1000);
    ASSERT_LE(v, 5'000'000);
  }
  EXPECT_FALSE(chance_ppm(c, 0));
  EXPECT_TRUE(chance_ppm(c, kPpm));
}

struct CountingStage {
  int polls = 0;
  int work_left = 0;
  std::vector<Nanos>* times = nullptr;
  World* w = nullptr;
  bool poll() {
    ++polls;
    if (times != nullptr) times->push_back(w->now());
    if (work_left > 0) {
      --work_left;
      return true;
    }
    return false;
  }
};

TEST(Scheduler, IdleStagesBackOffAndWakeOnIo) {
  World w(5, base_fault_config());
  Node& n = w.add_node("n");
  CountingStage s;
  w.scheduler().add_stage(n.id(), s, "s");
  test::run_for(w, 100 * kMs);
  // idle_max is 100 us in the base config: about 1000 polls in 100 ms, not 10^5.
  EXPECT_GT(s.polls, 500);
  EXPECT_LT(s.polls, 2000);
  const int before = s.polls;
  const Nanos t = w.now();
  w.scheduler().wake(n.id());
  w.step();
  EXPECT_EQ(s.polls, before + 1);
  EXPECT_LT(w.now() - t, 10 * kUs);
}

TEST(Scheduler, BusyStageIsPolledAtCpuCostCadence) {
  World w(5, base_fault_config());
  Node& n = w.add_node("n");
  CountingStage s;
  s.work_left = 1000;
  w.scheduler().add_stage(n.id(), s, "s");
  test::run_for(w, 200 * kUs);  // base cpu_min = 100 ns
  EXPECT_GE(s.polls, 1000);
  EXPECT_EQ(w.scheduler().busy_polls(), 1000u);
}

std::vector<int> interleaving(std::uint64_t seed) {
  World w(seed, draw_fault_config(seed, Mode::NoFaults, 0));
  Node& a = w.add_node("a");
  Node& b = w.add_node("b");
  std::vector<int> order;
  struct Tagged {
    int tag;
    std::vector<int>* out;
    int left = 50;
    bool poll() {
      if (left == 0) return false;
      --left;
      out->push_back(tag);
      return true;
    }
  } sa{1, &order}, sb{2, &order};
  w.scheduler().add_stage(a.id(), sa, "a");
  w.scheduler().add_stage(b.id(), sb, "b");
  test::run_for(w, 10 * kMs);
  return order;
}

TEST(Scheduler, InterleavingIsSeedControlled) {
  EXPECT_EQ(interleaving(11), interleaving(11));
  std::set<std::vector<int>> distinct;
  for (std::uint64_t s = 1; s <= 8; ++s) distinct.insert(interleaving(s));
  EXPECT_GT(distinct.size(), 4u);
}

TEST(World, RunPhasesHealThenConvergeThenFinalChecks) {
  World w(3, base_fault_config());
  Node& n = w.add_node("n");
  CountingStage s;
  w.scheduler().add_stage(n.id(), s, "s");
  bool healed = false;
  bool final_ran = false;
  w.on_heal([&] { healed = true; });
  const OracleId o = w.oracles().activate("O-TEST");
  w.oracles().add_final_check(o, [&] { final_ran = true; });
  PhasePlan p;
  p.safety_ns = 10 * kMs;
  p.convergence_ns = 50 * kMs;
  Nanos converged_at = 0;
  const RunResult r = w.run(p, [&] {
    if (w.now() >= 15 * kMs && converged_at == 0) converged_at = w.now();
    return converged_at != 0;
  });
  EXPECT_TRUE(healed);
  EXPECT_TRUE(r.converged);
  EXPECT_TRUE(final_ran);
  EXPECT_FALSE(r.failed);
  EXPECT_GE(r.virtual_ns, 15 * kMs);
  EXPECT_LT(r.virtual_ns, 17 * kMs);
}

TEST(World, NoConvergenceFailsOLive) {
  World w(3, base_fault_config());
  Node& n = w.add_node("n");
  CountingStage s;
  w.scheduler().add_stage(n.id(), s, "s");
  PhasePlan p;
  p.safety_ns = 5 * kMs;
  p.convergence_ns = 20 * kMs;
  const RunResult r = w.run(p, [] { return false; });
  EXPECT_TRUE(r.failed);
  EXPECT_EQ(r.failure.oracle, "O-LIVE");
  EXPECT_EQ(r.virtual_ns, 25 * kMs);
}

TEST(World, TicksMaxTruncates) {
  World w(3, base_fault_config());
  Node& n = w.add_node("n");
  CountingStage s;
  w.scheduler().add_stage(n.id(), s, "s");
  PhasePlan p;
  p.ticks_max = 123;
  const RunResult r = w.run(p, [] { return false; });
  EXPECT_TRUE(r.truncated);
  EXPECT_FALSE(r.failed);
  EXPECT_EQ(r.events, 123u);
}

}  // namespace
}  // namespace lle::sim

#include <gtest/gtest.h>

#include <cstdlib>

#include "env/concepts.h"
#include "sim/clock.h"
#include "sim/dist.h"
#include "sim/fault/injector.h"
#include "sim/node.h"
#include "sim/world.h"
#include "test_util.h"

namespace lle::sim {
namespace {

static_assert(env::ClockLike<Clock>);

TEST(Clock, MonotonicIsVirtualTimeAndTscFollowsIt) {
  World w(1, base_fault_config());
  Node& n = w.add_node("n");
  Clock& c = n.clock();
  EXPECT_EQ(c.now_mono(), 0);
  w.add_node("m");
  test::run_for(w, 0);
  const std::uint64_t t0 = c.tsc();
  struct Nop {
    static Dispatch on(void*, const Event&) { return {}; }
  };
  const HandlerId h = w.register_handler(nullptr, &Nop::on, "nop");
  w.schedule(5 * kMs, h, 0, kNoNode);
  w.step();
  EXPECT_EQ(c.now_mono(), 5 * kMs);
  EXPECT_EQ(c.tsc() - t0, static_cast<std::uint64_t>(5 * kMs) * kTscPerNs);
}

TEST(Clock, NoClockFaultsMeansRealtimeIsEpochPlusVirtual) {
  World w(9, draw_fault_config(9, Mode::Swarm, class_bit(FaultClass::Clock)));
  Node& n = w.add_node("n");
  EXPECT_EQ(n.clock().params().drift_ppb, 0);
  EXPECT_EQ(n.clock().params().offset_ns, 0);
  EXPECT_EQ(n.clock().real_at(123'456'789), kSimEpochRealNs + 123'456'789);
}

TEST(Clock, DriftStaysWithin500PpmAndVariesAcrossSeeds) {
  bool saw_nonzero = false;
  for (std::uint64_t seed = 1; seed <= 200; ++seed) {
    const FaultConfig f = draw_fault_config(seed, Mode::Swarm, 0);
    World w(seed, f);
    for (int i = 0; i < 4; ++i) {
      Node& n = w.add_node("n" + std::to_string(i));
      const std::int64_t d = n.clock().params().drift_ppb;
      ASSERT_LE(std::llabs(d), 500'000);
      ASSERT_LE(std::llabs(d), f[Param::ClockDriftPpb]);
      saw_nonzero = saw_nonzero || d != 0;
      // Linear drift: after 10 s of virtual time realtime is off by d * 10 ns/ppb.
      const Nanos t = 10 * kSec;
      EXPECT_EQ(n.clock().real_at(t) - n.clock().real_at(0), t + d * 10);
    }
  }
  EXPECT_TRUE(saw_nonzero);
}

TEST(Clock, StepsMoveRealtimeButNeverMonotonic) {
  World w(1, base_fault_config());
  Node& n = w.add_node("n");
  Clock& c = n.clock();
  const Nanos mono = c.now_mono();
  const Nanos real = c.now_real();
  c.step(-kSec);
  EXPECT_EQ(c.now_real(), real - kSec);
  EXPECT_EQ(c.now_mono(), mono);
  c.step(750 * kMs);
  EXPECT_EQ(c.now_real(), real - 250 * kMs);
  EXPECT_EQ(c.step_count(), 2u);
}

TEST(Clock, InjectedStepsStayWithinOneSecond) {
  std::uint64_t steps = 0;
  for (std::uint64_t seed = 1; seed <= 100; ++seed) {
    const FaultConfig f = draw_fault_config(seed, Mode::Swarm, 0);
    World w(seed, f);
    w.add_node("a");
    w.add_node("b");
    const FaultSchedule s = w.injector().generate(0, 10 * kSec);
    for (const FaultEvent& e : s.events) {
      if (e.kind != FaultKind::ClockStep) continue;
      ++steps;
      ASSERT_LE(std::llabs(static_cast<Nanos>(e.a)), kSec);
    }
  }
  EXPECT_GT(steps, 0u);
}

}  // namespace
}  // namespace lle::sim

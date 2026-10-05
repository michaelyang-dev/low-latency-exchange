// In-process checks of exchanged's own pieces (apps/exchanged), next to the end-to-end
// tests: the input SCQs' single-consumer guard, the ring-occupancy gauges.
#include <gtest/gtest.h>

#include <thread>

#include "concurrent/mpsc_scq.h"
#include "exchanged/consumer_guard.h"
#include "exchanged/ring_gauge.h"

namespace lle::exch {
namespace {

TEST(ScqConsumerGuard, HandOversBetweenTheTwoConsumersPass) {
  ScqConsumerGuard g;
  for (int i = 0; i < 3; ++i) {
    { const ScqConsumerScope s(g, ScqConsumerGuard::kSeq); }
    { const ScqConsumerScope s(g, ScqConsumerGuard::kRepl); }
  }
  // Re-entering as the same consumer is fine (nested scopes on one thread).
  const ScqConsumerScope a(g, ScqConsumerGuard::kSeq);
  const ScqConsumerScope b(g, ScqConsumerGuard::kSeq);
}

TEST(ScqConsumerGuardDeathTest, OverlappingConsumersAreCaughtInDebugBuilds) {
#if defined(NDEBUG)
  GTEST_SKIP() << "the guard is compiled out without debug assertions";
#else
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_DEATH(
      {
        ScqConsumerGuard g;
        const ScqConsumerScope seq(g, ScqConsumerGuard::kSeq);
        std::thread t([&] { const ScqConsumerScope repl(g, ScqConsumerGuard::kRepl); });
        t.join();
      },
      "two consumers of the input SCQs");
#endif
}

// ring_<R>_{used,hwm,peak,window} (ring_gauge.h): peak is the largest sample of the last
// completed 1 s window, window counts completed windows, hwm never drops.
TEST(RingGauge, PeaksPerCompletedWindowAndAHighWaterMark) {
  constexpr Nanos s = RingGauge::kWindow;
  RingGauge g;
  g.cap = 100;
  g.sample(10, 5 * s);
  g.sample(40, 5 * s + s / 2);
  g.sample(20, 5 * s + s - 1);
  EXPECT_EQ(g.used, 20u);
  EXPECT_EQ(g.hwm, 40u);
  EXPECT_EQ(g.window, 0u) << "the first window is still open";
  EXPECT_EQ(g.peak, 0u);
  g.sample(5, 6 * s);  // window 1 closes with its largest sample
  EXPECT_EQ(g.window, 1u);
  EXPECT_EQ(g.peak, 40u);
  EXPECT_EQ(g.used, 5u);
  g.sample(7, 6 * s + 1);
  g.sample(3, 7 * s);
  EXPECT_EQ(g.window, 2u);
  EXPECT_EQ(g.peak, 7u) << "the second window's peak, not the high-water mark";
  EXPECT_EQ(g.hwm, 40u);
  // Nothing sampled for 3 s: the counter jumps (readers see the gap).
  g.sample(9, 10 * s + 3);
  EXPECT_EQ(g.window, 5u);
  EXPECT_EQ(g.peak, 3u);
  g.sample(1, 11 * s);
  EXPECT_EQ(g.window, 6u);
  EXPECT_EQ(g.peak, 9u);
}

// The input queues' occupancy as the seq stage samples it (MpscScqRing::size_approx).
TEST(RingGauge, ScqSizeFollowsPushesAndPops) {
  conc::MpscScqRing<int, 8> q;
  EXPECT_EQ(q.size_approx(), 0u);
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(q.try_push(i));
  EXPECT_EQ(q.size_approx(), 5u);
  int v = 0;
  ASSERT_TRUE(q.try_pop(v));
  ASSERT_TRUE(q.try_pop(v));
  EXPECT_EQ(q.size_approx(), 3u);
  for (int i = 0; i < 5; ++i) ASSERT_TRUE(q.try_push(i));
  EXPECT_EQ(q.size_approx(), 8u);
  EXPECT_FALSE(q.try_push(9));
  EXPECT_EQ(q.size_approx(), 8u) << "never above the capacity";
  while (q.try_pop(v)) {
  }
  EXPECT_EQ(q.size_approx(), 0u);
  EXPECT_FALSE(q.try_pop(v));
  EXPECT_EQ(q.size_approx(), 0u) << "an empty poll does not move it";
}

}  // namespace
}  // namespace lle::exch

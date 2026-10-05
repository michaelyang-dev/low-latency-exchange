#include "concurrent/wait.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>

namespace lle::conc {
namespace {

TEST(Wait, SpinUntilCountsFailedPolls) {
  int calls = 0;
  const auto failed = spin_until([&] { return ++calls == 5; }, Spin{});
  EXPECT_EQ(failed, 4u);
  calls = 0;
  EXPECT_EQ(spin_until([&] { return ++calls == 3; }, SpinPause{}), 2u);
  calls = 0;
  EXPECT_EQ(spin_until([&] { return ++calls == 40; }, Backoff{2}), 39u);
  EXPECT_EQ(spin_until([] { return true; }), 0u);
}

TEST(Wait, SpinUntilForGivesUp) {
  int calls = 0;
  EXPECT_FALSE(spin_until_for([&] { ++calls; return false; }, 10, Spin{}));
  EXPECT_EQ(calls, 11);  // initial poll + 10 retries
  EXPECT_TRUE(spin_until_for([] { return true; }, 0, Spin{}));
}

TEST(Wait, BackoffEscalatesToYieldAndResets) {
  Backoff b(3);
  for (int i = 0; i < 4; ++i) {
    EXPECT_FALSE(b.yielding());
    b.wait();
  }
  EXPECT_TRUE(b.yielding());
  b.wait();  // yields
  b.reset();
  EXPECT_FALSE(b.yielding());
}

TEST(Wait, CrossThreadFlag) {
  std::atomic<bool> flag{false};
  std::thread t([&] { flag.store(true, std::memory_order_release); });
  spin_until([&] { return flag.load(std::memory_order_acquire); }, Backoff{});
  t.join();
  EXPECT_TRUE(flag.load());
}

static_assert(WaitPolicy<Spin> && WaitPolicy<SpinPause> && WaitPolicy<Backoff>);

}  // namespace
}  // namespace lle::conc

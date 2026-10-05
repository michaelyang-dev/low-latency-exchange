// Stalled-producer demonstration (08-concurrency-runtime §5, §7): a producer is
// suspended right after claiming its slot. SCQ keeps delivering the other producers'
// items; the Vyukov ring's consumer is stuck behind the hole until the stalled
// producer resumes. This is the executable counterpart of
// verify/genmc/mpsc_stalled_producer.cpp.
//
// This file is its own test binary: it defines the LLE_TEST_STOP_AFTER_CLAIM hook
// before including the queues, so no other translation unit may instantiate them.
#include <atomic>
#include <cstdint>
#include <thread>

namespace {

constexpr std::uint64_t kStallValue = 0xDEAD'BEEF;
std::atomic<bool> g_parked{false};
std::atomic<bool> g_release{false};

// Parks the producer pushing kStallValue until the test releases it, then lets the push
// complete (a preempted, not a dead, producer).
bool stall_hook(std::uint64_t v) noexcept {
  if (v != kStallValue) return false;
  g_parked.store(true, std::memory_order_release);
  while (!g_release.load(std::memory_order_acquire)) std::this_thread::yield();
  return false;
}

}  // namespace

#define LLE_TEST_STOP_AFTER_CLAIM(v) stall_hook(v)
#include <gtest/gtest.h>

#include "concurrent/mpsc_scq.h"
#include "concurrent/mpsc_vyukov.h"

namespace lle::conc {
namespace {

constexpr std::uint64_t kOthers = 6;                 // items pushed by the healthy producer
constexpr std::uint64_t kAttempts = 2'000'000;       // consumer polls while the stall lasts

template <class Q>
struct Outcome {
  std::uint64_t delivered_during_stall = 0;
  bool got_stalled_item_after_release = false;
  std::uint64_t delivered_after_release = 0;
};

template <class Q>
Outcome<Q> run_scenario() {
  g_parked.store(false);
  g_release.store(false);
  Q q;
  Outcome<Q> out;
  std::thread stalled([&] { EXPECT_TRUE(q.try_push(kStallValue)); });
  while (!g_parked.load(std::memory_order_acquire)) std::this_thread::yield();

  std::thread healthy([&] {
    for (std::uint64_t i = 1; i <= kOthers; ++i) EXPECT_TRUE(q.try_push(i));
  });
  healthy.join();  // every healthy push has completed

  std::uint64_t v = 0;
  for (std::uint64_t a = 0; a < kAttempts && out.delivered_during_stall < kOthers; ++a) {
    if (q.try_pop(v)) {
      EXPECT_EQ(v, out.delivered_during_stall + 1);  // healthy producer's FIFO order
      ++out.delivered_during_stall;
    }
  }

  g_release.store(true, std::memory_order_release);
  stalled.join();
  while (q.try_pop(v)) {
    if (v == kStallValue) {
      out.got_stalled_item_after_release = true;
    } else {
      ++out.delivered_after_release;
    }
  }
  return out;
}

TEST(StalledProducer, ScqKeepsDeliveringOtherProducers) {
  const auto r = run_scenario<MpscScqRing<std::uint64_t, 8>>();
  EXPECT_EQ(r.delivered_during_stall, kOthers);  // lock-free: not blocked by the stall
  EXPECT_TRUE(r.got_stalled_item_after_release);  // the resumed producer re-claims a slot
  EXPECT_EQ(r.delivered_after_release, 0u);
}

TEST(StalledProducer, VyukovConsumerBlocksBehindTheHole) {
  const auto r = run_scenario<VyukovMpscRing<std::uint64_t, 8>>();
  EXPECT_EQ(r.delivered_during_stall, 0u);  // blocked: completed items sit behind the hole
  EXPECT_TRUE(r.got_stalled_item_after_release);
  EXPECT_EQ(r.delivered_after_release, kOthers);
}

}  // namespace
}  // namespace lle::conc

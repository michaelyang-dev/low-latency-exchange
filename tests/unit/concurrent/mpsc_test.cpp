// Single-threaded semantics of the MPSC queues (SCQ and the Vyukov baseline).
// Concurrency is covered by mpsc_stress_test.cpp, stalled_producer_test.cpp and the
// GenMC harnesses in verify/genmc/.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/prng.h"
#include "concurrent/mpsc_scq.h"
#include "concurrent/mpsc_vyukov.h"

namespace lle::conc {
namespace {

template <class Q>
void fill_drain_cycle() {
  Q q;
  constexpr std::size_t kCap = Q::capacity();
  std::uint64_t in = 1, out = 1;
  for (std::size_t round = 0; round < 8 * kCap + 5; ++round) {
    const std::size_t fill = 1 + round % kCap;
    for (std::size_t i = 0; i < fill; ++i) ASSERT_TRUE(q.try_push(in++)) << "round " << round;
    if (fill == kCap) EXPECT_FALSE(q.try_push(0));
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < fill; ++i) {
      ASSERT_TRUE(q.try_pop(v));
      EXPECT_EQ(v, out++);
    }
    EXPECT_FALSE(q.try_pop(v));
  }
}

TEST(MpscScq, Capacity1) { fill_drain_cycle<MpscScqRing<std::uint64_t, 1>>(); }
TEST(MpscScq, Capacity2) { fill_drain_cycle<MpscScqRing<std::uint64_t, 2>>(); }
TEST(MpscScq, Capacity4) { fill_drain_cycle<MpscScqRing<std::uint64_t, 4>>(); }
TEST(MpscScq, Capacity64) { fill_drain_cycle<MpscScqRing<std::uint64_t, 64>>(); }
TEST(MpscVyukov, Capacity2) { fill_drain_cycle<VyukovMpscRing<std::uint64_t, 2>>(); }
TEST(MpscVyukov, Capacity4) { fill_drain_cycle<VyukovMpscRing<std::uint64_t, 4>>(); }
TEST(MpscVyukov, Capacity64) { fill_drain_cycle<VyukovMpscRing<std::uint64_t, 64>>(); }

template <class Q>
void random_interleaving(std::uint64_t seed) {
  Q q;
  Prng rng(seed);
  std::uint64_t in = 0, out = 0;
  std::size_t size = 0;
  for (int step = 0; step < 200'000; ++step) {
    if (rng.chance(1, 2)) {
      const bool ok = q.try_push(in);
      ASSERT_EQ(ok, size < Q::capacity());
      if (ok) {
        ++in;
        ++size;
      }
    } else {
      std::uint64_t v = 0;
      const bool ok = q.try_pop(v);
      ASSERT_EQ(ok, size > 0);
      if (ok) {
        ASSERT_EQ(v, out++);
        --size;
      }
    }
  }
}

TEST(MpscScq, MatchesSequentialModel) {
  random_interleaving<MpscScqRing<std::uint64_t, 1>>(1);
  random_interleaving<MpscScqRing<std::uint64_t, 2>>(2);
  random_interleaving<MpscScqRing<std::uint64_t, 4>>(3);
  random_interleaving<MpscScqRing<std::uint64_t, 32>>(4);  // > one line of entries: Cache_Remap active
}

// The single-consumer specialization (ADR-031) behaves identically.
TEST(MpscScqSingleConsumer, Capacities) {
  fill_drain_cycle<MpscScqRing<std::uint64_t, 1, true>>();
  fill_drain_cycle<MpscScqRing<std::uint64_t, 2, true>>();
  fill_drain_cycle<MpscScqRing<std::uint64_t, 4, true>>();
  fill_drain_cycle<MpscScqRing<std::uint64_t, 64, true>>();
}
TEST(MpscScqSingleConsumer, MatchesSequentialModel) {
  random_interleaving<MpscScqRing<std::uint64_t, 1, true>>(11);
  random_interleaving<MpscScqRing<std::uint64_t, 4, true>>(12);
  random_interleaving<MpscScqRing<std::uint64_t, 32, true>>(13);
}

TEST(MpscVyukov, MatchesSequentialModel) {
  random_interleaving<VyukovMpscRing<std::uint64_t, 2>>(5);
  random_interleaving<VyukovMpscRing<std::uint64_t, 16>>(6);
}

TEST(MpscScq, LargePayload) {
  struct Msg {
    std::uint64_t seq;
    std::uint8_t body[200];
  };
  MpscScqRing<Msg, 8> q;
  for (std::uint64_t i = 0; i < 8; ++i) {
    Msg m{};
    m.seq = i;
    for (std::size_t b = 0; b < sizeof(m.body); ++b) m.body[b] = static_cast<std::uint8_t>(i + b);
    ASSERT_TRUE(q.try_push(m));
  }
  Msg m{};
  EXPECT_FALSE(q.try_push(m));
  for (std::uint64_t i = 0; i < 8; ++i) {
    ASSERT_TRUE(q.try_pop(m));
    EXPECT_EQ(m.seq, i);
    for (std::size_t b = 0; b < sizeof(m.body); ++b) ASSERT_EQ(m.body[b], static_cast<std::uint8_t>(i + b));
  }
}

// The index ring on its own: a full ring hands out 0..N-1 in order; an empty ring
// reports empty; indices come back FIFO; Threshold re-arms after an enqueue.
TEST(ScqIndexRing, FullAndEmptyInitialStates) {
  detail::ScqIndexRing<4> full, empty;
  full.init_full();
  empty.init_empty();
  using R = detail::ScqIndexRing<4>;
  EXPECT_EQ(empty.dequeue(), R::kEmpty);
  for (std::uint64_t i = 0; i < 4; ++i) EXPECT_EQ(full.dequeue(), i);
  EXPECT_EQ(full.dequeue(), R::kEmpty);
  const detail::NoClaimHook hook;
  EXPECT_TRUE(empty.enqueue(3, hook));
  EXPECT_TRUE(empty.enqueue(1, hook));
  EXPECT_EQ(empty.dequeue(), 3u);
  EXPECT_EQ(empty.dequeue(), 1u);
  EXPECT_EQ(empty.dequeue(), R::kEmpty);
  // Repeated empty dequeues drive Threshold negative; the next enqueue re-arms it.
  for (int i = 0; i < 20; ++i) EXPECT_EQ(empty.dequeue(), R::kEmpty);
  EXPECT_TRUE(empty.enqueue(2, hook));
  EXPECT_EQ(empty.dequeue(), 2u);
}

TEST(ScqIndexRing, EntryEncoding) {
  using R = detail::ScqIndexRing<4>;
  EXPECT_EQ(R::kEntries, 8u);
  EXPECT_EQ(R::kOrder, 3u);
  EXPECT_EQ(R::kBottom, 7u);
  EXPECT_EQ(R::kSafeBit, 8u);
  EXPECT_EQ(R::kThreshold, 11);
  using R1 = detail::ScqIndexRing<1>;
  EXPECT_EQ(R1::kEntries, 2u);
  EXPECT_EQ(R1::kBottom, 1u);
  EXPECT_EQ(R1::kThreshold, 2);
}

}  // namespace
}  // namespace lle::conc

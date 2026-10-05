#include "concurrent/spsc_ring.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/cache.h"

namespace lle::conc {
namespace {

struct Pair {
  std::uint32_t a;
  std::uint32_t b;
};

template <std::size_t Cap>
void fill_drain_cycle() {
  SpscRing<std::uint64_t, Cap> q;
  std::uint64_t next_in = 0, next_out = 0;
  // Several laps around the ring with every fill level from 1 to Cap.
  for (std::size_t round = 0; round < 4 * Cap + 3; ++round) {
    const std::size_t fill = 1 + round % Cap;
    for (std::size_t i = 0; i < fill; ++i) ASSERT_TRUE(q.try_push(next_in++));
    EXPECT_EQ(q.size_approx(), fill);
    if (fill == Cap) EXPECT_FALSE(q.try_push(999));
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < fill; ++i) {
      ASSERT_TRUE(q.try_pop(v));
      EXPECT_EQ(v, next_out++);
    }
    EXPECT_FALSE(q.try_pop(v));
    EXPECT_EQ(q.size_approx(), 0u);
  }
}

TEST(SpscRing, Capacity1) { fill_drain_cycle<1>(); }
TEST(SpscRing, Capacity2) { fill_drain_cycle<2>(); }
TEST(SpscRing, Capacity4) { fill_drain_cycle<4>(); }
TEST(SpscRing, Capacity64) { fill_drain_cycle<64>(); }

TEST(SpscRing, FullAndEmptyEdges) {
  SpscRing<int, 4> q;
  int v = 0;
  EXPECT_FALSE(q.try_pop(v));
  EXPECT_EQ(q.front(), nullptr);
  for (int i = 0; i < 4; ++i) EXPECT_TRUE(q.try_push(i));
  EXPECT_FALSE(q.try_push(4));
  EXPECT_EQ(q.try_claim(), nullptr);
  EXPECT_EQ(q.size_approx(), 4u);
  ASSERT_TRUE(q.try_pop(v));
  EXPECT_EQ(v, 0);
  EXPECT_TRUE(q.try_push(4));  // one slot freed
  EXPECT_FALSE(q.try_push(5));
  for (int i = 1; i <= 4; ++i) {
    ASSERT_TRUE(q.try_pop(v));
    EXPECT_EQ(v, i);
  }
  EXPECT_FALSE(q.try_pop(v));
}

TEST(SpscRing, WrapsManyTimes) {
  SpscRing<std::uint64_t, 8> q;
  std::uint64_t out = 0, expect = 0;
  for (std::uint64_t i = 0; i < 10'000; ++i) {
    ASSERT_TRUE(q.try_push(i));
    if (i % 3 == 2) {
      while (q.try_pop(out)) EXPECT_EQ(out, expect++);
    }
  }
  while (q.try_pop(out)) EXPECT_EQ(out, expect++);
  EXPECT_EQ(expect, 10'000u);
}

TEST(SpscRing, ZeroCopyClaimCommit) {
  SpscRing<Pair, 2> q;
  Pair* s = q.try_claim();
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(q.try_claim(), s);  // not published yet: same slot again
  s->a = 7;
  s->b = 8;
  EXPECT_EQ(q.size_approx(), 0u);
  Pair out{};
  EXPECT_FALSE(q.try_pop(out));  // nothing visible before commit
  q.commit();
  EXPECT_EQ(q.size_approx(), 1u);
  Pair* s2 = q.try_claim();
  ASSERT_NE(s2, nullptr);
  EXPECT_NE(s2, s);
  s2->a = 9;
  s2->b = 10;
  q.commit();
  EXPECT_EQ(q.try_claim(), nullptr);  // full
  const Pair* f = q.front();
  ASSERT_NE(f, nullptr);
  EXPECT_EQ(f, s);  // zero-copy read sees the slot written in place
  EXPECT_EQ(f->a, 7u);
  q.pop();
  ASSERT_TRUE(q.try_pop(out));
  EXPECT_EQ(out.a, 9u);
  EXPECT_EQ(out.b, 10u);
}

TEST(SpscRing, TryEmplace) {
  SpscRing<Pair, 4> q;
  EXPECT_TRUE(q.try_emplace(1u, 2u));
  EXPECT_TRUE(q.try_emplace(3u, 4u));
  Pair p{};
  ASSERT_TRUE(q.try_pop(p));
  EXPECT_EQ(p.a, 1u);
  EXPECT_EQ(p.b, 2u);
  ASSERT_TRUE(q.try_pop(p));
  EXPECT_EQ(p.a, 3u);
  EXPECT_EQ(p.b, 4u);
}

TEST(SpscRing, DrainBatchesAndRespectsMax) {
  SpscRing<int, 16> q;
  for (int i = 0; i < 10; ++i) ASSERT_TRUE(q.try_push(i));
  std::vector<int> seen;
  auto take = [&](const int& v) { seen.push_back(v); };
  EXPECT_EQ(q.drain(take, 4), 4u);
  EXPECT_EQ(q.size_approx(), 6u);
  EXPECT_EQ(q.drain(take, 100), 6u);
  EXPECT_EQ(q.drain(take, 100), 0u);
  ASSERT_EQ(seen.size(), 10u);
  for (int i = 0; i < 10; ++i) EXPECT_EQ(seen[static_cast<std::size_t>(i)], i);
  // Drain across the wrap point.
  for (int i = 0; i < 16; ++i) ASSERT_TRUE(q.try_push(100 + i));
  EXPECT_FALSE(q.try_push(0));
  seen.clear();
  EXPECT_EQ(q.drain(take, 0), 0u);
  EXPECT_EQ(q.drain(take, 16), 16u);
  for (int i = 0; i < 16; ++i) EXPECT_EQ(seen[static_cast<std::size_t>(i)], 100 + i);
}

TEST(SpscRing, DrainedSlotsAreReusable) {
  SpscRing<int, 2> q;
  int sum = 0;
  for (int round = 0; round < 50; ++round) {
    ASSERT_TRUE(q.try_push(round));
    ASSERT_TRUE(q.try_push(-round));
    EXPECT_FALSE(q.try_push(0));
    EXPECT_EQ(q.drain([&](const int& v) { sum += v; }, 8), 2u);
  }
  EXPECT_EQ(sum, 0);
}

TEST(SpscRing, LayoutKeepsIndicesOnSeparateLines) {
  using Q = SpscRing<std::uint64_t, 4>;
  EXPECT_EQ(alignof(Q), kFalseSharingBytes);
  // w_, rcache_, r_, wcache_ and the slot array each start a line.
  EXPECT_GE(sizeof(Q), 5 * kFalseSharingBytes);
  EXPECT_EQ(sizeof(Q) % kFalseSharingBytes, 0u);
}

}  // namespace
}  // namespace lle::conc

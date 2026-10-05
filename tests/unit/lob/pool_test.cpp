#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <set>
#include <vector>

#include "common/prng.h"
#include "lob/arena.h"
#include "lob/slab_pool.h"

namespace lle::lob {
namespace {

struct Rec32 {
  std::uint64_t a = 1;
  std::uint64_t b = 2;
  std::uint32_t c = 3;
  std::uint32_t d = 4;
  std::uint64_t e = 5;
};
static_assert(sizeof(Rec32) == 32);

TEST(SlabPool, SlabIsTwoMiB) {
  using P = SlabPool<Rec32>;
  EXPECT_EQ(P::kSlotBytes, 32u);
  EXPECT_EQ(P::kSlabBytes, kHugePageBytes);
}

TEST(SlabPool, AllocConstructsAndHandlesAreDense) {
  SlabPool<Rec32> p;
  const auto h0 = p.alloc();
  const auto h1 = p.alloc();
  EXPECT_EQ(h0, 0u);
  EXPECT_EQ(h1, 1u);
  EXPECT_EQ(p[h0].a, 1u);
  EXPECT_EQ(p[h1].e, 5u);
  EXPECT_EQ(p.live(), 2u);
}

TEST(SlabPool, FreeListIsLifo) {
  SlabPool<Rec32> p;
  const auto a = p.alloc();
  const auto b = p.alloc();
  const auto c = p.alloc();
  p.free(b);
  p.free(a);
  EXPECT_EQ(p.alloc(), a);  // most recently freed first (cache-hot)
  EXPECT_EQ(p.alloc(), b);
  EXPECT_EQ(p.alloc(), 3u);
  EXPECT_EQ(p.live(), 4u);
  static_cast<void>(c);
}

TEST(SlabPool, ReserveMeansNoGrowth) {
  SlabPool<Rec32> p(100'000);
  const std::size_t slabs = p.slab_count();
  EXPECT_GE(p.capacity(), 100'000u);
  std::vector<SlabPool<Rec32>::Handle> hs;
  for (int i = 0; i < 100'000; ++i) hs.push_back(p.alloc());
  for (int round = 0; round < 3; ++round) {
    for (auto h : hs) p.free(h);
    for (auto& h : hs) h = p.alloc();
  }
  EXPECT_EQ(p.slab_count(), slabs);
}

TEST(SlabPool, GrowsAcrossSlabsWithStableAddresses) {
  SlabPool<Rec32> p;  // no reserve
  std::vector<Rec32*> ptrs;
  std::vector<SlabPool<Rec32>::Handle> hs;
  const std::size_t n = SlabPool<Rec32>::kSlabSize * 2 + 17;
  for (std::size_t i = 0; i < n; ++i) {
    hs.push_back(p.alloc());
    p[hs.back()].a = i;
    ptrs.push_back(p.ptr(hs.back()));
  }
  EXPECT_EQ(p.slab_count(), 3u);
  for (std::size_t i = 0; i < n; ++i) {
    EXPECT_EQ(p.ptr(hs[i]), ptrs[i]);
    EXPECT_EQ(p[hs[i]].a, i);
  }
}

TEST(SlabPool, RandomChurnKeepsHandlesUnique) {
  SlabPool<Rec32> p(1024);
  Prng rng(7);
  std::vector<SlabPool<Rec32>::Handle> live;
  std::set<SlabPool<Rec32>::Handle> set;
  for (int i = 0; i < 200'000; ++i) {
    if (live.empty() || rng.chance(11, 20)) {
      const auto h = p.alloc();
      ASSERT_TRUE(set.insert(h).second);
      p[h].a = h;
      live.push_back(h);
    } else {
      const std::size_t k = static_cast<std::size_t>(rng.below(live.size()));
      ASSERT_EQ(p[live[k]].a, live[k]);
      p.free(live[k]);
      set.erase(live[k]);
      live[k] = live.back();
      live.pop_back();
    }
  }
  EXPECT_EQ(p.live(), live.size());
}

TEST(SlabPool, SmallTypesUseHandleSizedSlots) {
  SlabPool<std::uint16_t> p;
  EXPECT_EQ(SlabPool<std::uint16_t>::kSlotBytes, 4u);
  const auto a = p.alloc(std::uint16_t{9});
  p.free(a);
  EXPECT_EQ(p.alloc(std::uint16_t{11}), a);
  EXPECT_EQ(p[a], 11u);
}

TEST(SlabPool, ArenaBackedPool) {
  SlabPool<Rec32, ArenaBacking<HugePages::kTransparent, true>> p(10);
  const auto h = p.alloc();
  p[h].e = 99;
  EXPECT_EQ(p[h].e, 99u);
  EXPECT_GE(arena_counters().maps, 1u);
}

TEST(Arena, MapsZeroedMemoryInEveryMode) {
  for (HugePages m : {HugePages::kOff, HugePages::kTransparent, HugePages::kHugetlb}) {
    ArenaInfo info;
    void* p = arena_map(3 * 4096 + 5, m, true, &info);
    ASSERT_NE(p, nullptr);
    EXPECT_GE(info.bytes, 3u * 4096 + 5);
    EXPECT_EQ(info.bytes, arena_round(3 * 4096 + 5, m));
    EXPECT_TRUE(info.prefaulted);
    const auto* b = static_cast<const unsigned char*>(p);
    for (std::size_t i = 0; i < info.bytes; i += 1024) ASSERT_EQ(b[i], 0);
    std::memset(p, 0xAB, 3 * 4096);
#if !defined(__linux__)
    EXPECT_FALSE(info.hugetlb);
    EXPECT_FALSE(info.thp_advised);
#endif
    arena_unmap(p, 3 * 4096 + 5, m);
  }
  EXPECT_EQ(arena_round(1, HugePages::kTransparent), kHugePageBytes);
}

}  // namespace
}  // namespace lle::lob

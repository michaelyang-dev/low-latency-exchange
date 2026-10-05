#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "common/prng.h"
#include "lob/fifo.h"
#include "lob/level.h"
#include "lob/levels.h"
#include "lob/slab_pool.h"

namespace lle::lob {
namespace {

using LevelT = Level<IntrusiveFifo::Queue<Handle32>, 1>;
using Pool = SlabPool<LevelT>;

template <template <class, class> class SideT, class B>
struct Case {
  using Side = SideT<LevelT, B>;
  using Better = B;
};
template <class L, class B>
using Win6 = WindowSide<L, B, 6>;
template <class L, class B>
using Win10 = WindowSide<L, B, 10>;

template <class C>
struct LevelsContract : ::testing::Test {
  using SideT = typename C::Side;
  using Better = typename C::Better;
  struct Cmp {
    bool operator()(PxE4 a, PxE4 b) const { return Better::better(a, b); }
  };
  SideT side;
  Pool pool;
  std::map<PxE4, LevelT*, Cmp> ref;  // begin() = best

  void TearDown() override { side.clear(pool); }

  LevelT* insert(PxE4 k) {
    bool created = false;
    LevelT* lv = side.find_or_insert(k, pool, created);
    const bool fresh = ref.find(k) == ref.end();
    EXPECT_EQ(created, fresh) << k;
    if (created) {
      lv->px = k;
      lv->count = 1;
      ref[k] = lv;
    } else {
      EXPECT_EQ(lv, ref[k]);
    }
    return lv;
  }
  void erase(PxE4 k) {
    LevelT* lv = ref.at(k);
    side.erase(k, lv, pool);
    ref.erase(k);
  }
  void verify() {
    ASSERT_EQ(side.size(), ref.size());
    ASSERT_EQ(side.best(), ref.empty() ? nullptr : ref.begin()->second);
    std::vector<PxE4> got;
    side.for_each([&](PxE4 k, const LevelT& lv) {
      got.push_back(k);
      EXPECT_EQ(lv.px, k);
    });
    std::vector<PxE4> want;
    for (const auto& [k, lv] : ref) want.push_back(k);
    ASSERT_EQ(got, want);
    std::string err;
    ASSERT_TRUE(side.check(&err)) << err;
  }
};

using Cases = ::testing::Types<Case<MapSide, Higher>, Case<MapSide, Lower>, Case<VecSide, Higher>,
                               Case<VecSide, Lower>, Case<Win6, Higher>, Case<Win6, Lower>, Case<Win10, Higher>,
                               Case<Win10, Lower>>;
TYPED_TEST_SUITE(LevelsContract, Cases);

TYPED_TEST(LevelsContract, OrdersBestFirst) {
  this->insert(100'000);
  this->insert(100'100);
  this->insert(99'900);
  this->insert(100'000);  // existing
  this->verify();
  EXPECT_EQ(this->side.find(99'900), this->ref.at(99'900));
  EXPECT_EQ(this->side.find(99'800), nullptr);
  this->erase(this->ref.begin()->first);  // the best
  this->verify();
  while (!this->ref.empty()) this->erase(this->ref.begin()->first);
  this->verify();
  EXPECT_EQ(this->side.best(), nullptr);
}

TYPED_TEST(LevelsContract, StubAndFarPrices) {
  // ITCH extremes: $0.0001, $0.01, sub-penny, $199,999.99, 2^32-1, 0.
  for (PxE4 k : {PxE4{503'100}, PxE4{1}, PxE4{100}, PxE4{503'155}, PxE4{1'999'999'900}, PxE4{0xFFFF'FFFFll},
                 PxE4{0}, PxE4{503'000}, PxE4{9'999}, PxE4{10'000}}) {
    this->insert(k);
    this->verify();
  }
  for (PxE4 k : {PxE4{0xFFFF'FFFFll}, PxE4{1}, PxE4{503'100}, PxE4{0}}) {
    this->erase(k);
    this->verify();
  }
}

TYPED_TEST(LevelsContract, RandomDifferential) {
  Prng rng(2024);
  PxE4 center = 500'000;
  for (int i = 0; i < 40'000; ++i) {
    const std::uint64_t r = rng.below(100);
    if (r < 55 || this->ref.empty()) {
      PxE4 k;
      const std::uint64_t d = rng.below(20);
      if (d < 14) {
        k = center + 100 * rng.range(-40, 40);  // near the touch, penny grid
      } else if (d < 16) {
        k = center + rng.range(-5'000, 5'000);  // off-grid
      } else if (d < 18) {
        k = rng.range(0, 0xFFFF'FFFFll);  // anywhere
      } else {
        k = rng.range(1, 9'999);  // sub-dollar
      }
      this->insert(k < 0 ? 0 : k);
    } else {
      auto it = this->ref.begin();
      // Mostly near the best (the common case), sometimes anywhere.
      std::advance(it, static_cast<std::ptrdiff_t>(rng.below(this->ref.size() < 8 || rng.chance(1, 4)
                                                                  ? this->ref.size()
                                                                  : 8)));
      this->erase(it->first);
    }
    if (rng.chance(1, 500)) center += 100 * rng.range(-300, 300);  // the market moves
    if (i % 1'000 == 0) this->verify();
  }
  this->verify();
}

TYPED_TEST(LevelsContract, ThousandsOfLevels) {
  for (PxE4 i = 0; i < 4'000; ++i) this->insert(1'000'000 + 100 * ((i * 7919) % 4'000));
  this->verify();
  for (PxE4 i = 0; i < 4'000; i += 2) this->erase(1'000'000 + 100 * i);
  this->verify();
}

// ---- WindowSide specifics ----------------------------------------------------------
TEST(WindowSide, RebasesWhenTheTouchLeavesTheWindow) {
  WindowSide<LevelT, Higher, 6> w;  // 64 slots
  Pool pool;
  bool created;
  // A $0.01 stub bid arrives first: the window starts there ($0.0001 grid).
  LevelT* stub = w.find_or_insert(100, pool, created);
  stub->px = 100;
  EXPECT_EQ(w.window_levels(), 1u);
  // The real touch at $50.00 is better and outside: re-base onto the penny grid.
  LevelT* touch = w.find_or_insert(500'000, pool, created);
  touch->px = 500'000;
  EXPECT_EQ(w.rebases(), 1u);
  EXPECT_EQ(w.window_levels(), 1u);
  EXPECT_EQ(w.far_levels(), 1u);
  EXPECT_EQ(w.best(), touch);
  // Levels just behind the touch go into the window, far ones stay far.
  w.find_or_insert(499'900, pool, created)->px = 499'900;
  w.find_or_insert(500'000 - 100 * 47, pool, created)->px = 500'000 - 100 * 47;  // slot 1
  w.find_or_insert(500'000 - 100 * 49, pool, created)->px = 500'000 - 100 * 49;  // below the window
  EXPECT_EQ(w.window_levels(), 3u);
  EXPECT_EQ(w.far_levels(), 2u);
  // A worse level outside the window never triggers a re-base.
  EXPECT_EQ(w.rebases(), 1u);
  std::string err;
  EXPECT_TRUE(w.check(&err)) << err;
  // Erasing the touch leaves the next window level as best.
  w.erase(500'000, touch, pool);
  EXPECT_EQ(w.best()->px, 499'900);
  EXPECT_TRUE(w.check(&err)) << err;
  w.clear(pool);
  EXPECT_EQ(pool.live(), 0u);
}

TEST(WindowSide, NegatedAsksShareTheHigherWindow) {
  // Asks stored as -px with Higher: best = lowest real price.
  WindowSide<LevelT, Higher, 6> w;
  Pool pool;
  bool created;
  for (PxE4 px : {PxE4{100'500}, PxE4{100'400}, PxE4{100'700}, PxE4{1'999'999'900}}) {
    w.find_or_insert(-px, pool, created)->px = px;
  }
  EXPECT_EQ(w.best()->px, 100'400);
  std::vector<PxE4> order;
  w.for_each([&](PxE4, const LevelT& lv) { order.push_back(lv.px); });
  EXPECT_EQ(order, (std::vector<PxE4>{100'400, 100'500, 100'700, 1'999'999'900}));
  std::string err;
  EXPECT_TRUE(w.check(&err)) << err;
  w.clear(pool);
}

TEST(VecSide, BestIsAtTheBack) {
  VecSide<LevelT, Lower> asks;
  Pool pool;
  bool created;
  for (PxE4 px : {PxE4{10'300}, PxE4{10'100}, PxE4{10'200}}) asks.find_or_insert(px, pool, created)->px = px;
  EXPECT_EQ(asks.best_key(), 10'100);
  EXPECT_EQ(asks.key_at(0), 10'300);  // worst at the front
  asks.clear(pool);
  EXPECT_EQ(pool.live(), 0u);
}

}  // namespace
}  // namespace lle::lob

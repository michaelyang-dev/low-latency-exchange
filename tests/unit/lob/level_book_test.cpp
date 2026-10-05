#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "lob/fifo.h"
#include "lob/level.h"
#include "lob/level_book.h"
#include "lob/levels.h"
#include "lob/slab_pool.h"

namespace lle::lob {
namespace {

using LevelT = Level<IntrusiveFifo::Queue<Handle32>, 1>;
using Pool = SlabPool<LevelT>;

template <class Levels, bool kNeg>
struct Case {
  using Book = LevelBook<Levels, LevelT, kNeg>;
};

template <class C>
struct LevelBookContract : ::testing::Test {
  typename C::Book book;
  Pool pool;
  void TearDown() override { book.clear(pool); }

  LevelT* add(Side s, PxE4 px, std::uint64_t qty) {
    bool created = false;
    LevelT* lv = book.find_or_insert(s, px, pool, created);
    lv->qty[0] += qty;
    ++lv->count;
    return lv;
  }
};

using Cases = ::testing::Types<Case<MapLevels, false>, Case<MapLevels, true>, Case<VecLevels, false>,
                               Case<VecLevels, true>, Case<WindowLevels<6>, false>, Case<WindowLevels<10>, true>>;
TYPED_TEST_SUITE(LevelBookContract, Cases);

TYPED_TEST(LevelBookContract, CachedBboTracksBothSides) {
  auto& b = this->book;
  EXPECT_EQ(b.bbo(), Bbo{});
  this->add(Side::Buy, 100'000, 300);
  EXPECT_TRUE(b.refresh(Side::Buy));
  EXPECT_FALSE(b.refresh(Side::Buy));  // nothing changed
  this->add(Side::Sell, 100'500, 50);
  this->add(Side::Sell, 100'400, 70);
  EXPECT_TRUE(b.refresh(Side::Sell));
  EXPECT_EQ(b.bbo(), (Bbo{{100'000, 300}, {100'400, 70}}));
  this->add(Side::Buy, 99'900, 10);  // behind the touch
  EXPECT_FALSE(b.refresh(Side::Buy));
  // Erase the best ask: next level becomes the touch.
  LevelT* best_ask = b.best(Side::Sell);
  ASSERT_NE(best_ask, nullptr);
  ASSERT_EQ(best_ask->px, 100'400);
  best_ask->count = 0;
  best_ask->qty[0] = 0;
  b.erase(Side::Sell, best_ask, this->pool);
  EXPECT_TRUE(b.refresh(Side::Sell));
  EXPECT_EQ(b.bbo().ask, (BboSide{100'500, 50}));
  std::string err;
  EXPECT_TRUE(b.check(&err)) << err;
  EXPECT_EQ(b.levels(Side::Buy), 2u);
  EXPECT_EQ(b.levels(Side::Sell), 1u);
}

TYPED_TEST(LevelBookContract, CrossedAndLockedAreRepresentable) {
  auto& b = this->book;
  this->add(Side::Buy, 200'000, 1);
  this->add(Side::Sell, 200'000, 2);  // locked
  this->add(Side::Sell, 199'900, 3);  // crossed
  b.refresh(Side::Buy);
  b.refresh(Side::Sell);
  EXPECT_EQ(b.bbo(), (Bbo{{200'000, 1}, {199'900, 3}}));
  std::string err;
  EXPECT_TRUE(b.check(&err)) << err;
}

TYPED_TEST(LevelBookContract, IterationBestToWorstPerSide) {
  for (PxE4 px : {PxE4{10'100}, PxE4{10'300}, PxE4{10'200}, PxE4{1}, PxE4{0xFFFF'FFFFll}}) {
    this->add(Side::Buy, px, 1);
    this->add(Side::Sell, px, 1);
  }
  std::vector<PxE4> bids, asks;
  this->book.for_each_level(Side::Buy, [&](const LevelT& lv) { bids.push_back(lv.px); });
  this->book.for_each_level(Side::Sell, [&](const LevelT& lv) { asks.push_back(lv.px); });
  EXPECT_EQ(bids, (std::vector<PxE4>{0xFFFF'FFFFll, 10'300, 10'200, 10'100, 1}));
  EXPECT_EQ(asks, (std::vector<PxE4>{1, 10'100, 10'200, 10'300, 0xFFFF'FFFFll}));
  const auto* found = this->book.find(Side::Sell, 10'200);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->px, 10'200);
  EXPECT_EQ(this->book.find(Side::Sell, 10'250), nullptr);
}

TEST(LevelBook, NegationStoresAskKeysNegated) {
  using B = LevelBook<VecLevels, LevelT, true>;
  EXPECT_EQ(B::key(Side::Sell, 100), -100);
  EXPECT_EQ(B::key(Side::Buy, 100), 100);
  using N = LevelBook<VecLevels, LevelT, false>;
  EXPECT_EQ(N::key(Side::Sell, 100), 100);
  static_assert(std::is_same_v<B::BidSide, B::AskSide>, "one container type for both sides");
  static_assert(!std::is_same_v<N::BidSide, N::AskSide>);
}

TEST(LevelBook, CheckDetectsStaleBbo) {
  LevelBook<VecLevels, LevelT, true> b;
  Pool pool;
  bool created;
  LevelT* lv = b.find_or_insert(Side::Buy, 500, pool, created);
  lv->qty[0] = 5;
  lv->count = 1;
  std::string err;
  EXPECT_FALSE(b.check(&err));  // refresh() not called
  EXPECT_NE(err.find("BBO"), std::string::npos);
  b.refresh(Side::Buy);
  EXPECT_TRUE(b.check(&err)) << err;
  b.clear(pool);
}

// ---- two queue classes per level (engine: displayed, then non-displayed) ----
struct Node {
  int id = 0;
  int cls = 0;
  IntrusiveFifo::Link<Handle32> link;
};
struct NodeStore {
  SlabPool<Node> pool;
  Node& rec(Handle32 h) { return pool[h]; }
  const Node& rec(Handle32 h) const { return pool[h]; }
};

TEST(Level, TwoQueueClassesKeepDisplayedAhead) {
  using L2 = Level<IntrusiveFifo::Queue<Handle32>, 2>;
  LevelBook<VecLevels, L2, true> b;
  SlabPool<L2> pool;
  NodeStore st;
  bool created;
  L2* lv = b.find_or_insert(Side::Sell, 100'000, pool, created);
  ASSERT_TRUE(created);
  auto enter = [&](int id, int cls, std::uint64_t qty) {
    const Handle32 h = st.pool.alloc();
    st.rec(h).id = id;
    st.rec(h).cls = cls;
    IntrusiveFifo::push_back(st, lv->q[cls], h);
    lv->qty[cls] += qty;
    ++lv->count;
    return h;
  };
  enter(1, 1, 500);  // non-displayed arrives first
  const Handle32 d2 = enter(2, 0, 100);
  enter(3, 1, 200);
  enter(4, 0, 300);
  // Matching walks class 0 (displayed by time) then class 1 (non-displayed by time).
  std::vector<int> order;
  for (int c = 0; c < L2::kQueueClasses; ++c) {
    IntrusiveFifo::for_each(st, lv->q[c], [&](Handle32 h) { order.push_back(st.rec(h).id); });
  }
  EXPECT_EQ(order, (std::vector<int>{2, 4, 1, 3}));
  EXPECT_EQ(lv->qty[0], 400u);
  EXPECT_EQ(lv->qty[1], 700u);
  EXPECT_EQ(lv->total_qty(), 1'100u);
  b.refresh(Side::Sell);
  EXPECT_EQ(b.bbo().ask, (BboSide{100'000, 400}));  // the cached top shows displayed shares
  std::string err;
  EXPECT_TRUE(IntrusiveFifo::check(st, lv->q[0], 2, &err)) << err;
  IntrusiveFifo::unlink(st, lv->q[0], d2);
  EXPECT_TRUE(IntrusiveFifo::check(st, lv->q[0], 1, &err)) << err;
  b.clear(pool);
}

}  // namespace
}  // namespace lle::lob

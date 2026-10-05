// MatchingBook (05-matching-engine §2, E-01): two FIFO queue classes per
// level on the shared LOB core, per-class totals, level lifecycle, BBO cache.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "engine/matching_book.h"
#include "engine/order.h"

namespace lle::engine {
namespace {

class BookTest : public ::testing::Test {
 protected:
  void SetUp() override { b_.reset(2); }

  Handle add(Locate l, Side s, PxE4 px, Qty q, Display d = Display::Visible) {
    const Handle h = b_.alloc();
    Order& o = b_.at(h);
    o.locate = l;
    o.side = s;
    o.px = px;
    o.leaves = q;
    o.display = d;
    o.ref = ++ref_;
    b_.insert(h);
    ++count_;
    return h;
  }
  void remove(Handle h) {
    b_.unlink(h);
    b_.free(h);
    --count_;
  }
  std::vector<OrderRef> queue(const BookLevel& lv, int cls) const {
    std::vector<OrderRef> v;
    b_.for_each_in(lv, cls, [&](Handle h) { v.push_back(b_.at(h).ref); });
    return v;
  }
  void expect_ok() {
    std::string err;
    EXPECT_TRUE(b_.check(&err, count_)) << err;
  }

  MatchingBook b_{BookConfig{64, 16, 8}};
  OrderRef ref_ = 0;
  std::size_t count_ = 0;
};

TEST_F(BookTest, TwoQueueClassesPerLevel) {
  const Handle h1 = add(1, Side::Sell, 100, 10, Display::Hidden);
  const Handle h2 = add(1, Side::Sell, 100, 20);
  const Handle h3 = add(1, Side::Sell, 100, 30, Display::Attributable);
  (void)h2;
  const BookLevel* lv = b_.best(1, Side::Sell);
  ASSERT_NE(lv, nullptr);
  EXPECT_EQ(lv->px, 100);
  EXPECT_EQ(lv->count, 3u);
  EXPECT_EQ(lv->qty[kDisplayed], 50u);
  EXPECT_EQ(lv->qty[kHidden], 10u);
  EXPECT_EQ(queue(*lv, kDisplayed), (std::vector<OrderRef>{2, 3}));
  EXPECT_EQ(queue(*lv, kHidden), (std::vector<OrderRef>{1}));
  // The cached BBO counts displayed shares only.
  EXPECT_EQ(b_.book(1).bbo().ask.qty, 50u);
  b_.reduce(h3, 5);
  EXPECT_EQ(lv->qty[kDisplayed], 45u);
  EXPECT_EQ(b_.book(1).bbo().ask.qty, 45u);
  remove(h1);
  EXPECT_EQ(lv->qty[kHidden], 0u);
  expect_ok();
}

TEST_F(BookTest, LevelsOrderedBestFirstAndErasedWhenEmpty) {
  const Handle a = add(1, Side::Buy, 100, 1);
  (void)add(1, Side::Buy, 102, 1);
  (void)add(1, Side::Buy, 101, 1);
  (void)add(1, Side::Sell, 105, 1);
  (void)add(1, Side::Sell, 103, 1);
  EXPECT_EQ(b_.best(1, Side::Buy)->px, 102);
  EXPECT_EQ(b_.best(1, Side::Sell)->px, 103);
  EXPECT_EQ(b_.level_count(1, Side::Buy), 3u);
  EXPECT_EQ(b_.level_at_rank(1, Side::Buy, 0)->px, 102);
  EXPECT_EQ(b_.level_at_rank(1, Side::Buy, 2)->px, 100);
  EXPECT_EQ(b_.level_at_rank(1, Side::Sell, 1)->px, 105);
  remove(a);
  EXPECT_EQ(b_.level_count(1, Side::Buy), 2u);
  EXPECT_EQ(b_.best(2, Side::Buy), nullptr);  // books are per locate
  expect_ok();
}

TEST_F(BookTest, FifoWithinClassSurvivesMiddleRemoval) {
  std::vector<Handle> hs;
  for (int i = 0; i < 5; ++i) hs.push_back(add(1, Side::Buy, 100, 10));
  remove(hs[2]);
  remove(hs[0]);
  const BookLevel* lv = b_.best(1, Side::Buy);
  EXPECT_EQ(queue(*lv, kDisplayed), (std::vector<OrderRef>{2, 4, 5}));
  (void)add(1, Side::Buy, 100, 10);
  EXPECT_EQ(queue(*lv, kDisplayed), (std::vector<OrderRef>{2, 4, 5, 6}));
  EXPECT_EQ(lv->qty[kDisplayed], 40u);
  expect_ok();
}

TEST_F(BookTest, InsertByPrioKeepsTimeOrder) {
  const Handle a = add(1, Side::Buy, 100, 10);
  b_.at(a).prio = 10;
  const Handle c = add(1, Side::Buy, 100, 10);
  b_.at(c).prio = 30;
  const Handle h = b_.alloc();
  Order& o = b_.at(h);
  o.locate = 1;
  o.side = Side::Buy;
  o.px = 100;
  o.leaves = 5;
  o.ref = 99;
  o.prio = 20;
  b_.insert_by_prio(h);
  ++count_;
  const BookLevel* lv = b_.best(1, Side::Buy);
  EXPECT_EQ(queue(*lv, kDisplayed), (std::vector<OrderRef>{1, 99, 2}));
  EXPECT_EQ(lv->qty[kDisplayed], 25u);
  expect_ok();
}

TEST_F(BookTest, CheckDetectsCorruption) {
  const Handle h = add(1, Side::Buy, 100, 10);
  b_.at(h).leaves = 11;  // level total no longer matches
  std::string err;
  EXPECT_FALSE(b_.check(&err, count_));
  b_.at(h).leaves = 10;
  expect_ok();
}

TEST(KeepsPriority, OnlyDecreaseAndRemark) {
  EXPECT_TRUE(keeps_priority(Change::Decrease));
  EXPECT_TRUE(keeps_priority(Change::Remark));
  EXPECT_FALSE(keeps_priority(Change::Increase));
  EXPECT_FALSE(keeps_priority(Change::PriceChange));
  EXPECT_FALSE(keeps_priority(Change::DisplayChange));
  EXPECT_FALSE(keeps_priority(Change::Replace));
}

}  // namespace
}  // namespace lle::engine

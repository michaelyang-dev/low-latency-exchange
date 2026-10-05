// RefBook's own scenario tests, with hand-computed expectations
// (04-order-book §8: "Its own unit tests come from hand-computed scenarios").
#include <gtest/gtest.h>

#include <cstdint>

#include "common/hash.h"
#include "ref_book.hpp"

namespace lle::lobfuzz {
namespace {

constexpr std::uint64_t kBboSeed = 0x6C6F'622D'6262'6F31ull;
constexpr std::uint64_t kBooksSeed = 0x6C6F'622D'626B'7331ull;

std::uint64_t step(std::uint64_t h, Locate l, PxE4 bp, std::uint64_t bq, PxE4 ap, std::uint64_t aq) {
  h = combine(h, l);
  h = combine(h, static_cast<std::uint64_t>(bp));
  h = combine(h, bq);
  h = combine(h, static_cast<std::uint64_t>(ap));
  return combine(h, aq);
}

TEST(RefBook, AddsAggregateAtTheTouch) {
  RefBook b;
  EXPECT_EQ(b.add(1, 7, Side::Buy, 100'000, 100), RefResult::kOk);
  EXPECT_TRUE(b.event_fired());
  EXPECT_EQ(b.add(2, 7, Side::Buy, 100'000, 200), RefResult::kOk);
  EXPECT_TRUE(b.event_fired());  // qty at the best bid changed 100 -> 300
  EXPECT_EQ(b.add(3, 7, Side::Buy, 99'900, 500), RefResult::kOk);
  EXPECT_FALSE(b.event_fired());  // behind the touch
  EXPECT_EQ(b.add(4, 7, Side::Sell, 100'500, 50), RefResult::kOk);
  EXPECT_TRUE(b.event_fired());
  EXPECT_EQ(b.top(7), (RefTop{100'000, 300, 100'500, 50}));
  EXPECT_EQ(b.event_count(), 3u);
  std::uint64_t h = kBboSeed;
  h = step(h, 7, 100'000, 100, 0, 0);
  h = step(h, 7, 100'000, 300, 0, 0);
  h = step(h, 7, 100'000, 300, 100'500, 50);
  EXPECT_EQ(b.event_digest(), h);
}

TEST(RefBook, ReduceKeepsPriorityAndRemovesAtZero) {
  RefBook b;
  b.add(1, 1, Side::Sell, 50'000, 100);
  b.add(2, 1, Side::Sell, 50'000, 100);
  EXPECT_EQ(b.reduce(1, 30), RefResult::kOk);  // E/X partial: stays at the front
  EXPECT_EQ(b.top(1).ask_qty, 170u);
  EXPECT_EQ(b.reduce(2, 100), RefResult::kOk);  // full execution behind the front
  EXPECT_EQ(b.top(1).ask_qty, 70u);
  EXPECT_EQ(b.live(), 1u);
  EXPECT_EQ(b.reduce(1, 71), RefResult::kOverReduce);  // removed anyway
  EXPECT_EQ(b.live(), 0u);
  EXPECT_EQ(b.top(1), RefTop{});
  std::string err;
  EXPECT_TRUE(b.check(&err)) << err;
}

TEST(RefBook, ReplaceMovesToTheBackWithNewPriority) {
  RefBook b;
  b.add(10, 2, Side::Buy, 10'000, 100);
  b.add(11, 2, Side::Buy, 10'000, 200);
  EXPECT_EQ(b.replace(10, 12, 10'000, 100), RefResult::kOk);  // same price: back of the queue
  // Expected books digest: one bid level [11:200, 12:100], no asks.
  std::uint64_t h = kBooksSeed;
  h = combine(h, std::uint64_t{2});
  h = combine(h, std::uint64_t{'B'});
  h = combine(h, std::uint64_t{1});
  h = combine(h, std::uint64_t{10'000});
  h = combine(h, std::uint64_t{2});
  h = combine(h, std::uint64_t{300});
  h = combine(h, std::uint64_t{11});
  h = combine(h, std::uint64_t{200});
  h = combine(h, std::uint64_t{12});
  h = combine(h, std::uint64_t{100});
  h = combine(h, std::uint64_t{'S'});
  h = combine(h, std::uint64_t{0});
  h = combine(h, std::uint64_t{2});
  EXPECT_EQ(b.books_digest(), h);
  EXPECT_EQ(b.replace(11, 11, 10'100, 5), RefResult::kOk);  // new == old: like D then A
  EXPECT_EQ(b.top(2), (RefTop{10'100, 5, 0, 0}));
}

TEST(RefBook, CrossedAndLockedBooksAreLegal) {
  RefBook b;
  b.add(1, 3, Side::Buy, 20'000, 10);
  b.add(2, 3, Side::Sell, 20'000, 10);  // locked
  b.add(3, 3, Side::Sell, 19'900, 10);  // crossed
  EXPECT_EQ(b.top(3), (RefTop{20'000, 10, 19'900, 10}));
}

TEST(RefBook, RejectionsChangeNothing) {
  RefBook b;
  b.add(1, 1, Side::Buy, 100, 5);
  const std::uint64_t d = b.books_digest();
  EXPECT_EQ(b.add(1, 1, Side::Sell, 200, 5), RefResult::kDuplicateRef);
  EXPECT_EQ(b.add(2, 1, Side::Buy, 100, 0), RefResult::kBadQty);
  EXPECT_EQ(b.add(2, 1, Side::Buy, -1, 5), RefResult::kBadPrice);
  EXPECT_EQ(b.add(2, 1, Side::Buy, 0x1'0000'0000ll, 5), RefResult::kBadPrice);
  EXPECT_EQ(b.add(2, 1, static_cast<Side>('X'), 100, 5), RefResult::kBadSide);
  EXPECT_EQ(b.reduce(9, 1), RefResult::kUnknownRef);
  EXPECT_EQ(b.reduce(1, 0), RefResult::kBadQty);
  EXPECT_EQ(b.remove(9), RefResult::kUnknownRef);
  EXPECT_EQ(b.replace(9, 10, 100, 1), RefResult::kUnknownRef);
  b.add(2, 1, Side::Buy, 100, 5);
  EXPECT_EQ(b.replace(1, 2, 100, 1), RefResult::kDuplicateRef);
  EXPECT_FALSE(b.event_fired());
  EXPECT_EQ(b.remove(2), RefResult::kOk);
  EXPECT_EQ(b.books_digest(), d);
}

TEST(RefBook, StubPricesAndHugeRefs) {
  RefBook b;
  const OrderRef big = (1ull << 40) + 3;
  EXPECT_EQ(b.add(big, 5, Side::Sell, 1'999'999'900, 100), RefResult::kOk);
  EXPECT_EQ(b.add(~0ull, 5, Side::Buy, 1, 100), RefResult::kOk);
  EXPECT_EQ(b.add(0, 5, Side::Buy, 0xFFFF'FFFFll, 1), RefResult::kOk);  // ref 0 and max price are valid
  EXPECT_EQ(b.top(5), (RefTop{0xFFFF'FFFFll, 1, 1'999'999'900, 100}));
  EXPECT_EQ(b.remove(big), RefResult::kOk);
  EXPECT_EQ(b.remove(~0ull), RefResult::kOk);
  EXPECT_EQ(b.remove(0), RefResult::kOk);
  EXPECT_EQ(b.live(), 0u);
  EXPECT_EQ(b.books_digest(), combine(kBooksSeed, std::uint64_t{0}));
}

}  // namespace
}  // namespace lle::lobfuzz

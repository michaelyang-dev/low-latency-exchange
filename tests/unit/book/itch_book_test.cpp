// ItchBook scenario tests with hand-computed expectations, run against every
// registered variant (B0 and the optimized ones), plus cross-variant digest
// equality on generated streams.
#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "book/digested_book.h"
#include "book/itch_book.h"
#include "book/variants.h"
#include "common/hash.h"
#include "diff.hpp"
#include "gen.hpp"

namespace lle::book {
namespace {

struct EventLog {
  std::vector<std::pair<Locate, lob::Bbo>> ev;
  void on_bbo_change(Locate l, const lob::Bbo& b) { ev.emplace_back(l, b); }
};
class EventLogListener final : public BookListener {
 public:
  void on_bbo_change(Locate l, const lob::Bbo& b) override { log.on_bbo_change(l, b); }
  EventLog log;
};

template <class V, bool = V::kVirtualListener>
struct Logged;
template <class V>
struct Logged<V, false> {
  explicit Logged(const BookConfig& c) : book(c) {}
  ItchBook<typename V::Policies, EventLog> book;
  EventLog& log() { return book.listener(); }
};
template <class V>
struct Logged<V, true> {
  explicit Logged(const BookConfig& c) : book(c, VirtualListener{&listener}) {}
  EventLogListener listener;  // outlives book
  ItchBook<typename V::Policies, VirtualListener> book;
  EventLog& log() { return listener.log; }
};

template <class T>
struct ToTypes;
template <class... V>
struct ToTypes<std::tuple<V...>> {
  using type = ::testing::Types<V...>;
};
struct VariantName {
  template <class V>
  static std::string GetName(int) {
    return std::string(V::kName);
  }
};

using OrderRow = std::tuple<PxE4, OrderRef, Qty>;
using LevelRow = std::tuple<PxE4, std::uint64_t, std::uint32_t>;

template <class V>
struct ItchBookTest : ::testing::Test {
  static BookConfig config() {
    BookConfig c;
    c.reserve_orders = 64;
    c.reserve_levels = 16;
    c.max_direct_ref = 1u << 14;  // two direct pages; larger refs use the fallback index
    return c;
  }
  Logged<V> lb{config()};
  auto& b() { return lb.book; }
  std::vector<std::pair<Locate, lob::Bbo>>& events() { return lb.log().ev; }

  std::vector<OrderRow> orders(Locate l, Side s) {
    std::vector<OrderRow> v;
    b().for_each_order(l, s, [&](PxE4 px, OrderRef r, Qty q) { v.emplace_back(px, r, q); });
    return v;
  }
  std::vector<LevelRow> levels(Locate l, Side s) {
    std::vector<LevelRow> v;
    b().for_each_level(l, s, [&](PxE4 px, std::uint64_t q, std::uint32_t n) { v.emplace_back(px, q, n); });
    return v;
  }
  void check() {
    std::string err;
    ASSERT_TRUE(b().check_invariants(&err)) << err;
  }
};

TYPED_TEST_SUITE(ItchBookTest, ToTypes<AllVariants>::type, VariantName);

using lob::Bbo;
using lob::BboSide;

TYPED_TEST(ItchBookTest, AddAppendsAtBackAndAggregates) {
  auto& b = this->b();
  b.stock_directory(7);
  EXPECT_EQ(b.add(1, 7, Side::Buy, 100'000, 100), Status::kOk);
  EXPECT_EQ(b.add(2, 7, Side::Buy, 100'000, 200), Status::kOk);
  EXPECT_EQ(b.add(3, 7, Side::Buy, 99'900, 500), Status::kOk);  // behind the touch: no event
  EXPECT_EQ(b.add(4, 7, Side::Sell, 100'500, 50), Status::kOk);
  const std::vector<std::pair<Locate, Bbo>> want = {
      {7, Bbo{{100'000, 100}, {}}},
      {7, Bbo{{100'000, 300}, {}}},
      {7, Bbo{{100'000, 300}, {100'500, 50}}},
  };
  EXPECT_EQ(this->events(), want);
  EXPECT_EQ(b.bbo(7), (Bbo{{100'000, 300}, {100'500, 50}}));
  EXPECT_EQ(this->orders(7, Side::Buy),
            (std::vector<OrderRow>{{100'000, 1, 100}, {100'000, 2, 200}, {99'900, 3, 500}}));
  EXPECT_EQ(this->levels(7, Side::Buy), (std::vector<LevelRow>{{100'000, 300, 2}, {99'900, 500, 1}}));
  EXPECT_EQ(b.live_orders(), 4u);
  this->check();
}

TYPED_TEST(ItchBookTest, ReduceByReferenceKeepsPriority) {
  auto& b = this->b();
  for (OrderRef r : {OrderRef{1}, OrderRef{2}, OrderRef{3}}) ASSERT_EQ(b.add(r, 1, Side::Sell, 50'000, 100), Status::kOk);
  this->events().clear();
  EXPECT_EQ(b.reduce(2, 40), Status::kOk);  // X: partial cancel in the middle, priority kept
  EXPECT_EQ(this->orders(1, Side::Sell),
            (std::vector<OrderRow>{{50'000, 1, 100}, {50'000, 2, 60}, {50'000, 3, 100}}));
  EXPECT_EQ(b.reduce(3, 100), Status::kOk);  // E behind the front: applied by reference
  EXPECT_EQ(this->orders(1, Side::Sell), (std::vector<OrderRow>{{50'000, 1, 100}, {50'000, 2, 60}}));
  EXPECT_EQ(b.reduce(1, 100), Status::kOk);  // front fill
  EXPECT_EQ(b.reduce(2, 61), Status::kOverReduce);  // removed anyway
  EXPECT_EQ(b.live_orders(), 0u);
  const std::vector<std::pair<Locate, Bbo>> want = {
      {1, Bbo{{}, {50'000, 260}}},
      {1, Bbo{{}, {50'000, 160}}},
      {1, Bbo{{}, {50'000, 60}}},
      {1, Bbo{}},
  };
  EXPECT_EQ(this->events(), want);
  this->check();
}

TYPED_TEST(ItchBookTest, ReplaceGetsNewPriorityAndInheritsSideAndLocate) {
  auto& b = this->b();
  b.add(10, 3, Side::Buy, 10'000, 100);
  b.add(11, 3, Side::Buy, 10'000, 200);
  this->events().clear();
  EXPECT_EQ(b.replace(10, 12, 10'000, 100), Status::kOk);  // same price: back of the queue
  EXPECT_EQ(this->orders(3, Side::Buy), (std::vector<OrderRow>{{10'000, 11, 200}, {10'000, 12, 100}}));
  EXPECT_TRUE(this->events().empty());  // the top (10,000 x 300) did not change
  EXPECT_EQ(b.replace(11, 13, 10'100, 200), Status::kOk);
  const auto o = b.find_order(13);
  ASSERT_TRUE(o.has_value());
  EXPECT_EQ(o->side, Side::Buy);
  EXPECT_EQ(o->locate, 3);
  EXPECT_EQ(o->px, 10'100);
  EXPECT_FALSE(b.find_order(11).has_value());
  EXPECT_EQ(b.replace(13, 13, 10'200, 5), Status::kOk);  // new ref == old ref: like D then A
  EXPECT_EQ(this->orders(3, Side::Buy), (std::vector<OrderRow>{{10'200, 13, 5}, {10'000, 12, 100}}));
  const std::vector<std::pair<Locate, Bbo>> want = {
      {3, Bbo{{10'100, 200}, {}}},
      {3, Bbo{{10'200, 5}, {}}},
  };
  EXPECT_EQ(this->events(), want);
  this->check();
}

TYPED_TEST(ItchBookTest, CrossedAndLockedBooksAreTolerated) {
  auto& b = this->b();
  b.add(1, 9, Side::Buy, 200'000, 10);
  b.add(2, 9, Side::Sell, 200'000, 20);  // locked
  EXPECT_EQ(b.bbo(9), (Bbo{{200'000, 10}, {200'000, 20}}));
  b.add(3, 9, Side::Sell, 199'900, 30);  // crossed (legal in halts and pauses)
  b.add(4, 9, Side::Buy, 200'100, 40);
  EXPECT_EQ(b.bbo(9), (Bbo{{200'100, 40}, {199'900, 30}}));
  this->check();
  EXPECT_EQ(b.remove(3), Status::kOk);
  EXPECT_EQ(b.bbo(9).ask, (BboSide{200'000, 20}));
}

TYPED_TEST(ItchBookTest, StubAndFarPrices) {
  auto& b = this->b();
  EXPECT_EQ(b.add(1, 2, Side::Sell, 1'999'999'900, 100), Status::kOk);  // $199,999.99
  EXPECT_EQ(b.add(2, 2, Side::Sell, 0xFFFF'FFFFll, 100), Status::kOk);  // max Price(4)
  EXPECT_EQ(b.add(3, 2, Side::Buy, 100, 100), Status::kOk);             // $0.01
  EXPECT_EQ(b.add(4, 2, Side::Buy, 1, 100), Status::kOk);               // $0.0001
  EXPECT_EQ(b.add(5, 2, Side::Buy, 0, 100), Status::kOk);               // zero is representable
  EXPECT_EQ(b.add(6, 2, Side::Buy, 503'100, 100), Status::kOk);         // the real touch
  EXPECT_EQ(b.add(7, 2, Side::Sell, 503'200, 100), Status::kOk);
  EXPECT_EQ(b.bbo(2), (Bbo{{503'100, 100}, {503'200, 100}}));
  EXPECT_EQ(this->levels(2, Side::Sell),
            (std::vector<LevelRow>{{503'200, 100, 1}, {1'999'999'900, 100, 1}, {0xFFFF'FFFFll, 100, 1}}));
  EXPECT_EQ(this->levels(2, Side::Buy),
            (std::vector<LevelRow>{{503'100, 100, 1}, {100, 100, 1}, {1, 100, 1}, {0, 100, 1}}));
  this->check();
  for (OrderRef r = 1; r <= 7; ++r) ASSERT_EQ(b.remove(r), Status::kOk);
  EXPECT_EQ(b.bbo(2), Bbo{});
  this->check();
}

TYPED_TEST(ItchBookTest, RefsAcrossPagesAndAbove2To32) {
  auto& b = this->b();
  const OrderRef refs[] = {0, 1, 8191, 8192, 16383, 16384, (1ull << 32) - 1, 1ull << 32, (1ull << 32) + 1,
                           1ull << 63, ~0ull};
  Qty q = 1;
  for (OrderRef r : refs) ASSERT_EQ(b.add(r, 4, Side::Buy, 10'000, q++), Status::kOk) << r;
  this->check();
  EXPECT_EQ(b.reduce(~0ull, 5), Status::kOk);  // 11 - 5
  EXPECT_EQ(b.replace(8191, 1ull << 40, 10'100, 7), Status::kOk);  // direct -> fallback
  EXPECT_EQ(b.replace(1ull << 32, 3, 10'100, 8), Status::kOk);     // fallback -> direct
  EXPECT_EQ(b.find_order(1ull << 40)->qty, 7u);
  EXPECT_EQ(b.find_order(3)->px, 10'100);
  EXPECT_EQ(b.find_order(~0ull)->qty, 6u);
  this->check();
  for (OrderRef r : std::initializer_list<OrderRef>{OrderRef{0}, OrderRef{1}, OrderRef{8192}, OrderRef{16383}, OrderRef{16384},
                     (1ull << 32) - 1, (1ull << 32) + 1, 1ull << 63, ~0ull, 1ull << 40, OrderRef{3}}) {
    ASSERT_EQ(b.remove(r), Status::kOk) << r;
  }
  EXPECT_EQ(b.live_orders(), 0u);
  this->check();
}

TYPED_TEST(ItchBookTest, DuplicateStockDirectoryIsIgnored) {
  auto& b = this->b();
  b.stock_directory(1335);
  b.add(1, 1335, Side::Buy, 250'000, 100);
  b.add(2, 1335, Side::Sell, 250'100, 100);
  const std::uint64_t d = b.books_digest();
  const std::size_t n = this->events().size();
  b.stock_directory(1335);  // re-sent R with identical bytes (R1a Q6 pitfall 4)
  EXPECT_EQ(b.books_digest(), d);
  EXPECT_EQ(this->events().size(), n);
  EXPECT_EQ(b.bbo(1335), (Bbo{{250'000, 100}, {250'100, 100}}));
  b.stock_directory(0);
  b.stock_directory(65535);
  EXPECT_EQ(b.books_digest(), d);
  this->check();
}

TYPED_TEST(ItchBookTest, RejectionsChangeNothing) {
  auto& b = this->b();
  b.add(1, 1, Side::Buy, 10'000, 5);
  b.add(2, 1, Side::Buy, 10'000, 5);
  const std::uint64_t d = b.books_digest();
  const std::size_t n = this->events().size();
  EXPECT_EQ(b.add(1, 1, Side::Sell, 20'000, 5), Status::kDuplicateRef);
  EXPECT_EQ(b.add(3, 1, Side::Buy, 10'000, 0), Status::kBadQty);
  EXPECT_EQ(b.add(3, 1, Side::Buy, -1, 5), Status::kBadPrice);
  EXPECT_EQ(b.add(3, 1, Side::Buy, 0x1'0000'0000ll, 5), Status::kBadPrice);
  EXPECT_EQ(b.add(3, 1, static_cast<Side>('X'), 10'000, 5), Status::kBadSide);
  EXPECT_EQ(b.reduce(9, 1), Status::kUnknownRef);
  EXPECT_EQ(b.reduce(1, 0), Status::kBadQty);
  EXPECT_EQ(b.remove(9), Status::kUnknownRef);
  EXPECT_EQ(b.replace(9, 10, 10'000, 1), Status::kUnknownRef);
  EXPECT_EQ(b.replace(1, 2, 10'000, 1), Status::kDuplicateRef);
  EXPECT_EQ(b.replace(1, 4, 10'000, 0), Status::kBadQty);
  EXPECT_EQ(b.replace(1, 4, -5, 1), Status::kBadPrice);
  EXPECT_EQ(b.books_digest(), d);
  EXPECT_EQ(this->events().size(), n);
  EXPECT_FALSE(b.find_order(4).has_value());
  EXPECT_FALSE(b.find_order(3).has_value());
  this->check();
}

TYPED_TEST(ItchBookTest, EmptyLevelsAreErasedAndRecreated) {
  auto& b = this->b();
  for (int i = 0; i < 100; ++i) {
    ASSERT_EQ(b.add(static_cast<OrderRef>(i), 5, Side::Sell, 30'000, 10), Status::kOk);
    ASSERT_EQ(b.remove(static_cast<OrderRef>(i)), Status::kOk);
  }
  EXPECT_EQ(this->levels(5, Side::Sell).size(), 0u);
  EXPECT_EQ(this->events().size(), 200u);  // appear, disappear, x100
  this->check();
}

TYPED_TEST(ItchBookTest, LocatesAreIndependent) {
  auto& b = this->b();
  for (Locate l : {Locate{0}, Locate{1}, Locate{65535}}) {
    ASSERT_EQ(b.add(100u + l, l, Side::Buy, 10'000, 1u + l), Status::kOk);
  }
  EXPECT_EQ(b.bbo(0).bid, (BboSide{10'000, 1}));
  EXPECT_EQ(b.bbo(1).bid, (BboSide{10'000, 2}));
  EXPECT_EQ(b.bbo(65535).bid, (BboSide{10'000, 65536}));
  EXPECT_EQ(b.bbo(2), Bbo{});
  ASSERT_EQ(this->events().size(), 3u);
  EXPECT_EQ(this->events()[2].first, 65535);
  EXPECT_EQ(b.remove(101), Status::kOk);
  EXPECT_EQ(this->events().back().first, 1);
  EXPECT_EQ(b.bbo(0).bid, (BboSide{10'000, 1}));
  this->check();
}

TYPED_TEST(ItchBookTest, TenThousandOrdersAtOneLevel) {
  auto& b = this->b();
  for (OrderRef r = 0; r < 10'000; ++r) ASSERT_EQ(b.add(r, 6, Side::Buy, 20'000, 999'999), Status::kOk);
  EXPECT_EQ(b.bbo(6).bid, (BboSide{20'000, 9'999'990'000ull}));  // exceeds 2^32: u64 totals
  for (OrderRef r = 1; r < 10'000; r += 3) ASSERT_EQ(b.remove(r), Status::kOk);
  const auto rows = this->orders(6, Side::Buy);
  ASSERT_EQ(rows.size(), 10'000u - 3'333u);
  OrderRef prev = 0;
  for (std::size_t i = 0; i < rows.size(); ++i) {
    const OrderRef r = std::get<1>(rows[i]);
    if (i > 0) {
      EXPECT_GT(r, prev);  // FIFO order preserved
    }
    EXPECT_NE(r % 3, 1u);
    prev = r;
  }
  this->check();
}

TYPED_TEST(ItchBookTest, MoreThanThreeThousandLevels) {
  auto& b = this->b();
  for (OrderRef i = 0; i < 3'500; ++i) {
    const PxE4 off = static_cast<PxE4>((i * 2'003) % 3'500) * 100;
    ASSERT_EQ(b.add(i, 8, Side::Buy, 1'000'000 - off, 1), Status::kOk);
    ASSERT_EQ(b.add(i + 10'000, 8, Side::Sell, 1'000'100 + off, 1), Status::kOk);
  }
  EXPECT_EQ(this->levels(8, Side::Buy).size(), 3'500u);
  EXPECT_EQ(this->levels(8, Side::Sell).size(), 3'500u);
  EXPECT_EQ(b.bbo(8), (Bbo{{1'000'000, 1}, {1'000'100, 1}}));
  this->check();
  for (OrderRef i = 0; i < 3'500; i += 2) ASSERT_EQ(b.remove(i), Status::kOk);
  this->check();
}

TYPED_TEST(ItchBookTest, BooksDigestFollowsTheDefinition) {
  auto& b = this->b();
  b.add(10, 2, Side::Buy, 10'000, 100);
  b.add(11, 2, Side::Buy, 10'000, 200);
  b.replace(10, 12, 10'000, 100);
  b.stock_directory(9);  // declared but empty: not in the digest
  std::uint64_t h = kBooksDigestSeed;
  for (std::uint64_t v : std::initializer_list<std::uint64_t>{2ull, std::uint64_t{'B'}, 1ull, 10'000ull, 2ull, 300ull, 11ull, 200ull, 12ull, 100ull,
                          std::uint64_t{'S'}, 0ull}) {
    h = combine(h, v);
  }
  h = combine(h, std::uint64_t{2});  // live orders
  EXPECT_EQ(b.books_digest(), h);
}

TYPED_TEST(ItchBookTest, EndOfDayDrainLeavesNothing) {
  auto& b = this->b();
  for (OrderRef r = 0; r < 500; ++r) {
    b.add(r * 4 + 92, static_cast<Locate>(1 + r % 5), r % 2 ? Side::Buy : Side::Sell,
          100'000 + static_cast<PxE4>(r % 37) * 100 * (r % 2 ? -1 : 1), 100);
  }
  for (OrderRef r = 0; r < 500; ++r) ASSERT_EQ(b.remove(r * 4 + 92), Status::kOk);
  EXPECT_EQ(b.live_orders(), 0u);
  EXPECT_EQ(b.books_digest(), combine(kBooksDigestSeed, std::uint64_t{0}));
  for (Locate l = 1; l <= 5; ++l) EXPECT_EQ(b.bbo(l), Bbo{});
  if constexpr (TypeParam::Policies::Levels::kPooled) {
    EXPECT_EQ(b.level_pool().live(), 0u);
  }
  this->check();
}

// ---- every variant, identical digests on generated streams -------------------------
TEST(Variants, IdenticalDigestsOnGeneratedStreams) {
  for (std::uint64_t seed = 1; seed <= 24; ++seed) {
    lobfuzz::Gen proto(seed);
    const BookConfig cfg = lobfuzz::book_config_for(proto.swarm());
    std::vector<lobfuzz::Op> ops;
    for (int i = 0; i < 6'000; ++i) ops.push_back(proto.next());
    lobfuzz::Op op;
    while (proto.next_drain(op)) ops.push_back(op);

    std::vector<std::tuple<std::string, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>> results;
    for_each_variant([&]<class V>() {
      DigestedBook<V> db(cfg);
      std::uint64_t mid = 0;
      for (std::size_t i = 0; i < ops.size(); ++i) {
        lobfuzz::apply_op(db.book(), ops[i]);
        if (i == 3'000) mid = db.book().books_digest();
        if (i % 1'500 == 0) {
          std::string err;
          ASSERT_TRUE(db.book().check_invariants(&err)) << V::kName << " seed " << seed << ": " << err;
        }
      }
      results.emplace_back(std::string(V::kName), db.recorder().digest.value, db.recorder().digest.events, mid,
                           db.book().books_digest());
    });
    for (const auto& r : results) {
      EXPECT_EQ(std::get<1>(r), std::get<1>(results[0])) << std::get<0>(r) << " seed " << seed;
      EXPECT_EQ(std::get<2>(r), std::get<2>(results[0])) << std::get<0>(r) << " seed " << seed;
      EXPECT_EQ(std::get<3>(r), std::get<3>(results[0])) << std::get<0>(r) << " seed " << seed;
      EXPECT_EQ(std::get<4>(r), std::get<4>(results[0])) << std::get<0>(r) << " seed " << seed;
    }
  }
}

TEST(Variants, RegistryNamesAreUnique) {
  std::vector<std::string> names;
  for_each_variant([&]<class V>() { names.emplace_back(V::kName); });
  EXPECT_EQ(names.size(), std::tuple_size_v<AllVariants>);
  for (std::size_t i = 0; i < names.size(); ++i) {
    for (std::size_t j = i + 1; j < names.size(); ++j) EXPECT_NE(names[i], names[j]);
  }
  int hits = 0;
  EXPECT_TRUE(visit_variant("opt", [&]<class V>() { hits += V::kName == "opt" ? 1 : 100; }));
  EXPECT_FALSE(visit_variant("nope", [&]<class V>() { hits += 1000; }));
  EXPECT_EQ(hits, 1);
}

}  // namespace
}  // namespace lle::book

// Generator tests: determinism, validity by construction, drain to empty,
// and that the swarm actually reaches the features 04-order-book §8 lists.
#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "book/variants.h"
#include "diff.hpp"
#include "gen.hpp"
#include "ref_book.hpp"

namespace lle::lobfuzz {
namespace {

TEST(Gen, SameSeedSameStream) {
  Gen a(42), b(42), c(43);
  bool differs = false;
  for (int i = 0; i < 20'000; ++i) {
    const Op x = a.next(), y = b.next(), z = c.next();
    ASSERT_EQ(to_string(x), to_string(y));
    differs |= to_string(x) != to_string(z);
  }
  EXPECT_TRUE(differs);
}

// Without invalid weight every generated operation must be accepted.
TEST(Gen, ValidByConstructionAndDrainsToEmpty) {
  int checked = 0;
  for (std::uint64_t seed = 1; seed < 200 && checked < 40; ++seed) {
    Gen g(seed);
    if (g.swarm().w_invalid != 0) continue;
    ++checked;
    RefBook ref;
    for (int i = 0; i < 5'000; ++i) {
      const Op op = g.next();
      ASSERT_EQ(apply_op(ref, op), 0) << "seed " << seed << " op " << i << ": " << to_string(op);
    }
    ASSERT_EQ(ref.live(), g.live());
    Op op;
    while (g.next_drain(op)) ASSERT_EQ(apply_op(ref, op), 0) << to_string(op);
    EXPECT_EQ(ref.live(), 0u);
    std::string err;
    EXPECT_TRUE(ref.check(&err)) << err;
  }
  EXPECT_GE(checked, 20);
}

// Invalid operations are reported, and the generator's model stays in sync.
TEST(Gen, InvalidOperationsKeepModelInSync) {
  int checked = 0;
  for (std::uint64_t seed = 1; seed < 400 && checked < 20; ++seed) {
    Gen g(seed);
    if (g.swarm().w_invalid < 10) continue;
    ++checked;
    RefBook ref;
    int rejected = 0;
    for (int i = 0; i < 5'000; ++i) rejected += apply_op(ref, g.next()) != 0 ? 1 : 0;
    EXPECT_GT(rejected, 0) << "seed " << seed;
    EXPECT_EQ(ref.live(), g.live()) << "seed " << seed;
  }
  EXPECT_GE(checked, 5);
}

TEST(Gen, SwarmCoversFeatures) {
  int deep = 0, wide = 0, high = 0, sparse = 0, stubs = 0, halts = 0, storms = 0, drain = 0;
  for (std::uint64_t seed = 1; seed <= 400; ++seed) {
    const Gen g(seed);
    const Swarm& s = g.swarm();
    deep += s.deep_queue;
    wide += s.wide;
    high += s.refs == RefMode::kHigh;
    sparse += s.refs == RefMode::kSparse;
    stubs += s.stubs;
    halts += s.halts;
    storms += s.storms;
    drain += s.drain;
  }
  EXPECT_GT(deep, 10);
  EXPECT_GT(wide, 10);
  EXPECT_GT(high, 40);
  EXPECT_GT(sparse, 40);
  EXPECT_GT(stubs, 40);
  EXPECT_GT(halts, 40);
  EXPECT_GT(storms, 40);
  EXPECT_GT(drain, 300);
}

// A deep-queue seed puts more than 10,000 orders at one level; a wide seed
// spreads one side over more than 3,000 levels.
TEST(Gen, DeepQueueAndWideBooksAreReached) {
  bool saw_deep = false, saw_wide = false;
  int tried = 0;
  for (std::uint64_t seed = 1; seed < 400 && !(saw_deep && saw_wide) && tried < 8; ++seed) {
    Gen g(seed);
    const Swarm sw = g.swarm();
    const bool want = (sw.deep_queue && !saw_deep) || (sw.wide && !saw_wide);
    if (!want || sw.w_add == 0 || (sw.w_delete + sw.w_exec + sw.w_replace) == 0) continue;
    ++tried;
    book::ItchBook<book::OptPolicies> b(book_config_for(sw));
    for (int i = 0; i < 120'000; ++i) apply_op(b, g.next());
    std::size_t max_levels = 0;
    std::uint32_t max_orders = 0;
    for (std::size_t loc = 0; loc < b.locates(); ++loc) {
      for (Side s : {Side::Buy, Side::Sell}) {
        std::size_t n = 0;
        b.for_each_level(static_cast<Locate>(loc), s, [&](PxE4, std::uint64_t, std::uint32_t c) {
          ++n;
          max_orders = c > max_orders ? c : max_orders;
        });
        max_levels = n > max_levels ? n : max_levels;
      }
    }
    if (sw.deep_queue && max_orders > 10'000) saw_deep = true;
    if (sw.wide && max_levels > 3'000) saw_wide = true;
  }
  EXPECT_TRUE(saw_deep);
  EXPECT_TRUE(saw_wide);
}

}  // namespace
}  // namespace lle::lobfuzz

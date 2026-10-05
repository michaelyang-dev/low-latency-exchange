// CrossCalculator (05-matching-engine §5, E-08): each step of the algorithm,
// the rule-derived worked example, and agreement with the brute force.
#include <gtest/gtest.h>

#include <vector>

#include "common/prng.h"
#include "cross_bruteforce.hpp"
#include "engine/cross.h"

namespace lle::engine {
namespace {

CrossInterest buy(PxE4 px, Qty q, bool cross = false) { return CrossInterest{px, q, true, false, cross, false}; }
CrossInterest sell(PxE4 px, Qty q, bool cross = false) { return CrossInterest{px, q, false, false, cross, false}; }
CrossInterest mkt(bool b, Qty q) { return CrossInterest{0, q, b, true, true, false}; }
CrossInterest io(bool b, PxE4 px, Qty q) { return CrossInterest{px, q, b, false, false, true}; }

CrossResult run(const std::vector<CrossInterest>& v, CrossParams p) {
  CrossCalculator c;
  const CrossResult r = c.compute(v, p);
  EXPECT_EQ(r, ref::brute_cross(v, p)) << "calculator and brute force disagree";
  return r;
}

// R2 D2.3/S4: IO @9.95, LOC @10.10, LOC @10.00, BBO 10.00 x 10.15 -> 5,000 at $10.00.
TEST(Cross, WorkedExampleCloseIoLoc) {
  std::vector<CrossInterest> v = {
      buy(101'000, 5'000, true),    // LOC buy 5,000 @ 10.10
      sell(100'000, 10'000, true),  // LOC sell 10,000 @ 10.00: a 5,000-share sell imbalance
      io(true, 99'500, 3'000),      // IO buy @ 9.95 (priced at most at the 10.00 bid): cannot reach the sells
  };
  CrossParams p{CrossKind::Close, (100'000 + 101'500) / 2, 0, 0, false};
  const CrossResult r = run(v, p);
  EXPECT_EQ(r.volume, 5'000u);
  EXPECT_EQ(r.price, 100'000);   // step C: the entered price where the sell imbalance remains
  EXPECT_EQ(r.side, 'S');
  EXPECT_EQ(r.imbalance, 5'000u);
}

TEST(Cross, StepAMaximizesVolume) {
  // 300 trade at 10.00 (buys >= 10.00: 300; sells <= 10.00: 300); 100 at 10.01.
  const std::vector<CrossInterest> v = {buy(100'100, 100), buy(100'000, 200), sell(100'000, 300), sell(100'100, 100)};
  const CrossResult r = run(v, CrossParams{CrossKind::Open, 0, 0, 0, false});
  EXPECT_EQ(r.volume, 300u);
  EXPECT_EQ(r.price, 100'000);
}

TEST(Cross, StepBMinimizesUnmatchedCrossShares) {
  // Equal volume (100) at 10.00 and 10.01; the MOO-style cross buy is only fully
  // matched where more sells are available... here the cross-order buy of 150
  // leaves 50 unmatched at both, so B ties and C decides; with a cross sell the
  // imbalance moves.
  const std::vector<CrossInterest> v = {buy(100'100, 150, true), sell(100'000, 100, true), sell(100'100, 100)};
  const CrossResult r = run(v, CrossParams{CrossKind::Open, 0, 0, 0, false});
  EXPECT_EQ(r.volume, 150u);  // at 10.01 both sells (200) are eligible: 150 trade
  EXPECT_EQ(r.price, 100'100);
  EXPECT_EQ(r.imbalance, 0u);
}

TEST(Cross, StepDClosestToReference) {
  // 100 match at any price in [10.00, 10.05]; no imbalance anywhere: D picks the
  // candidate nearest the reference 10.04 among {10.00, 10.05, ref}.
  const std::vector<CrossInterest> v = {buy(100'500, 100), sell(100'000, 100)};
  const CrossResult r = run(v, CrossParams{CrossKind::Open, 100'400, 0, 0, false});
  EXPECT_EQ(r.price, 100'400);
  const CrossResult r2 = run(v, CrossParams{CrossKind::Open, 0, 0, 0, false});
  EXPECT_EQ(r2.price, 100'000);  // no reference: the lower price
}

TEST(Cross, StepEThresholdIsSoftHardWindowRestricts) {
  const std::vector<CrossInterest> v = {buy(110'000, 100), sell(100'000, 100), buy(100'200, 10)};
  // Unrestricted the winner is 10.00 (110 buys eligible there? only 100 + 0)... the
  // soft window [10.50, 10.80] moves it inside.
  const CrossResult soft = run(v, CrossParams{CrossKind::Open, 0, 105'000, 108'000, false});
  EXPECT_GE(soft.price, 105'000);
  EXPECT_LE(soft.price, 108'000);
  const CrossResult hard = run(v, CrossParams{CrossKind::Open, 0, 100'100, 100'300, true});
  EXPECT_GE(hard.price, 100'100);
  EXPECT_LE(hard.price, 100'300);
}

TEST(Cross, ImbalanceOnlyOffsetsButNeverAdds) {
  // Regular: 100 buy vs 300 sell at 10.00 -> 200-share sell excess; an IO buy of
  // 500 can take only those 200.
  std::vector<CrossInterest> v = {buy(100'000, 100, true), sell(100'000, 300, true), io(true, 100'000, 500)};
  const CrossResult r = run(v, CrossParams{CrossKind::Close, 0, 0, 0, false});
  EXPECT_EQ(r.volume, 300u);
  // An IO on the excess side does nothing.
  v = {buy(100'000, 300, true), sell(100'000, 100, true), io(true, 100'000, 500)};
  EXPECT_EQ(run(v, CrossParams{CrossKind::Close, 0, 0, 0, false}).volume, 100u);
}

TEST(Cross, MarketOrdersAndHaltImbalance) {
  const std::vector<CrossInterest> v = {mkt(true, 300), sell(100'000, 100), sell(100'100, 100)};
  CrossParams p{CrossKind::Halt, 100'050, 0, 0, false};
  const CrossResult r = run(v, p);
  EXPECT_EQ(r.volume, 200u);
  EXPECT_TRUE(r.market_unexecuted);  // 100 market shares cannot execute
  EXPECT_EQ(r.side, 'B');
  EXPECT_EQ(r.imbalance, 100u);
  EXPECT_EQ(r.price, 100'100);
}

TEST(Cross, EmptyAndOneSided) {
  EXPECT_FALSE(run({}, CrossParams{}).valid);
  const CrossResult r = run({buy(100'000, 100)}, CrossParams{CrossKind::Open, 0, 0, 0, false});
  EXPECT_TRUE(r.valid);
  EXPECT_EQ(r.volume, 0u);
}

// Random books: the calculator and the brute force agree exactly.
TEST(Cross, AgreesWithBruteForceOnRandomBooks) {
  Prng rng(20261001);
  CrossCalculator calc;
  std::vector<CrossInterest> v;
  for (int k = 0; k < 200'000; ++k) {
    v.clear();
    const std::size_t n = rng.below(24);
    const PxE4 base = 100'000;
    for (std::size_t i = 0; i < n; ++i) {
      CrossInterest c;
      c.buy = rng.chance(1, 2);
      c.market = rng.chance(1, 12);
      c.px = base + static_cast<PxE4>(rng.range(-8, 8)) * 100;
      c.qty = static_cast<Qty>(rng.below(5) == 0 ? 0 : 1 + rng.below(1'000));
      c.imbalance_only = !c.market && rng.chance(1, 8);
      c.cross_order = !c.imbalance_only && rng.chance(1, 2);
      v.push_back(c);
    }
    CrossParams p;
    p.kind = static_cast<CrossKind>("OCH"[rng.below(3)]);
    p.ref = rng.chance(1, 4) ? 0 : base + static_cast<PxE4>(rng.range(-10, 10)) * 50;
    if (rng.chance(1, 2)) {
      p.lo = base + static_cast<PxE4>(rng.range(-6, 2)) * 100;
      p.hi = p.lo + static_cast<PxE4>(rng.range(0, 8)) * 100;
      p.hard = rng.chance(1, 3);
    }
    const CrossResult a = calc.compute(v, p);
    const CrossResult b = ref::brute_cross(v, p);
    ASSERT_EQ(a, b) << "case " << k;
  }
}

}  // namespace
}  // namespace lle::engine

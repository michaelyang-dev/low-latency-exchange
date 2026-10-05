// Golden scenarios for the extended order types (05 §3 "Extended", E-13):
// reserve orders (MaxFloor) with refreshes, minimum quantity (aggregate),
// midpoint pegs (NBBO := own BBO) and the Rule 201 short sale price test.
// Expected messages are derived by hand from the rules in R2 D1.1-D1.3 and
// docs/design/matching-rules.md (the comments give the derivation).
//
// Fixture (engine_test_util.h): AAPL (locate 1, $0.01 tick, round lot 100),
// account A on session 1, account B on session 2; the regular session.
#include <gtest/gtest.h>

#include <array>

#include "golden_builders.h"

namespace lle::engine::testing {
namespace {

using Extended = EngineFixture;
using LFk = ouch50::LiquidityFlag;

ouch50::TagSet max_floor(std::uint32_t v) {
  ouch50::TagSet t;
  t.set_max_floor(v);
  return t;
}
ouch50::TagSet min_qty(std::uint32_t v) {
  ouch50::TagSet t;
  t.set_min_qty(v);
  return t;
}
ouch50::TagSet midpoint_peg() {
  ouch50::TagSet t;
  t.set_price_type(ouch50::PriceType::MidpointPeg);
  return t;
}

// ---------------------------------------------------------------- reserve

TEST_F(Extended, ReserveRefreshAfterTheDisplayIsTaken) {
  auto t = ts();
  // 500 shares showing 200: ITCH shows the display only.
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 500, .price = kP100}, max_floor(200))),
                   {O(kSessA, acc(t, {1, OS::Buy, 500, "AAPL", kP100, 1}, max_floor(200))),
                    I(iadd(t, kAAPL, 1, Side::Buy, 200, "AAPL", kP100))}));
  // A 250-share sell takes the display (200, 'E', liquidity 'A'), then 50 of the
  // reserve at the back of the non-displayed queue ('P', liquidity 'u'). After
  // the taker the display is refreshed to 200 from the reserve with a new ITCH
  // reference (3, the next exchange reference) and time priority: ITCH 'A' and
  // OUCH 'R' reason 'R' with SecondaryOrdRefNum 3 and DisplayQuantity 200.
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 250, .price = kP100})),
                   {O(kSessB, acc(t, {1, OS::Sell, 250, "AAPL", kP100, 2})),
                    O(kSessA, exe(t, 1, 200, kP100, LFk::Added, 1)), O(kSessB, exe(t, 1, 200, kP100, LFk::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 200, 1)),
                    O(kSessA, exe(t, 1, 50, kP100, LFk::ReserveAddedNonDisplayed, 2)),
                    O(kSessB, exe(t, 1, 50, kP100, LFk::Removed, 2)), I(itrade(t, kAAPL, 50, "AAPL", kP100, 2)),
                    I(iadd(t, kAAPL, 3, Side::Buy, 200, "AAPL", kP100)), O(kSessA, rst(t, 1, 3, 200))}));
  // A decrease to 300 total (250 executed, 50 left open): the reserve (50) goes
  // first, then 150 of the display ('X' on the new reference).
  t = ts();
  EXPECT_TRUE(
      same(a(cancel_msg(1, 300)), {O(kSessA, can(t, 1, 200, CR::UserRequested)), I(ixcl(t, kAAPL, 3, 150))}));
  EXPECT_EQ(eng_.live_orders(), 1u);
}

TEST_F(Extended, ReserveOddLotRemainderAndExhaustion) {
  (void)a(enter_msg({.urn = 1, .qty = 600, .price = kP100}, max_floor(200)));  // ref 1: 200 shown, 400 reserve
  // 150 executed leaves an odd lot (50) showing: refreshed after the taker to
  // 200 (50 + 150 from the reserve): ITCH 'D' of the remainder, then 'A'.
  auto t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 150, .price = kP100})),
                   {O(kSessB, acc(t, {1, OS::Sell, 150, "AAPL", kP100, 2})),
                    O(kSessA, exe(t, 1, 150, kP100, LFk::Added, 1)), O(kSessB, exe(t, 1, 150, kP100, LFk::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 150, 1)), I(idel(t, kAAPL, 1)),
                    I(iadd(t, kAAPL, 3, Side::Buy, 200, "AAPL", kP100)), O(kSessA, rst(t, 1, 3, 200))}));
  // An IOC sell for 1,000 at 99.00 takes the display (200) and the reserve (250):
  // nothing is left to refresh, the order is complete; 550 cancel.
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 1'000, .price = 990'000, .tif = TIF::Ioc})),
                   {O(kSessB, acc(t, {2, OS::Sell, 1'000, "AAPL", 990'000, 4, true, TIF::Ioc})),
                    O(kSessA, exe(t, 1, 200, kP100, LFk::Added, 2)), O(kSessB, exe(t, 2, 200, kP100, LFk::Removed, 2)),
                    I(iexe(t, kAAPL, 3, 200, 2)),
                    O(kSessA, exe(t, 1, 250, kP100, LFk::ReserveAddedNonDisplayed, 3)),
                    O(kSessB, exe(t, 2, 250, kP100, LFk::Removed, 3)), I(itrade(t, kAAPL, 250, "AAPL", kP100, 3)),
                    O(kSessB, can(t, 2, 550, CR::ImmediateOrCancel))}));
  EXPECT_EQ(eng_.live_orders(), 0u);
}

// ---------------------------------------------------------------- minimum quantity

TEST_F(Extended, MinimumQuantityIsAggregateAndImmediate) {
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}));      // ref 1
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'000'100}));  // ref 2
  // 200 shares are within 100.01: a MinQty of 300 is not met, nothing executes.
  // MinQty orders never rest: the 'A' shows TIF IOC and Dead, and nothing follows it.
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 300, .price = 1'000'100}, min_qty(300))),
                   {O(kSessA, acc(t, {1, OS::Buy, 300, "AAPL", 1'000'100, 3, false, TIF::Ioc}, min_qty(300)))}));
  // A MinQty of 200 is met in aggregate across both levels.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 300, .price = 1'000'100}, min_qty(200))),
                   {O(kSessA, acc(t, {2, OS::Buy, 300, "AAPL", 1'000'100, 4, true, TIF::Ioc}, min_qty(200))),
                    O(kSessB, exe(t, 1, 100, kP100, LFk::Added, 1)), O(kSessA, exe(t, 2, 100, kP100, LFk::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1)), O(kSessB, exe(t, 2, 100, 1'000'100, LFk::Added, 2)),
                    O(kSessA, exe(t, 2, 100, 1'000'100, LFk::Removed, 2)), I(iexe(t, kAAPL, 2, 100, 2)),
                    O(kSessA, can(t, 2, 100, CR::ImmediateOrCancel))}));
}

// ---------------------------------------------------------------- midpoint peg

TEST_F(Extended, MidpointPegRestsAndExecutesAtTheMidpoint) {
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = kP100}));                         // ref 1: bid 100.00
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'001'000}));  // ref 2: offer 100.10
  // A sell peg capped at 99.00: midpoint 100.05 is above the bid, nothing to
  // take; it rests off the book (never on ITCH), Display forced to 'N'.
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 300, .price = 990'000}, midpoint_peg())),
                   {O(kSessA, acc(t, {1, OS::Sell, 300, "AAPL", 990'000, 3, true, TIF::Day, DSP::Hidden},
                                  midpoint_peg()))}));
  // A buy at 100.05 meets the peg at the midpoint before the 100.10 offer:
  // liquidity 'k' (midpoint added) and 'R'; ITCH 'P' at 100.05.
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 3, .qty = 100, .price = 1'000'500})),
                   {O(kSessB, acc(t, {3, OS::Buy, 100, "AAPL", 1'000'500, 4})),
                    O(kSessA, exe(t, 1, 100, 1'000'500, LFk::MidpointAdded, 1)),
                    O(kSessB, exe(t, 3, 100, 1'000'500, LFk::Removed, 1)),
                    I(itrade(t, kAAPL, 100, "AAPL", 1'000'500, 1))}));
  // A buy at 100.20 takes the rest of the peg at the midpoint, then the offer.
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 4, .qty = 500, .price = 1'002'000})),
                   {O(kSessB, acc(t, {4, OS::Buy, 500, "AAPL", 1'002'000, 5})),
                    O(kSessA, exe(t, 1, 200, 1'000'500, LFk::MidpointAdded, 2)),
                    O(kSessB, exe(t, 4, 200, 1'000'500, LFk::Removed, 2)),
                    I(itrade(t, kAAPL, 200, "AAPL", 1'000'500, 2)),
                    O(kSessB, exe(t, 2, 100, 1'001'000, LFk::Added, 3)),
                    O(kSessB, exe(t, 4, 100, 1'001'000, LFk::Removed, 3)), I(iexe(t, kAAPL, 2, 100, 3)),
                    I(iadd(t, kAAPL, 5, Side::Buy, 200, "AAPL", 1'002'000))}));
}

TEST_F(Extended, MidpointPegTaker) {
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = kP100}));                         // ref 1
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'001'000}));  // ref 2
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 200, .price = kP100}, midpoint_peg()));  // ref 3: rests
  // A buy peg capped at 101.00 takes the sell peg at the midpoint: 'm' (midpoint
  // removed) for the taker, 'k' for the resting peg; the IOC remainder cancels.
  const auto t = ts();
  EXPECT_TRUE(
      same(a(enter_msg({.urn = 1, .qty = 300, .price = 1'010'000, .tif = TIF::Ioc}, midpoint_peg())),
           {O(kSessA, acc(t, {1, OS::Buy, 300, "AAPL", 1'010'000, 4, true, TIF::Ioc, DSP::Hidden}, midpoint_peg())),
            O(kSessB, exe(t, 3, 200, 1'000'500, LFk::MidpointAdded, 1)),
            O(kSessA, exe(t, 1, 200, 1'000'500, LFk::MidpointRemoved, 1)),
            I(itrade(t, kAAPL, 200, "AAPL", 1'000'500, 1)), O(kSessA, can(t, 1, 100, CR::ImmediateOrCancel))}));
}

// ---------------------------------------------------------------- Rule 201

TEST_F(Extended, ShortSalePriceTest) {
  auto t = ts();
  EXPECT_TRUE(same(run(sc_.admin(AdminCommand::RegSho, AdminArgsBuilder{}.symbol("AAPL").u8(AdminTag::Action, '1'))),
                   {I(iy(t, kAAPL, "AAPL", '1'))}));
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = kP100}));  // NBB 100.00
  // With the test on, a short sale must be priced above the NBB.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::SellShort, .qty = 100, .price = kP100})),
                   {O(kSessA, rej(t, 1, RR::RiskShortSellRestricted))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .side = OS::SellShort, .qty = 100, .price = 1'000'100})),
                   {O(kSessA, acc(t, {2, OS::SellShort, 100, "AAPL", 1'000'100, 2})),
                    I(iadd(t, kAAPL, 2, Side::Sell, 100, "AAPL", 1'000'100))}));
  // Short exempt and long sales are not tested.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .side = OS::SellShortExempt, .qty = 100, .price = kP100})),
                   {O(kSessA, acc(t, {3, OS::SellShortExempt, 100, "AAPL", kP100, 3})),
                    O(kSessB, exe(t, 1, 100, kP100, LFk::Added, 1)), O(kSessA, exe(t, 3, 100, kP100, LFk::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1))}));
}

TEST_F(Extended, Rule201TriggersAtTenPercentDown) {
  // Prior close $100.00: a trade at 90.00 (90%) turns the test on ('Y' '1')
  // right after the execution's messages.
  std::array<SymbolEntry, 1> syms{};
  syms[0].symbol = Symbol8("AAPL");
  syms[0].prior_close = kP100;
  (void)run(sc_.symbols(syms));  // before the first OUCH: the table may be reloaded
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = 900'100}));
  (void)b(enter_msg({.urn = 2, .qty = 100, .price = 900'000}));
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 200, .price = 900'000})),
                   {O(kSessA, acc(t, {1, OS::Sell, 200, "AAPL", 900'000, 3})),
                    O(kSessB, exe(t, 1, 100, 900'100, LFk::Added, 1)), O(kSessA, exe(t, 1, 100, 900'100, LFk::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1)), O(kSessB, exe(t, 2, 100, 900'000, LFk::Added, 2)),
                    O(kSessA, exe(t, 1, 100, 900'000, LFk::Removed, 2)), I(iexe(t, kAAPL, 2, 100, 2)),
                    I(iy(t, kAAPL, "AAPL", '1'))}));
}

TEST_F(Extended, ShortSaleNeedsAKnownRegShoState) {
  std::array<SymbolEntry, 1> syms{};
  syms[0].symbol = Symbol8("AAPL");
  syms[0].regsho = 'x';  // not '0' or '2': unknown
  (void)run(sc_.symbols(syms));
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::SellShort, .qty = 100, .price = kP100})),
                   {O(kSessA, rej(t, 1, RR::RegShoStateNotAvailable))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .side = OS::SellShortExempt, .qty = 100, .price = kP100})),
                   {O(kSessA, acc(t, {2, OS::SellShortExempt, 100, "AAPL", kP100, 1})),
                    I(iadd(t, kAAPL, 1, Side::Sell, 100, "AAPL", kP100))}));
}

}  // namespace
}  // namespace lle::engine::testing

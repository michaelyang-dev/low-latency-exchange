// Golden scenarios for the matching engine (05-matching-engine §3-§4, T02).
//
// Every expected message is written out field by field with hand-computed
// values (exchange references, match numbers, quantities, prices, flags,
// timestamps); SimpleRestRawBytes additionally spells out the exact wire
// bytes from the OUCH 5.0 and ITCH 5.0 layout tables. The fixture's sink
// checks every emitted ITCH message with the strict ITCH validator and every
// OUCH message with ouch50::validate_outbound.
//
// Fixture: AAPL (locate 1, tick $0.01), MSFT (2), HALF (3, tick $0.005);
// account A = 100 (firms FIRM [default], FRM2) on sessions 1 and 3 (session 3
// cancels post-only orders instead of sliding and disallows market orders);
// account B = 200 (firm OTHR) on session 2. Records are 1 us apart from 09:30.
#include <gtest/gtest.h>

#include "golden_builders.h"

namespace lle::engine::testing {
namespace {

using Golden = EngineFixture;

// ---------------------------------------------------------------- simple rest
TEST_F(Golden, SimpleRestRawBytes) {
  // 09:30:00 + 4 us (four setup records) = 34,200,000,004,000 ns = 0x1F1ACED9FFA0.
  ASSERT_EQ(ts(), 34'200'000'004'000u);
  const auto o = a(enter_msg({.urn = 1, .qty = 100, .price = kP100, .cl_ord_id = "ORD1"}));
  // OUCH 5.0 s3.2 Order Accepted: A | ts u64 | UserRefNum | Side | Quantity | Symbol(8) | Price u64
  // | TIF | Display | OrderRef u64 | Capacity | ISO | CrossType | OrderState | ClOrdID(14) | AppLen=0.
  const auto ouch_a = unhex(
      "41 00001f1aced9ffa0 00000001 42 00000064 4141504c20202020 00000000000f4240 30 59 0000000000000001"
      " 41 4e 4e 4c 4f524431202020202020202020 20 0000");
  // ITCH 5.0 1.3.1 Add Order: A | locate | tracking | ts(6) | ref | side | shares | stock | price(4).
  const auto itch_a = unhex("41 0001 0000 1f1aced9ffa0 0000000000000001 42 00000064 4141504c20202020 000f4240");
  ASSERT_EQ(ouch_a.size(), 64u);
  ASSERT_EQ(itch_a.size(), 36u);
  EXPECT_TRUE(same(o, {O(kSessA, ouch_a), I(itch_a)}));
}

TEST_F(Golden, SimpleRestHiddenAndAttributed) {
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 300, .price = kP100, .display = DSP::Hidden})),
                   {O(kSessA, acc(t, {1, OS::Sell, 300, "AAPL", kP100, 1, true, TIF::Day, DSP::Hidden}))}));
  t = ts();
  EXPECT_TRUE(
      same(a(enter_msg({.urn = 2, .side = OS::Sell, .qty = 200, .price = 1'000'100, .display = DSP::Attributable})),
           {O(kSessA, acc(t, {2, OS::Sell, 200, "AAPL", 1'000'100, 2, true, TIF::Day, DSP::Attributable})),
            I(iaddf(t, kAAPL, 2, Side::Sell, 200, "AAPL", 1'000'100, "FIRM"))}));
}

// ---------------------------------------------------------------- fills
TEST_F(Golden, FullAndPartialFillsAcrossLevels) {
  for (UserRefNum u = 1; u <= 3; ++u)
    (void)b(enter_msg({.urn = u, .side = OS::Sell, .qty = 100 * u, .price = kP100 + 100 * u}));  // refs 1..3
  auto t = ts();
  // Buy 250 @100.02: 100 @100.01 (ref 1, match 1), 150 @100.02 (ref 2, match 2); nothing rests.
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 250, .price = 1'000'200})),
                   {O(kSessA, acc(t, {1, OS::Buy, 250, "AAPL", 1'000'200, 4})),
                    O(kSessB, exe(t, 1, 100, 1'000'100, LF::Added, 1)), O(kSessA, exe(t, 1, 100, 1'000'100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1)), O(kSessB, exe(t, 2, 150, 1'000'200, LF::Added, 2)),
                    O(kSessA, exe(t, 1, 150, 1'000'200, LF::Removed, 2)), I(iexe(t, kAAPL, 2, 150, 2))}));
  t = ts();
  // Buy 100 @100.05: the 50 left on ref 2, then 50 of ref 3; the buy is fully filled.
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 100, .price = 1'000'500})),
                   {O(kSessA, acc(t, {2, OS::Buy, 100, "AAPL", 1'000'500, 5})),
                    O(kSessB, exe(t, 2, 50, 1'000'200, LF::Added, 3)), O(kSessA, exe(t, 2, 50, 1'000'200, LF::Removed, 3)),
                    I(iexe(t, kAAPL, 2, 50, 3)), O(kSessB, exe(t, 3, 50, 1'000'300, LF::Added, 4)),
                    O(kSessA, exe(t, 2, 50, 1'000'300, LF::Removed, 4)), I(iexe(t, kAAPL, 3, 50, 4))}));
  t = ts();
  // Sell side partial: buy 400 @100.03 takes the remaining 250 of ref 3 and rests 150.
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .qty = 400, .price = 1'000'300})),
                   {O(kSessA, acc(t, {3, OS::Buy, 400, "AAPL", 1'000'300, 6})),
                    O(kSessB, exe(t, 3, 250, 1'000'300, LF::Added, 5)), O(kSessA, exe(t, 3, 250, 1'000'300, LF::Removed, 5)),
                    I(iexe(t, kAAPL, 3, 250, 5)), I(iadd(t, kAAPL, 6, Side::Buy, 150, "AAPL", 1'000'300))}));
  EXPECT_EQ(eng_.live_orders(), 1u);
}

TEST_F(Golden, HiddenVersusDisplayedPriority) {
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100, .display = DSP::Hidden}));      // ref 1
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = kP100}));                             // ref 2
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .price = 999'900, .display = DSP::Hidden}));  // ref 3
  const auto t = ts();
  // Price first (hidden @99.99), then displayed before the earlier hidden order at $100.00.
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 250, .price = kP100})),
                   {O(kSessA, acc(t, {1, OS::Buy, 250, "AAPL", kP100, 4})),
                    O(kSessB, exe(t, 3, 100, 999'900, LF::NonDisplayedAdded, 1)),
                    O(kSessA, exe(t, 1, 100, 999'900, LF::Removed, 1)), I(itrade(t, kAAPL, 100, "AAPL", 999'900, 1)),
                    O(kSessB, exe(t, 2, 100, kP100, LF::Added, 2)), O(kSessA, exe(t, 1, 100, kP100, LF::Removed, 2)),
                    I(iexe(t, kAAPL, 2, 100, 2)), O(kSessB, exe(t, 1, 50, kP100, LF::NonDisplayedAdded, 3)),
                    O(kSessA, exe(t, 1, 50, kP100, LF::Removed, 3)), I(itrade(t, kAAPL, 50, "AAPL", kP100, 3))}));
}

TEST_F(Golden, IocRemainderCancels) {
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}));
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 300, .price = kP100, .tif = TIF::Ioc})),
                   {O(kSessA, acc(t, {1, OS::Buy, 300, "AAPL", kP100, 2, true, TIF::Ioc})),
                    O(kSessB, exe(t, 1, 100, kP100, LF::Added, 1)), O(kSessA, exe(t, 1, 100, kP100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1)), O(kSessA, can(t, 1, 200, CR::ImmediateOrCancel))}));
  // Nothing to match: accepted dead ('D') and nothing more (OUCH 5.0 §3.2: "no additional
  // messages will be received for that order"), no ITCH either.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 300, .price = kP100, .tif = TIF::Ioc})),
                   {O(kSessA, acc(t, {2, OS::Buy, 300, "AAPL", kP100, 3, false, TIF::Ioc}))}));
}

TEST_F(Golden, MarketOrderCollar) {
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}));      // ref 1
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'040'000}));  // ref 2 @104.00
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .price = 1'060'000}));  // ref 3 @106.00
  // Reference = best offer $100.00; collar = max($0.25, 5%) = $5.00 -> buys up to $105.00.
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 300, .price = ouch50::kMarketPrice, .tif = TIF::Ioc})),
                   {O(kSessA, acc(t, {1, OS::Buy, 300, "AAPL", ouch50::kMarketPrice, 4, true, TIF::Ioc})),
                    O(kSessB, exe(t, 1, 100, kP100, LF::Added, 1)), O(kSessA, exe(t, 1, 100, kP100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 100, 1)), O(kSessB, exe(t, 2, 100, 1'040'000, LF::Added, 2)),
                    O(kSessA, exe(t, 1, 100, 1'040'000, LF::Removed, 2)), I(iexe(t, kAAPL, 2, 100, 2)),
                    O(kSessA, can(t, 1, 100, CR::MarketCollars))}));
  // A market sell with no bids: accepted dead, and that is all. ($200,000 also means market.)
  t = ts();
  EXPECT_TRUE(
      same(a(enter_msg({.urn = 2, .side = OS::Sell, .qty = 50, .price = ouch50::kMarketPriceAlt, .tif = TIF::Ioc})),
           {O(kSessA, acc(t, {2, OS::Sell, 50, "AAPL", ouch50::kMarketPriceAlt, 5, false, TIF::Ioc}))}));
}

// ---------------------------------------------------------------- replace / modify
TEST_F(Golden, ReplaceLosesPriority) {
  (void)a(enter_msg({.urn = 1, .qty = 100, .price = kP100}));  // ref 1
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = kP100}));  // ref 2
  auto t = ts();
  // Same price and size: new reference 3, back of the queue, ITCH 'U'.
  EXPECT_TRUE(same(a(replace_msg({.orig = 1, .urn = 2, .qty = 100, .price = kP100})),
                   {O(kSessA, rpl(t, {1, 2, OS::Buy, 100, "AAPL", kP100, 3})), I(irep(t, kAAPL, 1, 3, 100, kP100))}));
  t = ts();
  // A seller now meets B's order (ref 2) first.
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = kP100})),
                   {O(kSessB, acc(t, {2, OS::Sell, 100, "AAPL", kP100, 4})),
                    O(kSessB, exe(t, 1, 100, kP100, LF::Added, 1)), O(kSessB, exe(t, 2, 100, kP100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 2, 100, 1))}));
  // Replace aimed at the dead original (UserRefNum 1): ignored, UserRefNum 9 not consumed.
  EXPECT_TRUE(same(a(replace_msg({.orig = 1, .urn = 9, .qty = 100, .price = kP100})), {}));
  // Marketable replace: original deleted on ITCH first, executions, remainder added fresh.
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 40, .price = 1'000'100}));  // ref 5
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 2, .urn = 9, .qty = 100, .price = 1'000'100})),
                   {O(kSessA, rpl(t, {2, 9, OS::Buy, 100, "AAPL", 1'000'100, 6})), I(idel(t, kAAPL, 3)),
                    O(kSessB, exe(t, 3, 40, 1'000'100, LF::Added, 2)), O(kSessA, exe(t, 9, 40, 1'000'100, LF::Removed, 2)),
                    I(iexe(t, kAAPL, 5, 40, 2)), I(iadd(t, kAAPL, 6, Side::Buy, 60, "AAPL", 1'000'100))}));
  // Replace quantity is the total liable over the chain: 100 with 40 executed -> 60 open...
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 9, .urn = 10, .qty = 100, .price = kP100})),
                   {O(kSessA, rpl(t, {9, 10, OS::Buy, 60, "AAPL", kP100, 7})), I(irep(t, kAAPL, 6, 7, 60, kP100))}));
  // ...and 30 (< 40 executed) leaves nothing: replaced dead, original deleted.
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 10, .urn = 11, .qty = 30, .price = kP100})),
                   {O(kSessA, rpl(t, {10, 11, OS::Buy, 0, "AAPL", kP100, 8, false})), I(idel(t, kAAPL, 7))}));
  EXPECT_EQ(eng_.live_orders(), 0u);
}

// OUCH 5.0 §3.2: "when the Order State field of an Accepted Message is Order Dead ('D'), no
// additional messages will be received for that order"; §3.3 says the same of a Replaced
// Message. A dead order never reaches the ITCH feed either.
TEST_F(Golden, OrderDeadIsTheLastMessage) {
  const auto audited_only = [](const std::vector<Msg>& v) { return v.size() == 1 && v[0].dest == Dest::Audit; };
  // An IOC with nothing to match: 'A' Dead, and requests for it find no order.
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 100, .price = kP100, .tif = TIF::Ioc})),
                   {O(kSessA, acc(t, {1, OS::Buy, 100, "AAPL", kP100, 1, false, TIF::Ioc}))}));
  EXPECT_TRUE(audited_only(a(cancel_msg(1, 0))));
  EXPECT_TRUE(audited_only(a(modify_msg(1, OS::Buy, 50))));
  // A resting order replaced by an IOC that cannot execute: 'U' Dead and the original's ITCH
  // 'D'; no 'C', and neither UserRefNum names an order afterwards.
  (void)a(enter_msg({.urn = 2, .qty = 100, .price = 990'000}));  // ref 2 @99.00
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 2, .urn = 3, .qty = 100, .price = 990'000, .tif = TIF::Ioc})),
                   {O(kSessA, rpl(t, {2, 3, OS::Buy, 100, "AAPL", 990'000, 3, false, TIF::Ioc})),
                    I(idel(t, kAAPL, 2))}));
  EXPECT_TRUE(audited_only(a(cancel_msg(3, 0))));
  EXPECT_TRUE(audited_only(a(cancel_msg(2, 0))));
  // Cancel-newest self-match: the aggressor dies on arrival, the resting order is untouched.
  (void)a(enter_msg({.urn = 4, .side = OS::Sell, .qty = 100, .price = 1'000'100}, aiq_tag('W')));  // ref 4
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 100, .price = 1'000'100}, aiq_tag('W'))),
                   {O(kSessA, acc(t, {5, OS::Buy, 100, "AAPL", 1'000'100, 5, false}, aiq_tag('W')))}));
  EXPECT_TRUE(audited_only(a(cancel_msg(5, 0))));
  EXPECT_EQ(eng_.live_orders(), 1u);
}

TEST_F(Golden, ReplaceWithInvalidDetailsCancelsOriginal) {
  (void)a(enter_msg({.urn = 1, .qty = 100, .price = kP100}));  // ref 1
  const auto t = ts();
  // $100.005 is off the $0.01 grid: the original is cancelled; UserRefNum 2 is not consumed.
  EXPECT_TRUE(same(a(replace_msg({.orig = 1, .urn = 2, .qty = 100, .price = 1'000'050})),
                   {O(kSessA, can(t, 1, 100, CR::UserRequested)), I(idel(t, kAAPL, 1))}));
  const auto t2 = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 10, .price = kP100})),
                   {O(kSessA, acc(t2, {2, OS::Buy, 10, "AAPL", kP100, 2})),
                    I(iadd(t2, kAAPL, 2, Side::Buy, 10, "AAPL", kP100))}));
}

TEST_F(Golden, ModifyKeepsPriority) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 200, .price = kP100}));  // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}));  // ref 2
  auto t = ts();
  // Re-mark S -> T (short) and cut to 150: priority kept, ITCH 'X' 50.
  out::OrderModified m{};
  m.user_ref_num = 1;
  m.side = OS::SellShort;
  m.quantity = 150;
  EXPECT_TRUE(same(a(modify_msg(1, OS::SellShort, 150)), {O(kSessA, ouch_out(m, t)), I(ixcl(t, kAAPL, 1, 50))}));
  // An increase is ignored, as is a Buy re-mark.
  EXPECT_TRUE(same(a(modify_msg(1, OS::SellShort, 500)), {}));
  EXPECT_TRUE(same(a(modify_msg(1, OS::Buy, 100)), {}));
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .qty = 150, .price = kP100})),
                   {O(kSessB, acc(t, {2, OS::Buy, 150, "AAPL", kP100, 3})),
                    O(kSessA, exe(t, 1, 150, kP100, LF::Added, 1)), O(kSessB, exe(t, 2, 150, kP100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 150, 1))}));
}

TEST_F(Golden, CancelIntendedSize) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 500, .price = kP100}));  // ref 1
  (void)b(enter_msg({.urn = 1, .qty = 200, .price = kP100}));                    // fills 200; 300 left
  auto t = ts();
  // Intended size 400 includes the 200 executed: 200 may still trade, so 100 go.
  EXPECT_TRUE(same(a(cancel_msg(1, 400)), {O(kSessA, can(t, 1, 100, CR::UserRequested)), I(ixcl(t, kAAPL, 1, 100))}));
  EXPECT_TRUE(same(a(cancel_msg(1, 400)), {}));  // idempotent resend
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(1, 150)), {O(kSessA, can(t, 1, 200, CR::UserRequested)), I(idel(t, kAAPL, 1))}));
}

// ---------------------------------------------------------------- session-level operations
TEST_F(Golden, MassCancelOrdering) {
  (void)a(enter_msg({.urn = 1, .qty = 100, .price = kP100}));                                    // ref 1 AAPL
  (void)a(enter_msg({.urn = 2, .qty = 100, .symbol = "MSFT", .price = 500'000}));                // ref 2 MSFT
  (void)a(enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .price = 1'010'000, .display = DSP::Hidden}));  // ref 3
  ouch50::TagSet frm2;
  frm2.set_firm(Mpid4("FRM2"));
  (void)a(enter_msg({.urn = 4, .qty = 100, .price = 990'000}, frm2));  // ref 4, other firm
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = 990'000}));        // ref 5, other account
  const auto t = ts();
  out::MassCancelResponse x{};
  x.user_ref_num = 5;
  x.firm = Mpid4("FIRM");
  EXPECT_TRUE(same(a(mass_cancel_msg(5, "FIRM")),
                   {O(kSessA, ouch_out(x, t)), O(kSessA, can(t, 1, 100, CR::UserRequested)), I(idel(t, kAAPL, 1)),
                    O(kSessA, can(t, 2, 100, CR::UserRequested)), I(idel(t, kMSFT, 2)),
                    O(kSessA, can(t, 3, 100, CR::UserRequested))}));
  EXPECT_EQ(eng_.live_orders(), 2u);
  // Symbol filter.
  const auto t2 = ts();
  out::MassCancelResponse x2{};
  x2.user_ref_num = 6;
  x2.firm = Mpid4("FRM2");
  x2.symbol = Symbol8("AAPL");
  EXPECT_TRUE(same(a(mass_cancel_msg(6, "FRM2", "AAPL")),
                   {O(kSessA, ouch_out(x2, t2)), O(kSessA, can(t2, 4, 100, CR::UserRequested)), I(idel(t2, kAAPL, 4))}));
}

TEST_F(Golden, DisableEnableOrderEntry) {
  (void)a(enter_msg({.urn = 1, .qty = 100, .price = kP100}));  // ref 1
  auto t = ts();
  out::DisableOrderEntryResponse g{};
  g.user_ref_num = 2;
  g.firm = Mpid4("FIRM");
  EXPECT_TRUE(same(a(disable_msg(2, "FIRM")), {O(kSessA, ouch_out(g, t))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .qty = 100, .price = kP100, .cl_ord_id = "BLOCKED"})),
                   {O(kSessA, rej(t, 3, RR::FirmNotAuthorized, "BLOCKED"))}));
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 1, .urn = 4, .qty = 100, .price = 990'000})),
                   {O(kSessA, rej(t, 4, RR::FirmNotAuthorized))}));
  // The other firm of the account is unaffected; cancels still work.
  ouch50::TagSet frm2;
  frm2.set_firm(Mpid4("FRM2"));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 10, .price = 990'000}, frm2)),
                   {O(kSessA, acc(t, {5, OS::Buy, 10, "AAPL", 990'000, 2}, frm2)),
                    I(iadd(t, kAAPL, 2, Side::Buy, 10, "AAPL", 990'000))}));
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(1, 0)), {O(kSessA, can(t, 1, 100, CR::UserRequested)), I(idel(t, kAAPL, 1))}));
  t = ts();
  out::EnableOrderEntryResponse k{};
  k.user_ref_num = 6;
  k.firm = Mpid4("FIRM");
  EXPECT_TRUE(same(a(enable_msg(6, "FIRM")), {O(kSessA, ouch_out(k, t))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 7, .qty = 100, .price = kP100})),
                   {O(kSessA, acc(t, {7, OS::Buy, 100, "AAPL", kP100, 3})),
                    I(iadd(t, kAAPL, 3, Side::Buy, 100, "AAPL", kP100))}));
}

TEST_F(Golden, AccountQueryAndResendIgnoredWhileCancelWorks) {
  ouch50::TagSet ch7 = tags_idx(7);
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 100, .price = kP100}, ch7)),
                   {O(kSessA, acc(t, {5, OS::Buy, 100, "AAPL", kP100, 1}, ch7)),
                    I(iadd(t, kAAPL, 1, Side::Buy, 100, "AAPL", kP100))}));
  // Benign resend (same UserRefNum on channel 7): ignored silently.
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 100, .price = kP100}, ch7)), {}));
  // Channel 0 is independent: UserRefNum 5 is new there.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 1, .price = 990'000})),
                   {O(kSessA, acc(t, {5, OS::Buy, 1, "AAPL", 990'000, 2})),
                    I(iadd(t, kAAPL, 2, Side::Buy, 1, "AAPL", 990'000))}));
  // Cancels reference the order and are never filtered: partial, then a resend of it is superfluous.
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(5, 60, ch7)), {O(kSessA, can(t, 5, 40, CR::UserRequested, 7)), I(ixcl(t, kAAPL, 1, 40))}));
  EXPECT_TRUE(same(a(cancel_msg(5, 60, ch7)), {}));
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .qty = 100, .price = kP100}, ch7)), {}));
  t = ts();
  out::AccountQueryResponse q{};
  q.next_user_ref_num = 6;
  EXPECT_TRUE(same(a(account_query_msg(ch7)), {O(kSessA, ouch_out(q, t, ch7))}));
  t = ts();
  out::AccountQueryResponse q0{};
  q0.next_user_ref_num = 6;
  EXPECT_TRUE(same(a(account_query_msg()), {O(kSessA, ouch_out(q0, t))}));
}

TEST_F(Golden, CancelOnDisconnect) {
  (void)run(sc_.session_event(kSessA, 0, SessionEventKind::Login));
  (void)run(sc_.session_event(kSessA, 1, SessionEventKind::MirrorAttach));
  (void)a(enter_msg({.urn = 1, .qty = 100, .price = kP100}));                                     // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'010'000}));               // ref 2
  (void)a(enter_msg({.urn = 2, .qty = 50, .price = 990'000, .display = DSP::Hidden}));            // ref 3
  EXPECT_TRUE(same(run(sc_.session_event(kSessA, 0, SessionEventKind::Disconnect)), {}));  // mirror still up
  const auto t = ts();
  EXPECT_TRUE(same(run(sc_.session_event(kSessA, 1, SessionEventKind::InstanceDown)),
                   {O(kSessA, can(t, 1, 100, CR::System)), I(idel(t, kAAPL, 1)), O(kSessA, can(t, 2, 50, CR::System))}));
  EXPECT_EQ(eng_.live_orders(), 1u);
}

// ---------------------------------------------------------------- post-only
TEST_F(Golden, PostOnlySlideAndCancel) {
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'000'100}));  // ref 1 @100.01
  ouch50::TagSet po;
  po.set_post_only(ouch50::PostOnly::PostOnly);
  auto t = ts();
  // Would lock 100.01: slid one tick to 100.00 (accepted price shows the slide).
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 100, .price = 1'000'100}, po)),
                   {O(kSessA, acc(t, {1, OS::Buy, 100, "AAPL", kP100, 2}, po)),
                    I(iadd(t, kAAPL, 2, Side::Buy, 100, "AAPL", kP100))}));
  // Session 3 cancels instead (a contra displayed order): accepted dead, no 'C' follows.
  t = ts();
  EXPECT_TRUE(same(ouch(kSessA2, enter_msg({.urn = 2, .qty = 100, .price = 1'000'200}, po)),
                   {O(kSessA2, acc(t, {2, OS::Buy, 100, "AAPL", 1'000'200, 3, false}, po))}));
  // Only non-displayed contra liquidity: dead as well.
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .symbol = "MSFT", .price = 500'000,
                     .display = DSP::Hidden}));  // ref 4
  t = ts();
  EXPECT_TRUE(same(ouch(kSessA2, enter_msg({.urn = 3, .qty = 100, .symbol = "MSFT", .price = 500'000}, po)),
                   {O(kSessA2, acc(t, {3, OS::Buy, 100, "MSFT", 500'000, 5, false}, po))}));
  // Half-penny tick: a sell crossing a $10.005 bid slides up one $0.005 tick.
  (void)b(enter_msg({.urn = 3, .qty = 100, .symbol = "HALF", .price = 100'050}));  // ref 6
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 4, .side = OS::Sell, .qty = 100, .symbol = "HALF", .price = 100'000}, po)),
                   {O(kSessA, acc(t, {4, OS::Sell, 100, "HALF", 100'100, 7}, po)),
                    I(iadd(t, kHALF, 7, Side::Sell, 100, "HALF", 100'100))}));
}

// ---------------------------------------------------------------- self-match prevention
TEST_F(Golden, SmpDecrementBothNoDetails) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}, aiq_tag('Y')));  // ref 1
  const auto t = ts();
  // Fully decremented with no execution: dead on arrival. The resting order gets its 'C'
  // reason 'Q' (and ITCH 'X'); the dead aggressor gets nothing after its 'A'.
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 60, .price = kP100}, aiq_tag('Y'))),
                   {O(kSessA, acc(t, {2, OS::Buy, 60, "AAPL", kP100, 2, false}, aiq_tag('Y'))),
                    O(kSessA, can(t, 1, 60, CR::SelfMatchPrevention)), I(ixcl(t, kAAPL, 1, 60))}));
}

TEST_F(Golden, SmpDecrementBothWithDetails) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 50, .price = kP100}, aiq_tag('D')));  // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'000'100}));           // ref 2
  const auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 120, .price = 1'000'100}, aiq_tag('D'))),
                   {O(kSessA, acc(t, {2, OS::Buy, 120, "AAPL", 1'000'100, 3}, aiq_tag('D'))),
                    O(kSessA, aiqc(t, 1, 50, kP100, LF::Added, 'D')), O(kSessA, aiqc(t, 2, 50, kP100, LF::Removed, 'D')),
                    I(idel(t, kAAPL, 1)), O(kSessB, exe(t, 1, 70, 1'000'100, LF::Added, 1)),
                    O(kSessA, exe(t, 2, 70, 1'000'100, LF::Removed, 1)), I(iexe(t, kAAPL, 2, 70, 1))}));
}

TEST_F(Golden, SmpCancelOldest) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}, aiq_tag('O')));  // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'000'100}));            // ref 2
  const auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 150, .price = 1'000'100}, aiq_tag('O'))),
                   {O(kSessA, acc(t, {2, OS::Buy, 150, "AAPL", 1'000'100, 3}, aiq_tag('O'))),
                    O(kSessA, can(t, 1, 100, CR::SelfMatchPrevention)), I(idel(t, kAAPL, 1)),
                    O(kSessB, exe(t, 1, 100, 1'000'100, LF::Added, 1)), O(kSessA, exe(t, 2, 100, 1'000'100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 2, 100, 1)), I(iadd(t, kAAPL, 3, Side::Buy, 50, "AAPL", 1'000'100))}));
}

TEST_F(Golden, SmpCancelNewest) {
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}, aiq_tag('W')));  // ref 1
  const auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 100, .price = kP100}, aiq_tag('W'))),
                   {O(kSessA, acc(t, {2, OS::Buy, 100, "AAPL", kP100, 2, false}, aiq_tag('W')))}));
  EXPECT_EQ(eng_.live_orders(), 1u);
}

TEST_F(Golden, SmpFirmVersusMatchAnyLevel) {
  ouch50::TagSet frm2 = aiq_tag('D');
  frm2.set_firm(Mpid4("FRM2"));
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}, frm2));  // ref 1, firm FRM2
  // Firm level: FIRM vs FRM2 is not a self-match, so it trades.
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 40, .price = kP100}, aiq_tag('D'))),
                   {O(kSessA, acc(t, {2, OS::Buy, 40, "AAPL", kP100, 2}, aiq_tag('D'))),
                    O(kSessA, exe(t, 1, 40, kP100, LF::Added, 1)), O(kSessA, exe(t, 2, 40, kP100, LF::Removed, 1)),
                    I(iexe(t, kAAPL, 1, 40, 1))}));
  // Match-any level ('1', with details): same account, any firm. Fully decremented, so dead:
  // only the resting order gets its 'D'.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .qty = 40, .price = kP100}, aiq_tag('1'))),
                   {O(kSessA, acc(t, {3, OS::Buy, 40, "AAPL", kP100, 3, false}, aiq_tag('1'))),
                    O(kSessA, aiqc(t, 1, 40, kP100, LF::Added, '1')), I(ixcl(t, kAAPL, 1, 40))}));
  // A different account never self-matches.
  t = ts();
  ouch50::TagSet any = aiq_tag('1');
  EXPECT_TRUE(same(b(enter_msg({.urn = 1, .qty = 20, .price = kP100}, any)),
                   {O(kSessB, acc(t, {1, OS::Buy, 20, "AAPL", kP100, 4}, any)),
                    O(kSessA, exe(t, 1, 20, kP100, LF::Added, 2)), O(kSessB, exe(t, 1, 20, kP100, LF::Removed, 2)),
                    I(iexe(t, kAAPL, 1, 20, 2))}));
}

// ---------------------------------------------------------------- state gate
TEST_F(Golden, HaltGateAndOperatorResume) {
  auto t = ts();
  itch50::StockTradingAction h{};
  h.stock = Symbol8("MSFT");
  h.trading_state = itch50::TradingState::Halted;
  h.reserved = ' ';
  h.reason = Alpha<4>("T1");
  EXPECT_TRUE(same(run(sc_.admin(AdminCommand::Halt, AdminArgsBuilder().symbol("MSFT").reason("T1"))),
                   {I(itch_bytes(h, kMSFT, t))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 10, .symbol = "MSFT", .price = 500'000, .tif = TIF::Ioc})),
                   {O(kSessA, rej(t, 2, RR::Halted))}));
  // A Day order rests without matching while halted.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .qty = 10, .symbol = "MSFT", .price = 500'000})),
                   {O(kSessA, acc(t, {3, OS::Buy, 10, "MSFT", 500'000, 1})),
                    I(iadd(t, kMSFT, 1, Side::Buy, 10, "MSFT", 500'000))}));
  // Operator release: the halt cross has nothing to cross (no 'Q'), then H 'T'.
  t = ts();
  h.trading_state = itch50::TradingState::Trading;
  h.reason = Alpha<4>{};
  EXPECT_TRUE(same(run(sc_.admin(AdminCommand::Resume, AdminArgsBuilder().symbol("MSFT"))),
                   {I(itch_bytes(h, kMSFT, t))}));
}

TEST_F(Golden, SystemEventsReachItchAndEverySession) {
  std::vector<ScheduleEntry> sched = params_only('R');
  sched.push_back(ScheduleEntry{1, TimerKind::SystemEvent, 'O', hms_ns(9, 30, 0)});
  sched.push_back(ScheduleEntry{2, TimerKind::SystemEvent, 'Q', hms_ns(9, 30, 1)});
  (void)run(sc_.schedule(sched));
  auto t = static_cast<std::uint64_t>(hms_ns(9, 30, 0) > sc_.now() ? hms_ns(9, 30, 0) : sc_.now());
  itch50::SystemEvent s{};
  s.event_code = itch50::EventCode::StartOfMessages;
  out::SystemEvent o{};
  o.event_code = ouch50::EventCode::StartOfDay;
  EXPECT_TRUE(same(run(sc_.fire(sched[1])),
                   {I(itch_bytes(s, 0, t)), O(kSessA, ouch_out(o, t)), O(kSessB, ouch_out(o, t)), O(kSessA2, ouch_out(o, t))}));
  t = static_cast<std::uint64_t>(hms_ns(9, 30, 1));
  s.event_code = itch50::EventCode::StartOfMarketHours;
  EXPECT_TRUE(same(run(sc_.fire(sched[2])), {I(itch_bytes(s, 0, t))}));
}

// ---------------------------------------------------------------- one test per reachable reject code
struct RejectCase {
  const char* name;
  RR code;
};

class GoldenRejects : public EngineFixture {
 protected:
  void expect_reject(std::span<const std::byte> msg, UserRefNum urn, RR code, std::uint32_t session = kSessA,
                     const char* cl = "") {
    const auto t = ts();
    EXPECT_TRUE(same(ouch(session, msg), {O(session, rej(t, urn, code, cl))})) << "code " << static_cast<int>(code);
  }
};

TEST_F(GoldenRejects, DestinationClosed0x0002AfterHoursForDayOrders) {
  (void)run(sc_.schedule(params_only('A')));  // post-market: market-hours (Day) orders are over
  expect_reject(enter_msg({.urn = 1, .tif = TIF::Day}), 1, RR::DestinationClosed);
}

TEST_F(GoldenRejects, DestinationClosed0x0002OutsideSystemHours) {
  (void)run(sc_.schedule(params_only('C')));  // outside system hours: everything
  expect_reject(enter_msg({.urn = 2, .tif = TIF::Gtx}), 2, RR::DestinationClosed);
}

TEST_F(GoldenRejects, InvalidDisplay0x0003) {
  auto m = enter_msg({.urn = 1, .cl_ord_id = "X1"});
  m[27] = std::byte{'Z'};  // outbound-only value
  expect_reject(m, 1, RR::InvalidDisplay, kSessA, "X1");
}

TEST_F(GoldenRejects, InvalidMaxFloor0x0004) {
  ouch50::TagSet t;
  t.set_max_floor(100);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::InvalidMaxFloor);                         // >= quantity
  ouch50::TagSet odd;
  odd.set_max_floor(50);
  expect_reject(enter_msg({.urn = 2, .qty = 500}, odd), 2, RR::InvalidMaxFloor);          // < a round lot
  expect_reject(enter_msg({.urn = 3, .qty = 500, .display = DSP::Hidden}, t), 3, RR::InvalidMaxFloor);
  expect_reject(enter_msg({.urn = 4, .qty = 500, .tif = TIF::Ioc}, t), 4, RR::InvalidMaxFloor);
}

TEST_F(GoldenRejects, InvalidPegType0x0005) {
  ouch50::TagSet t;
  t.set_price_type(ouch50::PriceType::PrimaryPeg);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::InvalidPegType);
  ouch50::TagSet off;
  off.set_peg_offset(-100);
  expect_reject(enter_msg({.urn = 2}, off), 2, RR::InvalidPegType);
}

TEST_F(GoldenRejects, Halted0x0007) {
  (void)run(sc_.admin(AdminCommand::Halt, AdminArgsBuilder().symbol("AAPL").reason("H10")));
  expect_reject(enter_msg({.urn = 1, .price = ouch50::kMarketPrice, .tif = TIF::Ioc}), 1, RR::Halted);
}

TEST_F(GoldenRejects, IsoNotAllowed0x0008) {
  expect_reject(enter_msg({.urn = 1, .iso = ouch50::IsoEligibility::Eligible}), 1, RR::IsoNotAllowed);
}

TEST_F(GoldenRejects, InvalidSide0x0009) {
  auto m = enter_msg({.urn = 1});
  m[5] = std::byte{'X'};
  expect_reject(m, 1, RR::InvalidSide);
}

TEST_F(GoldenRejects, FirmNotAuthorized0x000C) {
  ouch50::TagSet t;
  t.set_firm(Mpid4("OTHR"));  // account B's firm
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::FirmNotAuthorized);
  expect_reject(disable_msg(2, "NOPE"), 2, RR::FirmNotAuthorized);
}

TEST_F(GoldenRejects, InvalidMinQuantity0x000D) {
  ouch50::TagSet t;
  t.set_min_qty(50);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::InvalidMinQuantity);  // < a round lot
  ouch50::TagSet big;
  big.set_min_qty(200);
  expect_reject(enter_msg({.urn = 2}, big), 2, RR::InvalidMinQuantity);  // > quantity
  ouch50::TagSet po;
  po.set_min_qty(100);
  po.set_post_only(ouch50::PostOnly::PostOnly);
  expect_reject(enter_msg({.urn = 3}, po), 3, RR::InvalidMinQuantity);
}

TEST_F(GoldenRejects, Other0x000F) {
  ouch50::TagSet t;
  t.set_discretion_price(990'000);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::Other);
  ouch50::TagSet po;
  po.set_post_only(ouch50::PostOnly::PostOnly);
  expect_reject(enter_msg({.urn = 2, .tif = TIF::Ioc}, po), 2, RR::Other);  // post-only IOC
  expect_reject(enter_msg({.urn = 3, .tif = TIF::Gtt}), 3, RR::Other);       // GTT without ExpireTime
  auto bad = enter_msg({.urn = 4});
  bad.push_back(std::byte{0});  // half an element: malformed appendage
  expect_reject(bad, 4, RR::Other);
}

TEST_F(GoldenRejects, PeggingNotAllowed0x0011) {
  ouch50::TagSet t;
  t.set_price_type(ouch50::PriceType::Midpoint);  // 'm'
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::PeggingNotAllowed);
  ouch50::TagSet m;
  m.set_price_type(ouch50::PriceType::MidpointPeg);
  expect_reject(enter_msg({.urn = 2, .price = ouch50::kMarketPrice, .tif = TIF::Ioc}, m), 2, RR::PeggingNotAllowed);
}

TEST_F(GoldenRejects, InvalidQuantity0x0013) {
  expect_reject(enter_msg({.urn = 1, .qty = 0}), 1, RR::InvalidQuantity);
  expect_reject(enter_msg({.urn = 2, .qty = 1'000'000}), 2, RR::InvalidQuantity);
}

TEST_F(GoldenRejects, InvalidCrossOrder0x0014) {
  expect_reject(enter_msg({.urn = 1, .cross = ouch50::CrossType::Opening}), 1, RR::InvalidCrossOrder);
  ouch50::TagSet t;
  t.set_handle_inst(ouch50::HandleInst::ImbalanceOnly);
  expect_reject(enter_msg({.urn = 2}, t), 2, RR::InvalidCrossOrder);
}

TEST_F(GoldenRejects, InvalidSymbol0x0017) {
  expect_reject(enter_msg({.urn = 1, .symbol = "NOPE"}), 1, RR::InvalidSymbol);
  expect_reject(mass_cancel_msg(2, "FIRM", "NOPE"), 2, RR::InvalidSymbol);
}

TEST_F(GoldenRejects, RetailNotAllowed0x001A) {
  ouch50::TagSet t;
  t.set_customer_type(ouch50::CustomerType::RetailDesignated);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::RetailNotAllowed);
}

TEST_F(GoldenRejects, InvalidMidpointPostOnlyPrice0x001B) {
  ouch50::TagSet t;
  t.set_price_type(ouch50::PriceType::MidpointPeg);
  t.set_post_only(ouch50::PostOnly::PostOnly);
  expect_reject(enter_msg({.urn = 1}, t), 1, RR::InvalidMidpointPostOnlyPrice);
}

TEST_F(GoldenRejects, InvalidPrice0x001D) {
  expect_reject(enter_msg({.urn = 1, .price = 1'000'050}), 1, RR::InvalidPrice);  // off the $0.01 grid
  expect_reject(enter_msg({.urn = 2, .price = ouch50::kMarketPrice}), 2, RR::InvalidPrice);  // market, Day
  expect_reject(enter_msg({.urn = 3, .price = 0}), 3, RR::InvalidPrice);
}

TEST_F(GoldenRejects, MarketOrderNotAllowed0x002C) {
  expect_reject(enter_msg({.urn = 1, .price = ouch50::kMarketPrice, .tif = TIF::Ioc}), 1,
                RR::RiskMarketOrderNotAllowed, kSessA2);
}

TEST_F(GoldenRejects, InvalidAiq0x0040) {
  expect_reject(enter_msg({.urn = 1}, aiq_tag('o')), 1, RR::InvalidAiq);  // organization level
}

TEST_F(GoldenRejects, RejectConsumesUserRefNum) {
  expect_reject(enter_msg({.urn = 7, .symbol = "NOPE"}), 7, RR::InvalidSymbol);
  EXPECT_TRUE(same(a(enter_msg({.urn = 7})), {}));  // a rejected UserRefNum cannot be reused
}

}  // namespace
}  // namespace lle::engine::testing

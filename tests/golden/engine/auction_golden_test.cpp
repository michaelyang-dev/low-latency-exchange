// Golden scenarios for the auction and halt machinery (05 §5, E-07..E-11):
// opening and closing crosses, early market-hours orders, freezes, late
// LOO/LOC handling, price tests, thresholds, the uncross sweep, EOII/NOII,
// news halts with collar extensions, the LULD pause (the FLAT example of R2
// D2.4), IPO release, market-wide circuit breakers and expiry sweeps.
//
// Every expected value is derived by hand from the rules in R2 D2.3-D2.7
// (docs/design/matching-rules.md cites them per rule); the comments show the
// derivation. The sink checks every ITCH message with the strict validator
// and every OUCH message with ouch50::validate_outbound.
//
// Fixture: AAPL (locate 1, prior close $100.00) and MSFT (locate 2, prior
// close $20.00), both on the $0.01 grid. Account A = 100 (firm FIRM) on
// sessions 1 (late cross orders accepted as entered) and 3 (repriced);
// account B = 200 (OTHR) on sessions 2 (accepted) and 4 (rejected). The day
// starts closed; timer 1 at 04:00 opens the pre-market. Short periods keep the
// halt scenarios small: HaltPeriodSec 5, ExtensionSec 3, LuldPauseSec 2,
// LimitStateSec 2, MwcbPeriodSec 3 (the LULD test sets ExtensionSec 1).
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "golden_builders.h"

namespace lle::engine::testing {
namespace {

constexpr std::uint32_t kS1 = 1;  // account A, late cross orders accepted
constexpr std::uint32_t kS2 = 2;  // account B, accepted
constexpr std::uint32_t kS3 = 3;  // account A, repriced
constexpr std::uint32_t kS4 = 4;  // account B, rejected
constexpr std::uint64_t kMkt = ouch50::kMarketPrice;
constexpr Locate kMS = 2;
using CT = ouch50::CrossType;

// Timer ids of the fixture schedule.
enum : std::uint32_t {
  kPreMarket = 1,
  kOpenFreeze,
  kEoiiOpen,
  kMooCutoff,
  kNoiiOpen,
  kLooCutoff,
  kCrossOpen,
  kCloseFreeze,
  kEoiiClose,
  kMocCutoff,
  kNoiiClose,
  kLocCutoff,
  kCrossClose,
  kSweepDay,
  kClock,
  kSweepAll,
  kSystemClose,
};

constexpr std::uint64_t W(Nanos n) { return static_cast<std::uint64_t>(n); }
constexpr Nanos at_s(int h, int m, int s) { return hms_ns(h, m, s); }

class Auction : public ::testing::Test {
 protected:
  void SetUp() override {
    sc_.day_start();
    std::array<SymbolEntry, 2> syms{};
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = prior_[0];
    syms[1].symbol = Symbol8("MSFT");
    syms[1].prior_close = prior_[1];
    std::array<AccountEntry, 2> accts{};
    accts[0].account_id = kAcctA;
    accts[0].firms[0] = Mpid4("FIRM");
    accts[1].account_id = kAcctB;
    accts[1].firms[0] = Mpid4("OTHR");
    constexpr std::uint8_t f = SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders;
    std::array<SessionEntry, 4> sess{};
    sess[0] = SessionEntry{kS1, kAcctA, f, 'N', LateCrossPolicy::Accept};
    sess[1] = SessionEntry{kS2, kAcctB, f, 'N', LateCrossPolicy::Accept};
    sess[2] = SessionEntry{kS3, kAcctA, f, 'N', LateCrossPolicy::Reprice};
    sess[3] = SessionEntry{kS4, kAcctB, f, 'N', LateCrossPolicy::Reject};
    auto entry = [](std::uint32_t id, TimerKind k, std::uint16_t arg, Nanos t) { return ScheduleEntry{id, k, arg, t}; };
    auto mile = [&](std::uint32_t id, Milestone m, Nanos t) {
      return entry(id, TimerKind::StateChange, static_cast<std::uint16_t>(m), t);
    };
    sched_ = {
        mile(kPreMarket, Milestone::PreMarket, at_s(4, 0, 0)),
        mile(kOpenFreeze, Milestone::OpenFreeze, at_s(9, 25, 0)),
        entry(kEoiiOpen, TimerKind::Eoii, 'O', at_s(9, 25, 0)),
        mile(kMooCutoff, Milestone::MooCutoff, at_s(9, 28, 0)),
        entry(kNoiiOpen, TimerKind::Noii, 'O', at_s(9, 28, 0)),
        mile(kLooCutoff, Milestone::LooCutoff, at_s(9, 29, 30)),
        entry(kCrossOpen, TimerKind::Cross, 'O', at_s(9, 30, 0)),
        mile(kCloseFreeze, Milestone::CloseFreeze, at_s(15, 50, 0)),
        entry(kEoiiClose, TimerKind::Eoii, 'C', at_s(15, 50, 0)),
        mile(kMocCutoff, Milestone::MocCutoff, at_s(15, 55, 0)),
        entry(kNoiiClose, TimerKind::Noii, 'C', at_s(15, 55, 0)),
        mile(kLocCutoff, Milestone::LocCutoff, at_s(15, 58, 0)),
        entry(kCrossClose, TimerKind::Cross, 'C', at_s(16, 0, 0)),
        entry(kSweepDay, TimerKind::ExpirySweep, 'D', at_s(16, 0, 0)),
        entry(kClock, TimerKind::Noii, 'H', at_s(4, 0, 1)),
        entry(kSweepAll, TimerKind::ExpirySweep, 'X', at_s(20, 0, 0)),
        mile(kSystemClose, Milestone::SystemClose, at_s(20, 0, 0)),
    };
    auto param = [&](Param p, std::int64_t v) {
      ScheduleEntry e;
      e.kind = static_cast<TimerKind>(0);
      e.arg = static_cast<std::uint16_t>(p);
      e.time_ns = v;
      sched_.push_back(e);
    };
    param(Param::InitialSession, 'C');
    param(Param::HaltPeriodSec, 5);
    param(Param::ExtensionSec, extension_sec_);
    param(Param::LuldPauseSec, 2);
    param(Param::LimitStateSec, 2);
    param(Param::MwcbPeriodSec, 3);
    sc_.symbols(syms);
    sc_.accounts(accts);
    sc_.sessions(sess);
    sc_.schedule(sched_);
    for (std::size_t i = 0; i < sc_.size(); ++i) eng_.apply(sc_[i], sink_);
    (void)sink_.take();
    ASSERT_EQ(eng_.session(), Session::Closed);
    EXPECT_TRUE(timer(kPreMarket, at_s(4, 0, 0)).empty());
    ASSERT_EQ(eng_.session(), Session::PreMarket);
  }

  void TearDown() override {
    EXPECT_EQ(sink_.bad(), 0u) << "an emitted message failed ITCH strict or OUCH outbound validation";
    std::string err;
    EXPECT_TRUE(eng_.check(&err)) << err;
  }

  std::vector<Msg> run(const InputRecord& r) {
    eng_.apply(r, sink_);
    return sink_.take();
  }
  std::vector<Msg> ouch(std::uint32_t s, std::span<const std::byte> m) {
    return run(sc_.ouch(s, s == kS2 || s == kS4 ? kAcctB : kAcctA, m));
  }
  std::vector<Msg> a(std::span<const std::byte> m) { return ouch(kS1, m); }
  std::vector<Msg> b(std::span<const std::byte> m) { return ouch(kS2, m); }
  // A Timer record for schedule entry `id`, fired at `t` (ns since midnight).
  std::vector<Msg> timer(std::uint32_t id, Nanos t) {
    const ScheduleEntry* e = nullptr;
    for (const ScheduleEntry& x : sched_)
      if (x.timer_id == id) e = &x;
    sc_.set_time(t);
    return run(sc_.add(RecordType::Timer, encode_timer(TimerRecord{id, e->kind, sc_.midnight() + t})));
  }
  std::vector<Msg> tick(Nanos t) { return timer(kClock, t); }
  std::vector<Msg> admin(AdminCommand c, const AdminArgsBuilder& args) { return run(sc_.admin(c, args)); }
  void at(Nanos t) { sc_.set_time(t); }
  [[nodiscard]] std::uint64_t ts() const { return static_cast<std::uint64_t>(sc_.now()); }
  // The opening cross with an empty book: the zero-share 'Q' for each symbol (match numbers 1, 2).
  void open_market() {
    const auto t = W(at_s(9, 30, 0));
    ASSERT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                     {I(iq(t, kAAPL, "AAPL", 0, 0, 1, 'O')), I(iq(t, kMS, "MSFT", 0, 0, 2, 'O'))}));
    ASSERT_EQ(eng_.session(), Session::Regular);
  }

  std::int64_t extension_sec_ = 3;
  std::array<PxE4, 2> prior_ = {1'000'000, 200'000};
  Scenario sc_{Scenario::kMidnight, at_s(3, 59, 0)};
  std::vector<ScheduleEntry> sched_;
  Engine eng_;
  CheckingSink sink_;
};

ouch50::TagSet imbalance_only() {
  ouch50::TagSet t;
  t.set_handle_inst(ouch50::HandleInst::ImbalanceOnly);
  return t;
}

// ---------------------------------------------------------------- opening cross

TEST_F(Auction, OpeningCrossWithHeldAndBookOrders) {
  at(at_s(9, 0, 0));
  // Pre-market: GTX orders trade and display; Day orders are held for the open (no ITCH).
  auto t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'001'000, .tif = TIF::Gtx})),
                   {O(kS2, acc(t, {1, OS::Sell, 100, "AAPL", 1'001'000, 1, true, TIF::Gtx})),
                    I(iadd(t, kAAPL, 1, Side::Sell, 100, "AAPL", 1'001'000))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 999'000, .tif = TIF::Gtx})),
                   {O(kS1, acc(t, {1, OS::Buy, 100, "AAPL", 999'000, 2, true, TIF::Gtx})),
                    I(iadd(t, kAAPL, 2, Side::Buy, 100, "AAPL", 999'000))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 300, .price = kMkt, .cross = CT::Opening})),
                   {O(kS1, acc(t, {2, OS::Buy, 300, "AAPL", kMkt, 3, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 200, .price = 999'500, .cross = CT::Opening})),
                   {O(kS2, acc(t, {2, OS::Sell, 200, "AAPL", 999'500, 4, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 200, .price = 1'000'500})),
                   {O(kS2, acc(t, {3, OS::Sell, 200, "AAPL", 1'000'500, 5}))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .side = OS::Buy, .qty = 100, .price = 1'000'000})),
                   {O(kS1, acc(t, {3, OS::Buy, 100, "AAPL", 1'000'000, 6}))}));
  t = ts();
  EXPECT_TRUE(
      same(b(enter_msg({.urn = 4, .side = OS::Sell, .qty = 300, .price = 990'000, .cross = CT::Opening}, imbalance_only())),
           {O(kS2, acc(t, {4, OS::Sell, 300, "AAPL", 990'000, 7, true, TIF::Day, DSP::Visible, "", CT::Opening},
                       imbalance_only()))}));

  // 09:30. Bid 99.90 / offer 100.10: midpoint 100.00, threshold max(10%, $0.50) = $10 -> [89.90, 110.10].
  // The OIO sell is priced at the offer, 100.10. Volume by price:
  //   99.95: buys 300 MOO + 100 held = 400, sells 200 LOO -> 200
  //   100.05: buys 300, sells 200 LOO + 200 held -> 300, imbalance 100 S (cross-order sells 400)
  //   100.10: buys 300, sells 500 + 300 OIO -> 300, imbalance 100 S
  // A: 100.05 and 100.10 (and the threshold price 110.10) tie; B ties; C: shares remain at the
  // entered prices 100.05 and 100.10; D: 100.05 is nearest the midpoint. Price test A passes.
  // Allocation: MOO by time; then sells by price: LOO 200 @99.95, held 100 of 200 @100.05.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, exe(T, 2, 200, 1'000'500, LF::OpeningCross, 1)),
                    O(kS2, exe(T, 2, 200, 1'000'500, LF::OpeningCross, 1)),
                    O(kS1, exe(T, 2, 100, 1'000'500, LF::OpeningCross, 2)),
                    O(kS2, exe(T, 3, 100, 1'000'500, LF::OpeningCross, 2)),
                    I(iq(T, kAAPL, "AAPL", 300, 1'000'500, 3, 'O')),
                    // Unexecuted on-open orders cancel; held orders join the book at the cross time.
                    O(kS2, can(T, 4, 300, CR::ImmediateOrCancel)),
                    I(iadd(T, kAAPL, 5, Side::Sell, 100, "AAPL", 1'000'500)),
                    I(iadd(T, kAAPL, 6, Side::Buy, 100, "AAPL", 1'000'000)),
                    I(iq(T, kMS, "MSFT", 0, 0, 4, 'O'))}));
  EXPECT_EQ(eng_.session(), Session::Regular);
  EXPECT_EQ(eng_.live_orders(), 4u);
}

TEST_F(Auction, OpeningImbalanceIndicators) {
  at(at_s(9, 0, 0));
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'002'000, .tif = TIF::Gtx}));  // ref 1
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 998'000, .tif = TIF::Gtx}));     // ref 2
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 500, .price = kMkt, .cross = CT::Opening}));    // ref 3
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 300, .price = 995'000, .cross = CT::Opening}));  // ref 4
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .price = 1'015'000, .cross = CT::Opening}));  // ref 5
  (void)b(enter_msg({.urn = 4, .side = OS::Sell, .qty = 200, .price = 1'003'000, .tif = TIF::Gtx}));  // ref 6
  EXPECT_TRUE(timer(kOpenFreeze, at_s(9, 25, 0)).empty());

  // EOII: only the CRP, within the Nasdaq BBO [99.80, 100.20]:
  //   99.80: buys 600, sells 300 -> 300 (imbalance 200 B); 100.00: 300 (200 B); 100.20: 400 (100 B).
  // Far and Near are 0 and the PVI blank; MSFT has no interest: 'O' and zeros.
  auto t = ts();
  EXPECT_TRUE(same(timer(kEoiiOpen, at_s(9, 25, 0)),
                   {I(inoii(t, kAAPL, "AAPL", {400, 100, 'B', 0, 0, 1'002'000, 'O', ' '})),
                    I(inoii(t, kMS, "MSFT", {0, 0, 'O', 0, 0, 0, 'O', ' '}))}));
  EXPECT_TRUE(timer(kMooCutoff, at_s(9, 28, 0)).empty());

  // NOII. Near (book + cross orders, threshold [89.80, 110.20]): 100.30 and 101.50 pair 500 with
  // no imbalance; shares remain at the entered price 100.30 (step C) and it is nearest the
  // midpoint -> 100.30. Far (cross orders only): 101.50 pairs 400 (100 B) -> 101.50.
  // PVI: |100.30 - 100.20| / 100.30 < 1% -> 'L'.
  t = ts();
  EXPECT_TRUE(same(timer(kNoiiOpen, at_s(9, 28, 0)),
                   {I(inoii(t, kAAPL, "AAPL", {400, 100, 'B', 1'015'000, 1'003'000, 1'002'000, 'O', 'L'})),
                    I(inoii(t, kMS, "MSFT", {0, 0, 'O', 0, 0, 0, 'O', ' '}))}));
  EXPECT_TRUE(timer(kLooCutoff, at_s(9, 29, 30)).empty());

  // The cross at Near (100.30, 500 shares): MOO by time against the sells by price: LOO 300
  // @99.50, the displayed 100 @100.20 and 100 of 200 @100.30. Book orders print 'C'
  // Printable=N; the LOO @101.50 is unexecuted and cancels.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, exe(T, 2, 300, 1'003'000, LF::OpeningCross, 1)),
                    O(kS2, exe(T, 2, 300, 1'003'000, LF::OpeningCross, 1)),
                    O(kS1, exe(T, 2, 100, 1'003'000, LF::OpeningCross, 2)),
                    O(kS2, exe(T, 1, 100, 1'003'000, LF::OpeningCross, 2)),
                    I(ixc(T, kAAPL, 1, 100, 2, 1'003'000)),
                    O(kS1, exe(T, 2, 100, 1'003'000, LF::OpeningCross, 3)),
                    O(kS2, exe(T, 4, 100, 1'003'000, LF::OpeningCross, 3)),
                    I(ixc(T, kAAPL, 6, 100, 3, 1'003'000)),
                    I(iq(T, kAAPL, "AAPL", 500, 1'003'000, 4, 'O')),
                    O(kS2, can(T, 3, 100, CR::ImmediateOrCancel)),
                    I(iq(T, kMS, "MSFT", 0, 0, 5, 'O'))}));
}

TEST_F(Auction, OpenFreezeCancelPendingAndReplaceReject) {
  at(at_s(9, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));    // ref 1
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = 990'000, .cross = CT::Opening}));  // ref 2
  (void)a(enter_msg({.urn = 3, .side = OS::Buy, .qty = 100, .price = 980'000}));                       // ref 3, held
  (void)a(enter_msg({.urn = 4, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));    // ref 4
  // Before the freeze a cancel is immediate.
  auto t = ts();
  EXPECT_TRUE(same(a(cancel_msg(4, 0)), {O(kS1, can(t, 4, 100, CR::UserRequested))}));
  EXPECT_TRUE(timer(kOpenFreeze, at_s(9, 25, 0)).empty());

  // During the freeze: a full cancel gets 'P' Cancel Pending (once), a partial cancel 'I'
  // Cancel Reject, a replace 'J' 0x0015 (the new UserRefNum is consumed); held orders too.
  at(at_s(9, 26, 0));
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(1, 0)), {O(kS1, pend(t, 1))}));
  EXPECT_TRUE(same(a(cancel_msg(1, 0)), {}));
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(2, 50)), {O(kS1, crej(t, 2))}));
  t = ts();
  EXPECT_TRUE(same(a(replace_msg({.orig = 3, .urn = 5, .qty = 100, .price = 985'000})),
                   {O(kS1, rej(t, 5, RR::ReplaceNotAllowed))}));
  t = ts();
  EXPECT_TRUE(same(a(cancel_msg(3, 0)), {O(kS1, pend(t, 3))}));

  // No sell interest: nothing crosses, the zero-share 'Q'. The pending cancels complete with
  // reason 'U'; the LOO is unexecuted ('I').
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {I(iq(T, kAAPL, "AAPL", 0, 0, 1, 'O')), O(kS1, can(T, 1, 100, CR::UserRequested)),
                    O(kS1, can(T, 2, 100, CR::ImmediateOrCancel)), O(kS1, can(T, 3, 100, CR::UserRequested)),
                    I(iq(T, kMS, "MSFT", 0, 0, 2, 'O'))}));
  EXPECT_EQ(eng_.live_orders(), 0u);
}

TEST_F(Auction, LateLimitOnOpenOrders) {
  at(at_s(9, 0, 0));
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'005'000, .cross = CT::Opening}));  // ref 1
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 300, .price = kMkt, .cross = CT::Opening}));       // ref 2
  EXPECT_TRUE(timer(kOpenFreeze, at_s(9, 25, 0)).empty());
  // 09:28: the CRP (no BBO, reference = prior close 100.00): 100.50 pairs 100 -> second reference 100.50.
  EXPECT_TRUE(timer(kMooCutoff, at_s(9, 28, 0)).empty());
  // Late LOO reference: buys max(100.00, 100.50) = 100.50, sells min = 100.00. UserRefNums
  // increase per account (OUCH 5.0 §1.2), across its sessions.
  at(at_s(9, 28, 10));
  auto t = ts();
  EXPECT_TRUE(same(ouch(kS3, enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = 1'010'000, .cross = CT::Opening})),
                   {O(kS3, acc(t, {2, OS::Buy, 100, "AAPL", 1'005'000, 3, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  t = ts();
  EXPECT_TRUE(same(ouch(kS4, enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 990'000, .cross = CT::Opening})),
                   {O(kS4, rej(t, 2, RR::LateLocTooAggressive))}));
  t = ts();
  EXPECT_TRUE(same(ouch(kS4, enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .price = 1'002'000, .cross = CT::Opening})),
                   {O(kS4, acc(t, {3, OS::Sell, 100, "AAPL", 1'002'000, 4, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .side = OS::Buy, .qty = 100, .price = 1'050'000, .cross = CT::Opening})),
                   {O(kS1, acc(t, {3, OS::Buy, 100, "AAPL", 1'050'000, 5, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  t = ts();
  EXPECT_TRUE(same(ouch(kS3, enter_msg({.urn = 4, .side = OS::Sell, .qty = 100, .price = 990'000, .cross = CT::Opening})),
                   {O(kS3, acc(t, {4, OS::Sell, 100, "AAPL", 1'000'000, 6, true, TIF::Day, DSP::Visible, "", CT::Opening}))}));
  // MOO entry closed at 09:28, LOO entry at 09:29:30.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening})),
                   {O(kS1, rej(t, 5, RR::InvalidCrossOrder))}));
  EXPECT_TRUE(timer(kLooCutoff, at_s(9, 29, 30)).empty());
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 6, .side = OS::Buy, .qty = 100, .price = 1'000'000, .cross = CT::Opening})),
                   {O(kS1, rej(t, 6, RR::InvalidCrossOrder))}));

  // The cross. Buys: MOO 300, LOO 100 @100.50 (repriced), LOO 100 @105.00; sells: 100 @100.00,
  // 100 @100.20, 100 @100.50. Volume 300 at 100.50 (imbalance 200 B) and at 105.00 (100 B):
  // step B picks 105.00. The MOO takes all 300; the LOOs are unexecuted.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, exe(T, 1, 100, 1'050'000, LF::OpeningCross, 1)),
                    O(kS3, exe(T, 4, 100, 1'050'000, LF::OpeningCross, 1)),
                    O(kS1, exe(T, 1, 100, 1'050'000, LF::OpeningCross, 2)),
                    O(kS4, exe(T, 3, 100, 1'050'000, LF::OpeningCross, 2)),
                    O(kS1, exe(T, 1, 100, 1'050'000, LF::OpeningCross, 3)),
                    O(kS2, exe(T, 1, 100, 1'050'000, LF::OpeningCross, 3)),
                    I(iq(T, kAAPL, "AAPL", 300, 1'050'000, 4, 'O')),
                    O(kS3, can(T, 2, 100, CR::ImmediateOrCancel)),
                    O(kS1, can(T, 3, 100, CR::ImmediateOrCancel)),
                    I(iq(T, kMS, "MSFT", 0, 0, 5, 'O'))}));
}

TEST_F(Auction, OpeningPriceTestsFail) {
  at(at_s(9, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));      // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'200'000, .cross = CT::Opening}));  // ref 2
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = 950'000}));                         // ref 3, held
  // The cross would be 100 @120.00. Test A: |120 - 100| > max(10% of 100, $0.50); B and C do not
  // apply (no last sale, no BBO). No cross: on-open and held orders cancel 'X', a zero 'Q'.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, can(T, 1, 100, CR::OpenProtection)), O(kS2, can(T, 1, 100, CR::OpenProtection)),
                    O(kS1, can(T, 2, 100, CR::OpenProtection)), I(iq(T, kAAPL, "AAPL", 0, 0, 1, 'O')),
                    I(iq(T, kMS, "MSFT", 0, 0, 2, 'O'))}));
  // The symbol opens normally.
  const auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 3, .side = OS::Buy, .qty = 100, .price = 1'000'000})),
                   {O(kS1, acc(t, {3, OS::Buy, 100, "AAPL", 1'000'000, 4})),
                    I(iadd(t, kAAPL, 4, Side::Buy, 100, "AAPL", 1'000'000))}));
}

// Price test B (R2 D2.3 step F): the last sale counts only when it printed at or after 09:15.
// A pre-market trade at 115.00, then a cross that would be 100 @120.00: test A fails
// (|120 - 100| > $10), C does not apply (empty book).
TEST_F(Auction, OpeningPriceTestBUsesALastSaleFrom0915) {
  at(at_s(9, 20, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 1'150'000, .tif = TIF::Gtx}));   // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'150'000, .tif = TIF::Gtx}));  // ref 2, match 1
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));       // ref 3
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'200'000, .cross = CT::Opening}));  // ref 4
  // B applies: |120.00 - 115.00| <= max(10% of 115.00, $0.50), so the cross happens.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, exe(T, 2, 100, 1'200'000, LF::OpeningCross, 2)),
                    O(kS2, exe(T, 2, 100, 1'200'000, LF::OpeningCross, 2)),
                    I(iq(T, kAAPL, "AAPL", 100, 1'200'000, 3, 'O')), I(iq(T, kMS, "MSFT", 0, 0, 4, 'O'))}));
}

TEST_F(Auction, OpeningPriceTestBIgnoresALastSaleBefore0915) {
  at(at_s(9, 14, 59));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 1'150'000, .tif = TIF::Gtx}));   // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'150'000, .tif = TIF::Gtx}));  // ref 2, match 1
  at(at_s(9, 20, 0));
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));       // ref 3
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'200'000, .cross = CT::Opening}));  // ref 4
  // Only test A applies, and fails: no cross.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, can(T, 2, 100, CR::OpenProtection)), O(kS2, can(T, 2, 100, CR::OpenProtection)),
                    I(iq(T, kAAPL, "AAPL", 0, 0, 2, 'O')), I(iq(T, kMS, "MSFT", 0, 0, 3, 'O'))}));
}

TEST_F(Auction, OpeningThresholdPriceTestCAndUncross) {
  at(at_s(9, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .symbol = "MSFT", .price = 100'000, .tif = TIF::Gtx}));  // 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .symbol = "MSFT", .price = 110'000, .tif = TIF::Gtx}));  // 2
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 500, .symbol = "MSFT", .price = 120'800}));  // 3, held
  // 12.10 is the most Limit Order Protection allows: 11.00 + max(10%, $0.50).
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 500, .symbol = "MSFT", .price = 121'000}));   // 4, held
  // 10.00 x 11.00: threshold max(10% of 10.50, $0.50) = 1.05 -> [8.95, 12.05] (R2 D2.4 example).
  // Unrestricted, 12.08 pairs 500; beyond the threshold, so the best price inside: 11.00 and
  // 12.05 pair 100 (imbalance 400 B), 11.00 is nearer the midpoint. Price test A fails
  // (|11 - 20| > $2), test C passes (|11.00 - 10.00| <= max(10% of 10.00, $0.50)).
  // The held orders then join the book crossed (12.10 bid over 12.08 offer) and the uncross
  // sweep trades 400 at the earlier order's price: 'E' for it, 'C' Printable=N for the later.
  const auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {I(iq(T, kAAPL, "AAPL", 0, 0, 1, 'O')),
                    O(kS1, exe(T, 2, 100, 110'000, LF::OpeningCross, 2)),
                    O(kS2, exe(T, 1, 100, 110'000, LF::OpeningCross, 2)),
                    I(ixc(T, kMS, 2, 100, 2, 110'000)),
                    I(iq(T, kMS, "MSFT", 100, 110'000, 3, 'O')),
                    // Rule 201: 11.00 is below 90% of the prior close (20.00).
                    I(iy(T, kMS, "MSFT", '1')),
                    I(iadd(T, kMS, 3, Side::Sell, 500, "MSFT", 120'800)),
                    I(iadd(T, kMS, 4, Side::Buy, 400, "MSFT", 121'000)),
                    O(kS2, exe(T, 2, 400, 120'800, LF::Added, 4)),
                    O(kS1, exe(T, 2, 400, 120'800, LF::Removed, 4)),
                    I(iexe(T, kMS, 3, 400, 4)),
                    I(ixc(T, kMS, 4, 400, 4, 120'800))}));
  EXPECT_EQ(eng_.live_orders(), 2u);  // bid 10.00, offer 100 @12.08
}

TEST_F(Auction, HaltedSymbolAtTheOpen) {
  at(at_s(9, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = kMkt, .cross = CT::Opening}));  // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 990'000}));                    // ref 2, held
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 100, .price = 1'010'000}));                   // ref 3, held
  at(at_s(9, 10, 0));
  auto t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::Halt, AdminArgsBuilder{}.symbol("AAPL")), {I(ih(t, kAAPL, "AAPL", 'H', "T1"))}));
  // A halted symbol does not cross: on-open orders cancel 'H', held orders join the book
  // without matching (it may stay crossed while halted), and there is no 'Q' for it.
  auto T = W(at_s(9, 30, 0));
  EXPECT_TRUE(same(timer(kCrossOpen, at_s(9, 30, 0)),
                   {O(kS1, can(T, 1, 100, CR::HaltedAfterOpen)), I(iadd(T, kAAPL, 2, Side::Sell, 100, "AAPL", 990'000)),
                    I(iadd(T, kAAPL, 3, Side::Buy, 100, "AAPL", 1'010'000)), I(iq(T, kMS, "MSFT", 0, 0, 1, 'O'))}));
  // Operator resume: the halt cross. 99.00, 100.00 and 101.00 all pair 100 with no imbalance and
  // no shares left at an entered price; 100.00 is the reference (prior close) itself.
  at(at_s(9, 31, 0));
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::Resume, AdminArgsBuilder{}.symbol("AAPL")),
                   {O(kS1, exe(t, 2, 100, 1'000'000, LF::HaltCross, 2)), O(kS2, exe(t, 1, 100, 1'000'000, LF::HaltCross, 2)),
                    I(ixc(t, kAAPL, 3, 100, 2, 1'000'000)), I(ixc(t, kAAPL, 2, 100, 2, 1'000'000)),
                    I(iq(t, kAAPL, "AAPL", 100, 1'000'000, 3, 'H')), I(ih(t, kAAPL, "AAPL", 'T', ""))}));
  EXPECT_EQ(eng_.live_orders(), 0u);
}

// ---------------------------------------------------------------- closing cross

TEST_F(Auction, ClosingCrossImbalanceAndExpirySweeps) {
  open_market();
  at(at_s(15, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 200, .price = 990'000}));                   // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'010'000}));                // ref 2
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'020'000, .tif = TIF::Gtx}));  // ref 3
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 300, .price = kMkt, .cross = CT::Closing}));    // ref 4 MOC
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 200, .price = 1'000'000, .cross = CT::Closing}));  // ref 5 LOC
  (void)a(enter_msg({.urn = 3, .side = OS::Buy, .qty = 400, .price = 1'010'000, .cross = CT::Closing},
                    imbalance_only()));  // ref 6 IO, priced at the bid 99.00
  EXPECT_TRUE(timer(kCloseFreeze, at_s(15, 50, 0)).empty());
  // CRP within [99.00, 101.00]: 100.00 pairs 200 (100 B), 101.00 pairs 300 with no imbalance.
  auto t = ts();
  EXPECT_TRUE(same(timer(kEoiiClose, at_s(15, 50, 0)),
                   {I(inoii(t, kAAPL, "AAPL", {300, 0, 'N', 0, 0, 1'010'000, 'C', ' '})),
                    I(inoii(t, kMS, "MSFT", {0, 0, 'O', 0, 0, 0, 'C', ' '}))}));
  EXPECT_TRUE(timer(kMocCutoff, at_s(15, 55, 0)).empty());
  // Near (threshold [89.00, 111.00]): 101.00, 102.00 and 111.00 pair 300 with no imbalance; shares
  // remain at the entered price 102.00 (step C) -> 102.00. Far: 100.00 (200, the IO at 99.00
  // cannot reach it). PVI: 1.00 / 102.00 < 1% -> 'L'.
  t = ts();
  EXPECT_TRUE(same(timer(kNoiiClose, at_s(15, 55, 0)),
                   {I(inoii(t, kAAPL, "AAPL", {300, 0, 'N', 1'000'000, 1'020'000, 1'010'000, 'C', 'L'})),
                    I(inoii(t, kMS, "MSFT", {0, 0, 'O', 0, 0, 0, 'C', ' '}))}));
  EXPECT_TRUE(timer(kLocCutoff, at_s(15, 58, 0)).empty());
  // The close at 102.00: MOC 300 against LOC 200 @100.00 and the displayed 100 @101.00 ('C').
  const auto T = W(at_s(16, 0, 0));
  EXPECT_TRUE(same(timer(kCrossClose, at_s(16, 0, 0)),
                   {O(kS1, exe(T, 2, 200, 1'020'000, LF::ClosingCross, 3)),
                    O(kS2, exe(T, 3, 200, 1'020'000, LF::ClosingCross, 3)),
                    O(kS1, exe(T, 2, 100, 1'020'000, LF::ClosingCross, 4)),
                    O(kS2, exe(T, 1, 100, 1'020'000, LF::ClosingCross, 4)),
                    I(ixc(T, kAAPL, 2, 100, 4, 1'020'000)),
                    I(iq(T, kAAPL, "AAPL", 300, 1'020'000, 5, 'C')),
                    O(kS1, can(T, 3, 400, CR::ImmediateOrCancel)),
                    I(iq(T, kMS, "MSFT", 0, 0, 6, 'C'))}));
  EXPECT_EQ(eng_.session(), Session::PostMarket);
  // Day orders expire after the close ('E'); GTX orders stay until the end of system hours.
  t = ts();
  EXPECT_TRUE(same(timer(kSweepDay, at_s(16, 0, 0)),
                   {O(kS1, can(t, 1, 200, CR::Closed)), I(idel(t, kAAPL, 1))}));
  at(at_s(16, 30, 0));
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 4, .side = OS::Buy, .qty = 100, .price = 1'000'000})),
                   {O(kS1, rej(t, 4, RR::DestinationClosed))}));
  t = W(at_s(20, 0, 0));
  EXPECT_TRUE(same(timer(kSweepAll, at_s(20, 0, 0)), {O(kS2, can(t, 2, 100, CR::Closed)), I(idel(t, kAAPL, 3))}));
  EXPECT_TRUE(timer(kSystemClose, at_s(20, 0, 0)).empty());
  EXPECT_EQ(eng_.session(), Session::Closed);
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 5, .side = OS::Buy, .qty = 100, .price = 1'000'000, .tif = TIF::Gtx})),
                   {O(kS1, rej(t, 5, RR::DestinationClosed))}));
}

TEST_F(Auction, GttExpiresOnTheClock) {
  open_market();
  at(at_s(10, 0, 0));
  ouch50::TagSet exp;
  exp.set_expire_time(36'002);  // 10:00:02
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 990'000, .tif = TIF::Gtt}, exp)),
                   {O(kS1, acc(t, {1, OS::Buy, 100, "AAPL", 990'000, 1, true, TIF::Gtt}, exp)),
                    I(iadd(t, kAAPL, 1, Side::Buy, 100, "AAPL", 990'000))}));
  EXPECT_TRUE(tick(at_s(10, 0, 1)).empty());
  t = W(at_s(10, 0, 2));
  EXPECT_TRUE(same(tick(at_s(10, 0, 2)), {O(kS1, can(t, 1, 100, CR::Timeout)), I(idel(t, kAAPL, 1))}));
}

// ---------------------------------------------------------------- halts

TEST_F(Auction, NewsHaltCollarExtensions) {
  open_market();
  at(at_s(10, 0, 0));
  auto t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::Halt, AdminArgsBuilder{}.symbol("AAPL")), {I(ih(t, kAAPL, "AAPL", 'H', "T1"))}));
  // While halted, orders rest without matching; immediate orders are rejected.
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 1'250'000})),
                   {O(kS1, acc(t, {1, OS::Buy, 100, "AAPL", 1'250'000, 1})),
                    I(iadd(t, kAAPL, 1, Side::Buy, 100, "AAPL", 1'250'000))}));
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'250'000})),
                   {O(kS2, acc(t, {1, OS::Sell, 100, "AAPL", 1'250'000, 2})),
                    I(iadd(t, kAAPL, 2, Side::Sell, 100, "AAPL", 1'250'000))}));
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'000'000, .tif = TIF::Ioc})),
                   {O(kS2, rej(t, 2, RR::Halted))}));
  // Quotation-only period at ARP 100.00: collars 100 +/- max($1, 10%) = 90 / 110 (R2 D2.4).
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::QuoteOnly, AdminArgsBuilder{}.symbol("AAPL").i64(AdminTag::Price, 1'000'000)),
                   {I(ih(t, kAAPL, "AAPL", 'Q', "T3")), I(ij(t, kAAPL, "AAPL", 1'000'000, 1'100'000, 900'000, 0))}));
  // Each second: the halt NOII (Far = Near = CRP = 125.00, 100 paired, no imbalance).
  auto noii = [&](std::uint64_t ts) {
    return I(inoii(ts, kAAPL, "AAPL", {100, 0, 'N', 1'250'000, 1'250'000, 1'250'000, 'H', 'L'}));
  };
  int s = 1;
  for (; s <= 4; ++s) EXPECT_TRUE(same(tick(at_s(10, 1, s)), {noii(W(at_s(10, 1, s)))})) << s;
  // 5 s: 125.00 is outside the collars -> extension 1, both widen by max($1, 10%): 80 / 120.
  t = W(at_s(10, 1, 5));
  EXPECT_TRUE(same(tick(at_s(10, 1, 5)), {noii(t), I(ij(t, kAAPL, "AAPL", 1'000'000, 1'200'000, 800'000, 1))}));
  for (s = 6; s <= 7; ++s) EXPECT_TRUE(same(tick(at_s(10, 1, s)), {noii(W(at_s(10, 1, s)))})) << s;
  // 3 s later: still outside -> extension 2 widens by max($1, 20%): 60 / 140.
  t = W(at_s(10, 1, 8));
  EXPECT_TRUE(same(tick(at_s(10, 1, 8)), {noii(t), I(ij(t, kAAPL, "AAPL", 1'000'000, 1'400'000, 600'000, 2))}));
  // From the third period the first NOII with no imbalance releases: the halt cross at 125.00.
  t = W(at_s(10, 1, 9));
  EXPECT_TRUE(same(tick(at_s(10, 1, 9)),
                   {noii(t), O(kS1, exe(t, 1, 100, 1'250'000, LF::HaltCross, 3)),
                    O(kS2, exe(t, 1, 100, 1'250'000, LF::HaltCross, 3)), I(ixc(t, kAAPL, 1, 100, 3, 1'250'000)),
                    I(ixc(t, kAAPL, 2, 100, 3, 1'250'000)), I(iq(t, kAAPL, "AAPL", 100, 1'250'000, 4, 'H')),
                    I(ih(t, kAAPL, "AAPL", 'T', ""))}));
  EXPECT_TRUE(tick(at_s(10, 1, 10)).empty());
}

// MSFT closed at the ITCH Price(4) maximum, $429,496.7295.
class AuctionHugePrior : public Auction {
 protected:
  AuctionHugePrior() { prior_[1] = 4'294'967'295; }
};

// Collars stay inside the ITCH price range: ARP 429,496.7295 +/- 10% would put the upper
// collar at 472,446.40; it is capped at 429,496.00. Out-of-range Admin prices are refused.
TEST_F(AuctionHugePrior, CollarsAndAdminPricesStayInTheItchRange) {
  open_market();
  at(at_s(10, 0, 0));
  auto t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::QuoteOnly, AdminArgsBuilder{}.symbol("MSFT")),
                   {I(ih(t, kMS, "MSFT", 'Q', "T3")),
                    I(ij(t, kMS, "MSFT", 4'294'967'295, 4'294'960'000, 3'865'470'600, 0))}));
  const auto audited_only = [](const std::vector<Msg>& v) { return v.size() == 1 && v[0].dest == Dest::Audit; };
  EXPECT_TRUE(audited_only(
      admin(AdminCommand::QuoteOnly, AdminArgsBuilder{}.symbol("AAPL").i64(AdminTag::Price, std::int64_t{1} << 40))));
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::IpoQuote, AdminArgsBuilder{}.symbol("AAPL")), {I(ih(t, kAAPL, "AAPL", 'Q', "IPOQ"))}));
  EXPECT_TRUE(audited_only(
      admin(AdminCommand::IpoRelease, AdminArgsBuilder{}.symbol("AAPL").i64(AdminTag::Band, std::int64_t{1} << 33))));
  EXPECT_EQ(eng_.symbol(1).halt, HaltPhase::IpoQuote);  // unchanged
}

class AuctionNoPrior : public Auction {
 protected:
  AuctionNoPrior() { prior_[1] = 0; }
};

// A late LOC needs a closing reference price (R2 D2.1): MSFT has no prior close
// and no trade, so neither the 15:50 nor the 15:55 CRP exists: 'J' 0x000E.
TEST_F(AuctionNoPrior, LateLocWithoutAClosingReferencePrice) {
  open_market();
  EXPECT_TRUE(timer(kCloseFreeze, at_s(15, 50, 0)).empty());
  EXPECT_TRUE(timer(kMocCutoff, at_s(15, 55, 0)).empty());
  at(at_s(15, 56, 0));
  auto t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .qty = 100, .symbol = "MSFT", .price = 200'000, .cross = CT::Closing})),
                   {O(kS1, rej(t, 1, RR::NoClosingReferencePrice))}));
  // AAPL has its prior close as the reference: accepted (port 1 accepts late orders as entered).
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 2, .qty = 100, .price = 1'000'000, .cross = CT::Closing})),
                   {O(kS1, acc(t, {2, OS::Buy, 100, "AAPL", 1'000'000, 1, true, TIF::Day, DSP::Visible, "", CT::Closing}))}));
}

class AuctionLuld : public Auction {
 protected:
  AuctionLuld() { extension_sec_ = 1; }
};

// R2 D2.4, verified on FLAT: a pause at the upper band 34.69; the upper collar 34.69 + 5%
// (1.73) = 36.42 widens by 1.73 per extension on a buy imbalance (38.15, ..., 67.56 at extension
// 18) while the lower collar stays at the lower band 28.39; it reopens at 66.48.
TEST_F(AuctionLuld, LimitStatePauseAndFlatCollars) {
  open_market();
  EXPECT_TRUE(same(admin(AdminCommand::LuldBands, AdminArgsBuilder{}
                                                      .symbol("MSFT")
                                                      .i64(AdminTag::Lower, 283'900)
                                                      .i64(AdminTag::Upper, 346'900)),
                   {}));
  at(at_s(10, 0, 0));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .symbol = "MSFT", .price = 346'900}));  // ref 1: NBB at the band
  // Limit state: the first tick sees it, the pause comes LimitStateSec (2) ticks later.
  EXPECT_TRUE(tick(at_s(10, 0, 1)).empty());
  EXPECT_TRUE(tick(at_s(10, 0, 2)).empty());
  auto t = W(at_s(10, 0, 3));
  EXPECT_TRUE(same(tick(at_s(10, 0, 3)),
                   {I(ih(t, kMS, "MSFT", 'P', "LUDP")), I(ij(t, kMS, "MSFT", 346'900, 364'200, 283'900, 0))}));
  at(at_s(10, 0, 3) + 500'000'000);
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .symbol = "MSFT", .price = 600'000}));  // ref 2
  (void)a(enter_msg({.urn = 2, .side = OS::Buy, .qty = 300, .symbol = "MSFT", .price = 664'800}));   // ref 3
  // Halt cross: 60.00 and 66.48 pair 100 with 200 B; shares remain at the entered 66.48 -> 66.48.
  auto noii = [&](std::uint64_t ts) {
    return I(inoii(ts, kMS, "MSFT", {100, 200, 'B', 664'800, 664'800, 664'800, 'H', 'L'}));
  };
  int s = 4;
  EXPECT_TRUE(same(tick(at_s(10, 0, s)), {noii(W(at_s(10, 0, s)))}));
  for (std::uint32_t ext = 1; ext <= 18; ++ext) {
    ++s;
    t = W(at_s(10, 0, s));
    const PxE4 hi = 364'200 + 17'300 * static_cast<PxE4>(ext);
    if (ext == 1) EXPECT_EQ(hi, 381'500);
    if (ext == 18) EXPECT_EQ(hi, 675'600);
    EXPECT_TRUE(same(tick(at_s(10, 0, s)), {noii(t), I(ij(t, kMS, "MSFT", 346'900, hi, 283'900, ext))})) << ext;
  }
  ++s;
  t = W(at_s(10, 0, s));
  EXPECT_TRUE(same(tick(at_s(10, 0, s)),
                   {noii(t), O(kS1, exe(t, 2, 100, 664'800, LF::HaltCross, 3)),
                    O(kS2, exe(t, 1, 100, 664'800, LF::HaltCross, 3)), I(ixc(t, kMS, 3, 100, 3, 664'800)),
                    I(ixc(t, kMS, 2, 100, 3, 664'800)), I(iq(t, kMS, "MSFT", 100, 664'800, 4, 'H')),
                    I(ih(t, kMS, "MSFT", 'T', ""))}));
}

TEST_F(Auction, IpoQuotationAndRelease) {
  open_market();
  at(at_s(10, 0, 0));
  auto t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::IpoSchedule, AdminArgsBuilder{}
                                                        .symbol("MSFT")
                                                        .i64(AdminTag::Price, 250'000)
                                                        .u32(AdminTag::Time, 36'900)
                                                        .u8(AdminTag::Qualifier, 'A')),
                   {I(ik(t, "MSFT", 36'900, 'A', 250'000))}));
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::IpoQuote, AdminArgsBuilder{}.symbol("MSFT")), {I(ih(t, kMS, "MSFT", 'Q', "IPOQ"))}));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 500, .symbol = "MSFT", .price = 260'000}));   // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 300, .symbol = "MSFT", .price = 250'000}));  // ref 2
  t = ts();
  EXPECT_TRUE(same(b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 200, .symbol = "MSFT", .price = kMkt,
                                .cross = CT::HaltIpo})),
                   {O(kS2, acc(t, {2, OS::Sell, 200, "MSFT", kMkt, 3, true, TIF::Day, DSP::Visible, "", CT::HaltIpo}))}));
  // 25.00 and 26.00 pair 500 with no imbalance; 25.00 is the IPO price (step D).
  auto noii = [&](std::uint64_t ts) {
    return I(inoii(ts, kMS, "MSFT", {500, 0, 'N', 250'000, 250'000, 250'000, 'H', 'L'}));
  };
  // The quotation period lasts until the underwriter's release.
  for (int s = 1; s <= 8; ++s) EXPECT_TRUE(same(tick(at_s(10, 1, s)), {noii(W(at_s(10, 1, s)))})) << s;
  EXPECT_TRUE(same(admin(AdminCommand::IpoRelease, AdminArgsBuilder{}.symbol("MSFT").i64(AdminTag::Band, 1'000)), {}));
  // Pre-launch: every market order executes and the price is within $0.10 of the expected
  // 25.00 -> the IPO cross (liquidity 'H'): the buy against the market sell, then the limit sell.
  t = W(at_s(10, 1, 9));
  EXPECT_TRUE(same(tick(at_s(10, 1, 9)),
                   {noii(t), O(kS1, exe(t, 1, 200, 250'000, LF::HaltIpoCross, 3)),
                    O(kS2, exe(t, 2, 200, 250'000, LF::HaltIpoCross, 3)), I(ixc(t, kMS, 1, 200, 3, 250'000)),
                    O(kS1, exe(t, 1, 300, 250'000, LF::HaltIpoCross, 4)),
                    O(kS2, exe(t, 1, 300, 250'000, LF::HaltIpoCross, 4)), I(ixc(t, kMS, 1, 300, 4, 250'000)),
                    I(ixc(t, kMS, 2, 300, 4, 250'000)), I(iq(t, kMS, "MSFT", 500, 250'000, 5, 'H')),
                    I(ih(t, kMS, "MSFT", 'T', ""))}));
}

TEST_F(Auction, MarketWideCircuitBreakerLevel1) {
  open_market();
  at(at_s(10, 0, 0));
  auto t = ts();
  // Px8 levels: 5,000.00 / 4,600.00 / 4,000.00.
  EXPECT_TRUE(same(admin(AdminCommand::MwcbLevels, AdminArgsBuilder{}
                                                       .i64(AdminTag::Level1, 500'000'000'000)
                                                       .i64(AdminTag::Level2, 460'000'000'000)
                                                       .i64(AdminTag::Level3, 400'000'000'000)),
                   {I(iv(t, 500'000'000'000, 460'000'000'000, 400'000'000'000))}));
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::MwcbBreach, AdminArgsBuilder{}.u8(AdminTag::Level, 1)),
                   {I(iw(t, '1')), I(ih(t, kAAPL, "AAPL", 'H', "MWC1")), I(ih(t, kMS, "MSFT", 'H', "MWC1"))}));
  (void)a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 1'050'000}));   // ref 1
  (void)b(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 1'040'000}));  // ref 2 (crossed while halted)
  // The halt lasts MwcbPeriodSec (3); then the reopening quotation period ('Q' MWCQ, no 'J').
  EXPECT_TRUE(tick(at_s(10, 0, 1)).empty());
  EXPECT_TRUE(tick(at_s(10, 0, 2)).empty());
  t = W(at_s(10, 0, 3));
  EXPECT_TRUE(same(tick(at_s(10, 0, 3)), {I(ih(t, kAAPL, "AAPL", 'Q', "MWCQ")), I(ih(t, kMS, "MSFT", 'Q', "MWCQ"))}));
  // AAPL: 104.00 and 105.00 pair 100; 104.00 is nearer the reference 100.00. MSFT has no interest.
  auto noii = [&](std::uint64_t ts) {
    return std::vector<Exp>{I(inoii(ts, kAAPL, "AAPL", {100, 0, 'N', 1'040'000, 1'040'000, 1'040'000, 'H', 'L'})),
                            I(inoii(ts, kMS, "MSFT", {0, 0, 'O', 0, 0, 0, 'H', ' '}))};
  };
  for (int s = 4; s <= 7; ++s) EXPECT_TRUE(same(tick(at_s(10, 0, s)), noii(W(at_s(10, 0, s))))) << s;
  // HaltPeriodSec (5) later, inside the +/-10% collars (90 / 110): the halt cross; MSFT reopens
  // with nothing to cross (no 'Q').
  t = W(at_s(10, 0, 8));
  auto want = noii(t);
  want.insert(want.begin() + 1, {O(kS1, exe(t, 1, 100, 1'040'000, LF::HaltCross, 3)),
                                 O(kS2, exe(t, 1, 100, 1'040'000, LF::HaltCross, 3)),
                                 I(ixc(t, kAAPL, 1, 100, 3, 1'040'000)), I(ixc(t, kAAPL, 2, 100, 3, 1'040'000)),
                                 I(iq(t, kAAPL, "AAPL", 100, 1'040'000, 4, 'H')), I(ih(t, kAAPL, "AAPL", 'T', ""))});
  want.push_back(I(ih(t, kMS, "MSFT", 'T', "")));
  EXPECT_TRUE(same(tick(at_s(10, 0, 8)), want));
}

TEST_F(Auction, MarketWideCircuitBreakerLevel3) {
  open_market();
  at(at_s(10, 0, 0));
  auto t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::MwcbBreach, AdminArgsBuilder{}.u8(AdminTag::Level, 3)),
                   {I(iw(t, '3')), I(ih(t, kAAPL, "AAPL", 'H', "MWC3")), I(ih(t, kMS, "MSFT", 'H', "MWC3"))}));
  // Halted for the rest of the day: the clock does nothing; IOC orders are rejected.
  for (int s = 1; s <= 10; ++s) EXPECT_TRUE(tick(at_s(10, 0, s)).empty()) << s;
  t = ts();
  EXPECT_TRUE(same(a(enter_msg({.urn = 1, .side = OS::Buy, .qty = 100, .price = 1'000'000, .tif = TIF::Ioc})),
                   {O(kS1, rej(t, 1, RR::Halted))}));
}

// Midpoint pegs (R2 D1.1): pulled while there is no valid midpoint and
// cancelled ('Z') when the next clock tick still finds them pulled; a halt
// cancels them ('H').
TEST_F(Auction, MidpointPegsPulledThenCancelledAndHalted) {
  open_market();
  at(at_s(10, 0, 0));
  ouch50::TagSet peg;
  peg.set_price_type(ouch50::PriceType::MidpointPeg);
  (void)b(enter_msg({.urn = 1, .qty = 100, .price = 1'000'000}));                         // ref 1
  (void)b(enter_msg({.urn = 2, .side = OS::Sell, .qty = 100, .price = 1'001'000}));      // ref 2
  (void)a(enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = 990'000}, peg));   // ref 3
  (void)a(enter_msg({.urn = 2, .qty = 100, .symbol = "MSFT", .price = 200'000}));        // ref 4: MSFT bid
  (void)b(enter_msg({.urn = 3, .side = OS::Sell, .qty = 100, .symbol = "MSFT", .price = 201'000}));  // ref 5
  (void)a(enter_msg({.urn = 3, .qty = 100, .symbol = "MSFT", .price = 210'000}, peg));  // ref 6
  EXPECT_TRUE(tick(at_s(10, 0, 1)).empty());
  (void)b(cancel_msg(2, 0));  // AAPL has no offer: its pegs are pulled
  EXPECT_TRUE(tick(at_s(10, 0, 2)).empty());
  auto t = W(at_s(10, 0, 3));
  EXPECT_TRUE(same(tick(at_s(10, 0, 3)), {O(kS1, can(t, 1, 100, CR::System))}));
  // MSFT halted: its peg cancels with reason 'H' after the 'H'.
  at(at_s(10, 0, 4));
  t = ts();
  EXPECT_TRUE(same(admin(AdminCommand::Halt, AdminArgsBuilder{}.symbol("MSFT")),
                   {I(ih(t, kMS, "MSFT", 'H', "T1")), O(kS1, can(t, 3, 100, CR::HaltedAfterOpen))}));
}

}  // namespace
}  // namespace lle::engine::testing

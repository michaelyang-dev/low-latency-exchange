// Pre-trade risk gate (05-matching-engine §7, T04): one test per reject code,
// the check order, the kill switch, replaces, Admin limit changes, the
// RiskLimits table and snapshot round trips.
//
// Fixture: AAPL (locate 1, prior close $100.00, ADV 10,000) and MSFT (locate 2,
// prior close $20.00); account A = 100 on sessions 1 and 3, account B = 200 on
// session 2. Records are 1 us apart; `later(ns)` moves the clock.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "engine/scenario.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine {
namespace {

using OS = ouch50::Side;
using TIF = ouch50::TimeInForce;
using RR = ouch50::RejectReason;
constexpr std::uint32_t kA = 100, kB = 200;
constexpr std::uint64_t kMkt = ouch50::kMarketPrice;
constexpr std::int64_t kP100 = 1'000'000;
constexpr std::int64_t kNot100 = 100 * kP100;  // notional of 100 shares at $100

struct Out {
  bool itch;
  std::uint32_t session;
  std::vector<std::byte> b;
  AuditCode audit{};
  bool is_audit = false;
};
struct Sink {
  std::vector<Out> v;
  void itch(std::uint64_t, std::span<const std::byte> b) { v.push_back(Out{true, 0, {b.begin(), b.end()}}); }
  void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
    v.push_back(Out{false, s, {b.begin(), b.end()}});
  }
  void audit(std::uint64_t, const AuditEvent& a) {
    Out o{false, a.session_id, {}};
    o.audit = a.code;
    o.is_audit = true;
    v.push_back(o);
  }
};

RiskEntry lim(std::uint32_t acct, RiskKind k, std::int64_t v, std::string_view sym = "") {
  RiskEntry e;
  e.account_id = acct;
  e.kind = k;
  e.value = v;
  if (!sym.empty()) e.symbol = Symbol8(sym);
  return e;
}

class Risk : public ::testing::Test {
 protected:
  // Day start, tables, the given risk limits, a schedule with the initial session.
  void start(const std::vector<RiskEntry>& limits, char session = 'R') {
    sc_.day_start();
    std::array<SymbolEntry, 2> syms{};
    syms[0].symbol = Symbol8("AAPL");
    syms[0].prior_close = kP100;
    syms[0].adv = 10'000;
    syms[1].symbol = Symbol8("MSFT");
    syms[1].prior_close = 200'000;
    std::array<AccountEntry, 2> accts{};
    accts[0].account_id = kA;
    accts[0].firms[0] = Mpid4("FIRM");
    accts[1].account_id = kB;
    accts[1].firms[0] = Mpid4("OTHR");
    constexpr std::uint8_t f = SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders;
    std::array<SessionEntry, 3> sess{};
    sess[0] = SessionEntry{1, kA, f, 'N'};
    sess[1] = SessionEntry{2, kB, f, 'N'};
    sess[2] = SessionEntry{3, kA, f, 'N'};
    sc_.symbols(syms);
    sc_.accounts(accts);
    sc_.sessions(sess);
    if (!limits.empty()) sc_.risk(limits);
    std::vector<ScheduleEntry> sched = params_only(session);
    ScheduleEntry clock{1, TimerKind::Noii, 'H', hms_ns(9, 30, 1)};
    sched.push_back(clock);
    sched.push_back(ScheduleEntry{2, TimerKind::Cross, 'C', hms_ns(16, 0, 0)});
    sc_.schedule(sched);
    for (std::size_t i = 0; i < sc_.size(); ++i) eng_.apply(sc_[i], sink_);
    sink_.v.clear();
  }
  void TearDown() override {
    std::string err;
    EXPECT_TRUE(eng_.check(&err)) << err;
  }

  std::vector<Out> run(const InputRecord& r) {
    sink_.v.clear();
    eng_.apply(r, sink_);
    return sink_.v;
  }
  std::vector<Out> send(std::uint32_t s, const std::vector<std::byte>& m) {
    return run(sc_.ouch(s, s == 2 ? kB : kA, m));
  }
  std::vector<Out> admin(AdminCommand c, const AdminArgsBuilder& b) { return run(sc_.admin(c, b)); }
  void later(Nanos ns) { sc_.set_time(sc_.now() + ns); }

  // The outcome of an Enter or Replace: 0 accepted / replaced, else the 'J' reject code.
  static std::uint16_t code(const std::vector<Out>& out) {
    for (const Out& o : out) {
      if (o.itch || o.is_audit || o.b.empty()) continue;
      const char t = static_cast<char>(o.b[0]);
      if (t == 'A' || t == 'U') return 0;
      if (t == 'J') return static_cast<std::uint16_t>((std::to_integer<unsigned>(o.b[13]) << 8) |
                                                      std::to_integer<unsigned>(o.b[14]));
    }
    return 0xFFFF;  // neither: ignored
  }
  static int count(const std::vector<Out>& out, char type, bool itch = false) {
    int n = 0;
    for (const Out& o : out)
      if (!o.is_audit && o.itch == itch && !o.b.empty() && static_cast<char>(o.b[0]) == type) ++n;
    return n;
  }
  static bool audited(const std::vector<Out>& out, AuditCode c) {
    for (const Out& o : out)
      if (o.is_audit && o.audit == c) return true;
    return false;
  }
  std::uint16_t enter(std::uint32_t s, UserRefNum urn, OS side, Qty q, std::uint64_t px, std::string_view sym = "AAPL",
                      TIF tif = TIF::Day, const ouch50::TagSet& tags = {},
                      ouch50::CrossType cross = ouch50::CrossType::Continuous) {
    return code(send(s, enter_msg({.urn = urn, .side = side, .qty = q, .symbol = sym, .price = px, .tif = tif,
                                   .cross = cross},
                                  tags)));
  }

  Scenario sc_;
  Engine eng_;
  Sink sink_;
};

constexpr std::uint16_t C(RR r) { return static_cast<std::uint16_t>(r); }

// ---------------------------------------------------------------- rates

TEST_F(Risk, PortRate0029) {
  start({lim(kA, RiskKind::PortRate, 2)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(1, 3, OS::Buy, 100, 990'000), C(RR::RiskPortMsgRateRestriction));
  EXPECT_EQ(enter(3, 4, OS::Buy, 100, 990'000), 0);  // the other session of the account has its own bucket
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 990'000), 0);  // account B has no limit
  later(500'000'000);                                 // half a second refills one token
  EXPECT_EQ(enter(1, 5, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(1, 6, OS::Buy, 100, 990'000), C(RR::RiskPortMsgRateRestriction));
}

TEST_F(Risk, SymbolRate0028) {
  start({lim(kA, RiskKind::SymbolRate, 1)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000), C(RR::RiskSymbolMsgRateRestriction));
  EXPECT_EQ(enter(1, 3, OS::Buy, 100, 190'000, "MSFT"), 0);
  EXPECT_EQ(enter(3, 4, OS::Buy, 100, 990'000), 0);
  later(1'000'000'000);
  EXPECT_EQ(enter(1, 5, OS::Buy, 100, 990'000), 0);
}

// ---------------------------------------------------------------- permissions

TEST_F(Risk, PreMarket002D) {
  start({lim(kA, RiskKind::Permissions, kNoPreMarket)}, 'P');
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), C(RR::RiskPreMarketNotAllowed));
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 990'000), 0);
}

TEST_F(Risk, PostMarket002E) {
  start({lim(kA, RiskKind::Permissions, kNoPostMarket)}, 'A');
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000, "AAPL", TIF::Gtx), C(RR::RiskPostMarketNotAllowed));
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 990'000, "AAPL", TIF::Gtx), 0);
}

TEST_F(Risk, ShortSale002BAndExempt002F) {
  start({lim(kA, RiskKind::Permissions, kNoShortSell), lim(kB, RiskKind::Permissions, kNoShortExempt)});
  EXPECT_EQ(enter(1, 1, OS::SellShort, 100, 1'010'000), C(RR::RiskShortSellNotAllowed));
  EXPECT_EQ(enter(1, 2, OS::SellShortExempt, 100, 1'010'000), 0);
  EXPECT_EQ(enter(1, 3, OS::Sell, 100, 1'010'000), 0);
  EXPECT_EQ(enter(2, 1, OS::SellShortExempt, 100, 1'010'000), C(RR::RiskShortSellExemptNotAllowed));
  EXPECT_EQ(enter(2, 2, OS::SellShort, 100, 1'010'000), 0);
}

TEST_F(Risk, MarketOrders002C) {
  start({lim(kA, RiskKind::Permissions, kNoMarketOrders)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kMkt, "AAPL", TIF::Ioc), C(RR::RiskMarketOrderNotAllowed));
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000, "AAPL", TIF::Ioc), 0);
}

TEST_F(Risk, IpoMarketBuy0033) {
  start({lim(kA, RiskKind::Permissions, kNoIpoMarketBuy)});
  (void)admin(AdminCommand::IpoQuote, AdminArgsBuilder{}.symbol("MSFT"));
  const auto H = ouch50::CrossType::HaltIpo;
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kMkt, "MSFT", TIF::Day, {}, H), C(RR::RiskIpoMarketBuyNotAllowed));
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 250'000, "MSFT", TIF::Day, {}, H), 0);
  EXPECT_EQ(enter(1, 3, OS::Sell, 100, kMkt, "MSFT", TIF::Day, {}, H), 0);
  EXPECT_EQ(enter(1, 4, OS::Buy, 100, kMkt, "AAPL", TIF::Ioc), 0);  // not an IPO symbol
}

// ---------------------------------------------------------------- symbol lists

TEST_F(Risk, Restricted0022) {
  start({lim(kA, RiskKind::Restricted, 1, "AAPL")});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), C(RR::RiskRestrictedStock));
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 190'000, "MSFT"), 0);
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 990'000), 0);
}

TEST_F(Risk, LocateRequired0027) {
  start({lim(kA, RiskKind::HardToBorrow, 1, "AAPL")});
  ouch50::TagSet located;
  located.set_shares_located(ouch50::SharesLocated::Yes);
  EXPECT_EQ(enter(1, 1, OS::SellShort, 100, 1'010'000), C(RR::RiskLocateRequired));
  EXPECT_EQ(enter(1, 2, OS::SellShortExempt, 100, 1'010'000), C(RR::RiskLocateRequired));
  EXPECT_EQ(enter(1, 3, OS::SellShort, 100, 1'010'000, "AAPL", TIF::Day, located), 0);
  EXPECT_EQ(enter(1, 4, OS::Sell, 100, 1'010'000), 0);
  EXPECT_EQ(enter(1, 5, OS::SellShort, 100, 210'000, "MSFT"), 0);
}

// ---------------------------------------------------------------- size and notional

TEST_F(Risk, MaxQuantity0031) {
  start({lim(kA, RiskKind::MaxOrderQty, 500)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 501, 990'000), C(RR::RiskMaxQuantityExceeded));
  EXPECT_EQ(enter(1, 2, OS::Buy, 500, 990'000), 0);
}

TEST_F(Risk, Adv0025) {
  start({lim(kA, RiskKind::AdvPct, 10)});  // 10% of AAPL's 10,000
  EXPECT_EQ(enter(1, 1, OS::Buy, 1'001, 990'000), C(RR::RiskExceedsAdvLimit));
  EXPECT_EQ(enter(1, 2, OS::Buy, 1'000, 990'000), 0);
  EXPECT_EQ(enter(1, 3, OS::Buy, 5'000, 190'000, "MSFT"), 0);  // no ADV: no check
}

TEST_F(Risk, OrderNotional0030) {
  start({lim(kA, RiskKind::MaxOrderNotional, kNot100)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 101, kP100), C(RR::RiskSingleOrderNotionalExceeded));
  // A market order is valued at the NBO, else the last sale, else the prior close ($100).
  EXPECT_EQ(enter(1, 3, OS::Sell, 101, kMkt, "AAPL", TIF::Ioc), C(RR::RiskSingleOrderNotionalExceeded));
  EXPECT_EQ(enter(1, 4, OS::Sell, 100, kMkt, "AAPL", TIF::Ioc), 0);  // fills against the 100 @100 bid
}

// ---------------------------------------------------------------- price protection

TEST_F(Risk, LimitOrderProtection0006) {
  start({lim(kB, RiskKind::Lop, 0)});
  // No NBO and no last sale: no reference, no check (the prior close is not used).
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 1'500'000), 0);
  EXPECT_EQ(code(send(1, cancel_msg(1, 0))), 0xFFFF);
  EXPECT_EQ(enter(2, 1, OS::Sell, 100, kP100), 0);  // NBO 100.00
  EXPECT_EQ(enter(2, 2, OS::Buy, 100, 900'000), 0);  // NBB 90.00
  // Buys: max(10% of 100.00, $0.50) = $10.00 through the NBO at most.
  EXPECT_EQ(enter(1, 2, OS::Buy, 10, 1'100'100), C(RR::FatFinger));
  EXPECT_EQ(enter(1, 3, OS::Buy, 10, 1'100'000), 0);
  // Sells: $9.00 below the NBB at most.
  EXPECT_EQ(enter(1, 4, OS::Sell, 10, 809'900), C(RR::FatFinger));
  EXPECT_EQ(enter(1, 5, OS::Sell, 10, 810'000), 0);
  // Off for account B; cross orders are exempt; halted symbols are exempt.
  EXPECT_EQ(enter(2, 3, OS::Buy, 10, 1'500'000), 0);
  (void)admin(AdminCommand::Halt, AdminArgsBuilder{}.symbol("AAPL"));
  EXPECT_EQ(enter(1, 6, OS::Buy, 10, 1'500'000), 0);
}

TEST_F(Risk, FatFinger0026) {
  start({lim(kA, RiskKind::FatFingerBps, 100), lim(kA, RiskKind::FatFingerAbs, 3'000), lim(kB, RiskKind::Lop, 0)});
  EXPECT_EQ(enter(2, 1, OS::Sell, 100, kP100), 0);  // NBO 100.00
  EXPECT_EQ(enter(1, 1, OS::Buy, 10, 1'003'100), C(RR::RiskFatFinger));  // $0.31 through > $0.30
  EXPECT_EQ(enter(1, 2, OS::Buy, 10, 1'003'000), 0);
  EXPECT_EQ(enter(2, 2, OS::Buy, 100, kP100 - 100'000), 0);  // NBB 90.00
  EXPECT_EQ(enter(1, 3, OS::Sell, 10, 900'000 - 9'100), C(RR::RiskFatFinger));  // 1.01% > 1%
}

TEST_F(Risk, MarketImpact0021) {
  start({lim(kA, RiskKind::Permissions, kNoThroughBand)});
  (void)admin(AdminCommand::LuldBands,
              AdminArgsBuilder{}.symbol("AAPL").i64(AdminTag::Lower, 950'000).i64(AdminTag::Upper, 1'050'000));
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 1'050'100), C(RR::RiskMarketImpact));
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 1'050'000), 0);
  EXPECT_EQ(enter(1, 3, OS::Sell, 100, 949'900), C(RR::RiskMarketImpact));
  EXPECT_EQ(enter(2, 1, OS::Sell, 100, 949'900), 0);
}

// ---------------------------------------------------------------- exposure

TEST_F(Risk, SymbolNotional001F) {
  start({lim(kA, RiskKind::SymbolNotional, 2 * kNot100, "AAPL")});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(1, 3, OS::Buy, 1, kP100), C(RR::ExceedsMaxAllowedNotional));
  EXPECT_EQ(enter(1, 4, OS::Buy, 10'000, 190'000, "MSFT"), 0);  // per symbol
  (void)send(1, cancel_msg(1, 50));                                // releases 50 shares
  EXPECT_EQ(enter(1, 5, OS::Buy, 50, kP100), 0);
  EXPECT_EQ(enter(1, 6, OS::Buy, 1, kP100), C(RR::ExceedsMaxAllowedNotional));
}

TEST_F(Risk, GrossExposureCountsExecutions0020) {
  start({lim(kA, RiskKind::GrossExposure, 3 * kNot100)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(2, 1, OS::Sell, 100, kP100), 0);  // executes: A open 0, executed 100 x $100
  EXPECT_EQ(static_cast<std::int64_t>(eng_.risk().executed(0)), kNot100);
  EXPECT_EQ(static_cast<std::int64_t>(eng_.risk().open(0)), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 200, kP100), 0);
  EXPECT_EQ(enter(1, 3, OS::Buy, 1, 10'000), C(RR::RiskAggregateExposureExceeded));
}

// ---------------------------------------------------------------- duplicates

TEST_F(Risk, Duplicate002A) {
  start({lim(kA, RiskKind::DupWindowSec, 2)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000), C(RR::RiskDuplicateMsgRateRestriction));
  EXPECT_EQ(enter(3, 3, OS::Buy, 100, 990'000), C(RR::RiskDuplicateMsgRateRestriction));  // per account
  EXPECT_EQ(enter(1, 4, OS::Buy, 100, 989'900), 0);
  EXPECT_EQ(enter(1, 5, OS::Buy, 101, 990'000), 0);
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 990'000), 0);
  later(1'000'000'000);
  EXPECT_EQ(enter(1, 6, OS::Buy, 100, 990'000), C(RR::RiskDuplicateMsgRateRestriction));
  later(1'000'000'000);  // two seconds after the first: outside the window
  EXPECT_EQ(enter(1, 7, OS::Buy, 100, 990'000), 0);
}

// ---------------------------------------------------------------- check order

TEST_F(Risk, FirstFailingCheckNamesTheCode) {
  start({lim(kA, RiskKind::Restricted, 1, "AAPL"), lim(kA, RiskKind::MaxOrderQty, 10),
         lim(kA, RiskKind::Permissions, kNoShortSell)});
  EXPECT_EQ(enter(1, 1, OS::SellShort, 100, 1'010'000), C(RR::RiskShortSellNotAllowed));  // 3 before 4 and 6
  EXPECT_EQ(enter(1, 2, OS::Sell, 100, 1'010'000), C(RR::RiskRestrictedStock));          // 4 before 6
  EXPECT_EQ(enter(1, 3, OS::Sell, 100, 210'000, "MSFT"), C(RR::RiskMaxQuantityExceeded));
  // Validation and the state gate come before risk.
  EXPECT_EQ(enter(1, 4, OS::Sell, 100, 1'010'050), C(RR::InvalidPrice));
}

// ---------------------------------------------------------------- kill switch

TEST_F(Risk, KillSwitchAdmin) {
  start({});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, 990'000), 0);
  EXPECT_EQ(enter(3, 2, OS::Buy, 100, 980'000, "MSFT"), 0);
  EXPECT_EQ(enter(2, 1, OS::Buy, 100, 970'000), 0);
  const auto k = admin(AdminCommand::KillSwitch, AdminArgsBuilder{}.u32(AdminTag::Account, kA));
  EXPECT_EQ(count(k, 'C'), 2);       // every order of the account, reason 'S'
  EXPECT_EQ(count(k, 'D', true), 2);  // and their ITCH deletes
  for (const Out& o : k)
    if (!o.itch && !o.is_audit && static_cast<char>(o.b[0]) == 'C') EXPECT_EQ(static_cast<char>(o.b[17]), 'S');
  EXPECT_EQ(eng_.live_orders(), 1u);
  EXPECT_EQ(enter(1, 3, OS::Buy, 100, 990'000), C(RR::FirmNotAuthorized));
  EXPECT_EQ(enter(3, 4, OS::Buy, 100, 990'000), C(RR::FirmNotAuthorized));
  EXPECT_EQ(enter(2, 2, OS::Buy, 100, 990'000), 0);
  EXPECT_TRUE(admin(AdminCommand::KillReset, AdminArgsBuilder{}.u32(AdminTag::Account, kA)).empty());
  EXPECT_EQ(enter(1, 5, OS::Buy, 100, 990'000), 0);
  EXPECT_TRUE(audited(admin(AdminCommand::KillSwitch, AdminArgsBuilder{}.u32(AdminTag::Account, 999)),
                      AuditCode::UnhandledRecord));
}

TEST_F(Risk, KillExposureLatchesAfterTheRecord) {
  start({lim(kA, RiskKind::KillExposure, kNot100 / 2)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000), 0);
  const auto out = send(2, enter_msg({.urn = 1, .side = OS::Sell, .qty = 100, .price = kP100}));
  // The execution first ('A', both 'E', ITCH 'E'), then A's other order cancels ('C' 'S', 'D').
  ASSERT_GE(out.size(), 6u);
  EXPECT_EQ(static_cast<char>(out[0].b[0]), 'A');
  EXPECT_EQ(static_cast<char>(out[out.size() - 2].b[0]), 'C');
  EXPECT_EQ(static_cast<char>(out[out.size() - 2].b[17]), 'S');
  EXPECT_TRUE(eng_.risk().killed(0));
  EXPECT_EQ(enter(1, 3, OS::Buy, 100, 990'000), C(RR::FirmNotAuthorized));
}

// The kill switch during a cross (05 §7 "kill_switch_during_cross"): the closing
// cross executes the account's MOC; its executed notional crosses KillExposure;
// after the whole cross is reported ('E's, 'Q') the account's other orders cancel.
TEST_F(Risk, KillExposureDuringTheClosingCross) {
  start({lim(kA, RiskKind::KillExposure, kNot100 / 2)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kMkt, "AAPL", TIF::Day, {}, ouch50::CrossType::Closing), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 995'000), 0);  // a resting Day order (bid 99.50: the close threshold window holds 100.00)
  EXPECT_EQ(enter(2, 1, OS::Sell, 100, kP100, "AAPL", TIF::Day, {}, ouch50::CrossType::Closing), 0);
  sc_.set_time(hms_ns(16, 0, 0));
  const auto out = run(sc_.add(RecordType::Timer, encode_timer(TimerRecord{2, TimerKind::Cross, sc_.midnight() + hms_ns(16, 0, 0)})));
  std::string seq;
  for (const Out& o : out)
    if (!o.is_audit) seq += o.itch ? std::string("i") + static_cast<char>(o.b[0]) : std::string("o") + static_cast<char>(o.b[0]);
  // OUCH E (buyer), OUCH E (seller), ITCH Q AAPL, ITCH Q MSFT, then the kill: OUCH C 'S', ITCH D.
  EXPECT_EQ(seq, "oEoEiQiQoCiD");
  EXPECT_TRUE(eng_.risk().killed(0));
  EXPECT_EQ(eng_.live_orders(), 0u);
}

// ---------------------------------------------------------------- replace, Admin, table

TEST_F(Risk, ReplaceRejectedKeepsTheOriginal) {
  start({lim(kA, RiskKind::MaxOrderQty, 500), lim(kA, RiskKind::GrossExposure, kNot100)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  // Gross: the replace releases the original's 100 x $100 first.
  EXPECT_EQ(code(send(1, replace_msg({.orig = 1, .urn = 2, .qty = 100, .price = 990'000}))), 0);
  EXPECT_EQ(code(send(1, replace_msg({.orig = 2, .urn = 3, .qty = 600, .price = 990'000}))),
            C(RR::RiskMaxQuantityExceeded));
  EXPECT_EQ(eng_.live_orders(), 1u);
  EXPECT_EQ(count(send(1, cancel_msg(2, 0)), 'C'), 1);  // still live under UserRefNum 2
  EXPECT_EQ(enter(1, 4, OS::Buy, 100, 990'000), 0);     // 3 was consumed by the reject
}

TEST_F(Risk, AdminRiskLimitChangesApplyAtTheirRecord) {
  start({});
  EXPECT_EQ(enter(1, 1, OS::Buy, 600, 990'000), 0);
  EXPECT_TRUE(admin(AdminCommand::RiskLimit, AdminArgsBuilder{}
                                                 .u32(AdminTag::Account, kA)
                                                 .u16(AdminTag::Kind, static_cast<std::uint16_t>(RiskKind::MaxOrderQty))
                                                 .i64(AdminTag::Value, 500))
                  .empty());
  EXPECT_EQ(enter(1, 2, OS::Buy, 600, 990'000), C(RR::RiskMaxQuantityExceeded));
  // Invalid values are refused (audited) and change nothing.
  EXPECT_TRUE(audited(admin(AdminCommand::RiskLimit, AdminArgsBuilder{}
                                                         .u32(AdminTag::Account, kA)
                                                         .u16(AdminTag::Kind, static_cast<std::uint16_t>(RiskKind::Lop))
                                                         .i64(AdminTag::Value, 2)),
                      AuditCode::UnhandledRecord));
  EXPECT_TRUE(audited(admin(AdminCommand::RiskLimit,
                            AdminArgsBuilder{}
                                .u32(AdminTag::Account, kA)
                                .u16(AdminTag::Kind, static_cast<std::uint16_t>(RiskKind::MaxOrderQty))
                                .i64(AdminTag::Value, 1)
                                .symbol("AAPL")),
                      AuditCode::UnhandledRecord));
  EXPECT_EQ(enter(1, 3, OS::Buy, 500, 990'000), 0);
  // A per-symbol notional limit set mid-day counts the orders already open.
  EXPECT_TRUE(admin(AdminCommand::RiskLimit,
                    AdminArgsBuilder{}
                        .u32(AdminTag::Account, kA)
                        .u16(AdminTag::Kind, static_cast<std::uint16_t>(RiskKind::SymbolNotional))
                        .i64(AdminTag::Value, std::int64_t{1'100} * 990'000)
                        .symbol("AAPL"))
                  .empty());
  EXPECT_EQ(static_cast<std::int64_t>(eng_.risk().symbol_open(0, 1)), std::int64_t{1'100} * 990'000);
  EXPECT_EQ(enter(1, 4, OS::Buy, 1, 990'000), C(RR::ExceedsMaxAllowedNotional));
}

TEST_F(Risk, InvalidTableIsRejectedWhole) {
  sc_.day_start();
  std::array<SymbolEntry, 1> syms{};
  syms[0].symbol = Symbol8("AAPL");
  std::array<AccountEntry, 1> accts{};
  accts[0].account_id = kA;
  accts[0].firms[0] = Mpid4("FIRM");
  std::array<SessionEntry, 1> sess{};
  sess[0] = SessionEntry{1, kA, SessionEntry::kMarketOrders, 'N'};
  sc_.symbols(syms);
  sc_.accounts(accts);
  sc_.sessions(sess);
  std::vector<RiskEntry> good = {lim(kA, RiskKind::MaxOrderQty, 500)};
  sc_.risk(good);
  std::vector<std::vector<RiskEntry>> bad = {
      {lim(kA, RiskKind::MaxOrderQty, 10), lim(999, RiskKind::MaxOrderQty, 10)},  // unknown account
      {lim(kA, RiskKind::MaxOrderQty, 10), lim(kA, RiskKind::Lop, 2)},           // invalid value
      {lim(kA, RiskKind::MaxOrderQty, 10, "AAPL")},                              // not per symbol
      {lim(kA, RiskKind::Restricted, 1, "NOPE")},                                // unknown symbol
      {lim(kA, RiskKind::DupWindowSec, 31)},
      {lim(kA, RiskKind::MaxOrderQty, -1)},
      {lim(kA, static_cast<RiskKind>(16), 1)},
      {lim(kA, RiskKind::Permissions, 128)},                                     // unknown permission bit
      {lim(kA, RiskKind::PortRate, RiskGate::kMaxRate + 1)},
      {lim(kA, RiskKind::SymbolRate, RiskGate::kMaxRate + 1)},
      {lim(kA, RiskKind::Restricted, 1)},                                        // needs a symbol
      {lim(kA, RiskKind::HardToBorrow, 2, "AAPL")},                              // 0 or 1
  };
  for (const auto& t : bad) sc_.risk(t);
  sc_.schedule(params_only('R'));
  int rejected = 0;
  for (std::size_t i = 0; i < sc_.size(); ++i) {
    sink_.v.clear();
    eng_.apply(sc_[i], sink_);
    rejected += audited(sink_.v, AuditCode::ConfigRejected) ? 1 : 0;
  }
  EXPECT_EQ(rejected, static_cast<int>(bad.size()));
  EXPECT_EQ(enter(1, 1, OS::Buy, 501, 990'000), C(RR::RiskMaxQuantityExceeded));
  EXPECT_EQ(enter(1, 2, OS::Buy, 500, 990'000), 0);
}

TEST_F(Risk, ReloadingAccountsClearsLimits) {
  sc_.day_start();
  std::array<SymbolEntry, 1> syms{};
  syms[0].symbol = Symbol8("AAPL");
  std::array<AccountEntry, 1> accts{};
  accts[0].account_id = kA;
  std::array<SessionEntry, 1> sess{};
  sess[0] = SessionEntry{1, kA, SessionEntry::kMarketOrders, 'N'};
  sc_.symbols(syms);
  sc_.accounts(accts);
  sc_.sessions(sess);
  std::vector<RiskEntry> good = {lim(kA, RiskKind::MaxOrderQty, 500)};
  sc_.risk(good);
  sc_.accounts(accts);
  sc_.sessions(sess);
  sc_.schedule(params_only('R'));
  for (std::size_t i = 0; i < sc_.size(); ++i) eng_.apply(sc_[i], sink_);
  EXPECT_EQ(enter(1, 1, OS::Buy, 501, 990'000), 0);
}

// The gate's state (buckets, duplicate filter, exposure, kill switches, rules)
// survives a snapshot: a restored engine continues identically.
TEST_F(Risk, SnapshotRoundTripContinuesIdentically) {
  start({lim(kA, RiskKind::PortRate, 3), lim(kA, RiskKind::DupWindowSec, 5), lim(kA, RiskKind::GrossExposure, 5 * kNot100),
         lim(kA, RiskKind::SymbolNotional, 3 * kNot100), lim(kB, RiskKind::HardToBorrow, 1, "AAPL"),
         lim(kB, RiskKind::KillExposure, kNot100 * 10)});
  EXPECT_EQ(enter(1, 1, OS::Buy, 100, kP100), 0);
  EXPECT_EQ(enter(2, 1, OS::Sell, 50, kP100), 0);
  EXPECT_EQ(enter(1, 2, OS::Buy, 100, 990'000), 0);
  std::vector<std::byte> snap;
  eng_.snapshot(snap);
  Engine copy;
  ASSERT_TRUE(copy.restore(snap));
  EXPECT_EQ(copy.state_hash(), eng_.state_hash());
  std::string err;
  EXPECT_TRUE(copy.check(&err)) << err;
  // Continue both with the same records.
  for (int i = 0; i < 40; ++i) {
    const auto& r = sc_.ouch(i % 2 == 0 ? 1 : 2, i % 2 == 0 ? kA : kB,
                             enter_msg({.urn = static_cast<UserRefNum>(10 + i),
                                        .side = i % 3 == 0 ? OS::Sell : OS::Buy,
                                        .qty = static_cast<Qty>(10 + i % 4),
                                        .price = static_cast<std::uint64_t>(990'000 + 100 * (i % 5))}));
    if (i % 7 == 0) later(300'000'000);
    Sink a, b;
    eng_.apply(r, a);
    copy.apply(r, b);
    ASSERT_EQ(a.v.size(), b.v.size()) << i;
    for (std::size_t k = 0; k < a.v.size(); ++k) EXPECT_EQ(a.v[k].b, b.v[k].b) << i;
  }
  EXPECT_EQ(copy.state_hash(), eng_.state_hash());
}

}  // namespace
}  // namespace lle::engine

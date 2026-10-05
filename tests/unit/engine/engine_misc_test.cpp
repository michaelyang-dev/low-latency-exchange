// Record handling around the matching core: payload and session checks,
// configuration freezing, day reset, KeepCrossOrders, audits.
#include <gtest/gtest.h>

#include "engine_test_util.h"

namespace lle::engine::testing {
namespace {

using ouch50::Side;

TEST_F(EngineFixture, UnknownSessionAndAccountMismatchAreDropped) {
  auto u = run(sc_.ouch(77, kAcctA, enter_msg({.urn = 1})));
  EXPECT_TRUE(has_audit(u, AuditCode::UnknownSession));
  auto m = run(sc_.ouch(kSessA, kAcctB, enter_msg({.urn = 1})));
  EXPECT_TRUE(has_audit(m, AuditCode::AccountMismatch));
  EXPECT_EQ(eng_.live_orders(), 0u);
  // Neither consumed UserRefNum 1.
  auto ok = a(enter_msg({.urn = 1}));
  ASSERT_EQ(ok.size(), 2u);
  EXPECT_EQ(ok[0].type(), 'A');
}

TEST_F(EngineFixture, MalformedPayloadsAndUnknownRecordsAreAudited) {
  EXPECT_TRUE(has_audit(run(sc_.add(RecordType::OuchInbound, {std::byte{1}})), AuditCode::MalformedPayload));
  EXPECT_TRUE(has_audit(run(sc_.add(RecordType::Timer, {})), AuditCode::MalformedPayload));
  EXPECT_TRUE(has_audit(run(sc_.add(static_cast<RecordType>(99), {})), AuditCode::UnhandledRecord));
  EXPECT_TRUE(run(sc_.add(RecordType::SnapshotMark, {})).empty());
  // A consuming message too short to carry its UserRefNum, and an invalid cancel.
  EXPECT_TRUE(has_audit(a(std::vector<std::byte>{std::byte{'O'}, std::byte{0}}), AuditCode::NoUserRefNum));
  EXPECT_TRUE(has_audit(a(std::vector<std::byte>{std::byte{'X'}, std::byte{0}}), AuditCode::InvalidNoReject));
}

TEST_F(EngineFixture, ConfigFreezesAtFirstOrderAndDayStartResets) {
  (void)a(enter_msg({.urn = 1}));
  std::array<SymbolEntry, 1> s{};
  s[0].symbol = Symbol8("LATE");
  EXPECT_TRUE(has_audit(run(sc_.symbols(s)), AuditCode::ConfigRejected));
  EXPECT_EQ(eng_.find_symbol(Symbol8("LATE")), 0);
  const std::uint64_t h = eng_.state_hash();
  (void)run(sc_.day_start());
  EXPECT_NE(eng_.state_hash(), h);
  EXPECT_EQ(eng_.live_orders(), 0u);
  EXPECT_EQ(eng_.next_ref(), 1u);
  EXPECT_EQ(eng_.symbols(), 0u);
  auto out = run(sc_.symbols(s));
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].type(), 'R');
  EXPECT_EQ(out[1].type(), 'Y');
  EXPECT_EQ(eng_.find_symbol(Symbol8("LATE")), 1);
}

TEST_F(EngineFixture, BadConfigTablesAreRejectedWhole) {
  (void)run(sc_.day_start());
  std::array<SymbolEntry, 2> dup{};
  dup[0].symbol = Symbol8("DUP");
  dup[1].symbol = Symbol8("DUP");
  EXPECT_TRUE(has_audit(run(sc_.symbols(dup)), AuditCode::ConfigRejected));
  std::array<SymbolEntry, 1> tick{};
  tick[0].symbol = Symbol8("BAD");
  tick[0].tick = 3;  // does not divide $1.00
  EXPECT_TRUE(has_audit(run(sc_.symbols(tick)), AuditCode::ConfigRejected));
  EXPECT_EQ(eng_.symbols(), 0u);
  std::array<SessionEntry, 1> orphan{};
  orphan[0] = SessionEntry{5, 999, 0, 'N'};  // no such account
  EXPECT_TRUE(has_audit(run(sc_.sessions(orphan)), AuditCode::ConfigRejected));
}

TEST_F(EngineFixture, ScheduleBoundsMalformedDayStartAndChunkOrder) {
  (void)run(sc_.day_start());
  const auto param = [](Param p, std::int64_t v) {
    ScheduleEntry e;
    e.arg = static_cast<std::uint16_t>(p);
    e.time_ns = v;
    return e;
  };
  // Parameters beyond their bounds reject the whole table (MarketParams::valid).
  for (const ScheduleEntry& e : {param(Param::ThresholdBps, 100'001), param(Param::PriceTestBps, std::int64_t{1} << 60),
                                 param(Param::ThresholdMin, kPxMaxLimit + 1), param(Param::PriceTests, 8),
                                 param(Param::HaltPeriodSec, 86'401), param(Param::LimitStateSec, -1)}) {
    const std::array<ScheduleEntry, 1> t{e};
    EXPECT_TRUE(has_audit(run(sc_.schedule(t)), AuditCode::ConfigRejected)) << e.arg;
  }
  const std::array<ScheduleEntry, 3> edge{param(Param::ThresholdBps, 100'000), param(Param::PriceTestMin, kPxMaxLimit),
                                          param(Param::ExtensionSec, 86'400)};
  EXPECT_FALSE(has_audit(run(sc_.schedule(edge)), AuditCode::ConfigRejected));

  EXPECT_TRUE(has_audit(run(sc_.add(RecordType::DayStart, {std::byte{1}})), AuditCode::MalformedPayload));

  // A table in several chunks applies only when they arrive in order.
  std::vector<SymbolEntry> many(kMaxConfigChunkBytes / SymbolEntry::kLen + 10);
  for (std::size_t i = 0; i < many.size(); ++i) {
    const char name[4] = {static_cast<char>('A' + i / 676), static_cast<char>('A' + i / 26 % 26),
                          static_cast<char>('A' + i % 26), '\0'};
    many[i].symbol = Symbol8(name);
  }
  const auto chunks = config_chunks(ConfigTable::Symbols, encode_symbols(many));
  ASSERT_EQ(chunks.size(), 2u);
  EXPECT_TRUE(has_audit(run(sc_.add(RecordType::Config, chunks[1])), AuditCode::ConfigRejected));
  EXPECT_TRUE(run(sc_.add(RecordType::Config, chunks[0])).empty());
  EXPECT_TRUE(run(sc_.add(RecordType::Config, chunks[0])).empty());  // chunk 0 again restarts the table
  (void)run(sc_.add(RecordType::Config, chunks[1]));
  EXPECT_EQ(eng_.symbols(), many.size());
}

TEST_F(EngineFixture, LogoutDoesNotCancelButLastDisconnectDoes) {
  (void)run(sc_.session_event(kSessB, 0, SessionEventKind::Login));
  (void)b(enter_msg({.urn = 1}));
  EXPECT_TRUE(run(sc_.session_event(kSessB, 0, SessionEventKind::Logout)).empty());
  EXPECT_EQ(eng_.live_orders(), 1u);
  // Disconnect of an instance that is not live changes nothing.
  EXPECT_TRUE(run(sc_.session_event(kSessB, 0, SessionEventKind::Disconnect)).empty());
  (void)run(sc_.session_event(kSessB, 2, SessionEventKind::Login));
  auto out = run(sc_.session_event(kSessB, 2, SessionEventKind::Disconnect));
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].type(), 'C');
  EXPECT_EQ(eng_.live_orders(), 0u);
}

TEST_F(EngineFixture, ReplaceSideTagRemarksButCannotFlipDirection) {
  (void)a(enter_msg({.urn = 1, .side = Side::Sell, .qty = 100}));
  ouch50::TagSet t;
  t.set_side(Side::SellShort);
  auto ok = a(replace_msg({.orig = 1, .urn = 2, .qty = 100}, t));
  ASSERT_GE(ok.size(), 1u);
  ASSERT_EQ(ok[0].type(), 'U');
  EXPECT_EQ(ouch50::out::OrderReplacedView(ok[0].bytes).side(), Side::SellShort);
  ouch50::TagSet flip;
  flip.set_side(Side::Buy);
  auto bad = a(replace_msg({.orig = 2, .urn = 3, .qty = 100}, flip));
  ASSERT_EQ(bad.size(), 2u);  // invalid details: the original is cancelled
  EXPECT_EQ(bad[0].type(), 'C');
  EXPECT_EQ(eng_.live_orders(), 0u);
}

TEST_F(EngineFixture, NonIocTimeInForceValuesRest) {
  ouch50::TagSet gtt;
  gtt.set_expire_time(57'600);
  (void)a(enter_msg({.urn = 1, .tif = ouch50::TimeInForce::Gtt}, gtt));
  (void)a(enter_msg({.urn = 2, .tif = ouch50::TimeInForce::Gtx}));
  (void)a(enter_msg({.urn = 3, .tif = ouch50::TimeInForce::AfterHours}));
  EXPECT_EQ(eng_.live_orders(), 3u);
  // A GTT replace keeps the original's ExpireTime when it is not restated.
  auto r = a(replace_msg({.orig = 1, .urn = 4, .qty = 50, .tif = ouch50::TimeInForce::Gtt}));
  ASSERT_GE(r.size(), 1u);
  EXPECT_EQ(r[0].type(), 'U');
}

TEST_F(EngineFixture, MassCancelSideAndGroupFilters) {
  ouch50::TagSet g1;
  g1.set_group_id(1);
  (void)a(enter_msg({.urn = 1, .side = Side::Buy, .price = 990'000}, g1));
  (void)a(enter_msg({.urn = 2, .side = Side::Sell, .price = 1'010'000}, g1));
  (void)a(enter_msg({.urn = 3, .side = Side::SellShort, .price = 1'020'000}));
  ouch50::TagSet sells;
  sells.set_side(Side::Sell);
  auto o = a(mass_cancel_msg(4, "", "", sells));  // blank firm = default firm; S covers S/T/E
  std::size_t cancels = 0;
  for (const Msg& m : o) cancels += m.dest == Dest::Ouch && m.type() == 'C' ? 1u : 0u;
  EXPECT_EQ(cancels, 2u);
  ouch50::TagSet grp;
  grp.set_group_id(2);
  o = a(mass_cancel_msg(5, "FIRM", "", grp));
  ASSERT_EQ(o.size(), 1u);  // only the 'X' response: no order in group 2
  EXPECT_EQ(o[0].type(), 'X');
  EXPECT_EQ(eng_.live_orders(), 1u);
}

// KeepCrossOrders spares cross orders (here an LOC) on cancel-on-disconnect.
TEST(EngineKeepCross, DisconnectSparesCrossOrdersWhenConfigured) {
  Scenario sc;
  Engine e;
  BufferSink sink;
  sc.day_start();
  std::array<SymbolEntry, 2> syms{};
  syms[0].symbol = Symbol8("AAPL");
  syms[1].symbol = Symbol8("MSFT");
  std::array<AccountEntry, 1> accts{};
  accts[0].account_id = 1;
  accts[0].firms[0] = Mpid4("FIRM");
  std::array<SessionEntry, 1> sess{};
  sess[0] = SessionEntry{1, 1, SessionEntry::kCancelOnDisconnect | SessionEntry::kKeepCrossOrders, 'N'};
  sc.symbols(syms);
  sc.accounts(accts);
  sc.sessions(sess);
  sc.session_event(1, 0, SessionEventKind::Login);
  sc.ouch(1, 1, enter_msg({.urn = 1, .side = Side::Buy, .symbol = "AAPL"}));
  sc.ouch(1, 1, enter_msg({.urn = 2, .side = Side::Sell, .symbol = "MSFT", .cross = ouch50::CrossType::Closing}));
  for (const InputRecord& r : sc.records()) e.apply(r, sink);
  ASSERT_EQ(e.live_orders(), 2u);
  sink.clear();
  e.apply(sc.session_event(1, 0, SessionEventKind::Disconnect), sink);
  std::size_t cancels = 0;
  for (const auto& en : sink.entries())
    if (en.dest == Dest::Ouch && sink.bytes(en)[0] == std::byte{'C'}) ++cancels;
  EXPECT_EQ(cancels, 1u);  // only the continuous AAPL order
  EXPECT_EQ(e.live_orders(), 1u);
  std::string err;
  EXPECT_TRUE(e.check(&err)) << err;
}

}  // namespace
}  // namespace lle::engine::testing

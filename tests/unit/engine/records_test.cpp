// Record payload layouts (engine/records.h): builders and parsers agree, and
// malformed payloads are refused.
#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "engine/records.h"

namespace lle::engine {
namespace {

TEST(Records, DayStartRoundTrip) {
  DayStart in;
  in.date = 20261001;
  in.local_midnight_ns = 1'790'827'200'000'000'000;
  in.build_id = 7;
  in.mold_session = Alpha<10>("MOLD000001");
  const auto p = encode_day_start(in);
  ASSERT_EQ(p.size(), DayStart::kLen);
  const auto d = parse_day_start(p);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->date, 20261001u);
  EXPECT_EQ(d->local_midnight_ns, 1'790'827'200'000'000'000);
  EXPECT_EQ(d->build_id, 7u);
  EXPECT_EQ(d->mold_session, Alpha<10>("MOLD000001"));
  auto bad = p;
  bad[0] = std::byte{2};  // unknown format version
  EXPECT_FALSE(parse_day_start(bad));
  EXPECT_FALSE(parse_day_start(std::span<const std::byte>(p).first(47)));
}

TEST(Records, ConfigTablesRoundTripAndChunk) {
  std::array<SymbolEntry, 2> s{};
  s[0].symbol = Symbol8("AAPL");
  s[1].symbol = Symbol8("HALF");
  s[1].tick = 50;
  s[1].round_lot = 10;
  s[1].prior_close = 123'400;
  s[1].luld_tier = '2';
  s[1].flags = SymbolEntry::kFlagTest;
  s[1].regsho = '2';
  s[1].adv = 9'999;
  const auto body = encode_symbols(s);
  const auto chunks = config_chunks(ConfigTable::Symbols, body);
  ASSERT_EQ(chunks.size(), 1u);
  const auto c = parse_config_chunk(chunks[0]);
  ASSERT_TRUE(c);
  EXPECT_EQ(c->table, ConfigTable::Symbols);
  EXPECT_EQ(c->count, 1u);
  const auto v = parse_table(c->bytes, SymbolEntry::kLen, SymbolEntry::kVersion);
  ASSERT_TRUE(v);
  EXPECT_EQ(v->count, 2u);
  const SymbolEntry e = parse_symbol_entry(v->body.data() + SymbolEntry::kLen);
  EXPECT_EQ(e.symbol, Symbol8("HALF"));
  EXPECT_EQ(e.tick, 50u);
  EXPECT_EQ(e.round_lot, 10u);
  EXPECT_EQ(e.prior_close, 123'400);
  EXPECT_EQ(e.luld_tier, '2');
  EXPECT_EQ(e.flags, SymbolEntry::kFlagTest);
  EXPECT_EQ(e.regsho, '2');
  EXPECT_EQ(e.adv, 9'999u);
  auto trunc = body;
  trunc.pop_back();
  EXPECT_FALSE(parse_table(trunc, SymbolEntry::kLen, SymbolEntry::kVersion));

  // A large table splits into chunks that reassemble to the original bytes.
  const std::vector<ScheduleEntry> sched = standard_schedule();
  const auto big = encode_schedule(sched);
  const auto parts = config_chunks(ConfigTable::Schedule, big);
  ASSERT_GT(parts.size(), 1u);
  std::vector<std::byte> joined;
  for (std::size_t k = 0; k < parts.size(); ++k) {
    const auto pc = parse_config_chunk(parts[k]);
    ASSERT_TRUE(pc);
    EXPECT_EQ(pc->index, k);
    EXPECT_EQ(pc->count, parts.size());
    EXPECT_EQ(pc->table_bytes, big.size());
    joined.insert(joined.end(), pc->bytes.begin(), pc->bytes.end());
  }
  EXPECT_EQ(joined, big);

  std::array<SessionEntry, 1> ss{};
  ss[0] = SessionEntry{9, 7, SessionEntry::kKeepCrossOrders, 'D', LateCrossPolicy::Reject};
  const auto ps = encode_sessions(ss);
  const auto hs = parse_table(ps, SessionEntry::kLen, SessionEntry::kVersion);
  ASSERT_TRUE(hs);
  const SessionEntry se = parse_session_entry(hs->body.data());
  EXPECT_EQ(se.session_id, 9u);
  EXPECT_EQ(se.flags, SessionEntry::kKeepCrossOrders);
  EXPECT_EQ(se.default_aiq, 'D');
  EXPECT_EQ(se.late_cross, LateCrossPolicy::Reject);

  std::array<RiskEntry, 1> rs{};
  rs[0] = RiskEntry{5, RiskKind::Restricted, 1, Symbol8("AAPL")};
  const auto pr = encode_risk(rs);
  const auto hr = parse_table(pr, RiskEntry::kLen, RiskEntry::kVersion);
  ASSERT_TRUE(hr);
  const RiskEntry re = parse_risk_entry(hr->body.data());
  EXPECT_EQ(re.account_id, 5u);
  EXPECT_EQ(re.kind, RiskKind::Restricted);
  EXPECT_EQ(re.value, 1);
  EXPECT_EQ(re.symbol, Symbol8("AAPL"));
}

TEST(Records, StandardScheduleShape) {
  const std::vector<ScheduleEntry> s = standard_schedule();
  std::size_t eoii = 0, noii_open = 0, noii_close = 0, ticks = 0;
  Nanos prev = -1;
  std::uint32_t id = 0;
  for (const ScheduleEntry& e : s) {
    if (e.timer_id == 0) continue;
    EXPECT_EQ(e.timer_id, ++id);
    EXPECT_GE(e.time_ns, prev);
    prev = e.time_ns;
    if (e.kind == TimerKind::Eoii) ++eoii;
    if (e.kind == TimerKind::Noii && e.arg == 'O') ++noii_open;
    if (e.kind == TimerKind::Noii && e.arg == 'C') ++noii_close;
    if (e.kind == TimerKind::Noii && e.arg == 'H') ++ticks;
  }
  EXPECT_EQ(eoii, 18u + 30u);   // every 10 s from 09:25 and 15:50
  EXPECT_EQ(noii_open, 120u);   // every 1 s from 09:28
  EXPECT_EQ(noii_close, 300u);  // every 1 s from 15:55
  EXPECT_EQ(ticks, 16u * 3600u - 1u);
}

TEST(Records, EventPayloadsRoundTrip) {
  const auto se = parse_session_event(encode_session_event(SessionEvent{5, 2, SessionEventKind::InstanceDown, 9}));
  ASSERT_TRUE(se);
  EXPECT_EQ(se->session_id, 5u);
  EXPECT_EQ(se->instance, 2u);
  EXPECT_EQ(se->event, SessionEventKind::InstanceDown);
  EXPECT_EQ(se->requested_seq, 9u);

  const std::vector<std::byte> msg = {std::byte{'Q'}, std::byte{0}, std::byte{0}};
  auto enc = encode_ouch_inbound(OuchInboundHeader{5, 100, 1}, msg);
  const auto oi = parse_ouch_inbound(enc);
  ASSERT_TRUE(oi);
  EXPECT_EQ(oi->hdr.session_id, 5u);
  EXPECT_EQ(oi->hdr.instance, 1u);
  EXPECT_EQ(oi->hdr.account, 100u);
  EXPECT_EQ(oi->msg.size(), 3u);
  enc.resize(enc.size() + 5);  // record padding is tolerated
  EXPECT_TRUE(parse_ouch_inbound(enc));
  enc.resize(17);
  EXPECT_FALSE(parse_ouch_inbound(enc));  // shorter than its length field

  const auto t = parse_timer(encode_timer(TimerRecord{42, TimerKind::Cross, 12345}));
  ASSERT_TRUE(t);
  EXPECT_EQ(t->timer_id, 42u);
  EXPECT_EQ(t->kind, TimerKind::Cross);
  EXPECT_EQ(t->scheduled_ns, 12345);

  const auto admin_bytes = encode_admin(
      AdminCommand::LuldBands, AdminArgsBuilder().symbol("AAPL").i64(AdminTag::Lower, 950'000).i64(AdminTag::Upper, 1'050'000));
  const auto ad = parse_admin(admin_bytes);
  ASSERT_TRUE(ad);
  EXPECT_EQ(ad->hdr.command, static_cast<std::uint16_t>(AdminCommand::LuldBands));
  const auto args = parse_admin_args(ad->args, ad->hdr.tlv_version);
  ASSERT_TRUE(args);
  EXPECT_TRUE(args->has(AdminTag::Symbol));
  EXPECT_EQ(args->symbol, Symbol8("AAPL"));
  EXPECT_EQ(args->lower, 950'000);
  EXPECT_EQ(args->upper, 1'050'000);
  EXPECT_FALSE(args->has(AdminTag::Price));
  // Repeated tags, wrong lengths and unknown tags are refused.
  EXPECT_FALSE(parse_admin_args(AdminArgsBuilder().symbol("A").symbol("B").bytes(), 1));
  EXPECT_FALSE(parse_admin_args(AdminArgsBuilder().u32(AdminTag::Price, 1).bytes(), 1));
  EXPECT_FALSE(parse_admin_args(AdminArgsBuilder().u32(static_cast<AdminTag>(31), 1).bytes(), 1));
  EXPECT_FALSE(parse_admin_args(AdminArgsBuilder().symbol("A").bytes(), 2));
}

}  // namespace
}  // namespace lle::engine

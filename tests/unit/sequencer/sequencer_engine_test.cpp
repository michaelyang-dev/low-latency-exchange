// Sequencer -> journal records -> engine (01 §4 steps 2-3; 06 §3): the
// payload layouts agree, and a day built from the engine's tables
// (seq::EngineDay) drives the engine through its schedule.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "common/endian.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/scenario.h"
#include "sequencer/engine_day.h"
#include "sequencer_test_env.h"

namespace lle::seq::testing {
namespace {

using engine::Engine;
using engine::InputRecord;

// Builds one journal record (canonical seal) and returns its bytes.
template <class P>
std::vector<std::byte> record(const P& p, std::uint64_t index = 7, std::uint16_t flags = 0) {
  std::vector<std::byte> b(journal::record_size(p));
  const journal::Sealer canonical;
  (void)journal::build_record(b.data(), journal::Stamp{index, 1'790'827'200'123'456'789, 3, 0x1234, flags}, p,
                              canonical);
  return b;
}

InputRecord input(const std::vector<std::byte>& b) {
  const auto v = journal::parse_record(b);
  EXPECT_TRUE(v.has_value());
  return engine::to_input(*v);
}

TEST(SequencerEngine, PayloadLayoutsAgree) {
  {
    journal::DayStart d;
    d.trading_date = 20261001;
    d.local_midnight_ns = 1'790'827'200'000'000'000;
    d.build_id = 0xABCDEF;
    d.mold_session = {'L', 'L', 'E', '0', '0', '0', '0', '0', '0', '1'};
    const auto b = record(d);
    const InputRecord r = input(b);
    EXPECT_EQ(r.index, 7u);
    EXPECT_EQ(r.epoch, 3u);
    EXPECT_EQ(r.type, static_cast<std::uint16_t>(engine::RecordType::DayStart));
    const auto e = engine::parse_day_start(r.payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->date, 20261001u);
    EXPECT_EQ(e->local_midnight_ns, d.local_midnight_ns);
    EXPECT_EQ(e->build_id, 0xABCDEFu);
    EXPECT_EQ(e->mold_session, Alpha<10>("LLE0000001"));
  }
  {
    const std::vector<std::byte> body = {std::byte{1}, std::byte{2}, std::byte{3}};  // 3 bytes: padded record
    const journal::ConfigChunk c{journal::ConfigTable::Accounts, 1, 4, 99, body};
    const auto b = record(c);
    const InputRecord r = input(b);
    EXPECT_EQ(r.payload.size() % 8, 0u);
    const auto e = engine::parse_config_chunk(r.payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->table, engine::ConfigTable::Accounts);
    EXPECT_EQ(e->index, 1u);
    EXPECT_EQ(e->count, 4u);
    EXPECT_EQ(e->table_bytes, 99u);
    ASSERT_EQ(e->bytes.size(), 3u);
    EXPECT_EQ(e->bytes[2], std::byte{3});
  }
  {
    const journal::SessionEvent s{42, 3, journal::SessionEventKind::Disconnect, 77};
    const auto e = engine::parse_session_event(input(record(s)).payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->session_id, 42u);
    EXPECT_EQ(e->instance, 3u);
    EXPECT_EQ(e->event, engine::SessionEventKind::Disconnect);
    EXPECT_EQ(e->requested_seq, 77u);
  }
  {
    const auto msg = engine::enter_msg({.urn = 5, .cl_ord_id = "X"});  // 47 bytes: odd, padded
    const journal::OuchInbound o{11, 100, 2, msg};
    const auto b = record(o, 9, journal::kFlagMalformedInput);
    const InputRecord r = input(b);
    EXPECT_EQ(r.flags, engine::kFlagMalformedInput);
    const auto e = engine::parse_ouch_inbound(r.payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->hdr.session_id, 11u);
    EXPECT_EQ(e->hdr.account, 100u);
    EXPECT_EQ(e->hdr.instance, 2u);
    ASSERT_EQ(e->msg.size(), msg.size());
    EXPECT_TRUE(std::equal(msg.begin(), msg.end(), e->msg.begin()));
  }
  {
    const journal::Timer t{17, journal::TimerKind::Cross, 1'790'861'400'000'000'000};
    const auto e = engine::parse_timer(input(record(t)).payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->timer_id, 17u);
    EXPECT_EQ(e->kind, engine::TimerKind::Cross);
    EXPECT_EQ(e->scheduled_ns, t.scheduled_ns);
  }
  {
    const auto args = engine::AdminArgsBuilder{}.symbol("AAPL").reason("T1").bytes();
    const journal::Admin a{1, 1, 900, args};
    const auto b = record(a);
    const auto e = engine::parse_admin(input(b).payload);
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->hdr.command, 1u);
    EXPECT_EQ(e->hdr.tlv_version, 1u);
    EXPECT_EQ(e->hdr.operator_id, 900u);
    const auto parsed = engine::parse_admin_args(e->args, e->hdr.tlv_version);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->symbol, Symbol8("AAPL"));
  }
}

struct Out {
  bool itch;
  std::uint32_t session;
  std::vector<std::byte> b;
};
struct Sink {
  std::vector<Out> v;
  void itch(std::uint64_t, std::span<const std::byte> b) { v.push_back(Out{true, 0, {b.begin(), b.end()}}); }
  void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
    v.push_back(Out{false, s, {b.begin(), b.end()}});
  }
  void audit(std::uint64_t, const engine::AuditEvent&) {}
};

constexpr Nanos kMidnight = engine::Scenario::kMidnight;

class Day {
 public:
  Day()
      : syms_(symbols()), accts_(accounts()), sess_(sessions()), sched_(engine::standard_schedule(false, false)),
        day_(EngineTables{syms_, accts_, sess_, {}, sched_}, kMidnight),
        rig_(std::size_t{1} << 22, std::vector<ScheduleEntry>(day_.timers().begin(), day_.timers().end())) {
    rig_.clock.real = kMidnight + hms_ns(3, 59, 0);
    rig_.clock.step = 1'000;
    journal::DayStart ds;
    ds.trading_date = 20261001;
    ds.local_midnight_ns = kMidnight;
    EXPECT_TRUE(rig_.seq->start_day(ds, day_.config(), 1, 7).has_value());
    drain();
  }

  // Moves the clock to `t` (since midnight) and runs the sequencer until idle.
  void at(Nanos t) {
    if (kMidnight + t > rig_.clock.real) rig_.clock.real = kMidnight + t;
    while (rig_.seq->poll()) drain();
    drain();
  }
  void login(std::uint32_t s) {
    ASSERT_TRUE(rig_.sessions->try_push(SessionEventMsg{s, 0, journal::SessionEventKind::Login, 0}));
  }
  void ouch(std::uint32_t s, std::uint32_t account, const std::vector<std::byte>& m) {
    InboundMsg in;
    in.session_id = s;
    in.account = account;
    in.len = static_cast<std::uint16_t>(m.size());
    std::copy(m.begin(), m.end(), in.bytes);
    ASSERT_TRUE(rig_.ouch->try_push(in));
  }
  void admin(engine::AdminCommand c, const engine::AdminArgsBuilder& args) {
    AdminMsg a;
    a.command = static_cast<std::uint16_t>(c);
    a.operator_id = 900;
    a.len = static_cast<std::uint32_t>(args.bytes().size());
    std::copy(args.bytes().begin(), args.bytes().end(), a.args);
    ASSERT_TRUE(rig_.admin->try_push(a));
  }

  // Journaled records so far, as raw bytes.
  const std::vector<std::vector<std::byte>>& records() const { return recs_; }
  [[nodiscard]] std::size_t timers_in_journal() const {
    std::size_t n = 0;
    for (const auto& b : recs_) n += journal::parse_record(b)->type() == journal::RecordType::Timer ? 1u : 0u;
    return n;
  }
  const EngineDay& day() const { return day_; }

 private:
  void drain() {
    for (auto& b : rig_.take(0)) recs_.push_back(std::move(b));
    (void)rig_.take(1);  // the second cursor (the journal writer in production)
  }
  static std::vector<engine::SymbolEntry> symbols() {
    std::vector<engine::SymbolEntry> s(2);
    s[0].symbol = Symbol8("AAPL");
    s[0].prior_close = 1'000'000;
    s[1].symbol = Symbol8("MSFT");
    s[1].prior_close = 200'000;
    return s;
  }
  static std::vector<engine::AccountEntry> accounts() {
    std::vector<engine::AccountEntry> a(2);
    a[0].account_id = 100;
    a[0].firms[0] = Mpid4("FIRM");
    a[1].account_id = 200;
    a[1].firms[0] = Mpid4("OTHR");
    return a;
  }
  static std::vector<engine::SessionEntry> sessions() {
    return {engine::SessionEntry{1, 100}, engine::SessionEntry{2, 200}};
  }

  std::vector<engine::SymbolEntry> syms_;
  std::vector<engine::AccountEntry> accts_;
  std::vector<engine::SessionEntry> sess_;
  std::vector<engine::ScheduleEntry> sched_;
  EngineDay day_;
  Rig rig_;
  std::vector<std::vector<std::byte>> recs_;
};

std::vector<Out> replay(const std::vector<std::vector<std::byte>>& recs, Engine& e) {
  Sink s;
  for (const auto& b : recs) e.apply(engine::to_input(*journal::parse_record(b)), s);
  return s.v;
}

TEST(SequencerEngine, EngineDayOrdersTablesAndTimers) {
  std::vector<engine::SymbolEntry> syms(1);
  syms[0].symbol = Symbol8("AAPL");
  std::vector<engine::AccountEntry> accts(1);
  accts[0].account_id = 1;
  std::vector<engine::SessionEntry> sess = {engine::SessionEntry{1, 1}};
  std::vector<engine::RiskEntry> risk(1);
  risk[0].account_id = 1;
  risk[0].kind = engine::RiskKind::MaxOrderQty;
  risk[0].value = 10;
  const auto sched = engine::standard_schedule(false, true);
  const EngineDay d(EngineTables{syms, accts, sess, risk, sched}, kMidnight);
  ASSERT_EQ(d.config().size(), 5u);
  EXPECT_EQ(d.config()[0].table, journal::ConfigTable::Symbols);
  EXPECT_EQ(d.config()[1].table, journal::ConfigTable::Accounts);
  EXPECT_EQ(d.config()[2].table, journal::ConfigTable::Sessions);
  EXPECT_EQ(d.config()[3].table, journal::ConfigTable::RiskLimits);
  EXPECT_EQ(d.config()[4].table, journal::ConfigTable::Schedule);
  EXPECT_EQ(d.timers().size(), sched.size() - 1);  // all but the InitialSession parameter
  for (std::size_t i = 1; i < d.timers().size(); ++i) {
    const auto& a = d.timers()[i - 1];
    const auto& b = d.timers()[i];
    EXPECT_TRUE(a.time < b.time || (a.time == b.time && a.id < b.id));
  }
  // Each timer matches its engine Schedule entry.
  for (const ScheduleEntry& t : d.timers()) {
    const auto& e = sched[t.id];  // standard_schedule: entry k (after the parameter) has id k
    ASSERT_EQ(e.timer_id, t.id);
    EXPECT_EQ(static_cast<std::uint16_t>(e.kind), static_cast<std::uint16_t>(t.kind));
    EXPECT_EQ(kMidnight + e.time_ns, t.time);
  }
}

TEST(SequencerEngine, ADayThroughTheSequencerDrivesTheEngine) {
  Day day;
  day.at(hms_ns(4, 0, 0) + 500'000'000);
  day.login(1);
  day.login(2);
  day.at(hms_ns(9, 0, 0));
  day.ouch(1, 100, engine::enter_msg({.urn = 1, .qty = 100, .price = ouch50::kMarketPrice,
                                      .cross = ouch50::CrossType::Opening}));
  day.ouch(2, 200, engine::enter_msg({.urn = 1, .side = ouch50::Side::Sell, .qty = 100, .price = 1'000'000,
                                      .cross = ouch50::CrossType::Opening}));
  day.at(hms_ns(9, 0, 1));
  day.at(hms_ns(9, 30, 0) + 500'000'000);
  day.admin(engine::AdminCommand::Halt, engine::AdminArgsBuilder{}.symbol("AAPL"));
  day.at(hms_ns(10, 0, 0));

  // Every timer due by 10:00 was journaled, in schedule order.
  std::size_t due = 0;
  for (const ScheduleEntry& t : day.day().timers()) due += t.time <= kMidnight + hms_ns(10, 0, 0) ? 1u : 0u;
  EXPECT_EQ(day.timers_in_journal(), due);

  Engine e;
  const std::vector<Out> out = replay(day.records(), e);
  EXPECT_EQ(e.session(), engine::Session::Regular);
  int accepted = 0, executed = 0, noii = 0, cross = 0, halted = 0;
  for (const Out& o : out) {
    const char t = static_cast<char>(o.b[0]);
    if (!o.itch) {
      accepted += t == 'A' ? 1 : 0;
      executed += t == 'E' ? 1 : 0;
      continue;
    }
    if (t == 'I' && load_be16(o.b.data() + 1) == 1) ++noii;
    if (t == 'Q' && load_be16(o.b.data() + 1) == 1) {
      ++cross;
      EXPECT_EQ(load_be64(o.b.data() + 11), 100u);              // shares
      EXPECT_EQ(load_be32(o.b.data() + 27), 1'000'000u);        // $100.00
      EXPECT_EQ(static_cast<char>(o.b[39]), 'O');               // opening cross
    }
    if (t == 'H' && load_be16(o.b.data() + 1) == 1 && static_cast<char>(o.b[19]) == 'H') ++halted;
  }
  EXPECT_EQ(accepted, 2);
  EXPECT_EQ(executed, 2);
  EXPECT_GT(noii, 100);  // EOII every 10 s from 09:25, NOII every second from 09:28
  EXPECT_EQ(cross, 1);
  EXPECT_EQ(halted, 1);

  // Deterministic: a second engine fed the same records agrees byte for byte.
  Engine f;
  const std::vector<Out> again = replay(day.records(), f);
  ASSERT_EQ(again.size(), out.size());
  for (std::size_t i = 0; i < out.size(); ++i) EXPECT_EQ(again[i].b, out[i].b);
  EXPECT_EQ(e.state_hash(), f.state_hash());
  std::string err;
  EXPECT_TRUE(e.check(&err)) << err;
}

}  // namespace
}  // namespace lle::seq::testing

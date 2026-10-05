// DST-008 regression test (scripted, seed-independent): nothing is journaled after the
// day's DayEnd, also when the backup takes over after the close. Found by
// `exsim --world=exchange_ha` (O-STREAM, O-ARB); see sim/ledger/bugs.yaml.
//
// At a takeover, a JOIN or a RESUME the replication stage resyncs the sequencer to the
// record log's tail, and resume() started it again. After the close that restarted the
// day: the new primary journaled the old primary's InstanceDowns, gateway input and a
// second DayEnd after the first (06 §10). Clients that already had End of Session got
// more messages, and subscribers' End of Session came short of the stream.
//
// Two paired exchange nodes and the witness run on the simulator (the production stages,
// replication stage and witness core of sim/exchange): no clients, no faults. The day ends,
// the primary dies, and the backup takes over. Its journal may hold nothing after DayEnd
// but the EpochStart of the new epoch. The scenario is fixed; no seed is drawn.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common/time.h"
#include "engine/records.h"
#include "journal/record.h"
#include "journal/replay.h"
#include "repl/types.h"
#include "sim/clock.h"
#include "sim/exchange/exchange_node.h"
#include "sim/exchange/witness_proc.h"
#include "sim/fault/swarm.h"
#include "sim/node.h"
#include "sim/world.h"

namespace lle::sim::exch {
namespace {

constexpr std::uint32_t kDay = 20261001;
constexpr std::uint16_t kWitnessPort = 41000;
constexpr char kWitnessState[] = "witness.state";

struct Pair {
  World w{1, base_fault_config()};
  ExchangeDay day;
  NodeParams params[2];
  Node* x[2] = {nullptr, nullptr};

  Pair() {
    day.date = kDay;
    engine::SymbolEntry s;
    s.symbol = Symbol8("AAPL");
    s.prior_close = 1'000'000;
    day.symbols.push_back(s);
    engine::AccountEntry a;
    a.account_id = 100;
    a.firms[0] = Mpid4("FRMA");
    day.accounts.push_back(a);
    engine::SessionEntry se{1, 100};
    se.flags = engine::SessionEntry::kCancelOnDisconnect;
    day.sessions.push_back(se);
    gw::SessionSpec spec;
    spec.session_id = 1;
    spec.account = 100;
    spec.username = "U01";
    const std::uint8_t salt[4] = {1, 2, 3, 4};
    spec.credential = gw::Credential::make("PW01", salt);
    spec.cancel_on_disconnect = true;
    day.specs.push_back(spec);
    // The standard day compressed from 09:24 so that 16:00 lands 40 ms in.
    const Nanos t0 = hms_ns(9, 24, 0), lead = 2'000'000;
    const std::int64_t speed = (hms_ns(16, 0, 0) - t0) / (40'000'000 - lead);
    for (engine::ScheduleEntry e : engine::standard_schedule(false, false)) {
      if (e.timer_id != 0 && e.time_ns > t0) e.time_ns = t0 + (e.time_ns - t0) / speed;
      day.schedule.push_back(e);
    }
    day.local_midnight = kSimEpochRealNs - (t0 - lead);
    EXPECT_TRUE(day.build().has_value());

    x[0] = &w.add_node("xa", NodeOptions{true, true});
    x[1] = &w.add_node("xb", NodeOptions{true, true});
    Node& wn = w.add_node("w", NodeOptions{true, true});
    for (std::size_t n = 0; n < 2; ++n) {
      NodeParams& p = params[n];
      p.node_id = static_cast<std::uint16_t>(n);
      p.follower = false;
      p.gw[0] = env::Endpoint{x[n]->ip(), 15000};
      p.gw[1] = env::Endpoint{x[n]->ip(), 15001};
      p.line_a = env::Endpoint{0xEF010101u, 30001};
      p.line_b = env::Endpoint{0xEF010102u, 30002};
      p.paired = true;
      p.initial_primary = 0;
      p.ha_bind = env::Endpoint{x[n]->ip(), 40000};
      p.ha_peer = env::Endpoint{x[1 - n]->ip(), 40000};
      p.witness = env::Endpoint{wn.ip(), kWitnessPort};
      p.t_d = 20'000'000;
      p.t_ack = 10'000'000;
      p.md_eos_linger = 5'000'000;
      x[n]->set_boot([this, n](Node& nd, BootReason) { nd.emplace_process<ExchangeProc>(nd, day, params[n], NodeHooks{}); });
    }
    const auto img = WitnessProc::initial_state(0);
    wn.disk().install(kWitnessState, img);
    wn.set_boot([](Node& nd, BootReason) {
      nd.emplace_process<WitnessProc>(nd, kWitnessPort, kWitnessState, Nanos{5'000'000}, WitnessProc::Hooks{});
    });
    for (std::size_t i = 0; i < w.node_count(); ++i) w.node(static_cast<NodeId>(i)).boot();
  }

  [[nodiscard]] ExchangeProc* proc(std::size_t n) {
    if (!x[n]->alive()) return nullptr;
    auto* p = dynamic_cast<ExchangeProc*>(x[n]->process());
    return p != nullptr && p->started() ? p : nullptr;
  }
  [[nodiscard]] repl::Role role(std::size_t n) {
    ExchangeProc* p = proc(n);
    return p == nullptr ? repl::Role::kNone : static_cast<repl::Role>(p->shared().role.load());
  }
  template <class P>
  bool run_until(P&& pred, Nanos limit) {
    const Nanos end = w.now() + limit;
    while (w.now() < end) {
      if (pred()) return true;
      w.run_until_time(w.now() + 100'000);
    }
    return pred();
  }

  // Record types after the journal's first DayEnd, on node n's disk.
  std::vector<journal::RecordType> after_day_end(std::size_t n) {
    SimReadOnlySegmentDir dir(*x[n], params[n].journal_prefix(kDay));
    struct V {
      bool ended = false;
      std::vector<journal::RecordType> after;
      bool on_record(const journal::RecordView& r) {
        if (ended) after.push_back(r.type());
        if (r.type() == journal::RecordType::DayEnd) ended = true;
        return true;
      }
    } v;
    (void)journal::replay(dir, journal::ReplayRange{1, ~std::uint64_t{0}}, v, kDay);
    EXPECT_TRUE(v.ended) << "node " << n << " never journaled DayEnd";
    return v.after;
  }
};

TEST(DST008, NothingIsJournaledAfterDayEndWhenTheBackupTakesOver) {
  Pair p;
  ASSERT_TRUE(p.run_until(
      [&] {
        return p.role(0) == repl::Role::kPrimary && p.role(1) == repl::Role::kBackup &&
               p.proc(0)->shared().day_end_index.load() != 0 && p.proc(1)->shared().day_end_index.load() != 0;
      },
      2'000'000'000))
      << "the pair never ended the day";
  // The primary dies after the close; the backup takes over.
  p.x[0]->request_crash();
  ASSERT_TRUE(p.run_until([&] { return repl::is_primary(p.role(1)); }, 2'000'000'000)) << "no takeover";
  p.w.run_until_time(p.w.now() + 200'000'000);
  for (const journal::RecordType t : p.after_day_end(1)) {
    EXPECT_EQ(t, journal::RecordType::EpochStart)
        << "the new primary journaled a record of type " << static_cast<int>(t) << " after DayEnd";
  }
}

}  // namespace
}  // namespace lle::sim::exch

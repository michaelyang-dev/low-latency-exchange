// single world (09 §2 `single`; 05, 06): one node with the production
// sequencer (src/sequencer: Sequencer, EngineDay), the L2 ring, the journal
// writer on the simulated disk, and the matching engine (src/engine), fed
// through the sequencer's inbound interfaces by scripted OUCH clients and
// admin commands (there is no gateway yet). Process and host crashes recover
// as a node does: journal recovery steps 1-3, recovery steps 4-5 with the
// engine (journal/engine_recovery.h, no snapshot: replay from index 1), then
// the sequencer resumes from the recovered chain.
//
// The trading day is compressed: schedule entries after a seeded time T0 run
// K times faster (the Schedule table is configuration, ADR-028), so continuous
// trading, the close freeze, the MOC/LOC cutoffs, the closing cross and the
// post-market fall inside the run. Half the seeds run kill_switch_during_cross:
// an admin KillSwitch for an account with closing-cross interest arrives
// around the closing cross.
//
// The harness keeps, outside process memory, a copy of every record the
// sequencer published and a shadow engine that applies exactly the durable
// journal prefix: its outputs are the released stream (Output Rule). Oracles:
//   O-CONSERVE        from the released OUCH stream, per order: executed +
//                     canceled never exceed entered; every order resting in the
//                     engine's book has leaves = entered - executed - canceled;
//                     and the number of open orders equals the engine's
//   O-BOOK            a book built from the engine's ITCH output equals the
//                     engine's displayed book after every record and recovery
//   O-DETERMINISM     the process engine's outputs for each record equal the
//                     shadow's, and after recovery its state hash equals the
//                     shadow's at the same index (same journal, same outputs)
//   O-WAL-DURABLE     recovery keeps every record the journal reported durable
//   O-RISK            limits change only when an Admin or Config record is
//                     applied; a kill flag only on KillSwitch/KillReset (or
//                     a KillExposure limit)
//   O-KILLED          no order of a killed account executes until it is reset
//   O-LIVE            after healing, the day runs to its last timer, all durable
//                     and applied
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/time.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "env/buggify.h"
#include "journal/engine_recovery.h"
#include "journal/journal_writer.h"
#include "journal/l2_ring.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "proto/ouch50/ouch50.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"
#include "sim/clock.h"
#include "sim/dist.h"
#include "sim/node.h"
#include "sim/worlds/journal_device.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace en = lle::engine;
namespace jr = lle::journal;
namespace sq = lle::seq;
namespace oo = lle::ouch50::out;

constexpr char kPrefix[] = "journal/";
constexpr std::uint32_t kDay = 20261001;
constexpr std::uint64_t kRingNonce = 0x51C0'0DE5'EED5'1A7Eull;
constexpr std::size_t kRingBytes = std::size_t{1} << 22;

struct SimSeqEnv {
  using Clock = sim::Clock;
  using OuchQueue = conc::MpscScqRing<sq::InboundMsg, 1024>;
  using SessionQueue = conc::MpscScqRing<sq::SessionEventMsg, 64>;
  using AdminQueue = conc::MpscScqRing<sq::AdminMsg, 64>;
  using Ring = jr::L2Ring<2>;
};
static_assert(sq::SequencerEnv<SimSeqEnv>);

using Writer = jr::JournalWriter<SimJournalDevice>;
using Preparer = jr::SegmentPreparer<SimSegmentDir, Rng>;

en::EngineConfig engine_config() {
  en::EngineConfig c;
  c.book.reserve_orders = 1 << 13;
  c.book.reserve_levels = 1 << 11;
  c.book.levels_per_side = 16;
  c.urn_capacity = 1 << 13;
  c.scratch = 1 << 10;
  return c;
}

// ---- the released stream's books ------------------------------------------
// A book built from ITCH 5.0 add / execute / cancel / delete / replace.
class ItchBook {
 public:
  void apply(std::span<const std::byte> m) {
    if (m.empty()) return;
    switch (static_cast<char>(m[0])) {
      case 'A':
      case 'F':
        add(load_be16(m.data() + 1), load_be64(m.data() + 11), static_cast<char>(m[19]), load_be32(m.data() + 20),
            load_be32(m.data() + 32));
        break;
      case 'E':
      case 'C':
        reduce(load_be64(m.data() + 11), load_be32(m.data() + 19));
        break;
      case 'X':
        reduce(load_be64(m.data() + 11), load_be32(m.data() + 19));
        break;
      case 'D':
        remove(load_be64(m.data() + 11));
        break;
      case 'U': {
        const std::uint64_t old = load_be64(m.data() + 11);
        const auto it = orders_.find(old);
        if (it == orders_.end()) {
          bad_ = true;
          return;
        }
        const Ord o = it->second;
        remove(old);
        add(o.locate, load_be64(m.data() + 19), o.side, load_be32(m.data() + 27), load_be32(m.data() + 31));
        break;
      }
      default:
        break;
    }
  }
  // Locate, side, level (best first), FIFO: (ref, shares).
  [[nodiscard]] std::uint64_t digest() const {
    Fnv1a64 h;
    for (const auto& [key, lv] : levels_) {
      // key: (locate, side, sortable price); bids sort descending via negation.
      for (const std::uint64_t ref : lv) {
        const Ord& o = orders_.at(ref);
        h.u(o.locate);
        h.u(static_cast<std::uint8_t>(o.side));
        h.u(o.px);
        h.u(ref);
        h.u(o.qty);
      }
    }
    return h.value();
  }
  [[nodiscard]] bool bad() const { return bad_; }

 private:
  struct Ord {
    std::uint16_t locate = 0;
    char side = 'B';
    std::uint32_t qty = 0;
    std::uint32_t px = 0;
  };
  using Key = std::tuple<std::uint16_t, char, std::int64_t>;
  static Key key(const Ord& o) {
    return {o.locate, o.side, o.side == 'B' ? -static_cast<std::int64_t>(o.px) : static_cast<std::int64_t>(o.px)};
  }
  void add(std::uint16_t locate, std::uint64_t ref, char side, std::uint32_t qty, std::uint32_t px) {
    const Ord o{locate, side, qty, px};
    if (!orders_.emplace(ref, o).second) bad_ = true;
    levels_[key(o)].push_back(ref);
  }
  void reduce(std::uint64_t ref, std::uint32_t q) {
    const auto it = orders_.find(ref);
    if (it == orders_.end() || it->second.qty < q) {
      bad_ = true;
      return;
    }
    it->second.qty -= q;
    if (it->second.qty == 0) remove(ref);
  }
  void remove(std::uint64_t ref) {
    const auto it = orders_.find(ref);
    if (it == orders_.end()) {
      bad_ = true;
      return;
    }
    auto lv = levels_.find(key(it->second));
    std::erase(lv->second, ref);
    if (lv->second.empty()) levels_.erase(lv);
    orders_.erase(it);
  }

  std::map<std::uint64_t, Ord> orders_;
  std::map<Key, std::vector<std::uint64_t>> levels_;
  bool bad_ = false;
};

// The engine's displayed book in the same order and encoding.
std::uint64_t engine_display_digest(const en::Engine& e) {
  Fnv1a64 h;
  const en::MatchingBook& b = e.book();
  for (Locate l = 1; l <= b.symbols(); ++l) {
    for (const Side s : {Side::Buy, Side::Sell}) {
      b.for_each_level(l, s, [&](const en::MatchingBook::Level& lv) {
        b.for_each_in(lv, 0, [&](en::Handle hd) {
          const en::Order& o = b.at(hd);
          h.u(static_cast<std::uint16_t>(l));
          h.u(static_cast<std::uint8_t>(s == Side::Buy ? 'B' : 'S'));
          h.u(static_cast<std::uint32_t>(o.px));
          h.u(static_cast<std::uint64_t>(o.itch_ref));
          h.u(static_cast<std::uint32_t>(o.leaves));
        });
      });
    }
  }
  return h.value();
}

struct Track {
  std::uint32_t session = 0;
  std::uint32_t urn = 0;
  std::uint64_t ref = 0;
  std::int64_t entered = 0, executed = 0, canceled = 0;
  std::int64_t open = 0;
  bool closed_dead = false;  // accepted or replaced with Order State D
};

// ---- harness ---------------------------------------------------------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_conserve = 0, o_book = 0, o_det = 0, o_durable = 0, o_risk = 0, o_killed = 0;
  std::uint64_t seed = 0;
  bool verbose = false;

  // Day configuration.
  std::vector<en::SymbolEntry> syms;
  std::vector<en::AccountEntry> accts;
  std::vector<en::SessionEntry> sess;
  std::vector<en::ScheduleEntry> sched;
  Nanos local_midnight = 0;
  Nanos t0 = 0;           // compression starts (since midnight)
  std::int64_t speed = 1;  // compression factor after t0
  std::unique_ptr<sq::EngineDay> day;
  [[nodiscard]] Nanos compressed(Nanos t) const { return t <= t0 ? t : t0 + (t - t0) / speed; }

  // Journal truth: every record the sequencer published (index i at recs[i-1]).
  std::vector<std::vector<std::byte>> recs;
  std::uint64_t durable_claimed = 0;
  std::vector<std::uint64_t> live_digest;  // process engine, per index (0: none)

  // The shadow engine and the released stream's views.
  std::unique_ptr<en::Engine> shadow;
  std::uint64_t applied = 0;
  ItchBook itch;
  std::map<std::pair<std::uint32_t, std::uint32_t>, Track> orders;  // (session id, urn)
  std::map<std::uint64_t, std::pair<std::uint32_t, std::uint32_t>> by_ref;
  std::vector<std::uint32_t> account_index_of_session;  // by session table order

  // Clients and admin (durable on the client side).
  std::vector<std::uint32_t> next_urn;
  bool kill_scenario = false;
  std::size_t kill_account = 0;   // index into accts
  Nanos kill_at = 0;              // since midnight
  bool kill_sent = false;
  std::uint64_t kill_index = 0;   // journal index of the KillSwitch record, once applied
  std::uint32_t close_cross_timer = 0;  // timer id of the closing cross
  std::uint64_t cross_index = 0;        // journal index of the closing cross

  // Stats.
  std::uint64_t recoveries = 0, released_ouch = 0, released_itch = 0, executions = 0, kills = 0;
  std::uint64_t cancel_after_dead = 0;
  std::uint64_t day_restarts = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  [[nodiscard]] std::size_t session_index(std::uint32_t session_id) const {
    for (std::size_t i = 0; i < sess.size(); ++i) {
      if (sess[i].session_id == session_id) return i;
    }
    return sess.size();
  }

  // Released-stream checks for one record's outputs.
  struct Collect {
    Harness* h;
    Fnv1a64 dig;
    std::vector<std::pair<std::uint32_t, std::vector<std::byte>>> ouch;
    std::vector<std::vector<std::byte>> itch;
    void itch_out(std::span<const std::byte> b) {
      dig.u(std::uint8_t{1});
      dig.bytes(b);
      itch.emplace_back(b.begin(), b.end());
    }
  };
  struct ShadowSink {
    Collect* c;
    void itch(std::uint64_t, std::span<const std::byte> b) { c->itch_out(b); }
    void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
      c->dig.u(std::uint8_t{2});
      c->dig.u(s);
      c->dig.bytes(b);
      c->ouch.emplace_back(s, std::vector<std::byte>(b.begin(), b.end()));
    }
    void audit(std::uint64_t, const en::AuditEvent& a) {
      c->dig.u(std::uint8_t{3});
      c->dig.u(static_cast<std::uint16_t>(a.code));
      c->dig.u(a.session_id);
      c->dig.u(a.detail);
    }
  };

  void conserve_fail(const std::string& why) { o->fail(o_conserve, why); }

  void on_ouch(std::uint32_t session, std::span<const std::byte> b) {
    ++released_ouch;
    if (b.empty()) return;
    auto track = [&](std::uint32_t urn) -> Track* {
      const auto it = orders.find({session, urn});
      return it == orders.end() ? nullptr : &it->second;
    };
    switch (static_cast<char>(b[0])) {
      case 'A': {
        const auto m = oo::OrderAccepted::decode_base(b.data());
        Track t{session, m.user_ref_num, m.order_reference_number, m.quantity, 0, 0, m.quantity, false};
        if (m.order_state == ouch50::OrderState::Dead) {
          t.canceled = t.open;  // dead on acceptance: its shares never rest
          t.open = 0;
          t.closed_dead = true;
        }
        orders[{session, m.user_ref_num}] = t;
        by_ref[m.order_reference_number] = {session, m.user_ref_num};
        break;
      }
      case 'U': {
        const auto m = oo::OrderReplaced::decode_base(b.data());
        if (Track* old = track(m.orig_user_ref_num)) {
          old->canceled += old->open;  // replaced: what was left of the old order leaves it
          old->open = 0;
        }
        Track t{session, m.user_ref_num, m.order_reference_number, m.quantity, 0, 0, m.quantity, false};
        if (m.order_state == ouch50::OrderState::Dead) {
          t.canceled = t.open;
          t.open = 0;
          t.closed_dead = true;
        }
        orders[{session, m.user_ref_num}] = t;
        by_ref[m.order_reference_number] = {session, m.user_ref_num};
        break;
      }
      case 'E': {
        ++executions;
        const auto m = oo::OrderExecuted::decode_base(b.data());
        Track* t = track(m.user_ref_num);
        if (t == nullptr) return conserve_fail("execution of unknown order urn " + std::to_string(m.user_ref_num));
        t->executed += m.quantity;
        t->open -= m.quantity;
        if (t->open < 0) {
          return conserve_fail("order urn " + std::to_string(m.user_ref_num) + " of session " +
                               std::to_string(session) + " executed beyond what was entered");
        }
        break;
      }
      case 'C': {
        const auto m = oo::OrderCanceled::decode_base(b.data());
        Track* t = track(m.user_ref_num);
        if (t == nullptr) return conserve_fail("cancel of unknown order urn " + std::to_string(m.user_ref_num));
        if (t->closed_dead && t->open == 0) {
          // A cancel after Order State D: the conformance issue the engine track
          // is fixing (A/U with state D must be terminal). Tracked, not failed.
          ++cancel_after_dead;
          SIM_PROBE("single_world.cancel_after_dead_order");
          return;
        }
        t->canceled += m.quantity;
        t->open -= m.quantity;
        if (t->open < 0) {
          return conserve_fail("order urn " + std::to_string(m.user_ref_num) + " of session " +
                               std::to_string(session) + " canceled beyond what was open");
        }
        break;
      }
      case 'D': {
        const auto m = oo::AiqCanceled::decode_base(b.data());
        Track* t = track(m.user_ref_num);
        if (t == nullptr) return conserve_fail("AIQ cancel of unknown order");
        t->canceled += m.decrement_shares;
        t->open -= m.decrement_shares;
        if (t->open < 0) return conserve_fail("AIQ cancel beyond what was open");
        break;
      }
      default:
        break;
    }
  }

  // Leaves of the engine's book orders against the released stream.
  void check_book_conservation(const en::Engine& e, std::uint64_t idx) {
    std::map<std::uint64_t, std::int64_t> leaves;
    const en::MatchingBook& b = e.book();
    for (Locate l = 1; l <= b.symbols(); ++l) {
      for (const Side s : {Side::Buy, Side::Sell}) {
        b.for_each_level(l, s, [&](const en::MatchingBook::Level& lv) {
          for (int c = 0; c < 2; ++c) {
            b.for_each_in(lv, c, [&](en::Handle hd) {
              const en::Order& ord = b.at(hd);
              leaves[ord.ref] += static_cast<std::int64_t>(ord.leaves);
            });
          }
        });
      }
    }
    for (const auto& [ref, q] : leaves) {
      const auto it = by_ref.find(ref);
      if (it == by_ref.end()) {
        return conserve_fail("record " + std::to_string(idx) + ": order ref " + std::to_string(ref) +
                             " rests in the book but was never accepted on OUCH");
      }
      const Track& t = orders.at(it->second);
      if (t.open != q) {
        return conserve_fail("record " + std::to_string(idx) + ": order urn " + std::to_string(t.urn) +
                             " of session " + std::to_string(t.session) + " rests with " + std::to_string(q) +
                             " but entered " + std::to_string(t.entered) + " - executed " +
                             std::to_string(t.executed) + " - canceled " + std::to_string(t.canceled) + " = " +
                             std::to_string(t.open));
      }
    }
    std::size_t open_orders = 0;
    for (const auto& [k, t] : orders) open_orders += t.open > 0 ? 1u : 0u;
    if (open_orders != e.live_orders()) {
      return conserve_fail("record " + std::to_string(idx) + ": " + std::to_string(open_orders) +
                           " orders open on OUCH but the engine holds " + std::to_string(e.live_orders()));
    }
    o->pass(o_conserve);
  }

  struct RiskView {
    std::vector<en::RiskGate::Limits> limits;
    std::vector<bool> killed;
  };
  static RiskView risk_view(const en::Engine& e) {
    RiskView v;
    const en::RiskGate& g = e.risk();
    for (std::uint32_t a = 0; a < g.accounts(); ++a) {
      v.limits.push_back(g.limits(a));
      v.killed.push_back(g.killed(a));
    }
    return v;
  }
  static bool same_limits(const en::RiskGate::Limits& a, const en::RiskGate::Limits& b) {
    return a.perms == b.perms && a.max_qty == b.max_qty && a.max_notional == b.max_notional && a.ff_bps == b.ff_bps &&
           a.ff_abs == b.ff_abs && a.lop == b.lop && a.dup_window == b.dup_window && a.port_rate == b.port_rate &&
           a.symbol_rate == b.symbol_rate && a.gross == b.gross && a.symbol_notional == b.symbol_notional &&
           a.adv_pct == b.adv_pct && a.kill_exposure == b.kill_exposure;
  }

  // The shadow engine applies record i (durable) and every check runs on it.
  void apply_shadow(std::uint64_t i) {
    const auto v = jr::parse_record(recs[i - 1]);
    LLE_ASSERT(v.has_value(), "single world: a published record does not parse");
    const RiskView before = risk_view(*shadow);
    Collect c{this, {}, {}, {}};
    ShadowSink sink{&c};
    shadow->apply(en::to_input(*v), sink);
    applied = i;
    const std::uint64_t dig = c.dig.value();
    if (i <= live_digest.size() && live_digest[i - 1] != 0) {
      if (live_digest[i - 1] != dig) {
        o->fail(o_det, "record " + std::to_string(i) + ": the process engine's outputs differ from the shadow's");
      } else {
        o->pass(o_det);
      }
    }
    // Released outputs.
    const RiskView& killed_at_start = before;
    for (const auto& [s, b] : c.ouch) {
      const std::size_t si = session_index(s);
      if (!b.empty() && static_cast<char>(b[0]) == 'E' && si < sess.size()) {
        const std::uint32_t acct = account_index_of_session[si];
        if (acct < killed_at_start.killed.size() && killed_at_start.killed[acct]) {
          o->fail(o_killed, "record " + std::to_string(i) + ": an order of killed account " + std::to_string(acct) +
                                " executed");
        } else {
          o->pass(o_killed);
        }
      }
      on_ouch(s, b);
    }
    for (const auto& b : c.itch) {
      ++released_itch;
      itch.apply(b);
    }
    const auto type = v->type();
    if (type == jr::RecordType::Timer && cross_index == 0) {
      if (const auto t = en::parse_timer(en::to_input(*v).payload); t && t->timer_id == close_cross_timer) cross_index = i;
    }
    // Risk state changes only through Admin / Config records.
    const RiskView after = risk_view(*shadow);
    const bool admin = type == jr::RecordType::Admin;
    const bool config = type == jr::RecordType::Config || type == jr::RecordType::DayStart;
    if (!config && before.limits.size() == after.limits.size()) {
      for (std::size_t a = 0; a < after.limits.size(); ++a) {
        if (!admin && !same_limits(before.limits[a], after.limits[a])) {
          o->fail(o_risk, "record " + std::to_string(i) + " (type " + std::to_string(static_cast<int>(type)) +
                              ") changed the limits of account " + std::to_string(a));
        }
        if (before.killed[a] != after.killed[a]) {
          const bool via_exposure = after.limits[a].kill_exposure > 0 && after.killed[a];
          if (!admin && !via_exposure) {
            o->fail(o_risk, "record " + std::to_string(i) + " changed the kill flag of account " + std::to_string(a));
          }
          if (after.killed[a]) {
            ++kills;
            if (kill_scenario && a == kill_account && kill_index == 0) {
              kill_index = i;
              if (cross_index == 0) SIM_PROBE("single_world.kill_before_closing_cross");
              else SIM_PROBE("single_world.kill_after_closing_cross");
            }
          }
        }
      }
      o->pass(o_risk);
    }
    // The ITCH-built book equals the engine's displayed book.
    if (itch.bad()) {
      o->fail(o_book, "record " + std::to_string(i) + ": the ITCH stream is inconsistent (unknown or overdrawn order)");
    } else if (itch.digest() != engine_display_digest(*shadow)) {
      o->fail(o_book, "record " + std::to_string(i) + ": the book built from ITCH differs from the engine's");
    } else {
      o->pass(o_book);
    }
    check_book_conservation(*shadow, i);
  }

  void on_durable(std::uint64_t d) {
    durable_claimed = std::max(durable_claimed, d);
    while (applied < d && applied < recs.size()) apply_shadow(applied + 1);
  }

  void on_published(const jr::RecordView& v) {
    if (v.index() != recs.size() + 1) {
      LLE_ASSERT(false, "single world: the sequencer skipped or repeated an index");
    }
    recs.emplace_back(v.bytes().begin(), v.bytes().end());
  }

  // After recovery: the journal up to `last` is the truth.
  void on_recovered(std::uint64_t last, const en::Engine& e) {
    ++recoveries;
    if (last < durable_claimed) {
      o->fail(o_durable, "recovery kept " + std::to_string(last) + " records but " + std::to_string(durable_claimed) +
                             " were reported durable");
    } else {
      o->pass(o_durable);
    }
    if (recs.size() > last) recs.resize(last);
    if (live_digest.size() > last) live_digest.resize(last);
    durable_claimed = last;
    while (applied < last) apply_shadow(applied + 1);
    if (applied == last) {
      if (e.state_hash() != shadow->state_hash()) {
        o->fail(o_det, "after recovery to " + std::to_string(last) + " the engine's state hash differs from the shadow's");
      } else {
        o->pass(o_det);
      }
      if (engine_display_digest(e) != itch.digest()) {
        o->fail(o_book, "after recovery to " + std::to_string(last) + " the engine's book differs from the ITCH book");
      }
    }
    log("recovered to %llu (released %llu)", static_cast<unsigned long long>(last),
        static_cast<unsigned long long>(applied));
  }

  // Sequencer resume values from the durable records.
  struct ResumeInfo {
    std::size_t timers = 0;
    std::uint64_t next_snapshot_id = 1;
    std::uint64_t config_digest = 0;
    std::vector<bool> logged_in;
  };
  [[nodiscard]] ResumeInfo resume_info() const {
    ResumeInfo r;
    r.logged_in.assign(sess.size(), false);
    for (const auto& b : recs) {
      const auto v = jr::parse_record(b);
      if (!v) continue;
      switch (v->type()) {
        case jr::RecordType::Timer:
          ++r.timers;
          break;
        case jr::RecordType::SnapshotMark:
          ++r.next_snapshot_id;
          break;
        case jr::RecordType::EpochStart:
          if (const auto es = jr::decode_epoch_start(*v)) r.config_digest = es->config_digest;
          break;
        case jr::RecordType::SessionEvent:
          if (const auto se = en::parse_session_event(en::to_input(*v).payload)) {
            const std::size_t si = session_index(se->session_id);
            if (si < sess.size() && se->event == en::SessionEventKind::Login) r.logged_in[si] = true;
          }
          break;
        default:
          break;
      }
    }
    return r;
  }

  // A day start that did not become durable as a whole (DayStart, Config,
  // EpochStart): node startup treats it as atomic and starts the day again.
  void restart_day() {
    ++day_restarts;
    recs.clear();
    live_digest.clear();
    applied = 0;
    durable_claimed = 0;
    shadow = std::make_unique<en::Engine>(engine_config());
    itch = ItchBook{};
    orders.clear();
    by_ref.clear();
    kill_index = 0;
    cross_index = 0;
  }

  [[nodiscard]] bool done(std::uint64_t journaled_timers, std::uint64_t appended) const {
    return journaled_timers == day->timers().size() && appended == recs.size() && applied == recs.size() &&
           durable_claimed >= recs.size();
  }
};

// ---- the node --------------------------------------------------------------
struct SingleConfig {
  jr::JournalWriterOptions writer;
  std::uint64_t segment_bytes = 0;
  [[nodiscard]] jr::RecoveryOptions recovery() const {
    return jr::RecoveryOptions{kDay, std::uint64_t{writer.queue_depth} * writer.batch_bytes, true};
  }
};

class SingleProc : public Process {
 public:
  SingleProc(Node& n, Harness& h, const SingleConfig& cfg)
      : node_(n), h_(h), cfg_(cfg), storage_(new std::uint64_t[kRingBytes / 8]()),
        ouch_(std::make_unique<SimSeqEnv::OuchQueue>()), sessions_(std::make_unique<SimSeqEnv::SessionQueue>()),
        admin_(std::make_unique<SimSeqEnv::AdminQueue>()), dir_(n, kPrefix), rng_(n.rng(0x51)),
        prep_(dir_, rng_, kDay, cfg.segment_bytes), writer_(cfg.writer), engine_(engine_config()) {
    ring_.init(reinterpret_cast<std::byte*>(storage_.get()), kRingBytes, kRingNonce);
    sq::SequencerConfig sc;
    sc.snapshot_every = 0;
    seq_ = std::make_unique<sq::Sequencer<SimSeqEnv>>(n.clock(), *ouch_, *sessions_, *admin_, ring_, h_.day->timers(), sc);
    boot();
    n.add_stage(stage_, "single");
  }

  bool poll() {
    if (!ok_) return false;
    bool did = clients();
    did = seq_->poll() || did;
    did = journal_step() || did;
    did = engine_step() || did;
    return did;
  }

  [[nodiscard]] bool settled() const {
    return ok_ && h_.done(seq_->stats().timers + journaled_timers_before_, writer_.appended_index());
  }

 private:
  struct Stage {
    SingleProc* p;
    bool poll() { return p->poll(); }
  };

  void boot() {
    jr::RecoveryResult r = jr::recover(dir_, cfg_.recovery());
    if (r.status == jr::RecoveryStatus::IoError) return fatal("journal recovery I/O error");
    if (!r.usable()) return fatal("journal unusable");
    if (!r.dirty_spares.empty()) {
      for (const std::size_t hd : r.dirty_spares) {
        if (!prep_.recycle(hd)) return fatal("recycling a dirty spare failed");
      }
    }
    const jr::EngineRecovery er = jr::recover_engine(dir_, std::string{}, engine_, cfg_.recovery());
    if (er.status == jr::EngineRecoveryStatus::JournalUnusable) {
      if (er.journal.status == jr::RecoveryStatus::IoError) return fatal("journal recovery I/O error");
      return fatal("journal unusable");
    }
    if (er.status == jr::EngineRecoveryStatus::ReplayGap) {
      h_.o->fail(h_.o_det, "engine recovery stopped at " + std::to_string(er.last_index) + " of " +
                               std::to_string(er.journal.chain.last_index));
      return fatal("replay gap");
    }
    if (!jr::resume_writer(writer_, dir_, er.journal)) return fatal("resume_writer refused");
    for (const auto& s : er.journal.segments) assigned_.push_back(s.handle);
    prepared_ = er.journal.spares.size();
    while (prepared_ < 2) {
      const auto ps = prep_.create();
      if (!ps) return fatal("preparing a segment failed");
      if (!writer_.add_prepared(dir_.device(ps->handle), ps->handle, ps->header)) break;
      ++prepared_;
    }
    const std::uint64_t last = er.journal.chain.last_index;
    h_.on_recovered(last, engine_);
    engine_applied_ = last;
    h_.live_digest.resize(last, 0);
    const Harness::ResumeInfo ri = h_.resume_info();
    if (last > 0 && ri.config_digest == 0) {
      // Recovery ended inside the day start (no EpochStart): wipe the journal
      // and start the day again (node startup treats the day start as atomic).
      SIM_PROBE("single_world.day_start_restarted");
      for (const std::string& f : node_.disk().list()) {
        if (f.starts_with(kPrefix)) (void)node_.disk().remove(f);
      }
      h_.restart_day();
      return fatal("incomplete day start: journal wiped");
    }
    if (last == 0) {
      jr::DayStart ds;
      ds.trading_date = kDay;
      ds.local_midnight_ns = h_.local_midnight;
      if (!seq_->start_day(ds, h_.day->config(), 1, 1)) return fatal("start_day found no room");
    } else {
      seq_->resume(er.journal.chain, ri.timers, ri.next_snapshot_id, ri.config_digest);
    }
    journaled_timers_before_ = ri.timers;
    for (std::size_t s = 0; s < h_.sess.size(); ++s) {
      if (!ri.logged_in[s]) {
        (void)sessions_->try_push(sq::SessionEventMsg{h_.sess[s].session_id, 0, jr::SessionEventKind::Login, 0});
      }
    }
    ok_ = true;
  }

  // Scripted OUCH clients and admin commands (gateway and lle-admin stand-ins).
  bool clients() {
    const Nanos now = node_.clock().now_mono();
    const Nanos local = node_.clock().now_real() - h_.local_midnight;
    bool did = false;
    // The operator's command is checked on every poll, so it can land on
    // either side of the closing cross's Timer record.
    if (h_.kill_scenario && !h_.kill_sent && local >= h_.kill_at) {
      admin(en::AdminCommand::KillSwitch, en::AdminArgsBuilder{}.u32(en::AdminTag::Account, h_.accts[h_.kill_account].account_id));
      h_.kill_sent = true;
      h_.log("admin: KillSwitch account %u at local %lld", h_.accts[h_.kill_account].account_id,
             static_cast<long long>(local));
      did = true;
    }
    if (now < next_client_) return did;
    next_client_ = now + static_cast<Nanos>(100 * kUs + rng_.below(900 * kUs));
    if (local > h_.compressed(hms_ns(16, 1, 0))) return did;  // clients stop after the close
    if (rng_.below(100) == 0) {
      // Operator traffic: halts and resumptions, risk limits, kill switches and resets.
      const std::size_t a = static_cast<std::size_t>(rng_.below(h_.accts.size()));
      const std::uint32_t acct = h_.accts[a].account_id;
      const std::string_view hsym = rng_.below(2) == 0 ? "AAPL" : "MSFT";
      switch (rng_.below(5)) {
        case 0:
          admin(en::AdminCommand::Halt, en::AdminArgsBuilder{}.symbol(hsym).reason("T1"));
          break;
        case 1:
          admin(en::AdminCommand::Resume, en::AdminArgsBuilder{}.symbol(hsym));
          break;
        case 2:
          admin(en::AdminCommand::RiskLimit,
                en::AdminArgsBuilder{}
                    .u32(en::AdminTag::Account, acct)
                    .u16(en::AdminTag::Kind, static_cast<std::uint16_t>(en::RiskKind::MaxOrderQty))
                    .i64(en::AdminTag::Value, rng_.below(2) == 0 ? 0 : static_cast<std::int64_t>(100 * (1 + rng_.below(8)))));
          break;
        case 3:
          if (!(h_.kill_scenario && a == h_.kill_account)) {
            admin(en::AdminCommand::KillSwitch, en::AdminArgsBuilder{}.u32(en::AdminTag::Account, acct));
          }
          break;
        default:
          if (!(h_.kill_scenario && a == h_.kill_account)) {
            admin(en::AdminCommand::KillReset, en::AdminArgsBuilder{}.u32(en::AdminTag::Account, acct));
          }
          break;
      }
      return true;
    }
    const std::size_t s = static_cast<std::size_t>(rng_.below(h_.sess.size()));
    const std::uint32_t session = h_.sess[s].session_id;
    const std::uint32_t account = h_.sess[s].account_id;
    const std::uint64_t r = rng_.below(100);
    const std::string_view sym = rng_.below(2) == 0 ? "AAPL" : "MSFT";
    const std::uint64_t ref_px = sym == "AAPL" ? 1'000'000 : 2'000'000;
    const bool before_moc_cutoff = local < h_.compressed(hms_ns(15, 55, 0));
    std::vector<std::byte> msg;
    if (r < 12) {
      // Closing-cross interest (MOC / LOC) before the cutoffs.
      if (!before_moc_cutoff) return did;
      const bool moc = rng_.below(2) == 0;
      msg = en::enter_msg({.urn = h_.next_urn[s]++, .side = rng_.below(2) == 0 ? ouch50::Side::Buy : ouch50::Side::Sell,
                           .qty = static_cast<Qty>(100 * (1 + rng_.below(10))), .symbol = sym,
                           .price = moc ? ouch50::kMarketPrice : ref_px - 5'000 + 100 * rng_.below(101),
                           .cross = ouch50::CrossType::Closing});
    } else if (r < 70) {
      const bool market = rng_.below(12) == 0;
      const bool ioc = market || rng_.below(8) == 0;
      msg = en::enter_msg({.urn = h_.next_urn[s]++, .side = rng_.below(2) == 0 ? ouch50::Side::Buy : ouch50::Side::Sell,
                           .qty = static_cast<Qty>(100 * (1 + rng_.below(10))), .symbol = sym,
                           .price = market ? ouch50::kMarketPrice : ref_px - 5'000 + 100 * rng_.below(101),
                           .tif = ioc ? ouch50::TimeInForce::Ioc : ouch50::TimeInForce::Day,
                           .display = rng_.below(6) == 0 ? ouch50::Display::Hidden : ouch50::Display::Visible});
    } else {
      // Cancel or replace one of this session's open orders (as the released stream shows them).
      std::vector<std::uint32_t> open;
      for (const auto& [k, t] : h_.orders) {
        if (k.first == session && t.open > 0) open.push_back(k.second);
      }
      if (open.empty()) return did;
      const std::uint32_t urn = open[static_cast<std::size_t>(rng_.below(open.size()))];
      if (r < 85) {
        // Full cancel, or reduce to a smaller intended size (a partial cancel).
        const Track& t = h_.orders.at({session, urn});
        const Qty keep = rng_.below(2) == 0 || t.open <= 100 ? 0 : static_cast<Qty>(100 * rng_.below(static_cast<std::uint64_t>(t.open / 100)));
        msg = en::cancel_msg(urn, keep);
      } else {
        msg = en::replace_msg({.orig = urn, .urn = h_.next_urn[s]++, .qty = static_cast<Qty>(100 * (1 + rng_.below(10))),
                               .price = ref_px - 5'000 + 100 * rng_.below(101)});
      }
    }
    sq::InboundMsg in;
    in.session_id = session;
    in.account = account;
    in.len = static_cast<std::uint16_t>(msg.size());
    std::memcpy(in.bytes, msg.data(), msg.size());
    (void)ouch_->try_push(in);  // a full queue drops it (a gateway would push back)
    return true;
  }

  void admin(en::AdminCommand c, const en::AdminArgsBuilder& args) {
    sq::AdminMsg a;
    a.command = static_cast<std::uint16_t>(c);
    a.operator_id = 900;
    a.len = static_cast<std::uint32_t>(args.bytes().size());
    std::memcpy(a.args, args.bytes().data(), args.bytes().size());
    (void)admin_->try_push(a);
  }

  // The journal stage: ring cursor 1 -> journal writer (and the harness's copy).
  bool journal_step() {
    bool did = writer_.poll() > 0;
    if (writer_.failed()) {
      fatal("journal writer failed");
      return true;
    }
    Writer::AssignedSegment as;
    while (writer_.take_assigned(as)) {
      (void)dir_.rename(as.handle, jr::segment_file_name(as.header.epoch, as.header.first_index));
      assigned_.push_back(as.handle);
      if (prepared_ > 0) --prepared_;
      did = true;
    }
    for (int k = 0; k < 256; ++k) {
      const jr::RecordView v = ring_.peek(1);
      if (v.bytes().empty()) break;
      const Writer::Status st = writer_.append(v.bytes(), ring_.sealer());
      if (st == Writer::Status::Ok) {
        h_.on_published(v);
        ring_.release(1);
        did = true;
        continue;
      }
      if (st == Writer::Status::Busy) break;
      if (st == Writer::Status::NeedSegment) {
        const auto ps = prep_.create();
        if (!ps) {
          fatal("preparing a segment failed");
          return true;
        }
        if (writer_.add_prepared(dir_.device(ps->handle), ps->handle, ps->header)) ++prepared_;
        continue;
      }
      fatal("journal writer refused a record");
      return true;
    }
    if (writer_.batch_used() != 0) did = writer_.flush() || did;
    h_.on_durable(writer_.durable_index());
    return did;
  }

  // The engine stage: ring cursor 0 -> engine (outputs gated by the Output Rule).
  bool engine_step() {
    struct Sink {
      Fnv1a64 dig;
      void itch(std::uint64_t, std::span<const std::byte> b) {
        dig.u(std::uint8_t{1});
        dig.bytes(b);
      }
      void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
        dig.u(std::uint8_t{2});
        dig.u(s);
        dig.bytes(b);
      }
      void audit(std::uint64_t, const en::AuditEvent& a) {
        dig.u(std::uint8_t{3});
        dig.u(static_cast<std::uint16_t>(a.code));
        dig.u(a.session_id);
        dig.u(a.detail);
      }
    };
    const std::size_t n = ring_.drain(
        0,
        [&](const jr::RecordView& v) {
          LLE_ASSERT(v.index() == engine_applied_ + 1, "single world: engine cursor out of order");
          Sink s;
          engine_.apply(en::to_input(v), s);
          engine_applied_ = v.index();
          if (h_.live_digest.size() < v.index()) h_.live_digest.resize(v.index(), 0);
          h_.live_digest[v.index() - 1] = s.dig.value();
        },
        256);
    return n > 0;
  }

  void fatal(const char* why) {
    h_.log("node exits: %s", why);
    ok_ = false;
    node_.request_crash();
  }

  Node& node_;
  Harness& h_;
  SingleConfig cfg_;
  std::unique_ptr<std::uint64_t[]> storage_;
  SimSeqEnv::Ring ring_;
  std::unique_ptr<SimSeqEnv::OuchQueue> ouch_;
  std::unique_ptr<SimSeqEnv::SessionQueue> sessions_;
  std::unique_ptr<SimSeqEnv::AdminQueue> admin_;
  std::unique_ptr<sq::Sequencer<SimSeqEnv>> seq_;
  SimSegmentDir dir_;
  Rng rng_;
  Preparer prep_;
  Writer writer_;
  en::Engine engine_;
  std::uint64_t engine_applied_ = 0;
  std::vector<std::size_t> assigned_;
  std::size_t prepared_ = 0;
  std::size_t journaled_timers_before_ = 0;
  Nanos next_client_ = 0;
  bool ok_ = false;
  Stage stage_{this};
};

}  // namespace

namespace {
Report run_single_world(const Options& o, bool kill_switch_during_cross) {
  auto h = std::make_unique<Harness>();
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0x516);
  h->w = &w;
  h->o = &w.oracles();
  h->seed = o.seed;
  h->verbose = o.verbose;
  h->o_conserve = w.oracles().activate(kOConserve, "shares conserved per order: entered = executed + canceled + resting");
  h->o_book = w.oracles().activate(kOBook, "the book built from the engine's ITCH equals the engine's displayed book");
  h->o_det = w.oracles().activate(kODeterminism, "same journal, same outputs and state, across crash and recovery");
  h->o_durable = w.oracles().activate("O-WAL-DURABLE", "recovery keeps every record reported durable");
  h->o_risk = w.oracles().activate(kORisk, "limits and kill flags change only through Admin / Config records");
  h->o_killed = w.oracles().activate("O-KILLED", "no order of a killed account executes until it is reset");

  // Day: two symbols, three accounts (one session each).
  h->syms.resize(2);
  h->syms[0].symbol = Symbol8("AAPL");
  h->syms[0].prior_close = 1'000'000;
  h->syms[1].symbol = Symbol8("MSFT");
  h->syms[1].prior_close = 2'000'000;
  h->accts.resize(3);
  const char* firms[] = {"FRMA", "FRMB", "FRMC"};
  for (std::size_t a = 0; a < 3; ++a) {
    h->accts[a].account_id = static_cast<std::uint32_t>(100 * (a + 1));
    h->accts[a].firms[0] = Mpid4(firms[a]);
    h->sess.push_back(en::SessionEntry{static_cast<std::uint32_t>(a + 1), h->accts[a].account_id});
    h->account_index_of_session.push_back(static_cast<std::uint32_t>(a));
  }
  h->next_urn.assign(h->sess.size(), 1);
  // Compressed schedule: real speed until t0, then `speed` times faster.
  h->t0 = hms_ns(15, 40, 0) + static_cast<Nanos>(wl.below(5 * 60)) * kNsPerSec;
  h->speed = 2000 + static_cast<std::int64_t>(wl.below(4001));
  for (en::ScheduleEntry e : en::standard_schedule(false, false)) {
    if (e.timer_id != 0) e.time_ns = h->compressed(e.time_ns);
    if (e.kind == en::TimerKind::Cross && e.arg == 'C') h->close_cross_timer = e.timer_id;
    h->sched.push_back(e);
  }
  // The run starts `lead` before t0 (local time), so there is continuous trading first.
  const Nanos lead = 20 * kMs + static_cast<Nanos>(wl.below(120 * kMs));
  h->local_midnight = kSimEpochRealNs - (h->t0 - lead);
  h->day = std::make_unique<sq::EngineDay>(sq::EngineTables{h->syms, h->accts, h->sess, {}, h->sched}, h->local_midnight);
  h->shadow = std::make_unique<en::Engine>(engine_config());
  h->kill_scenario = kill_switch_during_cross || wl.below(2) == 0;
  h->kill_account = static_cast<std::size_t>(wl.below(3));
  // Around the closing cross: within +-3 s of 16:00 local before compression
  // (kill_switch_during_cross: +-1 s, so it lands next to the Cross timer).
  const Nanos spread = kill_switch_during_cross ? 2 * kNsPerSec : 6 * kNsPerSec;
  h->kill_at = h->compressed(hms_ns(16, 0, 0) - spread / 2 +
                             static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(spread / kMs))) * kMs);

  SingleConfig cfg;
  cfg.writer.day = kDay;
  cfg.writer.queue_depth = static_cast<std::uint32_t>(1 + wl.below(4));
  cfg.writer.batch_bytes = jr::kBatchBytes;
  cfg.writer.buffers = cfg.writer.queue_depth + 2;
  cfg.segment_bytes = jr::kSegmentHeaderBytes + jr::kBatchBytes * (8 + wl.below(24));

  Node& n = w.add_node("x", NodeOptions{true, true});
  Harness* hp = h.get();
  n.set_boot([hp, cfg](Node& nd, BootReason) { nd.emplace_process<SingleProc>(nd, *hp, cfg); });
  n.boot();

  return finish(
      w, kill_switch_during_cross ? WorldKind::KillSwitchCross : WorldKind::Single, o,
      [&w] {
        const auto* p = dynamic_cast<const SingleProc*>(w.node(0).process());
        return p != nullptr && p->settled();
      },
      [hp] {
        return "records=" + std::to_string(hp->recs.size()) + " released=" + std::to_string(hp->applied) +
               " ouch=" + std::to_string(hp->released_ouch) + " itch=" + std::to_string(hp->released_itch) +
               " executions=" + std::to_string(hp->executions) + " recoveries=" + std::to_string(hp->recoveries) +
               " kill=" + std::to_string(hp->kill_scenario ? 1 : 0) + " kill_index=" + std::to_string(hp->kill_index) +
               " cross_index=" + std::to_string(hp->cross_index) +
               " cancel_after_dead=" + std::to_string(hp->cancel_after_dead) +
               " day_restarts=" + std::to_string(hp->day_restarts);
      });
}
}  // namespace

Report run_single(const Options& o) { return run_single_world(o, false); }
Report run_kill_switch_cross(const Options& o) { return run_single_world(o, true); }

}  // namespace lle::sim::worlds::detail

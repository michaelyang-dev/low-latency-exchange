// World `exchange` (09 §2, sim phase 4): one assembled exchange node, the production
// stages and start-up of apps/exchanged (sim/exchange/exchange_node.h), with real
// SoupBinTCP/OUCH clients and MoldUDP64 subscribers around it.
//
//   x       the node: gateways gw0/gw1, sequencer, engine, io (journal + output log),
//           md (lines A/B + re-request server), snapshotd's follower; process and
//           host crashes, disk faults; recovery through basic_replay_day.
//   cN      one client per session (soup::ClientSession, OUCH 5.0): enters, cancels
//           (full and partial), replaces, IOC and market orders, crossing flow (partial
//           fills); drops connections (cancel-on-disconnect sessions among them), logs
//           out, logs in again asking for earlier sequence numbers, sends malformed
//           and over-long messages; resends unacknowledged orders after a re-login.
//   sN      subscribers: mold::LineArbiter over lossy lines A and B, gaps re-requested.
//   op      the operator: halts and resumes (Admin records), pushed into the node's
//           admin queue as lle-admin would.
//
// The day is the standard schedule (no 1 Hz clock), compressed from 09:24 so that the
// close lands inside or just after the faulted phase; the node ends the day after the
// last timer (auto_end) and the run converges when every client and subscriber has
// End of Session.
//
// Truth is the node's journal at the end, replayed through a fresh engine
// (regeneration). Oracles:
//   O-STREAM        every SoupBinTCP message a client received, first time and on
//                   every replay after re-logins and crashes, equals the regeneration
//                   byte for byte; at End of Session a client holds all of its stream.
//   O-ARB           every subscriber delivers the regenerated ITCH stream in order, once,
//                   and ends at S + 1.
//   O-EXACTLY-ONCE  no UserRefNum of a session is consumed twice; every consumed one has
//                   exactly one response (Accepted, Replaced or Rejected).
//   O-SEQ           the journal holds each gateway push of OUCH and session events once,
//                   in push order; pushes are lost only in a crash's lost suffix.
//   O-COD           cancel-on-disconnect: once the Disconnect (or, after a crash, the
//                   InstanceDown) of a session's connection is sequenced, no order that
//                   connection had sent is open or executes; and no order of a connection
//                   that died in a crash executes after the restart (ADR-032: its
//                   InstanceDown comes before every overdue timer).
//   O-OUTPUT-COMMIT the Output Rule (solo: durable_index): every output a client or
//                   subscriber received comes from a record that was durable on the
//                   simulated disk when it was received.
//   O-RECOVER       the node starts on every journal it left (no refused recovery once
//                   faults are healed).
//   O-LIVE          convergence within bound B after healing.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "client/feed_handler.h"
#include "common/endian.h"
#include "common/types.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "env/buggify.h"
#include "gateway/credentials.h"
#include "journal/record.h"
#include "journal/replay.h"
#include "proto/glimpse/glimpse.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/client_session.h"
#include "proto/soupbin/soupbin.h"
#include "sequencer/sequencer.h"
#include "sim/clock.h"
#include "sim/dist.h"
#include "sim/exchange/exchange_node.h"
#include "sim/exchange/truth.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/journal_device.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

namespace {

namespace en = lle::engine;
namespace jr = lle::journal;
namespace sq = lle::seq;
namespace oo = lle::ouch50::out;
namespace sb = lle::soup;
namespace mo = lle::mold;
namespace ex = lle::sim::exch;
using ex::ExchangeDay;
using ex::ExchangeProc;
using ex::NodeParams;

constexpr std::uint32_t kDay = 20261001;
constexpr std::uint16_t kGwPort[2] = {15000, 15001};
constexpr std::uint16_t kRerequestPort = 30003;
constexpr std::uint16_t kSubPort = 31000;
constexpr std::uint16_t kGlimpsePort = 30004;
constexpr std::string_view kGlimpsePassword = "SPIN";
constexpr env::Endpoint kLine[2] = {{0xEF010101u, 30001}, {0xEF010102u, 30002}};  // 239.1.1.1 / .2
constexpr std::uint16_t kInstance = 1;  // the node's id: every gateway session instance
constexpr std::int64_t kTick = 100;     // $0.01 in PxE4

// ---- what the gateways pushed (taps) ------------------------------------------------
struct Push {
  bool ouch = false;
  std::uint32_t session = 0;
  std::uint32_t incarnation = 0;  // node incarnation that pushed it
  Nanos at = 0;                   // virtual time
  // OUCH
  std::vector<std::byte> payload;
  std::uint16_t flags = 0;
  // session event
  jr::SessionEventKind event = jr::SessionEventKind::Login;
  SeqNo requested = 0;
  // matching
  std::uint64_t index = 0;  // journal index of its record (0: lost)
  bool after_end = false;   // pushed once the sequencer had ended the day (never journaled, 06 §10)
};

// ---- the regenerated day (truth): sim/exchange/truth.h ------------------------------
using ex::OrderLife;
using ex::Out;
using ex::Rec;
using ex::SubTruth;
using ex::Truth;

// ---- the clients' durable state -----------------------------------------------------
struct Connection {
  Nanos connect_at = 0, login_at = 0, end_at = 0;
  SeqNo requested = 0;
  char end = ' ';  // 'D' dropped by the client, 'O' logout, 'S' closed by the server / reset
};
struct Sent {
  char kind = 'O';  // 'O' enter, 'U' replace, 'B' malformed / truncated (consumes, expects 'J')
  std::vector<std::byte> msg;
  std::uint32_t conn = 0;
  int sends = 0;
  bool resolved = false;
};
struct Ledger {
  std::uint32_t session = 0;
  std::uint32_t account = 0;
  std::string user, pass;
  std::uint8_t gateway = 0;
  bool cod = false;
  sb::SessionId soup_session;
  UserRefNum next_urn = 1;
  SeqNo next_expected = 1;
  std::vector<std::vector<std::byte>> msgs;  // msgs[k-1]: SoupBinTCP message k
  std::vector<Nanos> rx_at;                  // first receipt of message k
  std::vector<Connection> conns;
  std::map<UserRefNum, Sent> sent;
  std::map<UserRefNum, std::int64_t> open;  // the client's view of its live orders
  std::map<UserRefNum, std::string> symbol_of;
  bool got_eos = false;
  SeqNo eos_at = 0;
  std::uint64_t replays_checked = 0, earlier_logins = 0, drops = 0, logouts = 0, resends = 0, bad = 0;
};

// ---- harness ------------------------------------------------------------------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_stream = 0, o_arb = 0, o_once = 0, o_seq = 0, o_cod = 0, o_commit = 0, o_recover = 0, o_replay = 0,
           o_book = 0;
  std::uint64_t seed = 0;
  bool verbose = false;

  ExchangeDay day;
  NodeParams params;
  Nanos t0 = 0;            // local time where compression starts
  std::int64_t speed = 1;  // compression after t0
  bool clock = false;      // the 1 Hz clock is on
  Nanos lead = 0;          // the run starts `lead` (local, uncompressed) before t0
  Nanos close_at = 0;      // virtual time of 16:00 local
  Nanos open_at = 0;       // virtual time of 09:30 local
  [[nodiscard]] Nanos compressed(Nanos t) const { return t <= t0 ? t : t0 + (t - t0) / speed; }
  [[nodiscard]] Nanos virtual_of(Nanos local) const { return compressed(local) - (t0 - lead); }

  std::vector<Push> pushes;
  std::map<std::uint32_t, std::vector<std::size_t>> pushes_of;  // per session, push order
  std::vector<std::uint64_t> boot_index;  // recovered index of each successful boot (incarnation order)
  std::vector<std::uint32_t> boot_incarnation;
  std::vector<Nanos> crash_at;  // per incarnation that ended (virtual time)
  std::uint64_t boots = 0, boot_failures = 0, stops = 0, recoveries = 0, snapshot_recoveries = 0;
  std::uint64_t rewritten = 0, appended = 0;
  std::uint64_t cod_races = 0, late_orders = 0, snapshots_written = 0, cod_fills_after_restart = 0;
  std::set<std::uint64_t> auction_snapshots;  // indices of snapshots written while an auction collected interest

  std::vector<Ledger> clients;
  std::vector<SubTruth> subs;
  std::uint64_t halts = 0, resumes = 0, operator_restarts = 0, incomplete_day_starts = 0, runbooks = 0;
  bool runbook_pending = false;

  // Durable time of every journal record (O-OUTPUT-COMMIT), from the node's journal
  // device: (index, content crc) -> first virtual time it was durable on the disk.
  ex::DurableMap durable_at;
  std::unique_ptr<worlds::JournalDurableObserver> durable_tap;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  [[nodiscard]] ExchangeProc* node_proc() const;

  // The sequencer takes no more input (06 §10): the day ended, or every timer of the
  // schedule is out and the seq stage is ending the day (SeqDriver: auto_end).
  [[nodiscard]] bool day_closed() const {
    const ExchangeProc* x = node_proc();
    if (x == nullptr || x->sequencer() == nullptr) return false;
    return !x->sequencer()->started() || x->sequencer()->next_timer() >= day.day->timers().size();
  }
  void on_ouch_push(const sq::InboundMsg& m) {
    Push p;
    p.ouch = true;
    p.after_end = day_closed();
    p.session = m.session_id;
    p.incarnation = w->node(0).incarnation();
    p.at = w->now();
    p.payload.assign(m.payload().begin(), m.payload().end());
    p.flags = m.flags;
    pushes_of[p.session].push_back(pushes.size());
    pushes.push_back(std::move(p));
  }
  void on_event_push(const sq::SessionEventMsg& m) {
    Push p;
    p.ouch = false;
    p.after_end = day_closed();
    p.session = m.session_id;
    p.incarnation = w->node(0).incarnation();
    p.at = w->now();
    p.event = m.event;
    p.requested = m.requested_seq;
    pushes_of[p.session].push_back(pushes.size());
    pushes.push_back(std::move(p));
  }

  Truth regenerate() const;
  void final_checks();
  void check_streams(const Truth& t);
  void check_arb(const Truth& t);
  void check_book(const Truth& t);
  void check_once(const Truth& t);
  void match_pushes(const Truth& t);
  void check_cod(const Truth& t);
  void check_commit(const Truth& t);
  void check_replay(const Truth& t);
};

// ---- regeneration ------------------------------------------------------------------
Truth Harness::regenerate() const {
  return ex::regenerate(w->node(0), params.journal_prefix(day.date), day.date, day.schedule);
}

// ---- oracles ------------------------------------------------------------------------
void Harness::check_streams(const Truth& t) {
  for (const Ledger& c : clients) {
    const auto it = t.ouch.find(c.session);
    const std::size_t have = it == t.ouch.end() ? 0 : it->second.size();
    if (c.msgs.size() > have) {
      o->fail(o_stream, "session " + std::to_string(c.session) + " received " + std::to_string(c.msgs.size()) +
                            " messages but the journal regenerates " + std::to_string(have));
      return;
    }
    for (std::size_t k = 0; k < c.msgs.size(); ++k) {
      const std::vector<std::byte>& want = it->second[k].bytes;
      if (c.msgs[k] != want) {
        o->fail(o_stream, "session " + std::to_string(c.session) + " message " + std::to_string(k + 1) +
                              " differs from the journal's regeneration (record " +
                              std::to_string(it->second[k].index) + ")");
        return;
      }
      o->pass(o_stream);
    }
    if (c.got_eos && c.msgs.size() != have) {
      o->fail(o_stream, "session " + std::to_string(c.session) + " got End of Session with " +
                            std::to_string(c.msgs.size()) + " of " + std::to_string(have) + " messages");
      return;
    }
  }
}

void Harness::check_arb(const Truth& t) {
  for (std::size_t s = 0; s < subs.size(); ++s) {
    const SubTruth& st = subs[s];
    if (st.msgs.size() > t.itch.size()) {
      o->fail(o_arb, "subscriber " + std::to_string(s) + " delivered " + std::to_string(st.msgs.size()) +
                         " messages but the journal regenerates " + std::to_string(t.itch.size()));
      return;
    }
    for (std::size_t k = 0; k < st.msgs.size(); ++k) {
      if (st.rx_at[k] == 0) continue;  // covered by a snapshot splice
      if (st.msgs[k] != t.itch[k].bytes) {
        o->fail(o_arb, "subscriber " + std::to_string(s) + " message " + std::to_string(k + 1) +
                           " differs from the journal's regeneration (record " + std::to_string(t.itch[k].index) + ")");
        return;
      }
      o->pass(o_arb);
    }
    if (st.ended && (st.end_at != t.itch.size() + 1 || st.next != st.end_at)) {
      o->fail(o_arb, "subscriber " + std::to_string(s) + " end of session at " + std::to_string(st.end_at) +
                         ", the stream holds " + std::to_string(t.itch.size()));
      return;
    }
  }
}

void Harness::check_once(const Truth& t) {
  for (const auto& [key, idx] : t.consumed) {
    if (idx.size() != 1) {
      o->fail(o_once, "session " + std::to_string(key.first) + " UserRefNum " + std::to_string(key.second) + " has " +
                          std::to_string(idx.size()) + " consuming responses (first at record " +
                          std::to_string(idx[0]) + ")");
      return;
    }
    o->pass(o_once);
  }
  // Every consuming message a client sent and saw sequenced got its response.
  for (const Ledger& c : clients) {
    for (const auto& [urn, s] : c.sent) {
      const bool consumed = t.consumed.count({c.session, urn}) != 0;
      if (s.resolved && !consumed) {
        o->fail(o_once, "session " + std::to_string(c.session) + " saw a response to UserRefNum " +
                            std::to_string(urn) + " that the journal does not regenerate");
        return;
      }
    }
  }
}

// Matches every journaled OUCH and session-event record that a gateway pushed to its
// push (per node incarnation and session, each class in push order).
void Harness::match_pushes(const Truth& t) {
  // Journal ranges of the incarnations: incarnation k sequenced (R_k, R_k+1].
  const std::uint64_t end = t.recs.size();
  for (std::size_t b = 0; b < boot_index.size(); ++b) {
    const std::uint32_t inc = boot_incarnation[b];
    const std::uint64_t lo = boot_index[b];
    const std::uint64_t hi = b + 1 < boot_index.size() ? boot_index[b + 1] : end;
    if (hi < lo) {
      o->fail(o_seq, "the journal shrank below what incarnation " + std::to_string(inc) + " recovered (" +
                         std::to_string(hi) + " < " + std::to_string(lo) + ")");
      return;
    }
    // Pushes of this incarnation, per (session, class), in order.
    std::map<std::pair<std::uint32_t, bool>, std::vector<std::size_t>> queue;
    for (std::size_t p = 0; p < pushes.size(); ++p)
      if (pushes[p].incarnation == inc) queue[{pushes[p].session, pushes[p].ouch}].push_back(p);
    std::map<std::pair<std::uint32_t, bool>, std::size_t> next;
    bool boot_batch = true;  // InstanceDown records the start-up pushed (continue_day)
    for (std::uint64_t i = lo + 1; i <= hi; ++i) {
      const Rec& r = t.recs[i - 1];
      const bool is_ouch = r.type == jr::RecordType::OuchInbound;
      const bool is_event = r.type == jr::RecordType::SessionEvent;
      if (!is_ouch && !is_event) continue;
      if (is_event && r.event == jr::SessionEventKind::InstanceDown && boot_batch) continue;
      boot_batch = false;
      auto& q = queue[{r.session, is_ouch}];
      std::size_t& k = next[{r.session, is_ouch}];
      if (k >= q.size()) {
        if (verbose) {
          for (const std::size_t pi : pushes_of[r.session]) {
            const Push& u = pushes[pi];
            std::fprintf(stderr, "push of session %u: inc %u t=%.3f ms ouch=%d event=%d index=%llu\n", u.session,
                         u.incarnation, static_cast<double>(u.at) / 1e6, u.ouch ? 1 : 0, static_cast<int>(u.event),
                         static_cast<unsigned long long>(u.index));
          }
        }
        o->fail(o_seq, "record " + std::to_string(i) + " (" + (is_ouch ? "OUCH" : "session event") + ", session " +
                           std::to_string(r.session) + ") matches no push of incarnation " + std::to_string(inc));
        return;
      }
      Push& p = pushes[q[k]];
      const bool same = is_ouch ? (p.payload == r.payload && p.flags == r.flags)
                                : (p.event == r.event && p.requested == r.requested && r.instance == kInstance);
      if (!same) {
        o->fail(o_seq, "record " + std::to_string(i) + " of session " + std::to_string(r.session) +
                           " is not the next push of its gateway (incarnation " + std::to_string(inc) + ")");
        return;
      }
      p.index = i;
      ++k;
      o->pass(o_seq);
    }
    // Unmatched pushes are lost: only a crash loses them (the last incarnation ends
    // with the run, not with a crash), or the end of the day: once every timer is out the
    // seq stage takes no more input and DayEnd closes the journal (06 §10), dropping
    // whatever is still queued.
    const bool crashed = b + 1 < boot_index.size();
    if (!crashed && t.day_end == 0) {
      for (const auto& [key, q] : queue) {
        std::size_t k = next[key];
        while (k < q.size() && pushes[q[k]].after_end) ++k;  // the sequencer had ended the day
        if (k < q.size() && verbose) {
          for (std::size_t j = next[key]; j < q.size() && j < next[key] + 8; ++j) {
            const Push& u = pushes[q[j]];
            std::fprintf(stderr, "unmatched push: session %u t=%.3f ms ouch=%d event=%d after_end=%d\n", u.session,
                         static_cast<double>(u.at) / 1e6, u.ouch ? 1 : 0, static_cast<int>(u.event),
                         u.after_end ? 1 : 0);
          }
        }
        if (k < q.size()) {
          o->fail(o_seq, std::to_string(q.size() - k) + " " + (key.second ? "OUCH" : "session-event") +
                             " pushes of session " + std::to_string(key.first) +
                             " never reached the journal and no crash followed");
          return;
        }
      }
    }
  }
}

void Harness::check_cod(const Truth& t) {
  // Per COD session: walk its pushes; every Disconnect (and every crash that killed a
  // logged-in connection) covers the orders pushed before it.
  for (const Ledger& c : clients) {
    if (!c.cod) continue;
    const auto pit = pushes_of.find(c.session);
    if (pit == pushes_of.end()) continue;
    const std::vector<std::size_t>& order = pit->second;
    // Orders by the push that consumed their UserRefNum.
    std::map<std::size_t, const OrderLife*> born;  // push position -> order
    for (std::size_t k = 0; k < order.size(); ++k) {
      const Push& p = pushes[order[k]];
      if (!p.ouch || p.index == 0) continue;
      for (const auto& [key, life] : t.orders) {
        if (key.first == c.session && life.accepted == p.index) born[k] = &life;
      }
    }
    auto dump = [&](std::uint64_t d) {
      if (!verbose) return;
      std::fprintf(stderr, "--- pushes of session %u (incarnation, time, kind, journal index):\n", c.session);
      for (std::size_t k = 0; k < order.size(); ++k) {
        const Push& p = pushes[order[k]];
        if (order.size() > 200 && p.index != 0 && (p.index + 40 < d || p.index > d + 40)) continue;
        if (p.ouch) {
          const auto urn = p.payload.size() >= 5 ? load_be32(p.payload.data() + 1) : 0u;
          std::fprintf(stderr, "  inc %u t=%.6f ms OUCH '%c' urn %u -> %llu\n", p.incarnation,
                       static_cast<double>(p.at) / 1e6, p.payload.empty() ? '?' : static_cast<char>(p.payload[0]), urn,
                       static_cast<unsigned long long>(p.index));
        } else {
          std::fprintf(stderr, "  inc %u t=%.6f ms EVENT %d req %llu -> %llu\n", p.incarnation,
                       static_cast<double>(p.at) / 1e6, static_cast<int>(p.event),
                       static_cast<unsigned long long>(p.requested), static_cast<unsigned long long>(p.index));
        }
      }
      std::fprintf(stderr, "--- records %llu..%llu:\n", static_cast<unsigned long long>(d > 30 ? d - 30 : 1),
                   static_cast<unsigned long long>(d + 10));
      for (std::uint64_t i = d > 30 ? d - 30 : 1; i <= d + 10 && i <= t.recs.size(); ++i) {
        const Rec& r = t.recs[i - 1];
        std::fprintf(stderr, "  %llu type %d session %u ts %lld %s\n", static_cast<unsigned long long>(i),
                     static_cast<int>(r.type), r.session, static_cast<long long>(r.ts),
                     r.type == jr::RecordType::SessionEvent
                         ? ("event " + std::to_string(static_cast<int>(r.event))).c_str()
                     : r.type == jr::RecordType::OuchInbound && !r.payload.empty()
                         ? (std::string("ouch ") + static_cast<char>(r.payload[0])).c_str()
                         : "");
      }
    };
    auto check_cover = [&](std::size_t upto, std::uint64_t d, const char* what) {
      for (const auto& [k, life] : born) {
        if (k >= upto) break;
        // Frozen in the opening freeze: spared by cancel-on-disconnect, it goes to the cross.
        if (life->accepted <= d && t.frozen_at(d, *life)) continue;
        if (life->accepted > d && (life->closed == 0 || life->closed > life->accepted)) {
          ++late_orders;
          dump(d);
          o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                             " was sent before its connection's " + what + " (record " + std::to_string(d) +
                             ") but entered after it, at record " + std::to_string(life->accepted) +
                             ", and was left open");
          return false;
        }
        if (life->accepted <= d && (life->closed == 0 || life->closed > d)) {
          dump(d);
          o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                             " is still open after its connection's " + what + " at record " + std::to_string(d));
          return false;
        }
        for (const std::uint64_t e : life->executions) {
          if (e > d) {
            dump(d);
            o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                               " executed at record " + std::to_string(e) + " after its connection's " + what +
                               " at record " + std::to_string(d));
            return false;
          }
        }
      }
      o->pass(o_cod);
      return true;
    };
    // Disconnects: the orders pushed before each are covered by its record.
    for (std::size_t k = 0; k < order.size(); ++k) {
      const Push& p = pushes[order[k]];
      if (p.ouch || p.event != jr::SessionEventKind::Disconnect || p.index == 0) continue;
      // Probe: a fill of this session sequenced after the gateway pushed the disconnect
      // and before it was sequenced (the fill won the race).
      const Nanos pushed_real = w->node(0).clock().real_at(p.at);
      for (const auto& [kk, life] : born) {
        if (kk >= k) break;
        for (std::size_t e = 0; e < life->executions.size(); ++e) {
          if (life->executions[e] < p.index && life->execution_ts[e] >= pushed_real) {
            ++cod_races;
            w->probes().hit("gw.cancel_on_disconnect_races_fill");
          }
        }
      }
      if (!check_cover(k, p.index, "disconnect")) return;
      // The mirror image: an order sent after this disconnect (on a later connection)
      // must not be entered before it and cancelled by it.
      for (auto it = born.upper_bound(k); it != born.end(); ++it) {
        const OrderLife* life = it->second;
        if (life->accepted < p.index && life->closed == p.index) {
          dump(p.index);
          o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                             " was sent after its previous connection's disconnect but entered before it (record " +
                             std::to_string(life->accepted) + ") and cancelled by it at record " +
                             std::to_string(p.index));
          return;
        }
      }
    }
    // Crashes: a connection logged in when the node died is gone; the restart's
    // InstanceDown (05 §4 step 8) is its disconnect.
    for (std::size_t b = 1; b < boot_index.size(); ++b) {
      const std::uint32_t inc = boot_incarnation[b];
      const std::uint64_t r = boot_index[b];
      std::size_t upto = 0;
      while (upto < order.size() && pushes[order[upto]].incarnation < inc) ++upto;
      bool alive = false;     // the gateway's view at the crash
      std::size_t since = 0;  // the push that started the connection alive at the crash
      std::uint32_t login_inc = 0;
      for (std::size_t k = 0; k < upto; ++k) {
        const Push& p = pushes[order[k]];
        if (p.ouch) continue;
        if (p.event == jr::SessionEventKind::Login) {
          alive = true;
          since = k;
          login_inc = p.incarnation;
        }
        if (p.event == jr::SessionEventKind::Logout) alive = false;
        if (p.event == jr::SessionEventKind::Disconnect) alive = p.index == 0;  // a lost disconnect: still live
      }
      // Only a connection of the incarnation that crashed dies in this crash; one logged in
      // before an earlier crash died with that one.
      if (!alive || login_inc < boot_incarnation[b - 1]) continue;
      // A Login lost in the crash's lost suffix: the recovered journal never had this
      // connection live, so the restart has no InstanceDown for it. A later InstanceDown
      // of the session belongs to a later connection.
      const bool journaled = pushes[order[since]].index != 0;
      std::uint64_t d = 0;
      for (std::uint64_t i = r + 1; journaled && i <= t.recs.size() && d == 0; ++i) {
        const Rec& rec = t.recs[i - 1];
        if (rec.type == jr::RecordType::SessionEvent && rec.event == jr::SessionEventKind::InstanceDown &&
            rec.session == c.session)
          d = i;
      }
      if (d == 0) {
        // No InstanceDown: the journal did not have the connection live. Its own orders
        // (sent after its Login) must not survive it.
        for (const auto& [k, life] : born) {
          if (k >= upto) break;
          if (k < since || t.frozen_at(r, *life)) continue;
          if (life->accepted <= r && (life->closed == 0 || life->closed > r)) {
            dump(r);
            o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                               " was left open by the crash before record " + std::to_string(r + 1) +
                               ": its connection is gone and no InstanceDown was sequenced");
            return;
          }
        }
        o->pass(o_cod);
        continue;
      }
      // ADR-032: the dead connection's InstanceDown comes first after the recovered
      // prefix, so none of its orders executes after the crash (the probe must never fire).
      for (const auto& [k, life] : born) {
        if (k >= upto) break;
        for (const std::uint64_t e : life->executions) {
          if (e > r && e < d) {
            ++cod_fills_after_restart;
            SIM_PROBE("exchange_world.cod_fill_before_instance_down");
            dump(d);
            o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life->urn) +
                               " of a connection that died in the crash executed at record " + std::to_string(e) +
                               ", after the restart at record " + std::to_string(r) + " and before its InstanceDown at " +
                               "record " + std::to_string(d) + " (ADR-032)");
            return;
          }
        }
      }
      if (!check_cover(upto, d, "crash")) return;
    }
  }
}

void Harness::check_commit(const Truth& t) {
  auto check = [&](std::uint64_t index, Nanos rx, const std::string& what) {
    const auto it = index == 0 || index > t.crc.size() ? durable_at.end() : durable_at.find({index, t.crc[index - 1]});
    if (it == durable_at.end() || it->second > rx) {
      o->fail(o_commit, what + " (record " + std::to_string(index) + ") was received at " + std::to_string(rx) +
                            " ns, before the record was durable" +
                            (it == durable_at.end() ? std::string(" (never seen durable)")
                                                    : " (durable at " + std::to_string(it->second) + " ns)"));
      return false;
    }
    o->pass(o_commit);
    return true;
  };
  for (const Ledger& c : clients) {
    const auto it = t.ouch.find(c.session);
    if (it == t.ouch.end()) continue;
    for (std::size_t k = 0; k < c.rx_at.size() && k < it->second.size(); ++k) {
      if (!check(it->second[k].index, c.rx_at[k],
                 "session " + std::to_string(c.session) + " message " + std::to_string(k + 1)))
        return;
    }
  }
  for (std::size_t s = 0; s < subs.size(); ++s) {
    for (std::size_t k = 0; k < subs[s].rx_at.size() && k < t.itch.size(); ++k) {
      if (subs[s].rx_at[k] == 0) continue;
      if (!check(t.itch[k].index, subs[s].rx_at[k],
                 "subscriber " + std::to_string(s) + " ITCH " + std::to_string(k + 1)))
        return;
    }
  }
}

void Harness::check_book(const Truth& t) {
  // A subscriber's book at End of Session (GLIMPSE spins included) equals a book built
  // from the journal's ITCH stream, and took every message (O-BOOK).
  std::uint64_t truth_digest = 0;
  bool built = false;
  for (std::size_t s = 0; s < subs.size(); ++s) {
    const SubTruth& st = subs[s];
    if (!st.book_taken) continue;
    if (!built) {
      book::OptBook<> b;
      for (const Out& m : t.itch) (void)book::apply_itch(b, m.bytes.data(), m.bytes.size());
      truth_digest = b.books_digest();
      built = true;
    }
    if (st.book_bad != 0) {
      o->fail(o_book, "subscriber " + std::to_string(s) + "'s book refused " + std::to_string(st.book_bad) +
                          " ITCH messages (unknown or duplicate order references, over-reduces)");
      return;
    }
    if (st.book_digest != truth_digest) {
      o->fail(o_book, "subscriber " + std::to_string(s) + "'s book at End of Session differs from the journal's");
      return;
    }
    o->pass(o_book);
  }
}

void Harness::check_replay(const Truth& t) {
  // The running node's engine is consistent, and once it has applied the whole journal
  // it equals a fresh replay of it (O-REPLAY): recovery, from the journal or a snapshot,
  // leaves no state the records do not explain.
  const ExchangeProc* x = node_proc();
  if (x == nullptr || x->engine() == nullptr || x->engine_stage() == nullptr) return;
  std::string err;
  if (!x->engine()->check(&err)) {
    o->fail(o_replay, "engine consistency: " + err);
    return;
  }
  for (std::size_t g = 0; g < 2; ++g) {
    // A session event lost to a full backlog leaves the journal without that
    // connection's Disconnect or Login (gateway.h: "must stay 0").
    if (x->gateway(g) != nullptr && x->gateway(g)->stats().events_dropped != 0) {
      o->fail(o_seq, "gateway " + std::to_string(g) + " dropped " +
                         std::to_string(x->gateway(g)->stats().events_dropped) + " session events");
      return;
    }
  }
  if (x->engine_stage()->applied() != t.recs.size()) return;
  if (x->engine()->state_hash() != t.state_hash) {
    o->fail(o_replay, "engine state after " + std::to_string(t.recs.size()) +
                          " records differs from a fresh replay of the journal");
    return;
  }
  o->pass(o_replay);
}

void Harness::final_checks() {
  const Truth t = regenerate();
  if (!t.ok) {
    o->fail(o_stream, "regeneration: " + t.error);
    return;
  }
  if (verbose) {
    for (std::size_t i = 0; i < t.recs.size(); ++i) {
      const Rec& r = t.recs[i];
      if (r.type == jr::RecordType::SessionEvent)
        std::fprintf(stderr, "record %zu: session %u event %d instance %u\n", i + 1, r.session,
                     static_cast<int>(r.event), r.instance);
    }
  }
  check_replay(t);
  check_streams(t);
  check_arb(t);
  check_book(t);
  check_once(t);
  match_pushes(t);
  check_cod(t);
  check_commit(t);
}

// ---- the node ------------------------------------------------------------------------
using ex::auction_in_progress;

void w_probe(Harness& h, std::string_view name) { h.w->probes().hit(name); }

ex::NodeHooks node_hooks(Harness& h) {
  ex::NodeHooks k;
  k.durable = h.durable_tap.get();
  if (h.verbose) k.log = [&h](const std::string& s) { h.log("%s", s.c_str()); };
  k.boot_failed = [&h](const std::string& why) {
    ++h.boot_failures;
    h.log("x: start-up refused: %s", why.c_str());
    // The journal as recovery found it: a day start without its EpochStart is refused
    // by design and the runbook moves the journal aside and starts the day again
    // (exchange-node.md §8, recovery.h); the refusal must say so.
    bool epoch_start = false;
    std::uint64_t records = 0;
    {
      ex::SimReadOnlySegmentDir dir(h.w->node(0), h.params.journal_prefix(h.day.date));
      struct P {
        bool* epoch_start;
        std::uint64_t* records;
        bool on_record(const jr::RecordView& r) {
          ++*records;
          if (r.type() == jr::RecordType::EpochStart) *epoch_start = true;
          return true;
        }
      } pr{&epoch_start, &records};
      (void)jr::replay(dir, jr::ReplayRange{1, ~std::uint64_t{0}}, pr, h.day.date);
    }
    if (records != 0 && !epoch_start) {
      ++h.incomplete_day_starts;
      SIM_PROBE("exchange_world.incomplete_day_start");
      // The verdict of the replay ("recovery: ..."); a journal::recover refusal (an I/O
      // error under faults) is not a verdict on the day start and is retried.
      if (why.starts_with("recovery:") && why.find("incomplete day start") == std::string::npos) {
        h.o->fail(h.o_recover, "a journal with an incomplete day start (" + std::to_string(records) +
                                   " records, no EpochStart) was refused as: " + why);
        return;
      }
      if (why.find("incomplete day start") != std::string::npos) h.runbook_pending = true;
      return;
    }
    if (!h.w->faults_active()) h.o->fail(h.o_recover, "the node refused to start after healing: " + why);
  };
  k.l2_restored = [&h](std::uint64_t records, std::uint64_t last) {
    h.log("x: L2 file: %llu records journaled through %llu", static_cast<unsigned long long>(records),
          static_cast<unsigned long long>(last));
    SIM_PROBE("exchange_world.l2_restored");
  };
  k.recovered = [&h](const lle::exch::RecoveredDay& d) {
    ++h.recoveries;
    if (d.snapshot_index != 0) {
      ++h.snapshot_recoveries;
      SIM_PROBE("exchange_world.recovery_from_snapshot");
      if (h.auction_snapshots.count(d.snapshot_index) != 0) SIM_PROBE("exchange_world.recovery_from_auction_snapshot");
    }
    h.rewritten += d.outlog_rewritten;
    h.appended += d.outlog_appended;
    if (d.outlog_rewritten != 0) SIM_PROBE("exchange_world.recovery_rewrote_outlog");
  };
  k.stopped = [&h](int code) {
    ++h.stops;
    h.log("x: a stage stopped the node (exit %d)", code);
  };
  k.snapshot_written = [&h](const en::Engine& e, std::uint64_t index) {
    ++h.snapshots_written;
    if (auction_in_progress(e)) {
      h.auction_snapshots.insert(index);
      w_probe(h, "snap.during_auction");
    }
  };
  k.taps.ouch = [&h](const sq::InboundMsg& m) { h.on_ouch_push(m); };
  k.taps.event = [&h](const sq::SessionEventMsg& m) { h.on_event_push(m); };
  return k;
}

// Debug (verbose runs): per journal segment, the last record index readable from the
// page cache and from the durable image.
void dump_journal_durability(Harness& h, Node& n) {
  if (!h.verbose) return;
  Disk& d = n.disk();
  const std::string prefix = h.params.journal_prefix(h.day.date);
  for (const std::string& name : d.list()) {
    if (!name.starts_with(prefix)) continue;
    const std::uint32_t f = d.open(name);
    auto last_in = [&](std::span<const std::byte> img) {
      std::uint64_t last = 0, first = 0;
      if (img.size() <= jr::kSegmentHeaderBytes) return std::pair<std::uint64_t, std::uint64_t>{0, 0};
      std::span<const std::byte> rest = img.subspan(jr::kSegmentHeaderBytes);
      while (rest.size() >= jr::kHeaderBytes) {
        const auto r = jr::parse_record(rest);
        if (!r) break;
        if (r->type() != jr::RecordType::Pad) {
          if (first == 0) first = r->index();
          last = r->index();
        }
        rest = rest.subspan(r->bytes().size());
      }
      return std::pair<std::uint64_t, std::uint64_t>{first, last};
    };
    const auto c = last_in(d.cache_image(f));
    const auto u = last_in(d.durable_image(f));
    h.log("journal %s: size %llu durable %llu: cache records %llu..%llu, durable records %llu..%llu",
          name.substr(prefix.size()).c_str(), static_cast<unsigned long long>(d.size(f)),
          static_cast<unsigned long long>(d.durable_size(f)), static_cast<unsigned long long>(c.first),
          static_cast<unsigned long long>(c.second), static_cast<unsigned long long>(u.first),
          static_cast<unsigned long long>(u.second));
  }
}

class NodeProc final : public Process {
 public:
  NodeProc(Node& n, Harness& h) : h_(h) {
    if (h.runbook_pending) {
      // The operator's runbook for an incomplete day start: the day's journal and output
      // log are moved aside and the day starts again (nothing was released).
      h.runbook_pending = false;
      ++h.runbooks;
      const std::string aside = "aside" + std::to_string(h.runbooks) + "/";
      const std::string jp = h.params.journal_prefix(h.day.date);
      const std::string op = h.params.outlog_root() + "/";
      for (const std::string& name : n.disk().list()) {
        if (name.starts_with(jp) || name.starts_with(op)) (void)n.disk().rename(name, aside + name);
      }
      h.log("operator: journal with an incomplete day start moved aside (%s)", aside.c_str());
    }
    dump_journal_durability(h, n);
    proc_ = std::make_unique<ExchangeProc>(n, h.day, h.params, node_hooks(h));
    dump_journal_durability(h, n);
    if (proc_->started()) {
      ++h_.boots;
      h_.boot_index.push_back(proc_->recovered_index());
      h_.boot_incarnation.push_back(n.incarnation());
    }
  }
  [[nodiscard]] ExchangeProc& proc() { return *proc_; }

 private:
  Harness& h_;
  std::unique_ptr<ExchangeProc> proc_;
};

ExchangeProc* Harness::node_proc() const {
  Node& n = w->node(0);
  if (!n.alive()) return nullptr;
  auto* p = dynamic_cast<NodeProc*>(n.process());
  return p != nullptr && p->proc().started() ? &p->proc() : nullptr;
}

// ---- clients --------------------------------------------------------------------------
class ClientProc final : public Process {
 public:
  ClientProc(Node& n, Harness& h, std::size_t c, env::Endpoint gw)
      : node_(n), h_(h), c_(c), gw_(gw), port_(n), rng_(n.rng(0xC11E)), stage_{this} {
    const std::uint64_t mean = 100 * kUs + rng_.below(1900 * kUs);
    send_mean_ = static_cast<Nanos>(mean);
    disrupt_mean_ = static_cast<Nanos>(20 * kMs + rng_.below(200 * kMs));
    n.add_stage(stage_, "client");
  }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    bool did = false;
    port_.poll([&](const env::StreamEvent& ev) {
      did = true;
      on_event(ev, now);
    });
    Ledger& L = h_.clients[c_];
    if (!conn_ && !L.got_eos && now >= next_try_) {
      conn_ = port_.connect(gw_);
      Connection cn;
      cn.connect_at = now;
      L.conns.push_back(cn);
      did = true;
    }
    if (session_) {
      if (now >= deadline_) {
        handle(session_->on_timer(now), now);
        did = true;
      }
      if (session_ && session_->state() == sb::ClientSession::State::Active) did = act(now) || did;
      did = flush(now) || did;
    }
    return did;
  }

 private:
  struct Stage {
    ClientProc* p;
    bool poll() { return p->poll(); }
  };

  void on_event(const env::StreamEvent& ev, Nanos now) {
    if (!conn_ || ev.conn != *conn_) return;
    switch (ev.kind) {
      case env::StreamEventKind::Connected: {
        Ledger& L = h_.clients[c_];
        sb::ClientConfig cfg;
        cfg.username = Alpha<sb::kUsernameLen>(L.user);
        cfg.password = Alpha<sb::kPasswordLen>(L.pass);
        cfg.session = L.soup_session;
        // Re-logins sometimes ask for earlier messages (replayed and compared).
        cfg.sequence = L.next_expected;
        if (L.next_expected > 1 && rng_.below(4) == 0) {
          cfg.sequence = 1 + rng_.below(L.next_expected - 1);
          ++L.earlier_logins;
        }
        requested_ = cfg.sequence;
        L.conns.back().requested = cfg.sequence;
        session_ = std::make_unique<sb::ClientSession>(cfg);
        handle(session_->connect(now), now);
        break;
      }
      case env::StreamEventKind::Data: {
        if (!session_) break;
        std::span<const std::byte> rest = ev.data;
        while (!rest.empty() && session_) {
          const sb::Actions& a = session_->on_bytes(rest, now);
          const std::size_t used = a.consumed;
          handle(a, now);
          if (used == 0) break;
          rest = rest.subspan(used);
        }
        break;
      }
      case env::StreamEventKind::Closed:
        drop(now, 'S');
        break;
      case env::StreamEventKind::Accepted:
        break;
    }
  }

  void handle(const sb::Actions& a, Nanos now) {
    Ledger& L = h_.clients[c_];
    for (const sb::Delivered& d : a.delivered) {
      if (d.seq == 0) continue;  // the gateway sends no unsequenced data
      deliver(L, d.seq, d.data, now);
    }
    for (const sb::Event& e : a.events) {
      switch (e.kind) {
        case sb::EventKind::LoggedIn:
          L.soup_session = session_->session();
          L.conns.back().login_at = now;
          h_.log("client %zu logged in at %llu (next expected %llu)", c_, static_cast<unsigned long long>(e.seq),
                 static_cast<unsigned long long>(L.next_expected));
          if (e.seq != requested_) {
            h_.o->fail(h_.o_stream, "session " + std::to_string(L.session) + " logged in at " + std::to_string(e.seq) +
                                        " but asked for " + std::to_string(requested_));
          }
          if (e.seq < L.next_expected) SIM_PROBE("exchange_world.relogin_replays_earlier");
          // Unanswered orders are sent again once the replay has had time to arrive.
          resend_at_ = now + 2 * kMs + static_cast<Nanos>(rng_.below(20 * kMs));
          resend_pending_ = true;
          next_send_ = resend_at_ + 1;
          next_disrupt_ = now + exp_ns(disrupt_mean_);
          break;
        case sb::EventKind::EndOfSession:
          L.got_eos = true;
          L.eos_at = e.seq;
          break;
        case sb::EventKind::LoginRejected:
          h_.log("client %zu login rejected '%c'", c_, e.code);
          break;
        case sb::EventKind::Closed:
          closing_ = true;
          break;
        default:
          break;
      }
    }
    deadline_ = a.deadline;
    if (a.close) closing_ = true;
  }

  void deliver(Ledger& L, SeqNo seq, std::span<const std::byte> m, Nanos now) {
    if (seq <= L.msgs.size()) {
      // A replay of a message already received: byte for byte the same.
      ++L.replays_checked;
      if (L.msgs[seq - 1].size() != m.size() || std::memcmp(L.msgs[seq - 1].data(), m.data(), m.size()) != 0) {
        h_.o->fail(h_.o_stream, "session " + std::to_string(L.session) + " message " + std::to_string(seq) +
                                    " replayed with different bytes");
      } else {
        h_.o->pass(h_.o_stream);
      }
      return;
    }
    if (seq != L.msgs.size() + 1) {
      h_.o->fail(h_.o_stream, "session " + std::to_string(L.session) + " received message " + std::to_string(seq) +
                                  " after " + std::to_string(L.msgs.size()));
      return;
    }
    L.msgs.emplace_back(m.begin(), m.end());
    L.rx_at.push_back(now);
    L.next_expected = seq + 1;
    apply(L, m);
  }

  // The client's view of its orders, from its OUCH stream.
  static void apply(Ledger& L, std::span<const std::byte> b) {
    if (b.empty()) return;
    auto resolve = [&](UserRefNum urn) {
      const auto it = L.sent.find(urn);
      if (it != L.sent.end()) it->second.resolved = true;
    };
    switch (static_cast<char>(b[0])) {
      case 'A': {
        const auto m = oo::OrderAccepted::decode_base(b.data());
        resolve(m.user_ref_num);
        if (m.order_state != ouch50::OrderState::Dead) L.open[m.user_ref_num] = m.quantity;
        break;
      }
      case 'U': {
        const auto m = oo::OrderReplaced::decode_base(b.data());
        resolve(m.user_ref_num);
        L.open.erase(m.orig_user_ref_num);
        if (m.order_state != ouch50::OrderState::Dead) L.open[m.user_ref_num] = m.quantity;
        break;
      }
      case 'J': {
        const auto m = oo::Rejected::decode_base(b.data());
        resolve(m.user_ref_num);
        break;
      }
      case 'E': {
        const auto m = oo::OrderExecuted::decode_base(b.data());
        const auto it = L.open.find(m.user_ref_num);
        if (it != L.open.end() && (it->second -= m.quantity) <= 0) L.open.erase(it);
        break;
      }
      case 'C': {
        const auto m = oo::OrderCanceled::decode_base(b.data());
        const auto it = L.open.find(m.user_ref_num);
        if (it != L.open.end() && (it->second -= m.quantity) <= 0) L.open.erase(it);
        break;
      }
      case 'D': {
        const auto m = oo::AiqCanceled::decode_base(b.data());
        const auto it = L.open.find(m.user_ref_num);
        if (it != L.open.end() && (it->second -= m.decrement_shares) <= 0) L.open.erase(it);
        break;
      }
      default:
        break;
    }
  }

  [[nodiscard]] Nanos exp_ns(Nanos mean) { return 1 + sim::exp_ns(rng_, mean); }

  // One step of the client's flow while logged in.
  bool act(Nanos now) {
    Ledger& L = h_.clients[c_];
    if (resend_pending_) {
      if (now < resend_at_) return false;
      resend_pending_ = false;
      // Enter Orders sent on an earlier connection that got no response, in UserRefNum
      // order, before anything new (a replace of an order that is gone gets no response
      // at all, so replaces are not sent again). A resend of one that was sequenced after
      // all is dropped by the engine (UserRefNum not above the last consumed).
      const auto conn = static_cast<std::uint32_t>(L.conns.size() - 1);
      for (auto& [urn, s] : L.sent) {
        if (s.resolved || s.kind != 'O' || s.conn >= conn || s.sends >= 4) continue;
        send(s.msg, now);
        s.conn = conn;
        ++s.sends;
        ++L.resends;
        SIM_PROBE("client.resend_after_lost_ack");
      }
      return true;
    }
    bool did = false;
    if (now >= next_disrupt_) {
      next_disrupt_ = now + exp_ns(disrupt_mean_);
      did = disrupt(now) || did;
      if (!session_ || closing_) return true;
    }
    if (now < next_send_) return did;
    next_send_ = now + exp_ns(send_mean_);
    if (now >= h_.close_at) return did;  // the market is closed: no new interest
    order(now);
    return true;
  }

  void order(Nanos now) {
    Ledger& L = h_.clients[c_];
    const std::size_t nsym = h_.day.symbols.size();
    const std::size_t si = static_cast<std::size_t>(rng_.below(nsym));
    const std::string sym(h_.day.symbols[si].symbol.view());
    const std::int64_t ref = h_.day.symbols[si].prior_close;
    const std::uint64_t r = rng_.below(100);
    const bool continuous = now >= h_.open_at;
    if (r < 62 || L.open.empty()) {
      const bool market = continuous && rng_.below(25) == 0;
      const bool ioc = market || (continuous && rng_.below(8) == 0);
      const UserRefNum urn = L.next_urn++;
      const auto px = static_cast<std::uint64_t>(ref + kTick * (static_cast<std::int64_t>(rng_.below(11)) - 5));
      std::vector<std::byte> msg =
          en::enter_msg({.urn = urn,
                         .side = rng_.below(2) == 0 ? ouch50::Side::Buy : ouch50::Side::Sell,
                         .qty = static_cast<Qty>(100 * (1 + rng_.below(10))),
                         .symbol = sym,
                         .price = market ? ouch50::kMarketPrice : px,
                         .tif = ioc ? ouch50::TimeInForce::Ioc : ouch50::TimeInForce::Day,
                         .display = rng_.below(8) == 0 ? ouch50::Display::Hidden : ouch50::Display::Visible});
      L.symbol_of[urn] = sym;
      track(urn, 'O', msg);
      send(msg, now);
      return;
    }
    // Cancel (full or partial) or replace one of the client's open orders.
    auto it = L.open.begin();
    std::advance(it, static_cast<std::ptrdiff_t>(rng_.below(L.open.size())));
    const UserRefNum target = it->first;
    if (r < 85) {
      const Qty keep = rng_.below(2) == 0 || it->second <= 100
                           ? 0
                           : static_cast<Qty>(100 * rng_.below(static_cast<std::uint64_t>(it->second / 100)));
      send(en::cancel_msg(target, keep), now);
      return;
    }
    const auto sit = L.symbol_of.find(target);
    std::int64_t ref2 = ref;
    for (const auto& s : h_.day.symbols)
      if (sit != L.symbol_of.end() && s.symbol.view() == sit->second) ref2 = s.prior_close;
    const UserRefNum urn = L.next_urn++;
    std::vector<std::byte> msg = en::replace_msg(
        {.orig = target,
         .urn = urn,
         .qty = static_cast<Qty>(100 * (1 + rng_.below(10))),
         .price = static_cast<std::uint64_t>(ref2 + kTick * (static_cast<std::int64_t>(rng_.below(11)) - 5))});
    if (sit != L.symbol_of.end()) L.symbol_of[urn] = sit->second;
    track(urn, 'U', msg);
    send(msg, now);
  }

  void track(UserRefNum urn, char kind, const std::vector<std::byte>& msg) {
    Ledger& L = h_.clients[c_];
    Sent s;
    s.kind = kind;
    s.msg = msg;
    s.conn = static_cast<std::uint32_t>(L.conns.size() - 1);
    s.sends = 1;
    L.sent[urn] = std::move(s);
  }

  bool disrupt(Nanos now) {
    Ledger& L = h_.clients[c_];
    const std::uint64_t r = rng_.below(100);
    if (r < 40) {
      // Abrupt drop: no Logout (cancel-on-disconnect for COD sessions).
      ++L.drops;
      port_.close(*conn_);
      drop(now, 'D');
      SIM_PROBE("exchange_world.client_drops_connection");
      return true;
    }
    if (r < 55) {
      ++L.logouts;
      handle(session_->logout(now), now);
      logout_ = true;
      return true;
    }
    if (r < 75) {
      // A malformed OUCH message (unknown type, wrong length): the engine rejects what
      // it can attribute, audits the rest.
      ++L.bad;
      std::vector<std::byte> msg = en::enter_msg({.urn = L.next_urn, .qty = 100, .symbol = "AAPL"});
      if (rng_.below(2) == 0) {
        msg.resize(msg.size() - 1 - rng_.below(8));  // truncated: fails validation
        track(L.next_urn++, 'B', msg);
      } else {
        msg[0] = std::byte{'z'};  // unknown type: no UserRefNum consumed
      }
      send(msg, now);
      SIM_PROBE("exchange_world.malformed_ouch");
      return true;
    }
    if (r < 90) {
      // Over-long but within the packet limit: the gateway truncates it and flags the
      // record malformed; the engine rejects it.
      ++L.bad;
      std::vector<std::byte> msg = en::enter_msg({.urn = L.next_urn, .qty = 100, .symbol = "MSFT"});
      msg.resize(sq::InboundMsg::kMaxBytes + 1 + rng_.below(200), std::byte{' '});
      track(L.next_urn++, 'B', msg);
      send(msg, now);
      SIM_PROBE("exchange_world.overlong_ouch_truncated");
      return true;
    }
    // A SoupBinTCP packet over the server's packet limit: the gateway closes the session.
    ++L.bad;
    (void)flush(now);
    std::vector<std::byte> pkt(3 + 1100 + rng_.below(400), std::byte{0});
    store_be16(pkt.data(), static_cast<std::uint16_t>(pkt.size() - 2));
    pkt[2] = std::byte{'U'};
    (void)port_.write(*conn_, pkt);
    SIM_PROBE("exchange_world.packet_over_limit");
    return true;
  }

  void send(std::span<const std::byte> msg, Nanos now) {
    if (!session_) return;
    handle(session_->send_unsequenced(msg, now), now);
  }

  bool flush(Nanos now) {
    if (!session_ || !conn_) return false;
    bool did = false;
    for (int guard = 0; guard < 64; ++guard) {
      const std::span<const std::byte> out = session_->actions().write;
      if (out.empty()) break;
      const std::size_t n = port_.write(*conn_, out);
      if (n == 0) break;
      session_->consume_tx(n);
      did = true;
    }
    if (closing_ && session_->actions().write.empty()) {
      port_.close(*conn_);
      drop(now, logout_ ? 'O' : 'S');
      did = true;
    }
    return did;
  }

  void drop(Nanos now, char why) {
    Ledger& L = h_.clients[c_];
    h_.log("client %zu connection ends (%c)", c_, why);
    if (!L.conns.empty() && L.conns.back().end_at == 0) {
      L.conns.back().end_at = now;
      L.conns.back().end = why;
    }
    session_.reset();
    conn_.reset();
    closing_ = false;
    logout_ = false;
    resend_pending_ = false;
    deadline_ = sb::kNever;
    next_try_ = now + kMs / 2 + static_cast<Nanos>(rng_.below(15 * kMs));
  }

  Node& node_;
  Harness& h_;
  std::size_t c_;
  env::Endpoint gw_;
  StreamPort port_;
  Rng rng_;
  std::optional<env::ConnId> conn_;
  std::unique_ptr<sb::ClientSession> session_;
  Nanos deadline_ = sb::kNever;
  Nanos next_try_ = 0;
  Nanos next_send_ = 0;
  Nanos next_disrupt_ = 0;
  Nanos resend_at_ = 0;
  Nanos send_mean_ = kMs;
  Nanos disrupt_mean_ = 100 * kMs;
  bool resend_pending_ = false;
  bool closing_ = false;
  bool logout_ = false;
  SeqNo requested_ = 0;
  Stage stage_;
};

// ---- subscribers ----------------------------------------------------------------------
// refclient's feed path (src/client/feed_handler.h): LineArbiter over lines A and B with
// the node's re-request server as both servers, and a GLIMPSE snapshot session when the
// arbiter asks for one (03-protocols §8), as refclient drives it.
class SubProc final : public Process {
 public:
  using Feed = client::FeedHandler<>;
  SubProc(Node& n, Harness& h, std::size_t s, const client::FeedConfig& cfg, env::Endpoint rr, env::Endpoint glimpse,
          sb::ClientConfig glimpse_login)
      : node_(n),
        h_(h),
        s_(s),
        rr_(rr),
        glimpse_(glimpse),
        login_(std::move(glimpse_login)),
        port_(n, kSubPort),
        snap_port_(n),
        feed_(std::make_unique<Feed>(cfg)),
        stage_{this} {
    port_.join(kLine[0]);
    port_.join(kLine[1]);
    n.add_stage(stage_, "subscriber");
  }

  bool poll() {
    bool did = false;
    const Nanos now = node_.clock().now_mono();
    now_ = now;
    port_.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      mo::Source src;
      if (d.dst == kLine[0]) {
        src = mo::Source::LineA;
      } else if (d.dst == kLine[1]) {
        src = mo::Source::LineB;
      } else if (d.src == rr_) {
        src = mo::Source::RerequestA;  // refclient: one server for both
      } else {
        return;
      }
      feed_->on_packet(src, d.data, now, *this);
    });
    if (now >= feed_->next_deadline()) {
      feed_->on_timer(now, *this);
      did = true;
    }
    snap_port_.poll([&](const env::StreamEvent& ev) {
      did = true;
      on_stream(ev, now);
    });
    if (snap_ && now >= snap_->actions().deadline) absorb(snap_->on_timer(now), now);
    if (snap_wanted_ && !snap_ && !snap_conn_ && now >= snap_retry_at_) {
      snap_conn_ = snap_port_.connect(glimpse_);
      snap_retry_at_ = now + 20 * kMs;
      snap_wanted_ = false;
      ++h_.subs[s_].snapshots;
      did = true;
    }
    flush_snapshot();
    return did;
  }

  // --- FeedHandler downstream ---
  void on_book_message(SeqNo seq, std::span<const std::byte> m) {
    SubTruth& t = h_.subs[s_];
    if (splicing_ && seq == splice_to_ && seq > t.next) {
      // End of Snapshot G(N) resumed the live stream at N: [next, N) came from the spin.
      t.covered += seq - t.next;
      t.next = seq;
    }
    if (seq != t.next) {
      h_.o->fail(h_.o_arb, "subscriber " + std::to_string(s_) + " delivered " + std::to_string(seq) + ", expected " +
                               std::to_string(t.next));
      return;
    }
    if (t.msgs.size() < seq) {
      t.msgs.resize(seq);
      t.rx_at.resize(seq, 0);
    }
    t.msgs[seq - 1].assign(m.begin(), m.end());
    t.rx_at[seq - 1] = now_;
    t.next = seq + 1;
    ++t.delivered;
  }
  void on_snapshot_message(std::span<const std::byte>) {}
  void send_request(mo::Server, std::span<const std::byte> req) { (void)port_.send(rr_, req); }
  void on_snapshot_needed(SeqNo next, SeqNo end) {
    h_.log("subscriber %zu needs a snapshot at %llu (known end %llu)", s_, static_cast<unsigned long long>(next),
           static_cast<unsigned long long>(end));
    snap_wanted_ = true;
    SIM_PROBE("exchange_world.subscriber_needs_snapshot");
  }
  void on_end_of_session(SeqNo e) {
    SubTruth& t = h_.subs[s_];
    t.ended = true;
    t.end_at = e;
    if (!t.book_taken) {
      t.book_taken = true;
      t.book_digest = feed_->book().books_digest();
      const auto& bs = feed_->stats().book_status;
      t.book_bad = 0;
      for (std::size_t k = 1; k < bs.size(); ++k) t.book_bad += bs[k];
    }
  }

 private:
  struct Stage {
    SubProc* p;
    bool poll() { return p->poll(); }
  };

  void on_stream(const env::StreamEvent& ev, Nanos now) {
    if (!snap_conn_ || ev.conn != *snap_conn_) return;
    switch (ev.kind) {
      case env::StreamEventKind::Connected: {
        h_.log("subscriber %zu GLIMPSE connected", s_);
        sb::ClientConfig c = login_;
        c.sequence = 1;  // the whole spin
        snap_.emplace(c);
        absorb(snap_->connect(now), now);
        break;
      }
      case env::StreamEventKind::Data: {
        std::span<const std::byte> in = ev.data;
        while (!in.empty() && snap_) {
          const sb::Actions& a = snap_->on_bytes(in, now);
          const std::size_t used = a.consumed;
          absorb(a, now);
          if (used == 0) break;
          in = in.subspan(used);
        }
        break;
      }
      case env::StreamEventKind::Closed:
        // Refused, reset or closed before End of Snapshot: try again (refclient checks
        // only a session that had started; a refused connect must retry as well).
        snap_conn_.reset();
        if (!snap_done_) failed();
        snap_.reset();
        snap_done_ = false;
        break;
      case env::StreamEventKind::Accepted:
        break;
    }
  }

  void absorb(const sb::Actions& a, Nanos now) {
    for (const sb::Event& e : a.events)
      if (e.kind == sb::EventKind::LoggedIn) feed_->begin_snapshot();
    for (const sb::Delivered& d : a.delivered) {
      if (d.seq == 0 || snap_done_) continue;
      const bool eos = !d.data.empty() && static_cast<char>(d.data[0]) == glimpse::kEndOfSnapshotType;
      std::optional<SeqNo> g;
      if (eos) {
        if (const auto x = glimpse::decode_end_of_snapshot(d.data)) g = *x;
      }
      splicing_ = g.has_value();
      splice_to_ = g ? *g : 0;
      const auto r = feed_->on_snapshot_payload(d.data, now, *this);
      splicing_ = false;
      if (r == Feed::SpinResult::Spliced) {
        SubTruth& t = h_.subs[s_];
        // The splice covers [next, G): those messages come from the spin, not the lines
        // (when buffered messages follow G, on_book_message already moved past it).
        if (g && t.next < *g) {
          t.covered += *g - t.next;
          t.next = *g;
        }
        if (t.msgs.size() < t.next - 1) {
          t.msgs.resize(t.next - 1);
          t.rx_at.resize(t.next - 1, 0);
        }
        SIM_PROBE("exchange_world.subscriber_spliced_snapshot");
      }
      if (r == Feed::SpinResult::Spliced || (r == Feed::SpinResult::Rejected && eos)) {
        snap_done_ = true;
        h_.log("subscriber %zu snapshot %s at %llu", s_, r == Feed::SpinResult::Spliced ? "spliced" : "rejected",
               static_cast<unsigned long long>(g.value_or(0)));
      }
    }
    if (snap_done_ && snap_ && snap_->state() == sb::ClientSession::State::Active) (void)snap_->logout(now);
    if (a.close || (snap_ && snap_->state() == sb::ClientSession::State::Closed)) {
      flush_snapshot();
      if (snap_conn_) snap_port_.close(*snap_conn_);
      snap_conn_.reset();
      if (!snap_done_) failed();
      snap_.reset();
      snap_done_ = false;
    }
  }

  void failed() {
    h_.log("subscriber %zu snapshot session failed", s_);
    ++h_.subs[s_].snapshot_failures;
    feed_->abort_snapshot();
    snap_wanted_ = feed_->arbiter().state() == mo::LineArbiter::State::AwaitingSnapshot;
  }

  void flush_snapshot() {
    if (!snap_ || !snap_conn_) return;
    for (int guard = 0; guard < 16; ++guard) {
      const std::span<const std::byte> tx = snap_->actions().write;
      if (tx.empty()) break;
      const std::size_t n = snap_port_.write(*snap_conn_, tx);
      if (n == 0) break;
      snap_->consume_tx(n);
    }
  }

  Node& node_;
  Harness& h_;
  std::size_t s_;
  env::Endpoint rr_;
  env::Endpoint glimpse_;
  sb::ClientConfig login_;
  DatagramPort port_;
  StreamPort snap_port_;
  std::unique_ptr<Feed> feed_;
  std::optional<env::ConnId> snap_conn_;
  std::optional<sb::ClientSession> snap_;
  bool snap_wanted_ = false;
  bool snap_done_ = false;
  bool splicing_ = false;
  SeqNo splice_to_ = 0;
  Nanos snap_retry_at_ = 0;
  Nanos now_ = 0;
  Stage stage_;
};

// ---- the operator ----------------------------------------------------------------------
class OperatorProc final : public Process {
 public:
  OperatorProc(Node& n, Harness& h) : node_(n), h_(h), rng_(n.rng(0x0B5)), stage_{this} {
    next_ = h_.open_at +
            static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(std::max<Nanos>(1, h_.close_at - h_.open_at))));
    n.add_stage(stage_, "operator");
  }
  bool poll() {
    const Nanos now = node_.clock().now_mono();
    // The output log is derived data: a failed write leaves it failed until the node
    // restarts and regenerates it from the journal (io_stage.h). Replays and GLIMPSE
    // depend on it, so once faults are healed the operator restarts a node that reports
    // output-log errors (the documented remedy).
    if (!h_.w->faults_active() && now >= next_check_) {
      next_check_ = now + 10 * kMs;
      ExchangeProc* x = h_.node_proc();
      if (x != nullptr && x->io() != nullptr && x->io()->stats().outlog_errors != 0) {
        ++h_.operator_restarts;
        h_.log("%s", "operator: output log failed: restarting the node");
        h_.w->node(0).request_crash();
        return true;
      }
    }
    if (now < next_ || now >= h_.close_at) return false;
    ExchangeProc* x = h_.node_proc();
    if (x == nullptr) {
      next_ = now + kMs;
      return false;
    }
    const auto& sym = h_.day.symbols[static_cast<std::size_t>(rng_.below(h_.day.symbols.size()))];
    sq::AdminMsg a;
    a.operator_id = 900;
    en::AdminArgsBuilder args;
    if (!halted_) {
      a.command = static_cast<std::uint16_t>(en::AdminCommand::Halt);
      args.symbol(sym.symbol).reason("T1");
      halted_sym_ = sym.symbol;
    } else {
      a.command = static_cast<std::uint16_t>(en::AdminCommand::Resume);
      args.symbol(halted_sym_);
    }
    a.len = static_cast<std::uint32_t>(args.bytes().size());
    std::memcpy(a.args, args.bytes().data(), args.bytes().size());
    if (!x->shared().admin.try_push(a)) {
      next_ = now + kMs;
      return false;
    }
    ++(halted_ ? h_.resumes : h_.halts);
    halted_ = !halted_;
    next_ = now + static_cast<Nanos>((h_.close_at - h_.open_at) / 8) + static_cast<Nanos>(rng_.below(5 * kMs));
    return true;
  }

 private:
  struct Stage {
    OperatorProc* p;
    bool poll() { return p->poll(); }
  };
  Node& node_;
  Harness& h_;
  Rng rng_;
  Nanos next_ = 0;
  Nanos next_check_ = 0;
  bool halted_ = false;
  Symbol8 halted_sym_{};
  Stage stage_;
};

}  // namespace

Report run_exchange(const Options& o) {
  auto hp = std::make_unique<Harness>();
  Harness& h = *hp;
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0xE8C);
  h.w = &w;
  h.o = &w.oracles();
  h.seed = o.seed;
  h.verbose = o.verbose;
  h.o_stream =
      w.oracles().activate("O-STREAM", "every SoupBinTCP message a client receives equals the journal's regeneration");
  h.o_arb = w.oracles().activate(kOArb, "subscribers deliver the regenerated ITCH stream in order, once");
  h.o_once = w.oracles().activate(kOExactlyOnce, "each UserRefNum of a session is consumed once, with one response");
  h.o_seq = w.oracles().activate(kOSeq,
                                 "the journal holds each gateway push once, in push order, losing only a crash suffix");
  h.o_cod = w.oracles().activate(
      "O-COD", "no order of a dropped connection is open or executes after its disconnect is sequenced");
  h.o_commit = w.oracles().activate(kOOutputCommit, "every output received comes from a record durable at that time");
  h.o_recover = w.oracles().activate("O-RECOVER", "the node starts on every journal it left");
  h.o_replay = w.oracles().activate(kOReplay, "the node's engine equals a fresh replay of its journal");
  h.o_book = w.oracles().activate(kOBook, "each subscriber's book at End of Session equals the journal's");
  h.durable_tap = std::make_unique<ex::DurableTap>(w, h.durable_at);

  // ---- the day ----
  ExchangeDay& d = h.day;
  d.date = kDay;
  const char* names[] = {"AAPL", "MSFT", "IBM"};
  const std::int64_t refs[] = {1'000'000, 2'000'000, 1'500'000};
  const std::size_t nsym = 2 + wl.below(2);
  for (std::size_t i = 0; i < nsym; ++i) {
    en::SymbolEntry s;
    s.symbol = Symbol8(names[i]);
    s.prior_close = refs[i];
    d.symbols.push_back(s);
  }
  const std::size_t nsess = 3 + wl.below(4);
  const char* firms[] = {"FRMA", "FRMB", "FRMC", "FRMD", "FRME", "FRMF"};
  h.clients.resize(nsess);
  for (std::size_t i = 0; i < nsess; ++i) {
    en::AccountEntry a;
    a.account_id = static_cast<std::uint32_t>(100 * (i + 1));
    a.firms[0] = Mpid4(firms[i]);
    d.accounts.push_back(a);
    const bool cod = wl.below(3) != 0;
    en::SessionEntry se{static_cast<std::uint32_t>(i + 1), a.account_id};
    se.flags =
        static_cast<std::uint8_t>((cod ? en::SessionEntry::kCancelOnDisconnect : 0) | en::SessionEntry::kMarketOrders);
    d.sessions.push_back(se);
    Ledger& L = h.clients[i];
    L.session = se.session_id;
    L.account = a.account_id;
    L.user = "U0" + std::to_string(i + 1);
    L.pass = "PW" + std::to_string(i + 1);
    L.gateway = static_cast<std::uint8_t>(i % 2);
    L.cod = cod;
    gw::SessionSpec spec;
    spec.session_id = se.session_id;
    spec.account = a.account_id;
    spec.username = L.user;
    const std::uint8_t salt[4] = {static_cast<std::uint8_t>(wl.below(256)), static_cast<std::uint8_t>(i), 0x5A, 0xA5};
    spec.credential = gw::Credential::make(L.pass, salt);
    spec.gateway = L.gateway;
    spec.cancel_on_disconnect = cod;
    d.specs.push_back(spec);
  }
  // Compressed standard day: real speed until t0, then `speed` times
  // faster, so 16:00 lands at a seeded point around the end of the faulted phase.
  h.t0 = hms_ns(9, 24, 0);
  h.lead = 2 * kMs + static_cast<Nanos>(wl.below(8 * kMs));
  const Nanos close_target =
      std::max<Nanos>(50 * kMs, static_cast<Nanos>(o.plan.safety_ns) / 2 +
                                    static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(o.plan.safety_ns))));
  h.speed = std::max<std::int64_t>(1, (hms_ns(16, 0, 0) - h.t0) / std::max<Nanos>(1, close_target - h.lead));
  // One seed in 16 runs production's 1 Hz clock ([day] noii_clock, on by default):
  // a timer record every second from 04:00:01, about 19,000 of them overdue when the day
  // starts at t0 and the rest compressed with the day, through the sequencer's timer
  // batches, replication and the engine's clock tick. A stream of its own keeps the
  // other draws as they were.
  Rng day_cfg = w.stream(Stream::Workload, 0xE8F);
  h.clock = day_cfg.below(16) == 0;
  for (en::ScheduleEntry e : en::standard_schedule(false, h.clock)) {
    if (e.timer_id != 0) e.time_ns = h.compressed(e.time_ns);
    d.schedule.push_back(e);
  }
  d.local_midnight = kSimEpochRealNs - (h.t0 - h.lead);
  h.open_at = h.virtual_of(hms_ns(9, 30, 0));
  h.close_at = h.virtual_of(hms_ns(16, 0, 0));
  if (auto r = d.build(); !r) {
    std::fprintf(stderr, "exchange world: %s\n", r.error().c_str());
  }

  // ---- the node ----
  Node& x = w.add_node("x", NodeOptions{true, true});
  NodeParams& p = h.params;
  p.node_id = kInstance;
  p.segment_bytes = jr::kSegmentHeaderBytes + jr::kBatchBytes * (8 + wl.below(24));
  p.l2_bytes = std::size_t{1} << (20 + wl.below(3));
  p.egress_bytes = std::size_t{1} << (17 + wl.below(5));
  // Snapshots every 50 to 1,550 records, 32 times as far apart on a day with the 1 Hz
  // clock (some 30 times the records; each snapshot carries the 0.9 MB schedule).
  p.snapshot_every = wl.below(4) == 0 ? 0 : (50 + wl.below(1500)) * (h.clock ? 32 : 1);
  p.use_snapshots = wl.below(8) != 0;
  p.follower = p.snapshot_every != 0;
  p.follower_poll = static_cast<Nanos>(2 * kMs + wl.below(20 * kMs));
  p.follower_keep = wl.below(3) == 0 ? 2 : 0;
  p.gw[0] = env::Endpoint{x.ip(), kGwPort[0]};
  p.gw[1] = env::Endpoint{x.ip(), kGwPort[1]};
  p.line_a = kLine[0];
  p.line_b = kLine[1];
  p.rerequest_port = kRerequestPort;
  p.glimpse_port = kGlimpsePort;
  p.glimpse_user = "GLIMPS";
  {
    const std::uint8_t salt[3] = {0x47, 0x4C, static_cast<std::uint8_t>(wl.below(256))};
    p.glimpse_credential = gw::Credential::make(kGlimpsePassword, salt);
  }
  p.replay_ring_msgs = wl.below(2) == 0 ? 64 + wl.below(512) : std::size_t{1} << 16;
  p.replay_ring_bytes = std::size_t{1} << 20;
  p.md_ring_messages = wl.below(2) == 0 ? 64 + wl.below(1024) : std::size_t{1} << 16;
  p.md_ring_bytes = std::size_t{1} << 22;
  p.max_packet_b = static_cast<std::size_t>(300 + wl.below(1173));
  p.md_heartbeat = static_cast<Nanos>(5 * kMs + wl.below(100 * kMs));
  p.md_eos_linger = 30 * kNsPerSec;  // production default: receivers that missed it hear it after healing
  // Half the seeds keep L2 in a file ([journal] l2_path, as every lab configuration
  // does): it outlives a process crash, and the next image journals what it held beyond
  // L3 before recovering (restore_l2). A stream of its own keeps the draws above.
  if (Rng l2_cfg = w.stream(Stream::Workload, 0xE90); l2_cfg.below(2) == 0) p.l2_file = std::make_shared<ex::L2File>();
  x.set_boot([&h](Node& nd, BootReason) { nd.emplace_process<NodeProc>(nd, h); });

  // ---- clients, subscribers, operator ----
  // Clients and subscribers may be paused (SIGSTOP): a paused client misses heartbeats,
  // the server's idle timeout closes its session (cancel-on-disconnect while it believes
  // it is connected), and a paused subscriber falls behind both lines.
  for (std::size_t c = 0; c < nsess; ++c) {
    Node& nc = w.add_node("c" + std::to_string(c + 1), NodeOptions{false, true});
    const env::Endpoint gw = p.gw[h.clients[c].gateway];
    nc.set_boot([&h, c, gw](Node& nd, BootReason) { nd.emplace_process<ClientProc>(nd, h, c, gw); });
  }
  client::FeedConfig fc;
  mo::LineArbiterConfig& ac = fc.arbiter;
  ac.session = mo::Session(d.mold_session);
  ac.first_seq = 1;
  ac.reorder_capacity = wl.below(2) == 0 ? 1024 : 4096;
  ac.gap_timeout = log_uniform(wl, 20 * kUs, 5 * kMs);
  ac.request_timeout = log_uniform(wl, kMs, 50 * kMs);
  ac.max_outstanding = static_cast<std::uint32_t>(1 + wl.below(8));
  ac.request_max_count = static_cast<std::uint16_t>(8 + wl.below(57));
  ac.snapshot_gap_messages = wl.below(3) == 0 ? 0 : 100 + wl.below(2000);
  ac.max_gap_age = wl.below(2) == 0 ? 0 : log_uniform(wl, 50 * kMs, 500 * kMs);
  const std::size_t nsub = 1 + wl.below(2);
  h.subs.resize(nsub);
  const env::Endpoint rr{x.ip(), kRerequestPort};
  const env::Endpoint glimpse{x.ip(), kGlimpsePort};
  sb::ClientConfig gl;
  gl.username = Alpha<sb::kUsernameLen>("GLIMPS");
  gl.password = Alpha<sb::kPasswordLen>(kGlimpsePassword);
  for (std::size_t s = 0; s < nsub; ++s) {
    Node& ns = w.add_node("s" + std::to_string(s + 1), NodeOptions{false, true});
    ns.set_boot([&h, s, fc, rr, glimpse, gl](Node& nd, BootReason) {
      nd.emplace_process<SubProc>(nd, h, s, fc, rr, glimpse, gl);
    });
  }
  Node& op = w.add_node("op", NodeOptions{false, false});
  op.set_boot([&h](Node& nd, BootReason) { nd.emplace_process<OperatorProc>(nd, h); });

  h.log("day: speed %lld open at %.3f ms close at %.3f ms, %zu sessions, %zu symbols", static_cast<long long>(h.speed),
        static_cast<double>(h.open_at) / 1e6, static_cast<double>(h.close_at) / 1e6, nsess, nsym);
  for (std::size_t i = 0; i < w.node_count(); ++i) w.node(static_cast<NodeId>(i)).boot();
  w.oracles().add_final_check(h.o_stream, [&h] { h.final_checks(); });

  return finish(
      w, WorldKind::Exchange, o,
      [&h, &w] {
        ExchangeProc* xp = h.node_proc();
        if (xp == nullptr || !xp->settled() || xp->shared().day_end_index.load() == 0) return false;
        for (const Ledger& c : h.clients)
          if (!c.got_eos) return false;
        for (const SubTruth& s : h.subs)
          if (!s.ended) return false;
        (void)w;
        return true;
      },
      [&h] {
        std::uint64_t msgs = 0, replays = 0, earlier = 0, drops = 0, resends = 0, bad = 0;
        for (const Ledger& c : h.clients) {
          msgs += c.msgs.size();
          replays += c.replays_checked;
          earlier += c.earlier_logins;
          drops += c.drops;
          resends += c.resends;
          bad += c.bad;
        }
        std::string node = "down";
        if (const ExchangeProc* xp = h.node_proc()) {
          const auto& sh = xp->shared();
          node = "seq=" + std::to_string(sh.sequenced.load()) +
                 "/applied=" + std::to_string(sh.egress_state.applied.load()) +
                 "/durable=" + std::to_string(sh.durable.load()) +
                 "/release=" + std::to_string(sh.egress_state.release.load()) +
                 "/day_end=" + std::to_string(sh.day_end_index.load()) + "/done=";
          for (std::size_t c = 0; c < md::kConsumers; ++c)
            node += std::to_string(sh.egress_state.done[c].load()) + (c + 1 < md::kConsumers ? "," : "");
        }
        if (h.verbose) {
          for (const Ledger& c : h.clients) {
            std::size_t logins = 0;
            for (const Connection& cn : c.conns) logins += cn.login_at != 0 ? 1u : 0u;
            std::fprintf(stderr, "client session %u: conns=%zu logins=%zu sent=%zu msgs=%zu open=%zu eos=%d\n",
                         c.session, c.conns.size(), logins, c.sent.size(), c.msgs.size(), c.open.size(),
                         c.got_eos ? 1 : 0);
          }
        }
        if (h.verbose) {
          for (std::size_t i = 0; i < h.subs.size(); ++i)
            std::fprintf(stderr,
                         "subscriber %zu: next=%llu delivered=%llu covered=%llu snapshots=%llu failed=%llu ended=%d "
                         "end_at=%llu\n",
                         i, static_cast<unsigned long long>(h.subs[i].next),
                         static_cast<unsigned long long>(h.subs[i].delivered),
                         static_cast<unsigned long long>(h.subs[i].covered),
                         static_cast<unsigned long long>(h.subs[i].snapshots),
                         static_cast<unsigned long long>(h.subs[i].snapshot_failures), h.subs[i].ended ? 1 : 0,
                         static_cast<unsigned long long>(h.subs[i].end_at));
          if (const ExchangeProc* xp = h.node_proc()) {
            if (const auto* sq2 = xp->sequencer()) {
              const auto& st = sq2->stats();
              std::fprintf(
                  stderr, "seq: records=%llu ouch=%llu events=%llu timers=%llu backpressure=%llu timer_bounded=%llu\n",
                  static_cast<unsigned long long>(st.records), static_cast<unsigned long long>(st.ouch),
                  static_cast<unsigned long long>(st.session_events), static_cast<unsigned long long>(st.timers),
                  static_cast<unsigned long long>(st.backpressure), static_cast<unsigned long long>(st.timer_bounded));
            }
            if (const auto* io = xp->io()) {
              const auto& st = io->stats();
              std::fprintf(
                  stderr, "io: appended=%llu outlog_itch=%llu outlog_soup=%llu outlog_errors=%llu\n",
                  static_cast<unsigned long long>(st.appended), static_cast<unsigned long long>(st.outlog_itch),
                  static_cast<unsigned long long>(st.outlog_soup), static_cast<unsigned long long>(st.outlog_errors));
            }
            if (const auto* g = xp->glimpse()) {
              const auto& st = g->stats();
              std::fprintf(stderr, "glimpse: spins=%llu spin_messages=%llu applied=%llu login_rejects=%llu\n",
                           static_cast<unsigned long long>(st.spins), static_cast<unsigned long long>(st.spin_messages),
                           static_cast<unsigned long long>(st.applied),
                           static_cast<unsigned long long>(st.login_rejects));
            }
            if (const auto* m = xp->md()) {
              const auto& st = m->stats();
              std::fprintf(
                  stderr,
                  "md: next_seq=%llu packets_a=%llu packets_b=%llu rerequests=%llu served=%llu refused=%llu ended=%d\n",
                  static_cast<unsigned long long>(m->next_seq()), static_cast<unsigned long long>(st.packets_a),
                  static_cast<unsigned long long>(st.packets_b), static_cast<unsigned long long>(st.rerequests),
                  static_cast<unsigned long long>(st.rerequests_served),
                  static_cast<unsigned long long>(st.rerequests_refused), st.ended ? 1 : 0);
            }
          }
        }
        std::size_t eos = 0, ended = 0;
        for (const Ledger& c : h.clients) eos += c.got_eos ? 1u : 0u;
        for (const SubTruth& t : h.subs) ended += t.ended ? 1u : 0u;
        return "node=" + node + " eos=" + std::to_string(eos) + "/" + std::to_string(h.clients.size()) +
               " sub_end=" + std::to_string(ended) + "/" + std::to_string(h.subs.size()) +
               " sessions=" + std::to_string(h.clients.size()) + " ouch=" + std::to_string(msgs) +
               " itch=" + std::to_string(h.subs.empty() ? 0 : h.subs[0].next - 1) +
               " pushes=" + std::to_string(h.pushes.size()) + " boots=" + std::to_string(h.boots) +
               " recoveries=" + std::to_string(h.recoveries) +
               " snap_recoveries=" + std::to_string(h.snapshot_recoveries) +
               " boot_failures=" + std::to_string(h.boot_failures) + " stops=" + std::to_string(h.stops) +
               " replays=" + std::to_string(replays) + " earlier_logins=" + std::to_string(earlier) +
               " drops=" + std::to_string(drops) + " resends=" + std::to_string(resends) +
               " bad=" + std::to_string(bad) + " halts=" + std::to_string(h.halts) +
               " cod_races=" + std::to_string(h.cod_races) + " snapshots=" + std::to_string(h.snapshots_written) +
               " auction_snapshots=" + std::to_string(h.auction_snapshots.size()) +
               " rewritten=" + std::to_string(h.rewritten) +
               " operator_restarts=" + std::to_string(h.operator_restarts) +
               " cod_fills_after_restart=" + std::to_string(h.cod_fills_after_restart);
      });
}

}  // namespace lle::sim::worlds::detail

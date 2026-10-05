// World `exchange_ha` (09 §2, sim phase 4): two assembled exchange nodes in paired mode
// (10 §3-§5) and the witness, the production stages, start-up, rejoin and replication
// of apps/exchanged (sim/exchange/exchange_node.h with NodeParams::paired), with real
// SoupBinTCP/OUCH clients under the HA client rule and MoldUDP64 subscribers on both
// lines.
//
//   xa, xb   the data nodes (ids 0 and 1; xa is the day's first primary): gateways,
//            sequencer and engine, io (journal + output log), md (line A on the
//            primary, line B on the backup, both after a takeover; a re-request
//            server and GLIMPSE on each node), the replication stage (repl::Replica)
//            with its record log, snapshotd's follower. Process and host crashes,
//            disk faults, partitions; a restart mid-day rejoins (RESUME, or
//            truncation, reload and catch-up, then JOIN).
//   w        witnessd (the production core) with its state file on its own disk.
//   cN       one client per session with refclient's HA order entry
//            (client::HaOrderEntry, 10 §3 step 5): instance 0 on xa, instance 1 on
//            xb (a mirror attach while xb is the backup); every message on the active
//            instance, pending until a response, re-sent on takeover. Crossing flow,
//            partial fills, cancels, replaces; drops of either instance (COD sessions
//            among them), malformed and over-long messages, packets over the limit.
//   sN       subscribers: client::FeedHandler (LineArbiter over lines A and B, xa's
//            and xb's re-request servers as servers A and B, GLIMPSE from either
//            node), plus a mold::LineComparator over every line packet.
//   op       the operator: halts and resumes on the current primary's admin queue,
//            sometimes holding a halt until a takeover; restarts a node whose output
//            log failed, after healing.
//   adv      targeted takeovers: the primary dies right after a partial fill reached
//            a client, or while a halt is held.
//
// The day is the exchange world's (standard schedule without the 1 Hz clock,
// compressed from 09:24); the run converges when the pair is primary and backup in one
// epoch with equal journals, the day has ended, and every client and subscriber has
// End of Session.
//
// Truth is the final journal (the primary's at the end), replayed through a fresh
// engine. Oracles:
//   O-STREAM        every SoupBinTCP message a client received, on either instance,
//                   equals the regeneration byte for byte (each instance's stream is
//                   parsed on its own, so the mirror's copy is checked too); at End of
//                   Session a client holds all of its stream.
//   O-NO-LOST-FILL  every execution a client or subscriber received, in any epoch from
//                   either node, is in the final journal (nothing released is lost by a
//                   takeover, a rejoin truncation or a reload).
//   O-ARB           every subscriber delivers the regenerated ITCH stream in order, once.
//   O-LINE          line A and line B carry the same bytes for every sequence number,
//                   across takeovers (mold::LineComparator, 03 §5).
//   O-EXACTLY-ONCE  in the final journal each UserRefNum of a session is consumed once
//                   with one response, though the HA client re-sends on takeover.
//   O-PREFIX        at the end both nodes' journals hold the same records (canonical
//                   content), and every client stream is a prefix of the final one.
//   O-SEQ           per data node and session, the gateway's pushes (OUCH and session
//                   events, one ordered channel) are journaled once each, in push order,
//                   whether sequenced on that node or FORWARDed to the primary; pushes
//                   are lost only with the incarnation that queued them.
//   O-COD           cancel-on-disconnect against the journal: when a COD session's last
//                   live instance goes (Disconnect or InstanceDown), no order it had is
//                   open or executes after that record; and after a takeover, a SOLO or a
//                   RESUME no order of a session whose live instances all died executes
//                   before their InstanceDown (ADR-032: they go first).
//   O-OUTPUT-COMMIT every output received derives from a record held by both nodes (in
//                   their L2 and record log) or durable on a node when it was received.
//   O-RECOVER       a node starts on every journal it left, once faults are healed.
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
#include "client/order_entry.h"
#include "common/endian.h"
#include "common/types.h"
#include "engine/engine.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "env/buggify.h"
#include "gateway/credentials.h"
#include "journal/reader.h"
#include "journal/record.h"
#include "journal/replay.h"
#include "proto/glimpse/glimpse.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/line_comparator.h"
#include "proto/moldudp64/moldudp64.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/client_session.h"
#include "proto/soupbin/framer.h"
#include "proto/soupbin/packets.h"
#include "proto/soupbin/soupbin.h"
#include "repl/types.h"
#include "sequencer/sequencer.h"
#include "sim/clock.h"
#include "sim/dist.h"
#include "sim/exchange/exchange_node.h"
#include "sim/exchange/truth.h"
#include "sim/exchange/witness_proc.h"
#include "sim/network.h"
#include "sim/node.h"
#include "sim/worlds/journal_device.h"
#include "sim/worlds/worlds.h"
#include "witness/control.h"

namespace lle::sim::worlds::detail {

namespace {

namespace en = lle::engine;
namespace jr = lle::journal;
namespace sq = lle::seq;
namespace oo = lle::ouch50::out;
namespace sb = lle::soup;
namespace mo = lle::mold;
namespace ex = lle::sim::exch;
namespace wit = lle::witness;
using ex::ExchangeDay;
using ex::ExchangeProc;
using ex::NodeParams;
using ex::OrderLife;
using ex::Out;
using ex::Rec;
using ex::SubTruth;
using ex::Truth;

constexpr std::uint32_t kDay = 20261001;
constexpr std::uint16_t kGwPort[2] = {15000, 15001};
constexpr std::uint16_t kRerequestPort = 30003;
constexpr std::uint16_t kGlimpsePort = 30004;
constexpr std::uint16_t kHaPort = 40000;
constexpr std::uint16_t kWitnessPort = 41000;
constexpr std::uint16_t kSubPort = 31000;
constexpr std::string_view kGlimpsePassword = "SPIN";
constexpr env::Endpoint kLine[2] = {{0xEF010101u, 30001}, {0xEF010102u, 30002}};  // 239.1.1.1 / .2
constexpr char kWitnessState[] = "witness.state";
constexpr std::int64_t kTick = 100;  // $0.01 in PxE4
constexpr NodeId kX[2] = {0, 1};     // the data nodes: sim node ids = repl node ids = gateway instances
constexpr NodeId kW = 2;

// ---- what the gateways pushed (taps on both nodes) -----------------------------------
struct Push {
  bool ouch = false;
  std::uint8_t node = 0;          // the data node whose gateway pushed it
  std::uint32_t session = 0;
  std::uint32_t incarnation = 0;  // that node's incarnation
  Nanos at = 0;
  std::vector<std::byte> payload;  // OUCH
  std::uint16_t flags = 0;
  jr::SessionEventKind event = jr::SessionEventKind::Login;  // session event
  SeqNo requested = 0;
  std::uint64_t index = 0;  // journal index of its record (0: not journaled)
  bool after_end = false;   // pushed once that node's sequencer had closed the day
};

// ---- the clients' state ---------------------------------------------------------------
struct Sent {
  char kind = 'O';  // 'O' enter, 'U' replace, 'B' malformed / truncated (consumes, expects 'J')
  std::vector<std::byte> msg;
  bool resolved = false;
};
struct HaLedger {
  std::uint32_t session = 0;
  std::uint32_t account = 0;
  std::string user, pass;
  std::uint8_t gateway = 0;
  bool cod = false;
  sb::SessionId soup_session;
  std::vector<std::vector<std::byte>> msgs;  // msgs[k-1]: SoupBinTCP message k (first copy, either instance)
  std::vector<Nanos> rx_at;                  // its first receipt
  std::map<UserRefNum, Sent> sent;
  std::map<UserRefNum, std::int64_t> open;  // the client's view of its live orders
  std::map<UserRefNum, std::string> symbol_of;
  bool got_eos = false;
  SeqNo eos_at = 0;
  std::uint64_t connects[2] = {0, 0}, logins[2] = {0, 0}, copies_checked = 0, drops = 0, bad = 0, partials = 0;
  std::uint64_t takeovers = 0, resent = 0;
};

// What one data node did, across its incarnations.
struct NodeTrack {
  std::uint64_t boots = 0, boot_failures = 0, exits = 0, stops = 0, rejoins = 0, truncations = 0, resumes = 0;
  std::uint64_t recoveries = 0, incomplete_day_starts = 0, runbooks = 0;
  bool runbook_pending = false;
  ex::DurableMap durable_at;  // (index, content crc) -> first time durable on this node's disk
  std::unique_ptr<ex::DurableTap> durable_tap;
  std::map<std::pair<std::uint64_t, std::uint32_t>, Nanos> held;  // (index, content crc) -> first time in L2
};

struct GrantSeen {
  Nanos at = 0;
  wit::Grant g;
};

// ---- harness --------------------------------------------------------------------------
struct Harness {
  World* w = nullptr;
  OracleRegistry* o = nullptr;
  OracleId o_stream = 0, o_lost = 0, o_arb = 0, o_line = 0, o_once = 0, o_prefix = 0, o_seq = 0, o_cod = 0,
           o_commit = 0, o_recover = 0;
  bool verbose = false;

  ExchangeDay day;
  NodeParams params[2];
  Nanos t0 = 0;
  std::int64_t speed = 1;
  Nanos lead = 0;
  Nanos close_at = 0, open_at = 0;
  [[nodiscard]] Nanos compressed(Nanos t) const { return t <= t0 ? t : t0 + (t - t0) / speed; }
  [[nodiscard]] Nanos virtual_of(Nanos local) const { return compressed(local) - (t0 - lead); }

  std::vector<Push> pushes;
  NodeTrack nodes[2];
  std::vector<GrantSeen> grants;
  std::uint64_t witness_starts = 0, witness_refusals = 0;
  const ex::WitnessProc* witness = nullptr;  // W's running image (nullptr: down)
  bool failing[2] = {false, false};          // an I/O error reached the node's current image
  std::uint64_t crashes_gated = 0;

  std::vector<HaLedger> clients;
  std::vector<SubTruth> subs;
  std::vector<std::unique_ptr<mo::LineComparator>> comparators;  // one per subscriber
  std::uint64_t halts = 0, resumes = 0, held_halts = 0, operator_restarts = 0;
  std::uint64_t targeted = 0, targeted_partial = 0, targeted_halt = 0;
  std::uint64_t cod_fills_before_down = 0, partial_takeovers = 0, halt_spans = 0;
  std::uint64_t snapshots_written = 0, auction_snapshots = 0, dropped_at_close = 0;

  template <class... A>
  void log(const char* fmt, A... a) {
    if (!verbose) return;
    std::fprintf(stderr, "[%10.3f ms] ", static_cast<double>(w->now()) / 1e6);
    std::fprintf(stderr, fmt, a...);
    std::fputc('\n', stderr);
  }

  [[nodiscard]] ExchangeProc* node_proc(std::size_t n) const;
  // The started node that is primary in the highest epoch (nullptr: none).
  [[nodiscard]] ExchangeProc* primary(std::size_t* which = nullptr) const {
    ExchangeProc* best = nullptr;
    std::uint64_t best_epoch = 0;
    for (std::size_t n = 0; n < 2; ++n) {
      ExchangeProc* x = node_proc(n);
      if (x == nullptr) continue;
      const auto r = static_cast<repl::Role>(x->shared().role.load());
      const std::uint64_t e = x->shared().epoch.load();
      if (repl::is_primary(r) && (best == nullptr || e > best_epoch)) {
        best = x;
        best_epoch = e;
        if (which != nullptr) *which = n;
      }
    }
    return best;
  }
  // The failure model (10 §1; HotStandbyLive: one failure at a time): a data node may fail
  // (crash, or an I/O error that stops it) only while the pair can survive it, under W's
  // current and durable state: x is not a member, or x is the solo primary of record (it
  // RESUMEs), or the other node runs as primary or backup in W's epoch with the
  // incarnation W recorded; never while a JOIN is in flight. W may fail while the pair is
  // primary and backup. As the ha world's gate (sim/ha/ha_world.cpp).
  [[nodiscard]] bool allowed_under(const wit::State& s, std::size_t x) const {
    const std::size_t y = 1 - x;
    const auto xi = static_cast<wit::NodeId>(x), yi = static_cast<wit::NodeId>(y);
    if (!wit::is_member(s.members, xi)) return true;
    if (s.members == wit::member_bit(xi) && s.primary == xi) return true;
    const ExchangeProc* other = node_proc(y);
    if (other == nullptr || other->repl() == nullptr || !wit::is_member(s.members, yi)) return false;
    const auto& r = other->repl()->replica();
    return (r.role() == repl::Role::kPrimary || r.role() == repl::Role::kBackup) && r.epoch() == s.epoch &&
           s.inc[y] == r.incarnation();
  }
  [[nodiscard]] bool joining() const {
    for (std::size_t n = 0; n < 2; ++n) {
      const ExchangeProc* x = node_proc(n);
      if (x != nullptr && x->repl() != nullptr && (x->repl()->replica().joining() || x->repl()->replica().join_window()))
        return true;
    }
    return false;
  }
  [[nodiscard]] bool may_fail(std::size_t x) const {
    if (witness == nullptr || witness->core() == nullptr || joining() || failing[1 - x]) return false;
    return allowed_under(witness->core()->state(), x) && allowed_under(witness->durable_state(), x);
  }
  [[nodiscard]] bool pair_up() const {
    const ExchangeProc* a = node_proc(0);
    const ExchangeProc* b = node_proc(1);
    if (a == nullptr || b == nullptr || a->repl() == nullptr || b->repl() == nullptr || joining() || failing[0] ||
        failing[1])
      return false;
    const auto ra = a->repl()->replica().role(), rb = b->repl()->replica().role();
    const bool pb = (ra == repl::Role::kPrimary && rb == repl::Role::kBackup) ||
                    (rb == repl::Role::kPrimary && ra == repl::Role::kBackup);
    return pb && a->repl()->replica().epoch() == b->repl()->replica().epoch();
  }
  [[nodiscard]] bool day_closed(std::size_t n) const {
    const ExchangeProc* x = node_proc(n);
    if (x == nullptr || x->sequencer() == nullptr) return false;
    return x->shared().day_end_index.load() != 0 ||
           (x->sequencer()->started() && x->sequencer()->next_timer() >= day.day->timers().size());
  }
  void on_push(std::size_t n, Push p) {
    p.node = static_cast<std::uint8_t>(n);
    p.incarnation = w->node(kX[n]).incarnation();
    p.at = w->now();
    p.after_end = day_closed(0) || day_closed(1);
    pushes.push_back(std::move(p));
  }

  void final_checks();
  void check_prefix(const Truth& t);
  void check_streams(const Truth& t);
  void check_lost(const Truth& t);
  void check_arb(const Truth& t);
  void check_lines();
  void check_once(const Truth& t);
  void match_pushes(const Truth& t);
  void check_cod(const Truth& t);
  void check_commit(const Truth& t, const std::vector<std::uint32_t>& crc);
  bool check_dead_instances(const Truth& t, std::uint64_t es_index, const Rec& es);
  void probes(const Truth& t);
};

// ---- oracles ----------------------------------------------------------------------------
void Harness::check_prefix(const Truth& t) {
  // Both journals hold the same records (the converged pair; a node still down at the
  // end is not compared).
  std::vector<std::uint32_t> crc[2];
  bool have[2] = {false, false};
  for (std::size_t n = 0; n < 2; ++n) {
    if (node_proc(n) == nullptr) continue;
    crc[n] = ex::canonical_crcs(w->node(kX[n]), params[n].journal_prefix(day.date), day.date);
    have[n] = true;
  }
  if (have[0] && have[1]) {
    const std::size_t m = std::min(crc[0].size(), crc[1].size());
    for (std::size_t i = 0; i < m; ++i) {
      if (crc[0][i] != crc[1][i]) {
        o->fail(o_prefix, "the journals of xa and xb differ at record " + std::to_string(i + 1));
        return;
      }
    }
    if (crc[0].size() != crc[1].size()) {
      o->fail(o_prefix, "the converged journals differ in length: xa " + std::to_string(crc[0].size()) + ", xb " +
                            std::to_string(crc[1].size()));
      return;
    }
    o->pass(o_prefix);
  }
  (void)t;
}

void Harness::check_streams(const Truth& t) {
  for (const HaLedger& c : clients) {
    const auto it = t.ouch.find(c.session);
    const std::size_t have = it == t.ouch.end() ? 0 : it->second.size();
    for (std::size_t k = 0; k < c.msgs.size() && k < have; ++k) {
      if (c.msgs[k] != it->second[k].bytes) {
        o->fail(o_stream, "session " + std::to_string(c.session) + " message " + std::to_string(k + 1) +
                              " differs from the final journal's regeneration (record " +
                              std::to_string(it->second[k].index) + ")");
        return;
      }
      o->pass(o_stream);
    }
    if (c.msgs.size() > have) {
      o->fail(o_stream, "session " + std::to_string(c.session) + " received " + std::to_string(c.msgs.size()) +
                            " messages but the final journal regenerates " + std::to_string(have));
      return;
    }
    if (c.got_eos && c.msgs.size() != have) {
      o->fail(o_stream, "session " + std::to_string(c.session) + " got End of Session with " +
                            std::to_string(c.msgs.size()) + " of " + std::to_string(have) + " messages");
      return;
    }
  }
}

// Executions released to anyone survive into the final journal.
void Harness::check_lost(const Truth& t) {
  for (const HaLedger& c : clients) {
    const auto it = t.ouch.find(c.session);
    for (std::size_t k = 0; k < c.msgs.size(); ++k) {
      if (c.msgs[k].empty() || static_cast<char>(c.msgs[k][0]) != 'E') continue;
      if (it == t.ouch.end() || k >= it->second.size() || it->second[k].bytes != c.msgs[k]) {
        o->fail(o_lost, "session " + std::to_string(c.session) + " received an execution as message " +
                            std::to_string(k + 1) + " that the final journal does not hold");
        return;
      }
      o->pass(o_lost);
    }
  }
  for (std::size_t s = 0; s < subs.size(); ++s) {
    const SubTruth& st = subs[s];
    for (std::size_t k = 0; k < st.msgs.size(); ++k) {
      if (st.rx_at[k] == 0 || st.msgs[k].empty()) continue;
      const char ty = static_cast<char>(st.msgs[k][0]);
      if (ty != 'E' && ty != 'C' && ty != 'P' && ty != 'Q') continue;
      if (k >= t.itch.size() || t.itch[k].bytes != st.msgs[k]) {
        o->fail(o_lost, "subscriber " + std::to_string(s) + " received a trade ('" + std::string(1, ty) +
                            "') as ITCH " + std::to_string(k + 1) + " that the final journal does not hold");
        return;
      }
      o->pass(o_lost);
    }
  }
}

void Harness::check_arb(const Truth& t) {
  for (std::size_t s = 0; s < subs.size(); ++s) {
    const SubTruth& st = subs[s];
    if (st.msgs.size() > t.itch.size()) {
      o->fail(o_arb, "subscriber " + std::to_string(s) + " delivered " + std::to_string(st.msgs.size()) +
                         " messages but the final journal regenerates " + std::to_string(t.itch.size()));
      return;
    }
    for (std::size_t k = 0; k < st.msgs.size(); ++k) {
      if (st.rx_at[k] == 0) continue;  // covered by a snapshot splice
      if (st.msgs[k] != t.itch[k].bytes) {
        o->fail(o_arb, "subscriber " + std::to_string(s) + " message " + std::to_string(k + 1) +
                           " differs from the final journal's regeneration (record " + std::to_string(t.itch[k].index) +
                           ")");
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

void Harness::check_lines() {
  for (std::size_t s = 0; s < comparators.size(); ++s) {
    mo::LineComparator& lc = *comparators[s];
    if (!lc.consistent()) {
      o->fail(o_line, "subscriber " + std::to_string(s) + ": lines A and B differ (" +
                          std::to_string(lc.stats().mismatches) + " mismatches, first at " +
                          std::to_string(lc.stats().first_mismatch) + ", " +
                          std::to_string(lc.stats().session_mismatches) + " session mismatches)");
      return;
    }
    o->pass(o_line);
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
  for (const HaLedger& c : clients) {
    for (const auto& [urn, s] : c.sent) {
      if (s.resolved && t.consumed.count({c.session, urn}) == 0) {
        o->fail(o_once, "session " + std::to_string(c.session) + " saw a response to UserRefNum " +
                            std::to_string(urn) + " that the final journal does not regenerate");
        return;
      }
    }
    // The HA client rule (clients.md §2.4): a response to message k means every message
    // before it was processed, so the client releases them. Every Enter Order sent before
    // one that got a response must therefore be consumed in the final journal, exactly
    // once (a Replace of an order already gone gets no response and consumes nothing).
    UserRefNum last = 0;
    for (const auto& [urn, s] : c.sent)
      if (s.resolved) last = std::max(last, urn);
    for (const auto& [urn, s] : c.sent) {
      if (urn >= last) break;
      if (s.kind != 'O') continue;
      if (t.consumed.count({c.session, urn}) == 0) {
        o->fail(o_once, "session " + std::to_string(c.session) + " Enter Order UserRefNum " + std::to_string(urn) +
                            " was sent before UserRefNum " + std::to_string(last) +
                            ", which got a response, but the final journal never consumed it (the client released it" +
                            " as processed)");
        return;
      }
      o->pass(o_once);
    }
  }
}

// Per (node, session), the journal's OUCH and session-event records with that node as
// instance follow the node's pushes in order: an order-preserving embedding of the
// records into the pushes in which every push left out is excusable (its incarnation
// ended: a crash or an exit loses what it had queued), except that a day that ended
// excuses the pushes after the last one journaled (still queued at the close, 06 §10).
// The embedding is found by dynamic programming over (record, push) suffixes, so an
// identical push of a dead incarnation cannot capture a later incarnation's record.
void Harness::match_pushes(const Truth& t) {
  std::map<std::pair<std::uint8_t, std::uint32_t>, std::vector<std::size_t>> queue;
  for (std::size_t p = 0; p < pushes.size(); ++p) queue[{pushes[p].node, pushes[p].session}].push_back(p);
  std::map<std::pair<std::uint8_t, std::uint32_t>, std::vector<std::uint64_t>> records;
  for (std::uint64_t i = 1; i <= t.recs.size(); ++i) {
    const Rec& r = t.recs[i - 1];
    const bool is_ouch = r.type == jr::RecordType::OuchInbound;
    const bool is_event = r.type == jr::RecordType::SessionEvent;
    if (!is_ouch && !is_event) continue;
    if (is_event && r.event == jr::SessionEventKind::InstanceDown) continue;  // not a gateway push
    if (r.instance > 1) {
      o->fail(o_seq, "record " + std::to_string(i) + " names instance " + std::to_string(r.instance));
      return;
    }
    records[{static_cast<std::uint8_t>(r.instance), r.session}].push_back(i);
  }
  // An incarnation ended (a crash, an exit): the node runs a later one, or is down.
  auto excusable = [&](const Push& p) {
    const Node& nd = w->node(kX[p.node]);
    return p.after_end || !nd.alive() || nd.incarnation() != p.incarnation;
  };
  auto same = [&](const Push& p, std::uint64_t i) {
    const Rec& r = t.recs[i - 1];
    const bool is_ouch = r.type == jr::RecordType::OuchInbound;
    if (p.ouch != is_ouch) return false;
    return is_ouch ? p.payload == r.payload && p.flags == r.flags
                   : p.event == r.event && p.requested == r.requested;
  };
  const bool closed = t.day_end != 0;
  std::set<std::pair<std::uint8_t, std::uint32_t>> keys;
  for (const auto& [k, v] : queue) keys.insert(k);
  for (const auto& [k, v] : records) keys.insert(k);
  for (const auto& key : keys) {
    const std::vector<std::size_t>& P = queue[key];
    const std::vector<std::uint64_t>& R = records[key];
    const std::size_t np = P.size(), nr = R.size();
    // F[i][j]: records i.. embed into pushes j..; row-major (nr+1) x (np+1).
    std::vector<char> F((nr + 1) * (np + 1), 0);
    auto f = [&](std::size_t i, std::size_t j) -> char& { return F[i * (np + 1) + j]; };
    {
      // No record left: the remaining pushes are excused by the close, or each by its
      // incarnation.
      bool all = true;
      for (std::size_t j = np + 1; j-- > 0;) {
        if (j < np && !excusable(pushes[P[j]])) all = false;
        f(nr, j) = closed || all ? 1 : 0;
      }
    }
    for (std::size_t i = nr; i-- > 0;) {
      f(i, np) = 0;
      for (std::size_t j = np; j-- > 0;) {
        const Push& p = pushes[P[j]];
        const bool take = same(p, R[i]) && f(i + 1, j + 1) != 0;
        const bool skip = excusable(p) && f(i, j + 1) != 0;
        f(i, j) = take || skip ? 1 : 0;
      }
    }
    if (f(0, 0) == 0) {
      // Diagnose with a plain greedy walk: the first record that matches no later push,
      // or the first push left out though its incarnation lives on.
      std::size_t j = 0;
      for (std::size_t i = 0; i < nr; ++i) {
        std::size_t m = j;
        while (m < np && !same(pushes[P[m]], R[i])) ++m;
        if (m == np) {
          const Rec& r = t.recs[R[i] - 1];
          o->fail(o_seq, "record " + std::to_string(R[i]) + " (" +
                             (r.type == jr::RecordType::OuchInbound ? "OUCH" : "session event") + ", session " +
                             std::to_string(key.second) + ", instance " + std::to_string(key.first) +
                             ") matches no later push of that node's gateway");
          return;
        }
        for (std::size_t x = j; x < m; ++x) {
          const Push& p = pushes[P[x]];
          if (excusable(p)) continue;
          o->fail(o_seq, std::string(p.ouch ? "an OUCH" : "a session-event") + " push of session " +
                             std::to_string(p.session) + " on node " + std::to_string(p.node) + " (incarnation " +
                             std::to_string(p.incarnation) + ", at " + std::to_string(p.at) +
                             " ns) is missing from the journal, which holds later pushes of that incarnation (record " +
                             std::to_string(R[i]) + ")");
          return;
        }
        j = m + 1;
      }
      for (std::size_t x = j; x < np; ++x) {
        const Push& p = pushes[P[x]];
        if (excusable(p)) continue;
        o->fail(o_seq, std::string(p.ouch ? "an OUCH" : "a session-event") + " push of session " +
                           std::to_string(p.session) + " on node " + std::to_string(p.node) + " (incarnation " +
                           std::to_string(p.incarnation) + ", at " + std::to_string(p.at) +
                           " ns) never reached the final journal and that incarnation did not end");
        return;
      }
      o->fail(o_seq, "the journal's records of session " + std::to_string(key.second) + ", instance " +
                         std::to_string(key.first) + " are not an embedding of that node's pushes");
      return;
    }
    // The embedding (earliest takes): mark the journaled pushes.
    std::size_t i = 0, j = 0;
    while (i < nr && j < np) {
      const Push& p = pushes[P[j]];
      if (same(p, R[i]) && f(i + 1, j + 1) != 0) {
        pushes[P[j]].index = R[i];
        ++i;
      } else if (!excusable(p)) {
        ++dropped_at_close;  // left out after the last journaled push: the day closed
      }
      ++j;
    }
    for (; j < np; ++j)
      if (!excusable(pushes[P[j]])) ++dropped_at_close;
    o->pass(o_seq);
  }
}

// Cancel-on-disconnect against the journal (matching-rules.md §13): live instances per
// session from Login/MirrorAttach and Logout/Disconnect/InstanceDown; when a COD
// session's last live instance goes by Disconnect or InstanceDown, every order it had
// is cancelled there (frozen orders are spared, 13.6).
void Harness::check_cod(const Truth& t) {
  std::map<std::uint32_t, bool> cod;
  for (const HaLedger& c : clients) cod[c.session] = c.cod;
  std::map<std::uint32_t, std::set<std::uint16_t>> live;
  for (std::uint64_t i = 1; i <= t.recs.size(); ++i) {
    const Rec& r = t.recs[i - 1];
    if (r.type != jr::RecordType::SessionEvent) continue;
    auto& L = live[r.session];
    switch (r.event) {
      case jr::SessionEventKind::Login:
      case jr::SessionEventKind::MirrorAttach:
        L.insert(r.instance);
        break;
      case jr::SessionEventKind::Logout:
        L.erase(r.instance);
        break;
      case jr::SessionEventKind::Disconnect:
      case jr::SessionEventKind::InstanceDown: {
        const bool was = L.erase(r.instance) != 0;
        if (!was || !L.empty()) {
          if (was && cod[r.session]) SIM_PROBE("exchange_ha.cod_spared_by_other_instance");
          break;
        }
        if (!cod[r.session]) break;
        SIM_PROBE("exchange_ha.cod_last_instance_gone");
        for (const auto& [key, life] : t.orders) {
          if (key.first != r.session || life.accepted >= i) continue;
          if (t.frozen_at(i, life.accepted)) continue;
          if (life.closed == 0 || life.closed > i) {
            o->fail(o_cod, "session " + std::to_string(r.session) + " UserRefNum " + std::to_string(life.urn) +
                               " is still open after its last instance went at record " + std::to_string(i));
            return;
          }
          for (const std::uint64_t e : life.executions) {
            if (e > i) {
              o->fail(o_cod, "session " + std::to_string(r.session) + " UserRefNum " + std::to_string(life.urn) +
                                 " executed at record " + std::to_string(e) + " after its last instance went at record " +
                                 std::to_string(i));
              return;
            }
          }
        }
        o->pass(o_cod);
        break;
      }
    }
  }
}

void Harness::check_commit(const Truth& t, const std::vector<std::uint32_t>& crc) {
  auto ok_at = [&](std::uint64_t index, Nanos rx) {
    if (index == 0 || index > crc.size()) return false;
    const auto key = std::pair{index, crc[index - 1]};
    Nanos both = 0;
    bool in_both = true;
    for (std::size_t n = 0; n < 2; ++n) {
      const auto it = nodes[n].held.find(key);
      if (it == nodes[n].held.end()) {
        in_both = false;
        break;
      }
      both = std::max(both, it->second);
    }
    if (in_both && both <= rx) return true;
    for (std::size_t n = 0; n < 2; ++n) {
      const auto it = nodes[n].durable_at.find(key);
      if (it != nodes[n].durable_at.end() && it->second <= rx) return true;
    }
    return false;
  };
  for (const HaLedger& c : clients) {
    const auto it = t.ouch.find(c.session);
    if (it == t.ouch.end()) continue;
    for (std::size_t k = 0; k < c.rx_at.size() && k < it->second.size(); ++k) {
      if (!ok_at(it->second[k].index, c.rx_at[k])) {
        o->fail(o_commit, "session " + std::to_string(c.session) + " message " + std::to_string(k + 1) + " (record " +
                              std::to_string(it->second[k].index) +
                              ") was received before the record was held by both nodes or durable on one");
        return;
      }
      o->pass(o_commit);
    }
  }
  for (std::size_t s = 0; s < subs.size(); ++s) {
    for (std::size_t k = 0; k < subs[s].rx_at.size() && k < t.itch.size(); ++k) {
      if (subs[s].rx_at[k] == 0) continue;
      if (!ok_at(t.itch[k].index, subs[s].rx_at[k])) {
        o->fail(o_commit, "subscriber " + std::to_string(s) + " ITCH " + std::to_string(k + 1) + " (record " +
                              std::to_string(t.itch[k].index) +
                              ") was received before the record was held by both nodes or durable on one");
        return;
      }
      o->pass(o_commit);
    }
  }
}

// Probes read from the final journal: a takeover while an order was partly filled, a
// halt whose reopening cross ran in a later epoch under another primary, and fills of
// a dead instance's COD orders sequenced after a takeover but before its InstanceDown.
// ADR-032 after a takeover, a SOLO or a RESUME: the instances that died (the old
// primary's, the lost backup's, the restarted solo primary's own) go down first after the
// new epoch's EpochStart, so no order of a cancel-on-disconnect session whose live
// instances all died executes between that EpochStart and its InstanceDown. Nothing is
// sequenced after DayEnd (DST-008), so an epoch after the close is not checked.
bool Harness::check_dead_instances(const Truth& t, std::uint64_t i, const Rec& es) {
  if (es.epoch <= 1 || (t.day_end != 0 && i > t.day_end)) return true;
  std::map<std::uint64_t, wit::MsgType> granted;
  for (const GrantSeen& g : grants) granted[g.g.epoch] = g.g.request;
  const auto g = granted.find(es.epoch);
  if (g == granted.end()) return true;
  std::uint16_t dead = 0;
  switch (g->second) {
    case wit::MsgType::kPromote:
    case wit::MsgType::kSolo: dead = static_cast<std::uint16_t>(1 - es.primary); break;
    case wit::MsgType::kResume: dead = static_cast<std::uint16_t>(es.primary); break;
    default: return true;  // JOIN: nobody died
  }
  std::map<std::uint32_t, std::set<std::uint16_t>> live;
  for (std::uint64_t j = 1; j < i; ++j) {
    const Rec& e = t.recs[j - 1];
    if (e.type != jr::RecordType::SessionEvent) continue;
    if (e.event == jr::SessionEventKind::Login || e.event == jr::SessionEventKind::MirrorAttach)
      live[e.session].insert(e.instance);
    else
      live[e.session].erase(e.instance);
  }
  for (const HaLedger& c : clients) {
    const auto& L = live[c.session];
    if (!c.cod || L.size() != 1 || L.count(dead) == 0) continue;
    std::uint64_t down = 0;
    for (std::uint64_t j = i + 1; j <= t.recs.size() && down == 0; ++j) {
      const Rec& e = t.recs[j - 1];
      if (e.type == jr::RecordType::SessionEvent && e.session == c.session &&
          e.event == jr::SessionEventKind::InstanceDown && e.instance == dead)
        down = j;
    }
    for (const auto& [key, life] : t.orders) {
      if (key.first != c.session || life.accepted >= i) continue;
      for (const std::uint64_t e : life.executions) {
        if (e > i && (down == 0 || e < down)) {
          ++cod_fills_before_down;
          SIM_PROBE("exchange_ha.cod_fill_before_instance_down");  // never, since ADR-032
          o->fail(o_cod, "session " + std::to_string(c.session) + " UserRefNum " + std::to_string(life.urn) +
                             " of instance " + std::to_string(dead) + ", which died before epoch " +
                             std::to_string(es.epoch) + " (EpochStart at record " + std::to_string(i) +
                             "), executed at record " + std::to_string(e) +
                             (down == 0 ? std::string(" and no InstanceDown followed")
                                        : " before its InstanceDown at record " + std::to_string(down)) +
                             " (ADR-032)");
          return false;
        }
      }
    }
  }
  o->pass(o_cod);
  return true;
}

void Harness::probes(const Truth& t) {
  std::map<std::uint32_t, std::uint32_t> primary_of;  // epoch -> primary
  std::uint32_t prev_primary = ~0u;
  for (std::uint64_t i = 1; i <= t.recs.size(); ++i) {
    const Rec& r = t.recs[i - 1];
    if (r.type != jr::RecordType::EpochStart) continue;
    primary_of[r.epoch] = r.primary;
    if (prev_primary != ~0u && r.primary != prev_primary) {
      // A takeover: an order partly filled and still resting at the new epoch's start.
      for (const auto& [key, life] : t.orders) {
        if (life.accepted >= i || (life.closed != 0 && life.closed < i)) continue;
        const bool filled = std::any_of(life.executions.begin(), life.executions.end(),
                                        [&](std::uint64_t e) { return e < i; });
        if (filled) {
          ++partial_takeovers;
          w->probes().hit("ha.failover_during_partial_fill");
          break;
        }
      }
    }
    prev_primary = r.primary;
    if (!check_dead_instances(t, i, r)) return;
  }
  // Halt -> Resume pairs (the operator halts one symbol at a time).
  std::uint64_t halt_at = 0;
  for (std::uint64_t i = 1; i <= t.recs.size(); ++i) {
    const Rec& r = t.recs[i - 1];
    if (r.type != jr::RecordType::Admin) continue;
    if (r.admin == static_cast<std::uint16_t>(en::AdminCommand::Halt)) {
      halt_at = i;
    } else if (r.admin == static_cast<std::uint16_t>(en::AdminCommand::Resume) && halt_at != 0) {
      const Rec& h = t.recs[halt_at - 1];
      if (r.epoch != h.epoch) {
        SIM_PROBE("exchange_ha.halt_resume_in_another_epoch");
        const auto a = primary_of.find(h.epoch), b = primary_of.find(r.epoch);
        if (a != primary_of.end() && b != primary_of.end() && a->second != b->second) {
          ++halt_spans;
          w->probes().hit("ha.halt_reopen_cross_spans_failover");
          // The reopening cross executed (a Cross message on the feed at the Resume).
          for (const Out& m : t.itch) {
            if (m.index == i && !m.bytes.empty() && static_cast<char>(m.bytes[0]) == 'Q') {
              SIM_PROBE("exchange_ha.halt_cross_executed_after_failover");
              break;
            }
          }
        }
      }
      halt_at = 0;
    }
  }
}

void Harness::final_checks() {
  // The final journal: the primary's (else any running node's).
  std::size_t src = 0;
  if (primary(&src) == nullptr) src = node_proc(0) != nullptr ? 0 : 1;
  const Truth t = ex::regenerate(w->node(kX[src]), params[src].journal_prefix(day.date), day.date, day.schedule);
  if (!t.ok) {
    o->fail(o_stream, "regeneration: " + t.error);
    return;
  }
  const std::vector<std::uint32_t>& crc = t.crc;
  check_prefix(t);
  check_streams(t);
  check_lost(t);
  check_arb(t);
  check_lines();
  check_once(t);
  match_pushes(t);
  check_cod(t);
  check_commit(t, crc);
  probes(t);
}

// ---- the data nodes -------------------------------------------------------------------
ex::NodeHooks node_hooks(Harness& h, std::size_t n) {
  ex::NodeHooks k;
  NodeTrack& nt = h.nodes[n];
  k.durable = nt.durable_tap.get();
  const char* name = n == 0 ? "xa" : "xb";
  if (h.verbose) k.log = [&h, name](const std::string& s) { h.log("%s: %s", name, s.c_str()); };
  k.boot_failed = [&h, n, name](const std::string& why) {
    NodeTrack& t = h.nodes[n];
    ++t.boot_failures;
    h.log("%s: start-up refused: %s", name, why.c_str());
    if (why.find("incomplete day start") != std::string::npos) {
      // The documented remedy (exchange-node.md §8): move the journal aside; the node
      // then joins from an empty journal.
      ++t.incomplete_day_starts;
      SIM_PROBE("exchange_ha.incomplete_day_start");
      t.runbook_pending = true;
      return;
    }
    if (!h.w->faults_active()) h.o->fail(h.o_recover, std::string(name) + " refused to start after healing: " + why);
  };
  k.recovered = [&h, n](const lle::exch::RecoveredDay&) { ++h.nodes[n].recoveries; };
  k.stopped = [&h, n, name](int code) {
    ++h.nodes[n].stops;
    h.log("%s: a stage stopped the node (exit %d)", name, code);
  };
  k.exited = [&h, n, name](int code) {
    ++h.nodes[n].exits;
    h.log("%s: exited (%d)", name, code);
    if (code == 3) SIM_PROBE("exchange_ha.deposed");
    if (code == 5) SIM_PROBE("exchange_ha.rejoin_restarted");
  };
  k.rejoining = [&h, n, name](std::uint64_t inc) {
    ++h.nodes[n].rejoins;
    h.log("%s: rejoining as incarnation %llu", name, static_cast<unsigned long long>(inc));
  };
  k.rejoined = [&h, n, name](repl::Role role, std::uint64_t index, std::uint64_t from) {
    h.log("%s: rejoined as %d at %llu (journal ended at %llu)", name, static_cast<int>(role),
          static_cast<unsigned long long>(index), static_cast<unsigned long long>(from));
    if (role == repl::Role::kSoloPrimary) {
      ++h.nodes[n].resumes;
      SIM_PROBE("exchange_ha.rejoin_resumed");
    }
    if (index < from) {
      ++h.nodes[n].truncations;
      SIM_PROBE("exchange_ha.rejoin_truncated");
    }
  };
  k.snapshot_written = [&h](const en::Engine& e, std::uint64_t) {
    ++h.snapshots_written;
    if (ex::auction_in_progress(e)) {
      ++h.auction_snapshots;
      h.w->probes().hit("snap.during_auction");
    }
  };
  k.taps.ouch = [&h, n](const sq::InboundMsg& m) {
    Push p;
    p.ouch = true;
    p.session = m.session_id;
    p.payload.assign(m.payload().begin(), m.payload().end());
    p.flags = m.flags;
    h.on_push(n, std::move(p));
  };
  k.taps.event = [&h, n](const sq::SessionEventMsg& m) {
    Push p;
    p.ouch = false;
    p.session = m.session_id;
    p.event = m.event;
    p.requested = m.requested_seq;
    h.on_push(n, std::move(p));
  };
  k.held = [&h, n](std::uint64_t index, std::uint32_t crc) {
    h.nodes[n].held.emplace(std::pair{index, crc}, h.w->now());
  };
  return k;
}

class NodeProc final : public Process {
 public:
  NodeProc(Node& nd, Harness& h, std::size_t n) {
    NodeTrack& t = h.nodes[n];
    if (t.runbook_pending) {
      // The runbook for an incomplete day start on a paired node (exchange-node.md §8):
      // the journal's segments are moved aside and the incarnation file stays, so the
      // node rejoins from an empty journal and catches up from its partner.
      t.runbook_pending = false;
      ++t.runbooks;
      const std::string aside = "aside" + std::to_string(t.runbooks) + "/";
      const std::string jp = h.params[n].journal_prefix(h.day.date);
      for (const std::string& name : nd.disk().list()) {
        if (name.starts_with(jp) && name.ends_with(".seg")) (void)nd.disk().rename(name, aside + name);
      }
      h.log("operator: %s's journal segments with an incomplete day start moved aside (%s)", n == 0 ? "xa" : "xb",
            aside.c_str());
    }
    h.failing[n] = false;  // a new image: the error that stopped the last one is behind it
    proc_ = std::make_unique<ExchangeProc>(nd, h.day, h.params[n], node_hooks(h, n));
    if (proc_->boot_error().empty()) ++t.boots;
  }
  [[nodiscard]] ExchangeProc& proc() { return *proc_; }

 private:
  std::unique_ptr<ExchangeProc> proc_;
};

ExchangeProc* Harness::node_proc(std::size_t n) const {
  Node& nd = w->node(kX[n]);
  if (!nd.alive()) return nullptr;
  auto* p = dynamic_cast<NodeProc*>(nd.process());
  return p != nullptr && p->proc().started() ? &p->proc() : nullptr;
}

// ---- the witness ----------------------------------------------------------------------
class WitnessHost final : public Process {
 public:
  WitnessHost(Node& n, Harness& h, Nanos tie_break) : h_(h) {
    ex::WitnessProc::Hooks hk;
    hk.grant = [&h](const wit::Grant& g) {
      // A JOIN grant goes to the primary and, as a copy, to the joiner: once.
      if (g.request == wit::MsgType::kJoin && g.to_node != g.primary) return;
      if (!h.grants.empty() && h.grants.back().g.epoch >= g.epoch) return;  // a retransmission
      h.grants.push_back(GrantSeen{h.w->now(), g});
      h.log("w: grants %s to node %u: epoch %llu primary %u members %u", wit::to_string(g.request), g.to_node,
            static_cast<unsigned long long>(g.epoch), g.primary, g.members);
      switch (g.request) {
        case wit::MsgType::kPromote: SIM_PROBE("exchange_ha.grant_promote"); break;
        case wit::MsgType::kSolo: SIM_PROBE("exchange_ha.grant_solo"); break;
        case wit::MsgType::kJoin: SIM_PROBE("exchange_ha.grant_join"); break;
        case wit::MsgType::kResume: SIM_PROBE("exchange_ha.grant_resume"); break;
        default: break;
      }
    };
    hk.refused = [&h](const std::string& why) {
      ++h.witness_refusals;
      h.log("w: %s", why.c_str());
    };
    hk.started = [&h](const wit::State&) { ++h.witness_starts; };
    proc_ = std::make_unique<ex::WitnessProc>(n, kWitnessPort, kWitnessState, tie_break, std::move(hk));
    if (proc_->core() != nullptr) h.witness = proc_.get();
  }
  ~WitnessHost() override {
    if (h_.witness == proc_.get()) h_.witness = nullptr;
  }

 private:
  Harness& h_;
  std::unique_ptr<ex::WitnessProc> proc_;
};

// ---- clients: the HA client rule (client::HaOrderEntry) ---------------------------------
class HaClientProc final : public Process {
 public:
  HaClientProc(Node& n, Harness& h, std::size_t c, std::array<env::Endpoint, 2> gw, Nanos heartbeat, Nanos idle)
      : node_(n),
        h_(h),
        c_(c),
        gw_(gw),
        port_(n),
        rng_(n.rng(0xC11E)),
        entry_(config(h.clients[c], heartbeat, idle)),
        stage_{this} {
    send_mean_ = static_cast<Nanos>(100 * kUs + rng_.below(1900 * kUs));
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
    HaLedger& L = h_.clients[c_];
    for (std::size_t i = 0; i < 2; ++i) {
      if (!conn_[i] && !L.got_eos && now >= next_try_[i]) {
        conn_[i] = port_.connect(gw_[i]);
        entry_.on_connecting(i);
        view_[i] = View{};
        ++L.connects[i];
        did = true;
      }
    }
    if (now >= entry_.next_deadline()) {
      entry_.on_timer(now);
      did = true;
    }
    if (entry_.active() >= 0) did = act(now) || did;
    did = flush(now) || did;
    L.takeovers = entry_.stats().takeovers;
    L.resent = entry_.stats().resent;
    return did;
  }

 private:
  struct Stage {
    HaClientProc* p;
    bool poll() { return p->poll(); }
  };
  // A passive parse of what one instance received: every Sequenced Data message with
  // its sequence number (from Login Accepted), checked against the session's stream.
  struct View {
    std::unique_ptr<sb::Framer> framer = std::make_unique<sb::Framer>(sb::kMaxPacketLength);
    SeqNo next = 0;  // 0: not logged in
  };

  static client::OrderEntryConfig config(const HaLedger& L, Nanos heartbeat, Nanos idle) {
    client::OrderEntryConfig c;
    c.session.username = Alpha<sb::kUsernameLen>(L.user);
    c.session.password = Alpha<sb::kPasswordLen>(L.pass);
    c.session.session = L.soup_session;
    c.session.sequence = 1;
    c.session.heartbeat_interval = heartbeat;
    c.session.idle_timeout = idle;
    c.session.login_timeout = 4 * idle;
    return c;  // refclient's pending capacity (OrderEntryConfig default)
  }

  [[nodiscard]] std::optional<std::size_t> instance_of(env::ConnId id) const {
    for (std::size_t i = 0; i < 2; ++i)
      if (conn_[i] && *conn_[i] == id) return i;
    return std::nullopt;
  }

  void on_event(const env::StreamEvent& ev, Nanos now) {
    const auto inst = instance_of(ev.conn);
    if (!inst) return;
    const std::size_t i = *inst;
    switch (ev.kind) {
      case env::StreamEventKind::Connected:
        entry_.on_connected(i, now);
        break;
      case env::StreamEventKind::Data: {
        observe(i, ev.data, now);
        entry_.on_bytes(i, ev.data, now, [&](SeqNo, std::span<const std::byte> m) { apply(m); });
        break;
      }
      case env::StreamEventKind::Closed:
        entry_.on_closed(i, now);
        drop(i, now);
        break;
      case env::StreamEventKind::Accepted:
        break;
    }
  }

  void observe(std::size_t i, std::span<const std::byte> in, Nanos now) {
    View& v = view_[i];
    HaLedger& L = h_.clients[c_];
    (void)v.framer->feed(in, [&](const sb::Packet& p) {
      switch (p.type) {
        case 'A':
          if (const auto a = sb::parse_login_accepted(p.payload)) {
            v.next = a->sequence;
            ++L.logins[i];
            if (a->sequence < L.msgs.size() + 1) SIM_PROBE("exchange_ha.login_replays_earlier");
          }
          break;
        case 'S':
          if (v.next != 0) deliver(L, v.next++, p.payload, now, i);
          break;
        case 'Z':
          L.got_eos = true;
          L.eos_at = v.next;
          break;
        default:
          break;
      }
      return true;
    });
  }

  void deliver(HaLedger& L, SeqNo seq, std::span<const std::byte> m, Nanos now, std::size_t i) {
    if (seq <= L.msgs.size()) {
      ++L.copies_checked;
      if (L.msgs[seq - 1].size() != m.size() || std::memcmp(L.msgs[seq - 1].data(), m.data(), m.size()) != 0) {
        h_.o->fail(h_.o_stream, "session " + std::to_string(L.session) + " message " + std::to_string(seq) +
                                    " arrived on instance " + std::to_string(i) +
                                    " with different bytes than its first copy");
      } else {
        h_.o->pass(h_.o_stream);
        if (i == 1) SIM_PROBE("exchange_ha.mirror_copy_checked");
      }
      return;
    }
    if (seq != L.msgs.size() + 1) {
      h_.o->fail(h_.o_stream, "session " + std::to_string(L.session) + " instance " + std::to_string(i) +
                                  " received message " + std::to_string(seq) + " after " +
                                  std::to_string(L.msgs.size()));
      return;
    }
    L.msgs.emplace_back(m.begin(), m.end());
    L.rx_at.push_back(now);
    if (i == 1) SIM_PROBE("exchange_ha.stream_from_mirror_port");
  }

  // The client's view of its orders, from the deduplicated stream; a partial fill may
  // trigger a targeted takeover (adversary).
  void apply(std::span<const std::byte> b) {
    HaLedger& L = h_.clients[c_];
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
        if (it != L.open.end()) {
          it->second -= m.quantity;
          if (it->second <= 0) {
            L.open.erase(it);
          } else {
            ++L.partials;
            partial_seen_ = true;
          }
        }
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

 public:
  // Whether a partial fill reached this client since the last call (the adversary's cue).
  bool take_partial() {
    const bool p = partial_seen_;
    partial_seen_ = false;
    return p;
  }

 private:
  [[nodiscard]] Nanos exp_ns(Nanos mean) { return 1 + sim::exp_ns(rng_, mean); }

  bool act(Nanos now) {
    bool did = false;
    if (now >= next_disrupt_) {
      next_disrupt_ = now + exp_ns(disrupt_mean_);
      did = disrupt(now) || did;
    }
    if (now < next_send_) return did;
    next_send_ = now + exp_ns(send_mean_);
    if (now >= h_.close_at) return did;
    order(now);
    return true;
  }

  void order(Nanos now) {
    HaLedger& L = h_.clients[c_];
    const std::size_t si = static_cast<std::size_t>(rng_.below(h_.day.symbols.size()));
    const std::string sym(h_.day.symbols[si].symbol.view());
    const std::int64_t ref = h_.day.symbols[si].prior_close;
    const std::uint64_t r = rng_.below(100);
    const bool continuous = now >= h_.open_at;
    if (r < 62 || L.open.empty()) {
      const bool market = continuous && rng_.below(25) == 0;
      const bool ioc = market || (continuous && rng_.below(8) == 0);
      const UserRefNum urn = entry_.next_urn();
      const auto px = static_cast<std::uint64_t>(ref + kTick * (static_cast<std::int64_t>(rng_.below(11)) - 5));
      std::vector<std::byte> msg =
          en::enter_msg({.urn = urn,
                         .side = rng_.below(2) == 0 ? ouch50::Side::Buy : ouch50::Side::Sell,
                         .qty = static_cast<Qty>(100 * (1 + rng_.below(10))),
                         .symbol = sym,
                         .price = market ? ouch50::kMarketPrice : px,
                         .tif = ioc ? ouch50::TimeInForce::Ioc : ouch50::TimeInForce::Day,
                         .display = rng_.below(8) == 0 ? ouch50::Display::Hidden : ouch50::Display::Visible});
      if (!entry_.send(msg, now)) return;  // the pending ring is full: not sent
      L.symbol_of[urn] = sym;
      track(urn, 'O', msg);
      return;
    }
    auto it = L.open.begin();
    std::advance(it, static_cast<std::ptrdiff_t>(rng_.below(L.open.size())));
    const UserRefNum target = it->first;
    if (r < 85) {
      const Qty keep = rng_.below(2) == 0 || it->second <= 100
                           ? 0
                           : static_cast<Qty>(100 * rng_.below(static_cast<std::uint64_t>(it->second / 100)));
      (void)entry_.send(en::cancel_msg(target, keep), now);  // refused when the pending ring is full
      return;
    }
    const auto sit = L.symbol_of.find(target);
    std::int64_t ref2 = ref;
    for (const auto& s : h_.day.symbols)
      if (sit != L.symbol_of.end() && s.symbol.view() == sit->second) ref2 = s.prior_close;
    const UserRefNum urn = entry_.next_urn();
    std::vector<std::byte> msg = en::replace_msg(
        {.orig = target,
         .urn = urn,
         .qty = static_cast<Qty>(100 * (1 + rng_.below(10))),
         .price = static_cast<std::uint64_t>(ref2 + kTick * (static_cast<std::int64_t>(rng_.below(11)) - 5))});
    if (!entry_.send(msg, now)) return;
    if (sit != L.symbol_of.end()) L.symbol_of[urn] = sit->second;
    track(urn, 'U', msg);
  }

  void track(UserRefNum urn, char kind, const std::vector<std::byte>& msg) {
    Sent s;
    s.kind = kind;
    s.msg = msg;
    h_.clients[c_].sent[urn] = std::move(s);
  }

  bool disrupt(Nanos now) {
    HaLedger& L = h_.clients[c_];
    const std::uint64_t r = rng_.below(100);
    if (r < 45) {
      // An instance's connection drops (no Logout): the other instance takes over; COD
      // cancels only when the session's last live instance goes.
      std::size_t i = rng_.below(3) == 0 ? 1 - static_cast<std::size_t>(entry_.active())
                                         : static_cast<std::size_t>(entry_.active());
      if (!conn_[i]) i = 1 - i;
      if (!conn_[i]) return false;
      ++L.drops;
      port_.close(*conn_[i]);
      entry_.on_closed(i, now);
      drop(i, now);
      SIM_PROBE("exchange_ha.client_drops_instance");
      return true;
    }
    if (r < 65) {
      ++L.bad;
      std::vector<std::byte> msg = en::enter_msg({.urn = entry_.next_urn(), .qty = 100, .symbol = "AAPL"});
      const bool truncated = rng_.below(2) == 0;
      if (truncated) {
        msg.resize(msg.size() - 1 - rng_.below(8));  // truncated: fails validation, consumes the UserRefNum
      } else {
        msg[0] = std::byte{'z'};  // unknown type: no UserRefNum consumed
      }
      if (entry_.send(msg, now) && truncated) track(load_be32(msg.data() + 1), 'B', msg);
      SIM_PROBE("exchange_ha.malformed_ouch");
      return true;
    }
    if (r < 85) {
      // Over-long, within the HA client's message bound: the gateway truncates it and
      // flags the record malformed; the engine rejects it.
      ++L.bad;
      std::vector<std::byte> msg = en::enter_msg({.urn = entry_.next_urn(), .qty = 100, .symbol = "MSFT"});
      const UserRefNum urn = load_be32(msg.data() + 1);
      msg.resize(sq::InboundMsg::kMaxBytes + 1 + rng_.below(client::HaOrderEntry::kMaxMsg - sq::InboundMsg::kMaxBytes),
                 std::byte{' '});
      if (entry_.send(msg, now)) track(urn, 'B', msg);
      SIM_PROBE("exchange_ha.overlong_ouch_truncated");
      return true;
    }
    // A SoupBinTCP packet over the server's limit on the active instance: the gateway
    // closes that session (a protocol violation), the other instance takes over.
    const auto i = static_cast<std::size_t>(entry_.active());
    if (!conn_[i]) return false;
    ++L.bad;
    (void)flush(now);
    std::vector<std::byte> pkt(3 + 1100 + rng_.below(400), std::byte{0});
    store_be16(pkt.data(), static_cast<std::uint16_t>(pkt.size() - 2));
    pkt[2] = std::byte{'U'};
    (void)port_.write(*conn_[i], pkt);
    SIM_PROBE("exchange_ha.packet_over_limit");
    return true;
  }

  bool flush(Nanos now) {
    bool did = false;
    for (std::size_t i = 0; i < 2; ++i) {
      if (!conn_[i]) continue;
      for (int guard = 0; guard < 64; ++guard) {
        const std::span<const std::byte> out = entry_.tx(i);
        if (out.empty()) break;
        const std::size_t n = port_.write(*conn_[i], out);
        if (n == 0) break;
        entry_.consume_tx(i, n);
        did = true;
      }
      if (entry_.wants_close(i) && entry_.tx(i).empty()) {
        port_.close(*conn_[i]);
        entry_.on_closed(i, now);
        drop(i, now);
        did = true;
      }
    }
    return did;
  }

  void drop(std::size_t i, Nanos now) {
    h_.log("client %zu instance %zu connection ends", c_, i);
    conn_[i].reset();
    view_[i] = View{};
    next_try_[i] = now + kMs / 2 + static_cast<Nanos>(rng_.below(15 * kMs));
  }

  Node& node_;
  Harness& h_;
  std::size_t c_;
  std::array<env::Endpoint, 2> gw_;
  StreamPort port_;
  Rng rng_;
  client::HaOrderEntry entry_;
  std::optional<env::ConnId> conn_[2];
  View view_[2];
  Nanos next_try_[2] = {0, 0};
  Nanos next_send_ = 0;
  Nanos next_disrupt_ = 0;
  Nanos send_mean_ = kMs;
  Nanos disrupt_mean_ = 100 * kMs;
  bool partial_seen_ = false;
  Stage stage_;
};

// ---- subscribers ------------------------------------------------------------------------
// refclient's feed path with both nodes as re-request servers (A = xa, B = xb) and
// GLIMPSE from either node, plus a LineComparator over every line packet.
class HaSubProc final : public Process {
 public:
  using Feed = client::FeedHandler<>;
  HaSubProc(Node& n, Harness& h, std::size_t s, const client::FeedConfig& cfg, std::array<env::Endpoint, 2> rr,
            std::array<env::Endpoint, 2> glimpse, sb::ClientConfig glimpse_login)
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
        compare(0, d.data);
      } else if (d.dst == kLine[1]) {
        src = mo::Source::LineB;
        compare(1, d.data);
      } else if (d.src == rr_[0]) {
        src = mo::Source::RerequestA;
      } else if (d.src == rr_[1]) {
        src = mo::Source::RerequestB;
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
      snap_conn_ = snap_port_.connect(glimpse_[snap_node_]);
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
  void send_request(mo::Server server, std::span<const std::byte> req) {
    (void)port_.send(rr_[server == mo::Server::A ? 0 : 1], req);
    if (server == mo::Server::B) SIM_PROBE("exchange_ha.rerequest_to_server_b");
  }
  void on_snapshot_needed(SeqNo, SeqNo) {
    snap_wanted_ = true;
    SIM_PROBE("exchange_ha.subscriber_needs_snapshot");
  }
  void on_end_of_session(SeqNo e) {
    SubTruth& t = h_.subs[s_];
    t.ended = true;
    t.end_at = e;
  }

 private:
  struct Stage {
    HaSubProc* p;
    bool poll() { return p->poll(); }
  };

  void compare(int line, std::span<const std::byte> pkt) {
    mo::LineComparator& lc = *h_.comparators[s_];
    const std::uint64_t before = lc.stats().mismatches + lc.stats().session_mismatches;
    const std::uint64_t compared = lc.stats().compared;
    lc.on_packet(line, pkt);
    if (lc.stats().mismatches + lc.stats().session_mismatches != before) {
      h_.o->fail(h_.o_line, "subscriber " + std::to_string(s_) + ": line " + (line == 0 ? "A" : "B") +
                                " carries different bytes than the other line (first mismatch at " +
                                std::to_string(lc.stats().first_mismatch) + ")");
    } else if (lc.stats().compared != compared) {
      h_.o->pass(h_.o_line);
    }
  }

  void on_stream(const env::StreamEvent& ev, Nanos now) {
    if (!snap_conn_ || ev.conn != *snap_conn_) return;
    switch (ev.kind) {
      case env::StreamEventKind::Connected: {
        sb::ClientConfig c = login_;
        c.sequence = 1;
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
        if (g && t.next < *g) {
          t.covered += *g - t.next;
          t.next = *g;
        }
        if (t.msgs.size() < t.next - 1) {
          t.msgs.resize(t.next - 1);
          t.rx_at.resize(t.next - 1, 0);
        }
        SIM_PROBE("exchange_ha.subscriber_spliced_snapshot");
        if (snap_node_ == 1) SIM_PROBE("exchange_ha.snapshot_from_xb");
      }
      if (r == Feed::SpinResult::Spliced || (r == Feed::SpinResult::Rejected && eos)) snap_done_ = true;
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
    ++h_.subs[s_].snapshot_failures;
    feed_->abort_snapshot();
    snap_node_ ^= 1u;  // try the other node next
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
  std::array<env::Endpoint, 2> rr_;
  std::array<env::Endpoint, 2> glimpse_;
  sb::ClientConfig login_;
  DatagramPort port_;
  StreamPort snap_port_;
  std::unique_ptr<Feed> feed_;
  std::optional<env::ConnId> snap_conn_;
  std::optional<sb::ClientSession> snap_;
  std::size_t snap_node_ = 0;
  bool snap_wanted_ = false;
  bool snap_done_ = false;
  bool splicing_ = false;
  SeqNo splice_to_ = 0;
  Nanos snap_retry_at_ = 0;
  Nanos now_ = 0;
  Stage stage_;
};

// ---- the operator ------------------------------------------------------------------------
class OperatorProc final : public Process {
 public:
  OperatorProc(Node& n, Harness& h) : node_(n), h_(h), rng_(n.rng(0x0B5)), stage_{this} {
    next_ = h_.open_at +
            static_cast<Nanos>(rng_.below(static_cast<std::uint64_t>(std::max<Nanos>(1, h_.close_at - h_.open_at))));
    n.add_stage(stage_, "operator");
  }
  [[nodiscard]] bool holding() const noexcept { return holding_; }

  bool poll() {
    const Nanos now = node_.clock().now_mono();
    if (!h_.w->faults_active() && now >= next_check_) {
      next_check_ = now + 10 * kMs;
      for (std::size_t n = 0; n < 2; ++n) {
        ExchangeProc* x = h_.node_proc(n);
        if (x != nullptr && x->io() != nullptr && x->io()->stats().outlog_errors != 0 && h_.may_fail(n)) {
          ++h_.operator_restarts;
          h_.log("operator: %s's output log failed: restarting it", n == 0 ? "xa" : "xb");
          h_.w->node(kX[n]).request_crash();
          return true;
        }
      }
    }
    if (now < next_ || now >= h_.close_at) return false;
    std::size_t pn = 0;
    ExchangeProc* x = h_.primary(&pn);
    if (x == nullptr) {
      next_ = now + kMs;
      return false;
    }
    const std::uint64_t epoch = x->shared().epoch.load();
    if (holding_) {
      // A halt held for a takeover: resume under the next primary (or give up).
      if (pn == halt_node_ && epoch == halt_epoch_ && now < hold_until_) {
        next_ = now + kMs;
        return false;
      }
      holding_ = false;
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
    h_.log("operator: %s on %s (epoch %llu)", halted_ ? "resume" : "halt", pn == 0 ? "xa" : "xb",
           static_cast<unsigned long long>(epoch));
    ++(halted_ ? h_.resumes : h_.halts);
    halted_ = !halted_;
    if (halted_ && rng_.below(2) == 0) {
      holding_ = true;
      ++h_.held_halts;
      halt_node_ = pn;
      halt_epoch_ = epoch;
      hold_until_ = now + static_cast<Nanos>((h_.close_at - h_.open_at) / 3);
    }
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
  bool holding_ = false;
  std::size_t halt_node_ = 0;
  std::uint64_t halt_epoch_ = 0;
  Nanos hold_until_ = 0;
  Symbol8 halted_sym_{};
  Stage stage_;
};

// ---- targeted takeovers ------------------------------------------------------------------
class AdversaryProc final : public Process {
 public:
  AdversaryProc(Node& n, Harness& h, std::vector<Node*> clients, Node* op, bool crashes)
      : node_(n), h_(h), clients_(std::move(clients)), op_(op), rng_(n.rng(0xAD5)), stage_{this} {
    budget_ = static_cast<int>(rng_.below(4));  // 0..3 targeted takeovers per run
    if (!crashes) budget_ = 0;                  // the run has no process crashes (--mode, --disable)
    partial_ = rng_.below(3) != 0;
    halt_ = rng_.below(2) == 0;
    n.add_stage(stage_, "adversary");
  }
  bool poll() {
    const Nanos now = node_.clock().now_mono();
    if (budget_ <= 0 || !h_.w->faults_active() || now < next_ || now >= h_.close_at) return false;
    next_ = now + kMs / 4;
    bool partial = false;
    for (Node* c : clients_) {
      auto* p = c->alive() ? dynamic_cast<HaClientProc*>(c->process()) : nullptr;
      if (p != nullptr && p->take_partial()) partial = true;
    }
    auto* op = op_->alive() ? dynamic_cast<OperatorProc*>(op_->process()) : nullptr;
    const bool holding = op != nullptr && op->holding();
    const bool fire = (partial_ && partial) || (halt_ && holding && rng_.below(8) == 0);
    if (!fire) return false;
    std::size_t pn = 0;
    if (h_.primary(&pn) == nullptr) return false;
    if (!h_.may_fail(pn)) {
      ++h_.crashes_gated;
      return false;
    }
    --budget_;
    ++h_.targeted;
    if (partial_ && partial) ++h_.targeted_partial;
    if (holding) ++h_.targeted_halt;
    h_.log("adversary: the primary %s dies (%s)", pn == 0 ? "xa" : "xb", partial ? "partial fill" : "halt held");
    h_.w->node(kX[pn]).request_crash();
    next_ = now + 30 * kMs;  // let the takeover happen
    return true;
  }

 private:
  struct Stage {
    AdversaryProc* p;
    bool poll() { return p->poll(); }
  };
  Node& node_;
  Harness& h_;
  std::vector<Node*> clients_;
  Node* op_;
  Rng rng_;
  int budget_ = 0;
  bool partial_ = false;
  bool halt_ = false;
  Nanos next_ = 0;
  Stage stage_;
};

}  // namespace

Report run_exchange_ha(const Options& o) {
  auto hp = std::make_unique<Harness>();
  Harness& h = *hp;
  World w(o.seed, o.faults);
  w.set_trace(o.trace);
  Rng wl = w.stream(Stream::Workload, 0xE8A);
  h.w = &w;
  h.o = &w.oracles();
  h.verbose = o.verbose;
  h.o_stream = w.oracles().activate(
      "O-STREAM", "every SoupBinTCP message a client receives, on either instance, equals the final journal's");
  h.o_lost = w.oracles().activate(kONoLostFill, "every execution released to anyone is in the final journal");
  h.o_arb = w.oracles().activate(kOArb, "subscribers deliver the regenerated ITCH stream in order, once");
  h.o_line = w.oracles().activate(kOLine, "lines A and B carry the same bytes for every sequence number");
  h.o_once = w.oracles().activate(kOExactlyOnce, "each UserRefNum of a session is consumed once, with one response");
  h.o_prefix = w.oracles().activate(kOPrefix, "the converged nodes' journals hold the same records");
  h.o_seq = w.oracles().activate(
      kOSeq, "per node and session, the gateway's pushes are journaled once each, in push order");
  h.o_cod = w.oracles().activate("O-COD", "no order of a COD session is open or executes after its last instance goes");
  h.o_commit = w.oracles().activate(
      kOOutputCommit, "every output received comes from a record held by both nodes or durable on one at that time");
  h.o_recover = w.oracles().activate("O-RECOVER", "a node starts on every journal it left");
  for (std::size_t n = 0; n < 2; ++n)
    h.nodes[n].durable_tap = std::make_unique<ex::DurableTap>(w, h.nodes[n].durable_at);

  // ---- the day (as the exchange world's) ----
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
    HaLedger& L = h.clients[i];
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
  h.t0 = hms_ns(9, 24, 0);
  h.lead = 2 * kMs + static_cast<Nanos>(wl.below(8 * kMs));
  const Nanos close_target =
      std::max<Nanos>(50 * kMs, static_cast<Nanos>(o.plan.safety_ns) / 2 +
                                    static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(o.plan.safety_ns))));
  h.speed = std::max<std::int64_t>(1, (hms_ns(16, 0, 0) - h.t0) / std::max<Nanos>(1, close_target - h.lead));
  for (en::ScheduleEntry e : en::standard_schedule(false, false)) {
    if (e.timer_id != 0) e.time_ns = h.compressed(e.time_ns);
    d.schedule.push_back(e);
  }
  d.local_midnight = kSimEpochRealNs - (h.t0 - h.lead);
  h.open_at = h.virtual_of(hms_ns(9, 30, 0));
  h.close_at = h.virtual_of(hms_ns(16, 0, 0));
  if (auto r = d.build(); !r) std::fprintf(stderr, "exchange_ha world: %s\n", r.error().c_str());

  // ---- the data nodes and the witness ----
  Node& xa = w.add_node("xa", NodeOptions{true, true});
  Node& xb = w.add_node("xb", NodeOptions{true, true});
  Node& wn = w.add_node("w", NodeOptions{true, true});
  LLE_ASSERT(xa.id() == kX[0] && xb.id() == kX[1] && wn.id() == kW, "node ids");
  Node* xs[2] = {&xa, &xb};
  // Replication timing (ExchangeConfig [ha]), drawn per seed as the ha world does.
  const Nanos t_d = 10 * kMs + static_cast<Nanos>(wl.below(15 * kMs + 1));
  const Nanos t_ack = 4 * kMs + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(t_d - 5 * kMs)));
  const Nanos rto = kMs + static_cast<Nanos>(wl.below(3 * kMs));
  const Nanos tie_break = 3 * kMs + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(t_d - 4 * kMs)));
  const Nanos soup_hb = 5 * kMs + static_cast<Nanos>(wl.below(45 * kMs));
  const Nanos soup_idle = 4 * soup_hb + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(6 * soup_hb)));
  NodeParams base;
  base.segment_bytes = jr::kSegmentHeaderBytes + jr::kBatchBytes * (8 + wl.below(24));
  base.l2_bytes = std::size_t{1} << (20 + wl.below(3));
  base.egress_bytes = std::size_t{1} << (17 + wl.below(5));
  base.snapshot_every = wl.below(4) == 0 ? 0 : 50 + wl.below(1500);
  base.use_snapshots = wl.below(8) != 0;
  base.follower = base.snapshot_every != 0;
  base.follower_poll = static_cast<Nanos>(2 * kMs + wl.below(20 * kMs));
  base.follower_keep = wl.below(3) == 0 ? 2 : 0;
  base.line_a = kLine[0];
  base.line_b = kLine[1];
  base.rerequest_port = kRerequestPort;
  base.glimpse_port = kGlimpsePort;
  base.glimpse_user = "GLIMPS";
  {
    const std::uint8_t salt[3] = {0x47, 0x4C, static_cast<std::uint8_t>(wl.below(256))};
    base.glimpse_credential = gw::Credential::make(kGlimpsePassword, salt);
  }
  base.replay_ring_msgs = wl.below(2) == 0 ? 64 + wl.below(512) : std::size_t{1} << 16;
  base.replay_ring_bytes = std::size_t{1} << 20;
  base.md_ring_messages = wl.below(2) == 0 ? 64 + wl.below(1024) : std::size_t{1} << 16;
  base.md_ring_bytes = std::size_t{1} << 22;
  base.max_packet_b = static_cast<std::size_t>(300 + wl.below(1173));
  base.md_heartbeat = static_cast<Nanos>(5 * kMs + wl.below(100 * kMs));
  base.md_eos_linger = 30 * kNsPerSec;
  base.soup_heartbeat = soup_hb;
  base.soup_idle_timeout = soup_idle;
  base.soup_login_timeout = 4 * soup_idle;
  base.paired = true;
  base.initial_primary = 0;
  base.witness = env::Endpoint{wn.ip(), kWitnessPort};
  base.ha_heartbeat = kMs;
  base.t_d = t_d;
  base.t_ack = t_ack;
  base.ha_rto = rto;
  base.rejoin_retry = 5 * kMs;
  base.repl_log_bytes = std::size_t{1} << (16 + wl.below(8));  // small arenas read older records back from L3
  for (std::size_t n = 0; n < 2; ++n) {
    NodeParams& p = h.params[n];
    p = base;
    p.node_id = static_cast<std::uint16_t>(n);
    p.gw[0] = env::Endpoint{xs[n]->ip(), kGwPort[0]};
    p.gw[1] = env::Endpoint{xs[n]->ip(), kGwPort[1]};
    p.ha_bind = env::Endpoint{xs[n]->ip(), kHaPort};
    p.ha_peer = env::Endpoint{xs[1 - n]->ip(), kHaPort};
    xs[n]->set_boot([&h, n](Node& nd, BootReason) { nd.emplace_process<NodeProc>(nd, h, n); });
  }
  {
    const auto img = ex::WitnessProc::initial_state(0);
    wn.disk().install(kWitnessState, img);
  }
  wn.set_boot([&h, tie_break](Node& nd, BootReason) { nd.emplace_process<WitnessHost>(nd, h, tie_break); });

  // ---- clients, subscribers, operator, adversary ----
  std::vector<Node*> client_nodes;
  for (std::size_t c = 0; c < nsess; ++c) {
    Node& nc = w.add_node("c" + std::to_string(c + 1), NodeOptions{false, false});
    const std::uint8_t g = h.clients[c].gateway;
    const std::array<env::Endpoint, 2> gw{h.params[0].gw[g], h.params[1].gw[g]};
    nc.set_boot([&h, c, gw, soup_hb, soup_idle](Node& nd, BootReason) {
      nd.emplace_process<HaClientProc>(nd, h, c, gw, soup_hb, soup_idle);
    });
    client_nodes.push_back(&nc);
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
  for (std::size_t s = 0; s < nsub; ++s) h.comparators.push_back(std::make_unique<mo::LineComparator>(std::size_t{1} << 16));
  const std::array<env::Endpoint, 2> rr{env::Endpoint{xa.ip(), kRerequestPort}, env::Endpoint{xb.ip(), kRerequestPort}};
  const std::array<env::Endpoint, 2> glimpse{env::Endpoint{xa.ip(), kGlimpsePort}, env::Endpoint{xb.ip(), kGlimpsePort}};
  sb::ClientConfig gl;
  gl.username = Alpha<sb::kUsernameLen>("GLIMPS");
  gl.password = Alpha<sb::kPasswordLen>(kGlimpsePassword);
  for (std::size_t s = 0; s < nsub; ++s) {
    Node& ns = w.add_node("s" + std::to_string(s + 1), NodeOptions{false, false});
    ns.set_boot([&h, s, fc, rr, glimpse, gl](Node& nd, BootReason) {
      nd.emplace_process<HaSubProc>(nd, h, s, fc, rr, glimpse, gl);
    });
  }
  Node& op = w.add_node("op", NodeOptions{false, false});
  op.set_boot([&h](Node& nd, BootReason) { nd.emplace_process<OperatorProc>(nd, h); });
  Node& adv = w.add_node("adv", NodeOptions{false, false});
  const bool crashes = o.faults.enabled(FaultClass::Crash);
  adv.set_boot([&h, client_nodes, &op, crashes](Node& nd, BootReason) {
    nd.emplace_process<AdversaryProc>(nd, h, client_nodes, &op, crashes);
  });

  h.log("day: speed %lld open at %.3f ms close at %.3f ms, %zu sessions, %zu symbols; t_d %.1f ms t_ack %.1f ms",
        static_cast<long long>(h.speed), static_cast<double>(h.open_at) / 1e6, static_cast<double>(h.close_at) / 1e6,
        nsess, nsym, static_cast<double>(t_d) / 1e6, static_cast<double>(t_ack) / 1e6);
  // Failures stay inside the failure model: crashes and I/O errors of a data node only
  // when the pair survives them, of W only while the pair is primary and backup.
  w.injector().set_crash_guard([&h](NodeId n) {
    const bool ok = n == kX[0] || n == kX[1] ? h.may_fail(n) : n == kW ? h.pair_up() : true;
    if (!ok) ++h.crashes_gated;
    return ok;
  });
  for (std::size_t n = 0; n < 2; ++n)
    xs[n]->disk().set_fault_gate([&h, n] { return h.may_fail(n); }, [&h, n] { h.failing[n] = true; });
  wn.disk().set_fault_gate([&h] { return h.pair_up(); });
  for (std::size_t i = 0; i < w.node_count(); ++i) w.node(static_cast<NodeId>(i)).boot();
  w.oracles().add_final_check(h.o_stream, [&h] { h.final_checks(); });

  return finish(
      w, WorldKind::ExchangeHa, o,
      [&h] {
        ExchangeProc* x[2] = {h.node_proc(0), h.node_proc(1)};
        if (x[0] == nullptr || x[1] == nullptr) return false;
        repl::Role r[2];
        for (std::size_t n = 0; n < 2; ++n) r[n] = static_cast<repl::Role>(x[n]->shared().role.load());
        const bool pair = (r[0] == repl::Role::kPrimary && r[1] == repl::Role::kBackup) ||
                          (r[1] == repl::Role::kPrimary && r[0] == repl::Role::kBackup);
        if (!pair || x[0]->shared().epoch.load() != x[1]->shared().epoch.load()) return false;
        for (std::size_t n = 0; n < 2; ++n) {
          if (!x[n]->settled() || x[n]->shared().day_end_index.load() == 0) return false;
        }
        if (x[0]->shared().sequenced.load() != x[1]->shared().sequenced.load()) return false;
        for (std::size_t n = 0; n < 2; ++n)
          if (x[n]->shared().durable.load() != x[n]->shared().sequenced.load()) return false;
        for (const HaLedger& c : h.clients)
          if (!c.got_eos) return false;
        for (const SubTruth& s : h.subs)
          if (!s.ended) return false;
        return true;
      },
      [&h] {
        std::uint64_t msgs = 0, copies = 0, drops = 0, bad = 0, takeovers = 0, resent = 0, partials = 0;
        for (const HaLedger& c : h.clients) {
          msgs += c.msgs.size();
          copies += c.copies_checked;
          drops += c.drops;
          bad += c.bad;
          takeovers += c.takeovers;
          resent += c.resent;
          partials += c.partials;
        }
        std::string nodes;
        for (std::size_t n = 0; n < 2; ++n) {
          nodes += n == 0 ? "xa=" : " xb=";
          if (const ExchangeProc* x = h.node_proc(n)) {
            const auto& sh = x->shared();
            nodes += "r" + std::to_string(sh.role.load()) + "/e" + std::to_string(sh.epoch.load()) + "/seq" +
                     std::to_string(sh.sequenced.load()) + "/dur" + std::to_string(sh.durable.load()) + "/rel" +
                     std::to_string(sh.egress_state.release.load()) + "/end" + std::to_string(sh.day_end_index.load());
          } else {
            nodes += "down";
          }
          if (const ExchangeProc* x = h.node_proc(n); x != nullptr && x->io() != nullptr && h.verbose) {
            const auto& st = x->io()->stats();
            nodes += "[io appended " + std::to_string(st.appended) + " prepared " + std::to_string(st.segments_prepared) +
                     " stall_prepares " + std::to_string(st.stall_prepares) + " outlog_errors " +
                     std::to_string(st.outlog_errors) + " failed " + std::to_string(x->io()->failed() ? 1 : 0) +
                     " io_durable " + std::to_string(x->io()->durable()) + " l2_hold " +
                     std::to_string(x->shared().io_hold.load() ? 1 : 0) + "]";
            if (x->repl() != nullptr) {
              const auto& r = x->repl()->replica();
              const auto jv = r.join_view();
              nodes += "[repl role " + std::to_string(static_cast<int>(r.role())) + " epoch " + std::to_string(r.epoch()) +
                       " commit " + std::to_string(r.commit_index()) + " ack " + std::to_string(r.backup_ack()) +
                       " release " + std::to_string(r.release_watermark()) + " join " + std::to_string(jv.active) +
                       "/" + std::to_string(jv.sent) + "/" + std::to_string(jv.window) + " jacked " +
                       std::to_string(jv.acked) + " rlog_tail " +
                       std::to_string(x->record_log() != nullptr ? x->record_log()->tail().last_index : 0) + "]";
            }
          }
          const NodeTrack& t = h.nodes[n];
          nodes += "(boots" + std::to_string(t.boots) + ",rejoins" + std::to_string(t.rejoins) + ",trunc" +
                   std::to_string(t.truncations) + ",resumes" + std::to_string(t.resumes) + ",exits" +
                   std::to_string(t.exits) + ",fail" + std::to_string(t.boot_failures) + ")";
        }
        std::uint64_t promotes = 0, solos = 0, joins = 0, resumes = 0;
        for (const GrantSeen& g : h.grants) {
          promotes += g.g.request == wit::MsgType::kPromote ? 1u : 0u;
          solos += g.g.request == wit::MsgType::kSolo ? 1u : 0u;
          joins += g.g.request == wit::MsgType::kJoin ? 1u : 0u;
          resumes += g.g.request == wit::MsgType::kResume ? 1u : 0u;
        }
        std::size_t eos = 0, ended = 0;
        for (const HaLedger& c : h.clients) eos += c.got_eos ? 1u : 0u;
        for (const SubTruth& t : h.subs) ended += t.ended ? 1u : 0u;
        std::uint64_t compared = 0;
        for (const auto& lc : h.comparators) compared += lc->stats().compared;
        return nodes + " grants=P" + std::to_string(promotes) + "/S" + std::to_string(solos) + "/J" +
               std::to_string(joins) + "/R" + std::to_string(resumes) + " eos=" + std::to_string(eos) + "/" +
               std::to_string(h.clients.size()) + " sub_end=" + std::to_string(ended) + "/" +
               std::to_string(h.subs.size()) + " ouch=" + std::to_string(msgs) + " copies=" + std::to_string(copies) +
               " itch=" + std::to_string(h.subs.empty() ? 0 : h.subs[0].next - 1) +
               " ab_compared=" + std::to_string(compared) + " pushes=" + std::to_string(h.pushes.size()) +
               " client_takeovers=" + std::to_string(takeovers) + " resent=" + std::to_string(resent) +
               " drops=" + std::to_string(drops) + " bad=" + std::to_string(bad) +
               " partials=" + std::to_string(partials) + " halts=" + std::to_string(h.halts) +
               " held_halts=" + std::to_string(h.held_halts) + " targeted=" + std::to_string(h.targeted) +
               " partial_takeovers=" + std::to_string(h.partial_takeovers) +
               " halt_spans=" + std::to_string(h.halt_spans) +
               " cod_fills_before_down=" + std::to_string(h.cod_fills_before_down) +
               " snapshots=" + std::to_string(h.snapshots_written) +
               " dropped_at_close=" + std::to_string(h.dropped_at_close) +
               " operator_restarts=" + std::to_string(h.operator_restarts) +
               " gated=" + std::to_string(h.crashes_gated);
      });
}

}  // namespace lle::sim::worlds::detail

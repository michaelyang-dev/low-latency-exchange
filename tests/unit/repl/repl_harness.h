#pragma once
// Test harness for the replication core: a FakeHost (log as a vector of canonical
// records, an L3 durable index the test controls, a fold-hash applier, recorded
// side effects), a two-node Cluster with the real witness core (persistence is
// immediate) and an in-memory network whose links the tests can cut, drop or
// duplicate. Deterministic: no clocks, no threads; time is a counter.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/hash.h"
#include "journal/record.h"
#include "repl/replica.h"
#include "repl/types.h"
#include "repl/wire.h"
#include "witness/control.h"
#include "witness/witness.h"

namespace lle::repl::test {

using Bytes = std::vector<std::byte>;
inline constexpr Nanos kMs = 1'000'000;
inline constexpr Nanos kUs = 1'000;
inline constexpr std::uint64_t kBuild = 0xB111'D000'0000'0001ull;

inline journal::Sealer& canonical_sealer() {
  static journal::Sealer s;
  return s;
}

struct ForwardCopy {
  std::uint32_t session = 0;
  std::uint16_t instance = 0;
  std::uint32_t account = 0;
  std::uint64_t seq = 0;
  wire::ForwardKind kind = wire::ForwardKind::kOuch;
  std::uint8_t event = 0;
  Bytes bytes;
  std::uint16_t flags = 0;  // journal record flags
};

struct FakeHost {
  // ---- log (L2 + L3) ----
  std::vector<Bytes> log;  // log[i - 1] = record i, canonical
  std::uint64_t durable = 0;
  bool flush_on_request = true;  // request_flush makes the whole log durable at once
  // L2 capacity in records (0: unlimited). As in exchanged, the L2 cursor follows the
  // applier: a record leaves L2 once applied, so at most l2_cap records past `applied`.
  std::size_t l2_cap = 0;
  bool refuse_appends = false;   // simulate a full L2 ring
  // ---- applier ----
  std::uint64_t applied = 0;
  std::uint64_t state = 0;
  std::uint64_t hash_interval = 4;
  std::uint64_t corrupt_hash_at = 0;  // nonzero: perturb the state hash from this index
  std::vector<std::uint64_t> reloads;
  // ---- effects ----
  std::deque<Bytes> to_peer;
  std::deque<Bytes> to_witness;
  std::vector<ForwardCopy> injected;
  bool refuse_inject = false;
  std::vector<std::pair<Role, std::uint64_t>> roles;
  std::vector<NodeId> instance_downs;
  std::vector<std::pair<Alarm, std::uint64_t>> alarms;
  std::vector<TraceEvent> traces;
  std::vector<std::uint64_t> truncations;
  bool deposed_flag = false;
  Nanos real = 1'790'000'000'000'000'000;
  std::uint64_t flush_requests = 0;
  // ---- snapshots ----
  std::optional<SnapshotOffer> offer;
  Bytes offer_image;
  std::uint64_t offer_state = 0;
  std::uint64_t released_snapshots = 0;
  Bytes rx_image;
  std::uint64_t rx_index = 0;
  bool rx_reject = false;
  std::uint64_t installed_index = 0;

  // ---- Host concept ----
  [[nodiscard]] journal::ChainState log_tail() const {
    if (log.empty()) return {};
    const journal::RecordView v{std::span<const std::byte>(log.back())};
    return journal::ChainState{v.index(), v.crc(), v.ts_ns(), v.epoch()};
  }
  [[nodiscard]] std::uint64_t durable_index() const { return std::min<std::uint64_t>(durable, log.size()); }
  [[nodiscard]] std::uint64_t applied_index() const { return applied; }
  bool log_append(std::span<const std::byte> rec) {
    if (refuse_appends) return false;
    if (l2_cap != 0 && log.size() >= applied + l2_cap) return false;  // L2 full
    const journal::RecordView v(rec);
    EXPECT_EQ(v.index(), log.size() + 1);
    log.emplace_back(rec.begin(), rec.end());
    return true;
  }
  std::uint32_t log_read(std::uint64_t idx, std::span<std::byte> out) const {
    if (idx == 0 || idx > log.size()) return 0;
    const Bytes& r = log[idx - 1];
    std::copy(r.begin(), r.end(), out.begin());
    return static_cast<std::uint32_t>(r.size());
  }
  EpochEndInfo log_epoch_end(std::uint64_t epoch) const {
    for (std::size_t i = log.size(); i > 0; --i) {
      const journal::RecordView v{std::span<const std::byte>(log[i - 1])};
      if (v.epoch() <= epoch) return EpochEndInfo{v.index(), v.crc(), v.epoch()};
    }
    return {};
  }
  EpochEndInfo log_epoch_start(std::uint64_t epoch) const {
    for (std::size_t i = 0; i < log.size(); ++i) {
      const journal::RecordView v{std::span<const std::byte>(log[i])};
      if (v.epoch() == epoch) return EpochEndInfo{v.index(), v.crc(), v.epoch()};
    }
    return {};
  }
  bool log_truncate(std::uint64_t t) {
    truncations.push_back(t);
    if (t < log.size()) log.resize(t);
    durable = std::min(durable, t);
    return true;
  }
  void request_flush() {
    ++flush_requests;
    if (flush_on_request) durable = log.size();
  }
  void reload_state(std::uint64_t t) {
    reloads.push_back(t);
    applied = 0;
    state = 0;
    apply_to(t, nullptr);
  }
  bool inject_inbound(const wire::Forward& f) {
    if (refuse_inject) return false;
    injected.push_back(ForwardCopy{f.session_id, f.instance, f.account, f.seq, f.kind, f.event,
                                   Bytes(f.bytes.begin(), f.bytes.end()), f.record_flags});
    return true;
  }
  void on_role(Role r, std::uint64_t e) { roles.emplace_back(r, e); }
  void instance_down(NodeId n) { instance_downs.push_back(n); }
  void deposed() { deposed_flag = true; }
  void alarm(Alarm a, std::uint64_t d) { alarms.emplace_back(a, d); }
  void send_peer(std::span<const std::byte> b) { to_peer.emplace_back(b.begin(), b.end()); }
  void send_witness(std::span<const std::byte> b) { to_witness.emplace_back(b.begin(), b.end()); }
  [[nodiscard]] Nanos now_real() const { return real; }
  void trace(const TraceEvent& e) { traces.push_back(e); }
  SnapshotOffer snapshot_offer() { return offer.value_or(SnapshotOffer{}); }
  std::uint32_t snapshot_read(std::uint64_t off, std::span<std::byte> out) {
    if (off >= offer_image.size()) return 0;
    const std::size_t n = std::min(out.size(), offer_image.size() - static_cast<std::size_t>(off));
    std::copy_n(offer_image.begin() + static_cast<std::ptrdiff_t>(off), n, out.begin());
    return static_cast<std::uint32_t>(n);
  }
  void snapshot_release() { ++released_snapshots; }
  bool snapshot_receive(std::uint64_t index, std::uint64_t total, std::uint64_t offset,
                        std::span<const std::byte> b) {
    if (offset == 0) {
      rx_image.assign(static_cast<std::size_t>(total), std::byte{0});
      rx_index = index;
    }
    std::copy(b.begin(), b.end(), rx_image.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
  }
  bool snapshot_install() {
    if (rx_reject || rx_image.size() < 8) return false;
    // Test snapshots carry the fold state in their first 8 bytes.
    std::uint64_t s = 0;
    for (std::size_t i = 0; i < 8; ++i) s |= static_cast<std::uint64_t>(rx_image[i]) << (8 * i);
    state = s;
    applied = rx_index;
    installed_index = rx_index;
    return true;
  }

  // ---- test helpers ----
  // Applies records applied+1..limit (the applier stage); reports checkpoints.
  template <class Rep>
  void apply_to(std::uint64_t limit, Rep* replica) {
    limit = std::min<std::uint64_t>(limit, log.size());
    while (applied < limit) {
      ++applied;
      const journal::RecordView v{std::span<const std::byte>(log[applied - 1])};
      state = combine(state, v.crc());
      if (corrupt_hash_at != 0 && applied >= corrupt_hash_at) state ^= 0x5A5A;
      if (replica != nullptr && hash_interval != 0 && applied % hash_interval == 0) replica->on_state_hash(applied, state);
    }
  }
  void apply_to(std::uint64_t limit, std::nullptr_t) {
    limit = std::min<std::uint64_t>(limit, log.size());
    while (applied < limit) {
      ++applied;
      const journal::RecordView v{std::span<const std::byte>(log[applied - 1])};
      state = combine(state, v.crc());
    }
  }

  // The sequencer: appends an OuchInbound record in `epoch`.
  std::uint64_t sequence(std::uint32_t epoch, std::uint32_t session, std::uint16_t instance, std::uint32_t account,
                         std::span<const std::byte> msg, std::uint16_t flags = 0) {
    journal::RecordBuilder b(canonical_sealer(), log_tail());
    b.set_epoch(epoch);
    Bytes buf(journal::kMaxRecordBytes);
    const auto r = b.append(std::span<std::byte>(buf), real += 1000,
                            journal::OuchInbound{session, account, instance, msg}, flags);
    EXPECT_FALSE(r.empty());
    buf.resize(r.size());
    log.push_back(std::move(buf));
    return log.size();
  }
  std::uint64_t sequence_n(std::uint32_t epoch, int n, std::uint32_t session = 7) {
    std::uint64_t last = 0;
    for (int i = 0; i < n; ++i) {
      const std::array<std::byte, 4> msg{std::byte{'O'}, static_cast<std::byte>(i), std::byte{0}, std::byte{1}};
      last = sequence(epoch, session, 1, 100, msg);
    }
    return last;
  }
  // A record of an arbitrary payload size (fragmentation tests).
  std::uint64_t sequence_big(std::uint32_t epoch, std::size_t msg_bytes) {
    Bytes msg(msg_bytes, std::byte{0x42});
    return sequence(epoch, 9, 1, 100, msg);
  }

  [[nodiscard]] std::uint32_t crc_of(std::uint64_t idx) const {
    return journal::RecordView{std::span<const std::byte>(log[idx - 1])}.crc();
  }
  [[nodiscard]] std::uint32_t epoch_of(std::uint64_t idx) const {
    return journal::RecordView{std::span<const std::byte>(log[idx - 1])}.epoch();
  }
  [[nodiscard]] bool is_epoch_start(std::uint64_t idx) const {
    return journal::RecordView{std::span<const std::byte>(log[idx - 1])}.type() == journal::RecordType::EpochStart;
  }
  [[nodiscard]] std::size_t count(TraceKind k) const {
    return static_cast<std::size_t>(std::count_if(traces.begin(), traces.end(), [&](const TraceEvent& e) { return e.kind == k; }));
  }
  [[nodiscard]] bool has_alarm(Alarm a) const {
    return std::any_of(alarms.begin(), alarms.end(), [&](const auto& x) { return x.first == a; });
  }
};

static_assert(Host<FakeHost>);

// The day-start journal: EpochStart(1) at index 1 on both nodes (HotStandby Init).
inline void day_start(FakeHost& h, NodeId primary) {
  journal::RecordBuilder b(canonical_sealer(), journal::ChainState{});
  b.set_epoch(1);
  Bytes buf(128);
  const auto r = b.append(std::span<std::byte>(buf), 1'790'000'000'000'000'000, journal::EpochStart{1, primary, 0});
  buf.resize(r.size());
  h.log.push_back(std::move(buf));
  h.durable = 1;
}

inline Config node_config(NodeId self, std::uint64_t inc = 0) {
  Config c;
  c.self = self;
  c.incarnation = inc;
  c.build_id = kBuild;
  c.heartbeat_ns = 1 * kMs;
  c.t_d = 20 * kMs;
  c.t_ack = 10 * kMs;
  c.rto_ns = 2 * kMs;
  c.witness_retry_ns = 2 * kMs;
  c.forward_retry_ns = 2 * kMs;
  c.rejoin_retry_ns = 5 * kMs;
  c.window_bytes = 64 * 1024;
  c.window_records = 1024;
  c.hash_interval = 4;
  c.join_lag_records = 8;
  return c;
}

using R = Replica<FakeHost>;

// Two data nodes and the witness, with a controllable network.
struct Cluster {
  struct Node {
    FakeHost host;
    std::unique_ptr<R> rep;
    Config cfg;
    bool up = true;
  };
  std::array<Node, 2> n;
  std::optional<witness::Witness> w;
  witness::Config wcfg{5 * kMs};
  Nanos now = 0;
  bool apply = true;  // run the fold applier up to apply_limit() every step

  // Link filters: return false to drop. dir: 0 = A->B, 1 = B->A.
  std::function<bool(int dir, const Bytes&)> data_filter = [](int, const Bytes&) { return true; };
  std::function<bool(NodeId from, const Bytes&)> to_w_filter = [](NodeId, const Bytes&) { return true; };
  std::function<bool(NodeId to, Bytes&)> from_w_filter = [](NodeId, Bytes&) { return true; };
  bool ab_cut = false;
  bool duplicate_data = false;
  // One-way latency of the A–B data link (0: delivered in the step it is sent).
  Nanos data_delay = 0;
  struct InFlight {
    Nanos due = 0;
    NodeId dst = 0;
    Bytes bytes;
  };
  std::deque<InFlight> in_flight;  // FIFO: one fixed delay keeps the link in order

  explicit Cluster(NodeId primary = 0) {
    for (NodeId i = 0; i < 2; ++i) {
      n[i].cfg = node_config(i);
      day_start(n[i].host, primary);
      n[i].rep = std::make_unique<R>(n[i].cfg, n[i].host);
    }
    witness::State s;
    s.epoch = 1;
    s.primary = primary;
    s.members = 0b11;
    w.emplace(wcfg, witness::Durable{s, 1, 0}, now);
    for (NodeId i = 0; i < 2; ++i) n[i].rep->start_paired(1, primary, 0, now);
  }

  R& rep(NodeId i) { return *n[i].rep; }
  FakeHost& host(NodeId i) { return n[i].host; }

  // Process crash: memory gone, the log (L2 + L3) survives. Restart with incarnation+1.
  void crash(NodeId i) {
    n[i].up = false;
    n[i].rep.reset();
  }
  // Host crash: the log is cut back to the L3-durable prefix.
  void host_crash(NodeId i) {
    crash(i);
    n[i].host.log.resize(std::min<std::size_t>(n[i].host.log.size(), n[i].host.durable));
  }
  void restart(NodeId i) {
    FakeHost& h = n[i].host;
    h.to_peer.clear();
    h.to_witness.clear();
    h.deposed_flag = false;
    h.applied = 0;
    h.state = 0;
    n[i].cfg.incarnation += 1;
    n[i].rep = std::make_unique<R>(n[i].cfg, h);
    n[i].up = true;
    n[i].rep->start_recovering(now);
  }

  // One step: time advances by dt; every node polls; datagrams in flight are delivered.
  void step(Nanos dt = 100 * kUs) {
    now += dt;
    for (NodeId i = 0; i < 2; ++i) {
      if (!n[i].up) continue;
      if (n[i].host.deposed_flag) {
        crash(i);
        continue;
      }
      n[i].rep->poll(now);
      if (apply) n[i].host.apply_to(n[i].rep->apply_limit(), n[i].rep.get());
    }
    deliver();
  }
  void run(Nanos dur, Nanos dt = 100 * kUs) {
    const Nanos end = now + dur;
    while (now < end) step(dt);
  }
  template <class P>
  bool run_until(P&& pred, Nanos limit, Nanos dt = 100 * kUs) {
    const Nanos end = now + limit;
    while (now < end) {
      if (pred()) return true;
      step(dt);
    }
    return pred();
  }

  void deliver() {
    for (NodeId i = 0; i < 2; ++i) {
      FakeHost& h = n[i].host;
      while (!h.to_witness.empty()) {
        Bytes b = std::move(h.to_witness.front());
        h.to_witness.pop_front();
        if (!to_w_filter(i, b)) continue;
        const auto m = witness::decode(b);
        if (!m) continue;
        w->handle(*m, env::Endpoint{i, 1}, now);
        while (auto job = w->begin_write()) w->on_persisted(job->generation);
        w->drain([&](const env::Endpoint& to, std::span<const std::byte> out) {
          const NodeId dst = static_cast<NodeId>(to.ipv4);
          Bytes copy(out.begin(), out.end());
          if (!from_w_filter(dst, copy) || !n[dst].up || !n[dst].rep) return;
          n[dst].rep->on_witness(copy, now);
        });
      }
      std::deque<Bytes> q;
      q.swap(h.to_peer);
      const NodeId dst = i == 0 ? 1 : 0;
      for (Bytes& b : q) {
        if (ab_cut || !data_filter(static_cast<int>(i), b)) continue;
        if (data_delay > 0) {
          in_flight.push_back(InFlight{now + data_delay, dst, std::move(b)});
          continue;
        }
        if (!n[dst].up || !n[dst].rep) continue;
        n[dst].rep->on_peer(b, now);
        if (duplicate_data && n[dst].up && n[dst].rep) n[dst].rep->on_peer(b, now);
      }
    }
    while (!in_flight.empty() && in_flight.front().due <= now) {
      InFlight f = std::move(in_flight.front());
      in_flight.pop_front();
      if (!n[f.dst].up || !n[f.dst].rep) continue;
      n[f.dst].rep->on_peer(f.bytes, now);
      if (duplicate_data && n[f.dst].up && n[f.dst].rep) n[f.dst].rep->on_peer(f.bytes, now);
    }
  }

  // The primary's sequencer: appends records while sequencing is allowed.
  std::uint64_t sequence(NodeId p, int count) {
    if (!rep(p).sequencing_allowed()) return 0;
    return host(p).sequence_n(static_cast<std::uint32_t>(rep(p).epoch()), count);
  }
};

inline bool is_type(const Bytes& b, wire::MsgType t) {
  const auto m = wire::decode(b);
  return m && wire::type_of(*m) == t;
}

}  // namespace lle::repl::test

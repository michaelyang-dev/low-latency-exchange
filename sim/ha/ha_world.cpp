#include "sim/ha/ha_world.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/segment_preparer.h"
#include "sim/dist.h"
#include "sim/ha/data_node.h"
#include "sim/ha/harness.h"
#include "sim/ha/toy_engine.h"
#include "sim/network.h"
#include "sim/node.h"
#include "witness/control.h"
#include "witness/witness.h"

namespace lle::sim::ha {

namespace wit = lle::witness;

// ---- Truth ----------------------------------------------------------------------------------

void Truth::on_release(NodeId n, std::uint64_t from, std::uint64_t upto, bool solo, std::uint64_t epoch,
                       std::uint64_t durable) {
  const auto& h = store[n].history;
  const NodeId peer = n == kA ? kB : kA;
  const auto it = primary_of_epoch.find(epoch);
  if (it == primary_of_epoch.end() || it->second != n) {
    fail(o_one, "n" + std::to_string(n) + " releases in epoch " + std::to_string(epoch) + " whose primary is " +
                    (it == primary_of_epoch.end() ? std::string("unknown") : "n" + std::to_string(it->second)));
    return;
  }
  for (std::uint64_t i = from + 1; i <= upto; ++i) {
    if (i > h.size()) {
      fail(o_commit, "n" + std::to_string(n) + " releases index " + std::to_string(i) + " beyond its log");
      return;
    }
    const std::uint32_t crc = crc_of(h[i - 1]);
    if (i <= released.size()) {
      if (released[i - 1] != crc) {
        fail(o_commit, "index " + std::to_string(i) + " released twice with different records (ReleasedConsistent)");
        return;
      }
    } else if (i == released.size() + 1) {
      released.push_back(crc);
      released_epoch.push_back(epoch);
    } else {
      fail(o_commit, "release gap at " + std::to_string(i));
      return;
    }
    if (solo) {
      // Solo mode: the record must be durable here (L3).
      if (i > durable) {
        fail(o_commit, "solo n" + std::to_string(n) + " releases " + std::to_string(i) + " above durable " +
                           std::to_string(durable));
        return;
      }
    } else if (ever_held[peer].count({i, crc}) == 0) {
      // Paired mode: held in L2 by both members (TLA ReleasedIsCommitted).
      fail(o_commit, "paired n" + std::to_string(n) + " releases " + std::to_string(i) +
                         " which the backup never held");
      return;
    }
  }
  o->pass(o_commit);
}

void Truth::on_primary(NodeId n, std::uint64_t epoch) {
  const auto [it, fresh] = primary_of_epoch.try_emplace(epoch, n);
  if (!fresh && it->second != n) {
    fail(o_one, "two primaries in epoch " + std::to_string(epoch));
    return;
  }
  o->pass(o_one);
  // LeaderCompleteness (HotStandby.tla): a primary of epoch e holds every output
  // released in an epoch <= e (a deposed primary that learns of an old grant late may
  // become primary of an epoch older than releases made since).
  const auto& h = store[n].history;
  for (std::uint64_t i = 1; i <= released.size(); ++i) {
    if (released_epoch[i - 1] > epoch) continue;
    if (i > h.size() || crc_of(h[i - 1]) != released[i - 1]) {
      fail(o_lost, "new primary n" + std::to_string(n) + " of epoch " + std::to_string(epoch) +
                       " lacks released record " + std::to_string(i));
      return;
    }
  }
  o->pass(o_lost);
}

namespace {

// ---- the witness on node W ------------------------------------------------------------------

constexpr char kStateFile[] = "witness.state";
constexpr std::size_t kStateBytes = wit::kSlotBytes * wit::kSlots;

}  // namespace

struct WitnessProc : Process {
  struct Stage {
    WitnessProc* p;
    bool poll() { return p->poll(); }
  };

  WitnessProc(Node& n, Truth& t, Nanos tie_break) : node_(n), t_(t), port(n, kWitnessPort), file(n, kStateFile), stage{this} {
    std::array<std::byte, kStateBytes> img{};
    (void)file.read(0, img);
    const auto d = wit::choose(std::span<const std::byte>(img).first(wit::kSlotBytes),
                               std::span<const std::byte>(img).subspan(wit::kSlotBytes));
    if (!d) {
      t_.fail(t_.o_internal, "witness: no valid state slot");
      return;
    }
    if (d->state.epoch < t_.witness_epoch_seen) {
      t_.fail(t_.o_internal, "witness restarted below an epoch it announced");
      return;
    }
    core.emplace(wit::Config{tie_break}, *d, n.clock().now_mono());
    durable_state = d->state;
    t_.witness = this;
    n.add_stage(stage, "witness");
  }
  ~WitnessProc() override {
    if (t_.witness == this) t_.witness = nullptr;
  }

  bool poll() {
    bool did = false;
    file.poll([&](const env::DiskCompletion& c) {
      did = true;
      writing_ = false;
      if (failed_) return;
      if (c.result < 0) {
        core->on_write_failed();
        failed_ = true;
        node_.request_crash();  // witnessd: a failed state write stops W
        return;
      }
      core->on_persisted(c.tag);
      durable_state = writing_state;
    });
    if (failed_ || !core) return did;
    const Nanos now = node_.clock().now_mono();
    port.poll_rx([&](const env::RxDatagram& d) {
      did = true;
      const auto m = wit::decode(d.data);
      if (m) core->handle(*m, d.src, now);
    });
    if (!writing_) {
      if (auto job = core->begin_write()) {
        writing_state = core->state();
        if (file.submit_write(static_cast<std::uint64_t>(job->slot) * wit::kSlotBytes, job->image, true,
                              job->generation)) {
          writing_ = true;
          did = true;
        } else {
          core->on_write_failed();
          failed_ = true;
          node_.request_crash();
        }
      }
    }
    core->drain([&](const env::Endpoint& to, std::span<const std::byte> b) {
      tap(b);
      port.send(to, b);
      did = true;
    });
    return did;
  }

  // Every GRANT the first time it leaves W (persisted by construction).
  void tap(std::span<const std::byte> b) {
    const auto m = wit::decode(b);
    if (!m) return;
    // A JOIN grant goes to the primary that relayed it and, as a copy, to the joiner; the
    // trace records the grant once, by the requester's copy.
    if (const auto* g = std::get_if<wit::Grant>(&*m);
        g != nullptr && g->epoch > t_.witness_epoch_seen && !(g->request == wit::MsgType::kJoin && g->to_node != g->primary)) {
      t_.witness_epoch_seen = g->epoch;
      t_.log("W grants %s to n%u inc %llu: epoch %llu primary n%u members %u", wit::to_string(g->request), g->to_node,
             static_cast<unsigned long long>(g->incarnation), static_cast<unsigned long long>(g->epoch), g->primary,
             g->members);
      t_.tla.emit(t_.w->now(), "w_grant", "type", wit::to_string(g->request), "to", g->to_node, "inc", g->incarnation,
                  "epoch", g->epoch, "fe", g->from_epoch, "primary", g->primary, "members", g->members);
    }
  }

  Node& node_;
  Truth& t_;
  DatagramPort port;
  DiskFile file;
  std::optional<wit::Witness> core;
  wit::State durable_state;  // what a restart of W comes back with
  wit::State writing_state;
  Stage stage;
  bool writing_ = false;
  bool failed_ = false;
};

namespace {

// ---- clients on node C ----------------------------------------------------------------------

struct ClientCfg {
  std::uint32_t orders = 20;
  Nanos order_mean_ns = 5 * kMs;
  Nanos reconnect_ns = 5 * kMs;
};

struct Client {
  struct Inst {
    env::ConnId conn = env::kNoConn;
    bool connected = false;
    bool logged_in = false;
    Nanos retry_at = 0;
    Bytes rx;
    Bytes tx;
  };
  std::uint32_t account = 0;
  std::array<Inst, 2> inst{};
  int active = -1;
  std::uint32_t next_urn = 1;
  std::uint32_t sent = 0;  // distinct orders created
  Nanos next_order_at = 0;
  std::deque<std::array<std::byte, kToyOrderBytes>> pending;  // created, not yet accepted (urn order)
  std::deque<std::uint32_t> pending_urn;
  std::uint64_t next_expected = 1;
  std::map<std::uint64_t, Bytes> ahead;  // received out of order
  std::vector<Bytes> stream;             // seq 1..next_expected-1
  std::uint64_t acked = 0;
  std::uint64_t fills = 0;
  Rng rng{1};
};

struct ClientsProc : Process {
  struct Stage {
    ClientsProc* p;
    bool poll() { return p->poll(); }
  };

  ClientsProc(Node& n, Truth& t, std::vector<Client>& clients, const ClientCfg& cfg)
      : node_(n), t_(t), port(n), clients_(clients), cfg_(cfg), stage{this} {
    for (std::size_t i = 0; i < clients_.size(); ++i) {
      Client& c = clients_[i];
      for (Client::Inst& in : c.inst) in = Client::Inst{};
      c.active = -1;
      c.next_order_at = n.clock().now_mono() + exp_ns(c.rng, cfg_.order_mean_ns);
    }
    n.add_stage(stage, "clients");
  }

  bool poll() {
    bool did = false;
    const Nanos now = node_.clock().now_mono();
    port.poll([&](const env::StreamEvent& ev) {
      did = true;
      Client* c = nullptr;
      int which = -1;
      for (Client& cl : clients_) {
        for (int k = 0; k < 2; ++k) {
          if (cl.inst[static_cast<std::size_t>(k)].conn == ev.conn) {
            c = &cl;
            which = k;
          }
        }
      }
      if (c == nullptr) return;
      Client::Inst& in = c->inst[static_cast<std::size_t>(which)];
      switch (ev.kind) {
        case env::StreamEventKind::Connected: {
          in.connected = true;
          in.logged_in = true;
          std::array<std::byte, 13> login{};
          login[0] = std::byte{'L'};
          store_le32(login.data() + 1, c->account);
          store_le64(login.data() + 5, c->next_expected);
          put_frame(in.tx, login);
          break;
        }
        case env::StreamEventKind::Data:
          in.rx.insert(in.rx.end(), ev.data.begin(), ev.data.end());
          parse(*c, which);
          break;
        case env::StreamEventKind::Closed:
          drop(*c, which, now);
          break;
        case env::StreamEventKind::Accepted:
          break;
      }
    });
    for (Client& c : clients_) did |= step(c, now);
    return did;
  }

  static void put_frame(Bytes& tx, std::span<const std::byte> payload) {
    const std::size_t at = tx.size();
    tx.resize(at + 2 + payload.size());
    store_le16(tx.data() + at, static_cast<std::uint16_t>(payload.size()));
    std::memcpy(tx.data() + at + 2, payload.data(), payload.size());
  }

  void drop(Client& c, int which, Nanos now) {
    Client::Inst& in = c.inst[static_cast<std::size_t>(which)];
    in = Client::Inst{};
    in.retry_at = now + 1 + exp_ns(c.rng, cfg_.reconnect_ns);
    if (c.active == which) c.active = -1;
  }

  void parse(Client& c, int which) {
    Client::Inst& in = c.inst[static_cast<std::size_t>(which)];
    std::size_t off = 0;
    while (in.rx.size() - off >= 2) {
      const std::size_t len = load_le16(in.rx.data() + off);
      if (in.rx.size() - off < 2 + len) break;
      const std::span<const std::byte> f(in.rx.data() + off + 2, len);
      off += 2 + len;
      if (len == 1 && f[0] == std::byte{'J'}) {
        in.logged_in = false;  // login refused: the server closes; we reconnect later
      } else if (len >= 9 && f[0] == std::byte{'S'}) {
        on_seq(c, load_le64(f.data() + 1), f.subspan(9));
        if (t_.o->failed()) return;
      }
    }
    in.rx.erase(in.rx.begin(), in.rx.begin() + static_cast<std::ptrdiff_t>(off));
  }

  void on_seq(Client& c, std::uint64_t seq, std::span<const std::byte> msg) {
    if (seq < c.next_expected) {
      const Bytes& had = c.stream[static_cast<std::size_t>(seq - 1)];
      if (!std::equal(had.begin(), had.end(), msg.begin(), msg.end())) {
        t_.fail(t_.o_prefix, "client " + std::to_string(c.account) + " got two different messages for seq " +
                                 std::to_string(seq));
      }
      return;
    }
    if (seq > c.next_expected) {
      c.ahead.try_emplace(seq, Bytes(msg.begin(), msg.end()));
      return;
    }
    accept(c, Bytes(msg.begin(), msg.end()));
    while (!c.ahead.empty() && c.ahead.begin()->first == c.next_expected) {
      Bytes b = std::move(c.ahead.begin()->second);
      c.ahead.erase(c.ahead.begin());
      accept(c, std::move(b));
    }
    while (!c.ahead.empty() && c.ahead.begin()->first < c.next_expected) c.ahead.erase(c.ahead.begin());
  }

  void accept(Client& c, Bytes msg) {
    const std::uint64_t seq = c.next_expected;
    auto& seen = t_.seen[c.account];
    const auto [it, fresh] = seen.try_emplace(seq, msg);
    if (!fresh && it->second != msg) {
      t_.fail(t_.o_prefix, "session " + std::to_string(c.account) + " seq " + std::to_string(seq) +
                               ": clients received different messages");
      return;
    }
    if (!msg.empty() && msg[0] == std::byte{'A'} && msg.size() == 13) {
      const std::uint32_t urn = load_le32(msg.data() + 1);
      ++c.acked;
      while (!c.pending_urn.empty() && c.pending_urn.front() <= urn) {
        c.pending_urn.pop_front();
        c.pending.pop_front();
      }
    } else if (!msg.empty() && msg[0] == std::byte{'E'}) {
      ++c.fills;
    }
    c.stream.push_back(std::move(msg));
    ++c.next_expected;
  }

  bool step(Client& c, Nanos now) {
    bool did = false;
    for (int k = 0; k < 2; ++k) {
      Client::Inst& in = c.inst[static_cast<std::size_t>(k)];
      if (in.conn == env::kNoConn && now >= in.retry_at) {
        const auto conn = port.connect(env::Endpoint{node_ip(static_cast<NodeId>(k)), kClientPort});
        if (conn) in.conn = *conn;
        did = true;
      }
      if (in.conn != env::kNoConn && in.connected && !in.logged_in) {
        port.close(in.conn);
        drop(c, k, now);
      }
    }
    // OUCH 5.0 client rule (10 §3): send on one instance; after losing it, re-send every
    // pending message in its original order on a surviving instance.
    if (c.active < 0 || !c.inst[static_cast<std::size_t>(c.active)].logged_in) {
      int pick = -1;
      for (int k = 0; k < 2; ++k) {
        if (c.inst[static_cast<std::size_t>(k)].logged_in) pick = k;
      }
      if (pick >= 0 && c.inst[0].logged_in && c.inst[1].logged_in) pick = static_cast<int>(c.rng.below(2));
      if (pick >= 0) {
        c.active = pick;
        if (!c.pending.empty()) SIM_PROBE("ha.client_resends_pending_on_failover");
        for (const auto& o : c.pending) put_frame(c.inst[static_cast<std::size_t>(pick)].tx, o);
        did = true;
      }
    }
    if (c.active >= 0 && c.sent < cfg_.orders && now >= c.next_order_at) {
      ToyOrder o;
      o.urn = c.next_urn++;
      o.side = c.rng.below(2) == 0 ? 'B' : 'S';
      o.px = 100 + static_cast<std::uint32_t>(c.rng.below(5));
      o.qty = 1 + static_cast<std::uint32_t>(c.rng.below(10));
      const auto bytes = encode_order(o);
      c.pending.push_back(bytes);
      c.pending_urn.push_back(o.urn);
      ++c.sent;
      put_frame(c.inst[static_cast<std::size_t>(c.active)].tx, bytes);
      c.next_order_at = now + 1 + exp_ns(c.rng, cfg_.order_mean_ns);
      did = true;
    }
    for (Client::Inst& in : c.inst) {
      if (in.conn == env::kNoConn || in.tx.empty() || !in.connected) continue;
      const std::size_t n = port.write(in.conn, in.tx);
      if (n != 0) {
        in.tx.erase(in.tx.begin(), in.tx.begin() + static_cast<std::ptrdiff_t>(n));
        did = true;
      }
    }
    return did;
  }

  Node& node_;
  Truth& t_;
  StreamPort port;
  std::vector<Client>& clients_;
  ClientCfg cfg_;
  Stage stage;
};

// ---- faults gated by the failure model ---------------------------------------------------------

struct Faults {
  World* w = nullptr;
  Truth* t = nullptr;
  HandlerId handler = 0;
  std::vector<FaultEvent> crashes;  // data-node crashes, fired by us
  Prng rng{1};
  journal::MemCrashOptions crash_opts;
  std::uint64_t fired = 0;

  static Dispatch on_event(void* ctx, const Event& ev) {
    auto* self = static_cast<Faults*>(ctx);
    if (ev.a >= self->crashes.size()) return {false, 0};
    return self->fire(self->crashes[ev.a]);
  }

  // 01 §9: crash-stop of one node at a time. Crashing node x must leave a configuration
  // that can make progress without manual repair, and a host crash must not open the
  // residual window (some node must still hold every released record).
  // Both W's in-memory configuration and the one it would restart with (a grant is not
  // final until persisted) must leave a node that can continue.
  [[nodiscard]] bool allowed(NodeId x, bool host) const {
    const WitnessProc* wp = t->witness;
    if (wp == nullptr || !wp->core) return false;
    return allowed_under(wp->core->state(), x, host) && allowed_under(wp->durable_state, x, host);
  }

  [[nodiscard]] bool allowed_under(const wit::State& s, NodeId x, bool host) const {
    const NodeId y = x == kA ? kB : kA;
    const HaNode* other = t->node[y];
    const bool y_up = other != nullptr && w->node(y).alive();
    bool ok = false;
    if (!wit::is_member(s.members, static_cast<wit::NodeId>(x))) {
      ok = true;  // not a member: harmless
    } else if (s.members == wit::member_bit(static_cast<wit::NodeId>(x)) && s.primary == x) {
      ok = true;  // the solo primary of record: it RESUMEs
    } else if (y_up) {
      const repl::Role r = other->repl().role();
      ok = (r == repl::Role::kPrimary || r == repl::Role::kBackup) && other->repl().epoch() == s.epoch &&
           s.inc[y] == other->incarnation() && wit::is_member(s.members, static_cast<wit::NodeId>(y));
    }
    // A JOIN in flight may still make the configuration {primary, joiner}, even after
    // the process that relayed it died (the datagram outlives it): then the survivor
    // must be the incarnation that grant records, alive (the primary goes solo; the
    // joiner takes over). Otherwise both recorded incarnations would be dead and only a
    // manual witness repair could continue.
    const Truth::PendingJoin& pj = t->pending_join;
    if (ok && pj.valid && pj.epoch == s.epoch) {
      if (x == pj.primary) ok = y_up && other->incarnation() == pj.joiner_inc;
      else ok = y_up && other->incarnation() == pj.primary_inc;
    }
    if (!ok || !host) return ok;
    // Residual window: after x loses its unsynced tail, every released record must still
    // exist somewhere (x's L3 or y's log).
    const auto& hy = t->store[y].history;
    const HaNode* xn = t->node[x];
    const std::uint64_t x_durable = xn != nullptr ? xn->durable() : 0;
    for (std::uint64_t i = x_durable + 1; i <= t->released.size(); ++i) {
      if (i > hy.size() || crc_of(hy[i - 1]) != t->released[i - 1]) return false;
    }
    return true;
  }

  Dispatch fire(const FaultEvent& f) {
    if (w->phase() != Phase::Safety) return {true, 0};
    Node& n = w->node(f.node);
    if (!n.alive()) return {true, 0};
    const bool host = f.a != 0;
    if (!allowed(f.node, host)) {
      ++t->crashes_gated;
      return {true, 2};
    }
    crash(f.node, host);
    n.restart_after(f.dur);
    ++fired;
    return {true, 1};
  }

  void crash(NodeId id, bool host) {
    Node& n = w->node(id);
    NodeStore& st = t->store[id];
    ++t->crashes;
    const std::uint64_t len_before = st.history.size();
    t->log("CRASH n%u (%s)", id, host ? "host" : "process");
    if (host) {
      ++t->host_crashes;
      // Power loss: unsynced journal writes are dropped, persisted or torn; the
      // hugetlbfs L2 ring is gone (its storage is re-nonced, so nothing in it validates).
      st.dir.crash(rng, crash_opts);
      std::uint64_t nonce = 0;
      do {
        nonce = st.nonce_rng.next_u64();
      } while (!journal::usable_nonce(nonce) || nonce == st.l2_nonce);
      st.l2_nonce = nonce;
      std::memset(st.l2.get(), 0, kL2Bytes);
      st.host_crashed = true;
    }
    t->tla.emit(w->now(), "crash", "n", id, "kind", host ? "host" : "proc", "len", len_before);
    n.crash(host ? CrashKind::Host : CrashKind::Process);
  }
};

// Writes the day-start journal of one node: EpochStart(1) at index 1, durable.
void day_start(NodeStore& st, NodeId primary0) {
  st.l2 = std::make_unique<std::byte[]>(kL2Bytes);
  std::memset(st.l2.get(), 0, kL2Bytes);
  do {
    st.l2_nonce = st.nonce_rng.next_u64();
  } while (!journal::usable_nonce(st.l2_nonce));
  journal::SegmentPreparer<journal::MemSegmentDir, Prng> prep(st.dir, st.nonce_rng, kDay, kSegmentBytes);
  journal::JournalWriterOptions o;
  o.day = kDay;
  journal::JournalWriter<journal::MemJournalDevice> wr(o);
  for (int i = 0; i < 2; ++i) {
    auto p = prep.create();
    LLE_ASSERT(p.has_value(), "day start: prepare");
    (void)wr.add_prepared(st.dir.device(p->handle), p->handle, p->header);
  }
  const journal::Sealer canonical;
  journal::RecordBuilder b(canonical, journal::ChainState{});
  b.set_epoch(1);
  Bytes rec(64);
  const auto r = b.append(std::span<std::byte>(rec), kSimEpochRealNs, journal::EpochStart{1, primary0, 0});
  rec.resize(r.size());
  using W = journal::JournalWriter<journal::MemJournalDevice>;
  W::Status ws = W::Status::Busy;
  for (int spins = 0; ws == W::Status::Busy; ++spins) {  // a spurious EAGAIN (SIM_BUGGIFY) is retried
    LLE_ASSERT(spins < 1000, "day start: writer busy");
    ws = wr.append(rec, canonical);
    if (ws == W::Status::Busy) (void)wr.poll();
  }
  LLE_ASSERT(ws == W::Status::Ok, "day start");
  for (int spins = 0; wr.durable_index() < 1; ++spins) {
    LLE_ASSERT(spins < 1000, "day start flush");
    (void)wr.flush();
    (void)wr.poll();
  }
  st.history.push_back(rec);
}

}  // namespace

PhasePlan default_plan() {
  PhasePlan p;
  p.safety_ns = 1'000'000'000;
  p.convergence_ns = 30'000'000'000;
  p.check_interval_ns = 5'000'000;
  return p;
}

Report run(const Options& o) {
  // The truth and the clients outlive the world: process destructors report to them.
  auto t = std::make_unique<Truth>();
  auto clients = std::make_unique<std::vector<Client>>();
  auto faults = std::make_unique<Faults>();
  World w(o.seed, o.faults);
  w.set_trace(o.event_trace);
  Rng wl = w.stream(Stream::Workload, 0x4A11);
  t->w = &w;
  t->o = &w.oracles();
  t->verbose = o.verbose;
  t->tla.set(o.tla_trace);
  t->o_prefix = w.oracles().activate(kOPrefix);
  t->o_lost = w.oracles().activate(kONoLostFill);
  t->o_once = w.oracles().activate(kOExactlyOnce);
  t->o_commit = w.oracles().activate(kOOutputCommit);
  t->o_one = w.oracles().activate(kOOnePrimary);
  t->o_replay = w.oracles().activate(kOReplay);
  t->o_internal = w.oracles().activate("O-HA-INTERNAL", "ha world: recovery, L2 restore and truncation agree with the harness");

  // ---- timing and workload, drawn per seed ----
  NodeParams np;
  repl::Config& rc = np.repl;
  rc.build_id = kBuildId;
  rc.heartbeat_ns = kMs;
  rc.t_d = 10 * kMs + static_cast<Nanos>(wl.below(15 * kMs + 1));
  rc.t_ack = 4 * kMs + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(rc.t_d - 5 * kMs)));
  rc.rto_ns = kMs + static_cast<Nanos>(wl.below(3 * kMs));
  rc.witness_retry_ns = 2 * kMs;
  rc.forward_retry_ns = 2 * kMs + static_cast<Nanos>(wl.below(3 * kMs));
  rc.rejoin_retry_ns = 5 * kMs;
  rc.window_bytes = 128 * 1024;
  rc.window_records = 4096;
  rc.hash_interval = std::uint64_t{8} << wl.below(4);
  rc.join_lag_records = 1 + wl.below(64);
  rc.snapshot_threshold = wl.below(3) == 0 ? 8 + wl.below(64) : ~std::uint64_t{0};
  const Nanos tie_break = 3 * kMs + static_cast<Nanos>(wl.below(static_cast<std::uint64_t>(rc.t_d - 4 * kMs)));
  if (o.ab_delay_min > 0) {
    // Long-RTT variant: timeouts above the minimum round trip (draws above are unchanged).
    const Nanos rtt = 2 * o.ab_delay_min;
    rc.rto_ns = std::max(rc.rto_ns, 2 * rtt);
    rc.forward_retry_ns = std::max(rc.forward_retry_ns, 2 * rtt);
    rc.t_ack = std::max(rc.t_ack, 3 * rtt);
    rc.t_d = std::max(rc.t_d, rc.t_ack + 5 * kMs);
  }
  np.primary0 = kA;
  ClientCfg cc;
  const std::uint32_t nclients = o.clients != 0 ? o.clients : 2 + static_cast<std::uint32_t>(wl.below(4));
  cc.orders = o.orders_per_client != 0 ? o.orders_per_client : 10 + static_cast<std::uint32_t>(wl.below(31));
  cc.order_mean_ns = kMs + static_cast<Nanos>(wl.below(20 * kMs));
  cc.reconnect_ns = kMs + static_cast<Nanos>(wl.below(10 * kMs));

  // ---- nodes ----
  Node& a = w.add_node("A", NodeOptions{true, true});
  Node& b = w.add_node("B", NodeOptions{true, true});
  Node& wn = w.add_node("W", NodeOptions{true, true});
  Node& cn = w.add_node("C", NodeOptions{false, false});
  LLE_ASSERT(a.id() == kA && b.id() == kB && wn.id() == kW && cn.id() == kC, "node ids");
  if (o.ab_delay_min > 0) {
    for (const auto& [x, y] : {std::pair{kA, kB}, std::pair{kB, kA}}) {
      LinkParams& lp = w.net().link_params(x, y);
      lp.delay_min = std::max(lp.delay_min, o.ab_delay_min);
    }
  }
  for (NodeId i = 0; i < 2; ++i) {
    t->store[i].nonce_rng = w.stream(Stream::Disk, 0x70000 + i);
    day_start(t->store[i], np.primary0);
    t->on_hold(i, 1, crc_of(t->store[i].history[0]));
  }
  t->primary_of_epoch[1] = np.primary0;
  {
    wit::State s;
    s.epoch = 1;
    s.primary = static_cast<wit::NodeId>(np.primary0);
    s.members = 0b11;
    std::array<std::byte, kStateBytes> img{};
    const wit::SlotImage s0 = wit::encode_slot(s, 1);
    std::memcpy(img.data(), s0.data(), s0.size());
    wn.disk().install(kStateFile, img);
    t->witness_epoch_seen = 1;
  }
  clients->resize(nclients);
  for (std::uint32_t i = 0; i < nclients; ++i) {
    (*clients)[i].account = 1 + i;
    (*clients)[i].rng = w.stream(Stream::Workload, 0xC1000 + i);
  }
  t->tla.emit(0, "init", "primary", np.primary0, "crc1", crc_of(t->store[0].history[0]), "clients", nclients);

  Truth* tp = t.get();
  std::vector<Client>* cp = clients.get();
  a.set_boot([=](Node& n, BootReason why) { n.emplace_process<HaNode>(n, *tp, np, why); });
  b.set_boot([=](Node& n, BootReason why) { n.emplace_process<HaNode>(n, *tp, np, why); });
  wn.set_boot([=](Node& n, BootReason) { n.emplace_process<WitnessProc>(n, *tp, tie_break); });
  cn.set_boot([=](Node& n, BootReason) { n.emplace_process<ClientsProc>(n, *tp, *cp, cc); });
  wn.boot();
  a.boot();
  b.boot();
  cn.boot();

  // ---- faults ----
  faults->w = &w;
  faults->t = tp;
  faults->rng = w.stream(Stream::Process, 0xFA0170);
  {
    const std::uint32_t keep = static_cast<std::uint32_t>(o.faults.u(Param::DiskCrashKeepPpm));
    const std::uint32_t torn = static_cast<std::uint32_t>(o.faults.u(Param::DiskCrashTornPpm));
    faults->crash_opts.w_full = keep / 1000;
    faults->crash_opts.w_torn = torn / 1000;
    faults->crash_opts.w_drop = std::max<std::uint32_t>(1, 1000 - std::min<std::uint32_t>(1000, (keep + torn) / 1000));
  }
  faults->handler = w.register_handler(faults.get(), &Faults::on_event, "ha_crash");
  Faults* fp = faults.get();
  t->may_fail = [fp, &o](NodeId n, bool host) { return o.ungated_disk_errors || fp->allowed(n, host); };
  FaultSchedule sched = w.injector().generate(w.now(), w.now() + o.plan.safety_ns);
  FaultSchedule generic;
  for (const FaultEvent& e : sched.events) {
    if (e.kind == FaultKind::Crash && e.node <= kB) {
      if (o.no_crash) continue;
      FaultEvent c = e;
      if (!o.host_crashes) c.a = 0;
      faults->crashes.push_back(c);
    } else {
      generic.events.push_back(e);
    }
  }
  for (std::size_t i = 0; i < faults->crashes.size(); ++i) {
    w.schedule(faults->crashes[i].at, faults->handler, 0, faults->crashes[i].node, i, 0, faults->crashes[i].a);
  }
  // A–B link cuts and "data NICs down" (fault F3: silent to W and clients, not to the peer).
  if (o.faults.enabled(FaultClass::Partition)) {
    Rng fr = w.stream(Stream::Network, 0xAB0C07);
    const Nanos mean = 50 * kMs + static_cast<Nanos>(fr.below(1000 * kMs));
    for (Nanos at = w.now() + 1 + exp_ns(fr, mean); at < w.now() + o.plan.safety_ns; at += 1 + exp_ns(fr, mean)) {
      const std::uint64_t kind = fr.below(3);
      const Nanos dur = uniform(fr, 2 * kMs, 300 * kMs);
      const NodeId x = static_cast<NodeId>(fr.below(2));
      if (kind < 2 && !o.ab_cuts) continue;
      FaultEvent e;
      e.at = at;
      e.kind = FaultKind::Partition;
      e.node = 1;
      e.dur = dur;
      if (kind < 2) {
        e.a = std::uint64_t{1} << kA;
        e.b = std::uint64_t{1} << kB;
      } else {
        e.a = std::uint64_t{1} << x;
        e.b = (std::uint64_t{1} << kW) | (std::uint64_t{1} << kC);
      }
      generic.events.push_back(e);
    }
    std::stable_sort(generic.events.begin(), generic.events.end(),
                     [](const FaultEvent& x, const FaultEvent& y) { return x.at < y.at; });
  }
  w.injector().install(generic);

  // ---- convergence (O-LIVE) ----
  // Returns "" when converged, otherwise what is still missing.
  const auto not_converged = [&w, tp, cp, &cc]() -> std::string {
    const HaNode* na = tp->node[kA];
    const HaNode* nb = tp->node[kB];
    const WitnessProc* wp = tp->witness;
    if (na == nullptr || nb == nullptr || wp == nullptr || !wp->core || !w.node(kA).alive() || !w.node(kB).alive())
      return "a process is down";
    const HaNode* p = na->repl().role() == repl::Role::kPrimary ? na : nb;
    const HaNode* q = p == na ? nb : na;
    const wit::State& s = wp->core->state();
    if (p->repl().role() != repl::Role::kPrimary || q->repl().role() != repl::Role::kBackup) {
      std::string why = std::string("roles ") + repl::to_string(na->repl().role()) + "/" + repl::to_string(nb->repl().role());
      for (const HaNode* x : {na, nb}) {
        if (x->repl().role() != repl::Role::kSoloPrimary) continue;
        const auto j = x->repl().join_view();
        why += " join{active " + std::to_string(j.active) + " sent " + std::to_string(j.sent) + " window " +
               std::to_string(j.window) + " acked " + std::to_string(j.acked) + "/" + std::to_string(x->tail()) +
               " snap " + std::to_string(j.snap_active) + std::to_string(j.snap_done) + " " +
               std::to_string(j.snap_acked) + "/" + std::to_string(j.snap_total) + "}";
      }
      return why;
    }
    if (p->repl().epoch() != s.epoch || q->repl().epoch() != s.epoch || s.primary != p->id() || s.members != 0b11 ||
        s.inc[q->id()] != q->incarnation() || s.inc[p->id()] != p->incarnation()) {
      return "configuration differs from the witness's";
    }
    if (p->tail() != q->tail() || p->repl().release_watermark() != p->tail()) {
      return "logs " + std::to_string(p->tail()) + "/" + std::to_string(q->tail()) + " released " +
             std::to_string(p->repl().release_watermark());
    }
    if (q->repl().release_watermark() != q->tail() || p->engine().applied() != p->tail() ||
        q->engine().applied() != q->tail() || p->engine().hash() != q->engine().hash()) {
      return "applied " + std::to_string(p->engine().applied()) + "/" + std::to_string(q->engine().applied());
    }
    for (const Client& c : *cp) {
      if (c.sent < cc.orders || !c.pending.empty()) {
        return "client " + std::to_string(c.account) + " sent " + std::to_string(c.sent) + " pending " +
               std::to_string(c.pending.size()) + " (first urn " +
               std::to_string(c.pending_urn.empty() ? 0 : c.pending_urn.front()) + ", engine last urn " +
               std::to_string(p->engine().last_urn(c.account)) + ") active " + std::to_string(c.active) + " inst " +
               std::to_string(c.inst[0].logged_in) + std::to_string(c.inst[1].logged_in) + " next_expected " +
               std::to_string(c.next_expected) + " primary n" + std::to_string(p->id());
      }
      const SessionStream* st = p->engine().session(c.account);
      const std::uint64_t want = st == nullptr ? 1 : st->next_seq();
      if (c.next_expected != want) {
        return "client " + std::to_string(c.account) + " at " + std::to_string(c.next_expected) + " of " +
               std::to_string(want);
      }
    }
    return {};
  };
  std::string last_reason;
  const auto converged = [&not_converged, &last_reason]() -> bool {
    last_reason = not_converged();
    return last_reason.empty();
  };

  // ---- final checks: the canonical output of the final committed journal ----
  w.oracles().add_final_check(t->o_prefix, [tp, cp] {
    const HaNode* p = tp->node[kA] != nullptr && tp->node[kA]->repl().role() == repl::Role::kPrimary ? tp->node[kA]
                                                                                                       : tp->node[kB];
    if (p == nullptr) return;
    ToyEngine canon;
    for (const Bytes& r : tp->store[p->id()].history) (void)canon.apply(view(r));
    // O-REPLAY: each node's engine state equals a fresh replay of its journal.
    for (NodeId i = 0; i < 2; ++i) {
      const HaNode* n = tp->node[i];
      if (n == nullptr) continue;
      ToyEngine fresh;
      for (const Bytes& r : tp->store[i].history) (void)fresh.apply(view(r));
      if (fresh.hash() != n->engine().hash() || fresh.applied() != n->engine().applied()) {
        tp->fail(tp->o_replay, "n" + std::to_string(i) + ": engine state differs from a replay of its journal");
        return;
      }
      tp->o->pass(tp->o_replay);
    }
    std::map<std::pair<std::uint32_t, std::uint32_t>, int> accepted;
    for (const auto& [session, st] : canon.sessions()) {
      for (const Output& out : st.outputs) {
        if (!out.bytes.empty() && out.bytes[0] == std::byte{'A'}) {
          const std::uint32_t urn = load_le32(out.bytes.data() + 1);
          if (++accepted[{session, urn}] > 1) {
            tp->fail(tp->o_once, "session " + std::to_string(session) + " UserRefNum " + std::to_string(urn) +
                                     " executed twice");
            return;
          }
        }
      }
    }
    tp->o->pass(tp->o_once);
    for (const Client& c : *cp) {
      const SessionStream* st = canon.session(c.account);
      for (std::size_t i = 0; i < c.stream.size(); ++i) {
        const Output* out = st == nullptr ? nullptr : st->at(i + 1);
        if (out == nullptr || out->bytes != c.stream[i]) {
          const bool fill = !c.stream[i].empty() && c.stream[i][0] == std::byte{'E'};
          tp->fail(fill ? tp->o_lost : tp->o_prefix,
                   "client " + std::to_string(c.account) + " message " + std::to_string(i + 1) +
                       (fill ? " (a fill)" : "") + " is not in the canonical output of the final journal");
          return;
        }
      }
      // Every order the client sent was executed exactly once.
      for (std::uint32_t urn = 1; urn <= c.sent; ++urn) {
        if (accepted[{c.account, urn}] != 1) {
          tp->fail(tp->o_once, "client " + std::to_string(c.account) + " order " + std::to_string(urn) +
                                   " executed " + std::to_string(accepted[{c.account, urn}]) + " times");
          return;
        }
      }
    }
    tp->o->pass(tp->o_prefix);
    tp->o->pass(tp->o_lost);
  });

  Report r;
  r.run = w.run(o.plan, converged);
  if (!r.run.converged && !r.run.failed) last_reason.clear();
  if (r.run.failed && r.run.failure.oracle == kOLive) t->log("not converged: %s", last_reason.c_str());
  r.stats = w.stats();
  r.probes = w.probes();
  r.oracles = w.oracles().list();
  r.faults_fired = w.injector().fired() + faults->fired;
  r.takeovers = t->takeovers;
  r.solos = t->solos;
  r.resumes = t->resumes;
  r.joins = t->joins;
  r.deposed = t->deposed;
  r.truncations = t->truncations;
  r.crashes = t->crashes;
  r.host_crashes = t->host_crashes;
  r.crashes_gated = t->crashes_gated;
  r.tla_events = t->tla.lines();
  std::uint64_t acked = 0;
  std::uint64_t fills = 0;
  for (const Client& c : *clients) {
    acked += c.acked;
    fills += c.fills;
  }
  r.orders_acked = acked;
  r.fills = fills;
  r.records = std::max(t->store[0].history.size(), t->store[1].history.size());
  r.summary = "records=" + std::to_string(r.records) + " acked=" + std::to_string(acked) + " fills=" +
              std::to_string(fills) + " takeovers=" + std::to_string(r.takeovers) + " solos=" + std::to_string(r.solos) +
              " resumes=" + std::to_string(r.resumes) + " joins=" + std::to_string(r.joins) +
              " deposed=" + std::to_string(r.deposed) + " truncations=" + std::to_string(r.truncations) +
              " crashes=" + std::to_string(r.crashes) + "(host " + std::to_string(r.host_crashes) + ", gated " +
              std::to_string(r.crashes_gated) + ")";
  // Tear the processes down while the truth still exists.
  return r;
}

}  // namespace lle::sim::ha

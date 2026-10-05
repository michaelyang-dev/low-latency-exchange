#pragma once
// Paired mode (10 §3-§4): the replication core (repl::Replica) wired to the node, on
// the seq thread.
//
// Threads: the sequencer (primary) and the replica (backup: replicated records; any
// role: the EpochStart of a granted epoch) both append to the L2 ring, and the replica
// decides when sequencing is allowed (10 §4: stopped while losing the backup and until a
// new epoch's EpochStart is in the log). By default they share the seq thread, which
// keeps L2 a single-writer ring and makes "sequencing allowed" exact. With `[ha]
// repl_thread = true` (or a `repl` entry in the core map) the replica runs on a thread
// of its own ("split") and the two hand over through Shared::split:
//   - the replica appends to L2 only after the seq thread has begun a poll that saw
//     sequencing disallowed (parked == disallow_gen); until then Host::log_append
//     answers "no room" and the core retries;
//   - the sequencer continues from the resync slot the replica wrote before it allowed
//     sequencing again, and the dead instances' InstanceDown records (ADR-032) reach its
//     first list in that same window, while the seq thread is parked;
//   - every record the sequencer commits reaches the replica's record log through an
//     SPSC tee (the record log is touched by the repl thread only);
//   - the input queues have one consumer at a time: the sequencer while sequencing is
//     allowed, the replica (FORWARD) while backup or candidate.
//
// The Host the core needs (repl/types.h):
//   log           the L2 ring (writes) and the RecordLog (canonical copies, reads by
//                 index, L3 fallback); durable_index from the io stage
//   applier       the engine stage, gated by apply_limit (backup: announced commit)
//   egress        the release watermark (paired: commit_index; solo: durable_index)
//   sequencer     inject_inbound pushes FORWARDed input into the sequencer's queues;
//                 instance_down journals InstanceDown for the old partner's instance,
//                 ahead of any overdue Timer: the sequencer's first list (ADR-032)
//   gateways      the mirror flag (logins become mirror-attaches) and, through the md
//                 stage, the lines this node transmits: line A on the primary, line B
//                 on the backup, both after a takeover
//   links         UDP to the peer (data plane) and to the witness (control plane)
// On a backup the gateways' input is not sequenced here but FORWARDed to the primary
// (Replica::forward retransmits until it shows up in the replicated journal).
//
// Day start: a paired day starts on both nodes from identical day-start records
// (clock.h: stamped at local midnight), then runs paired; takeover (PROMOTE) and loss
// of the backup (SOLO) are handled by the core.
//
// Restart (10 §5): a data node restarting mid-day comes up RECOVERING with a new
// incarnation (start_recovering). The handshake runs before the node's pipeline starts
// (poll_prestart, on the starting thread): the witness either grants RESUME (this node
// is the solo primary of record: engine reloaded to its tail, then a new epoch) or names
// the primary to rejoin; EPOCH_END truncation of the journal and the engine reload to
// the truncation point (RejoinHooks) then run while nothing else touches the journal,
// the engine or the output log. Catch-up, JOIN and paired service run live. A later
// request to truncate below the tail or reload elsewhere (a primary that restarted
// during our catch-up, or a resynchronization from scratch) cannot be done under the
// running stages: the node exits with code 5 and restarts the handshake.
//
// Work time (T32, md/work_meter.h): items are the datagrams received and sent, the
// records appended (replicated) or taken from the tee, state hashes, forwarded inputs
// and pushed session events. In combined mode the meter is closed before the driver's
// step, which has a meter of its own (seq), so the two never count the same time.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "exchanged/clock.h"
#include "exchanged/metrics.h"
#include "exchanged/record_log.h"
#include "exchanged/seq_stage.h"
#include "exchanged/shared.h"
#include "gateway/inbound.h"
#include "journal/record.h"
#include "log/nlog.h"
#include "md/publisher.h"
#include "md/work_meter.h"
#include "net/common/port.h"
#include "net/sock/udp_port.h"
#include "repl/replica.h"

namespace lle::exch {

// The engine state after a reload (the sequencer's position in the kept journal).
struct ReloadResult {
  bool ok = false;
  std::size_t timers = 0;
  std::uint64_t next_snapshot_id = 1;
  std::uint64_t config_digest = 0;
};

// Rejoin steps that touch the node's journal, engine and output log (node.cpp). Called
// only before the pipeline starts.
struct RejoinHooks {
  std::function<bool(std::uint64_t)> truncate;          // journal (L3) and RecordLog to index t
  std::function<ReloadResult(std::uint64_t)> reload;    // engine and output log from records 1..t
};

// Exit code of a node that must restart its rejoin handshake.
inline constexpr int kExitRestartRejoin = 5;

struct ReplStageConfig {
  repl::Config repl;
  env::Endpoint bind{};     // this node's data-plane endpoint
  env::Endpoint peer{};     // the partner's
  env::Endpoint witness{};  // witnessd
  repl::NodeId initial_primary = 0;
  std::uint64_t peer_incarnation = 1;  // the backup's incarnation at day start (witness --incN)
  std::vector<std::uint32_t> sessions;  // every session id (instance_down)
};

// The production environment of the replication stage: the node clock, kernel UDP
// sockets, the metrics segment, the record log over POSIX segment files, and exit by
// std::_Exit (a deposed node, a rejoin that must restart). The simulator instantiates
// BasicReplStage on its clock, network and disk, where exit() ends the process image.
struct ReplEnv {
  using Clock = NodeClock;
  using Udp = net::sock::UdpPort;
  using Metrics = NodeMetrics;
  using Log = RecordLog;
  using Sequencer = exch::Sequencer;
  using Driver = SeqDriver;
  [[noreturn]] static void exit(int code) {
    std::fflush(stderr);
    std::_Exit(code);
  }
};

template <class Env>
class BasicReplStage {
 public:
  using Clock = typename Env::Clock;
  using Log = typename Env::Log;
  using SequencerT = typename Env::Sequencer;
  using DriverT = typename Env::Driver;
  using Metrics = typename Env::Metrics;
  struct Host {
    BasicReplStage* s;
    [[nodiscard]] journal::ChainState log_tail() const {
      if (s->split_) s->drain_tee();  // the sequencer's records so far
      return s->log_->tail();
    }
    [[nodiscard]] std::uint64_t durable_index() const { return s->sh_->durable.load(); }
    [[nodiscard]] std::uint64_t applied_index() const { return s->sh_->egress_state.applied.load(); }
    bool log_append(std::span<const std::byte> rec) { return s->append(rec); }
    std::uint32_t log_read(std::uint64_t idx, std::span<std::byte> out) const { return s->log_->read(idx, out); }
    repl::EpochEndInfo log_epoch_end(std::uint64_t e) const { return s->epoch_end(e); }
    repl::EpochEndInfo log_epoch_start(std::uint64_t e) const { return s->epoch_start(e); }
    bool log_truncate(std::uint64_t t) { return s->truncate(t); }
    void request_flush() {}  // the io stage submits its open batch on every poll (06 §6)
    void reload_state(std::uint64_t t) { s->reload(t); }
    bool inject_inbound(const repl::wire::Forward& f) { return s->inject(f); }
    void on_role(repl::Role r, std::uint64_t e) { s->on_role(r, e); }
    void instance_down(repl::NodeId peer) { s->instance_down(peer); }
    void deposed() { s->on_deposed(); }
    void alarm(repl::Alarm a, std::uint64_t d) { s->on_alarm(a, d); }
    void send_peer(std::span<const std::byte> b) {
      s->work_.start();
      s->work_.add();
      (void)s->data_.send(s->cfg_.peer, b);
    }
    void send_witness(std::span<const std::byte> b) {
      s->work_.start();
      s->work_.add();
      (void)s->ctl_.send(s->cfg_.witness, b);
    }
    [[nodiscard]] Nanos now_real() const { return s->clock_->now_real(); }
    void trace(const repl::TraceEvent& e) { s->on_trace(e); }
    repl::SnapshotOffer snapshot_offer() { return {}; }  // catch-up by journal records only
    std::uint32_t snapshot_read(std::uint64_t, std::span<std::byte>) { return 0; }
    void snapshot_release() {}
    bool snapshot_receive(std::uint64_t, std::uint64_t, std::uint64_t, std::span<const std::byte>) { return false; }
    bool snapshot_install() { return false; }
  };

  BasicReplStage(Shared& sh, Clock& clock, SequencerT& sequencer, DriverT& driver, Log& log,
                 const ReplStageConfig& cfg, Metrics& metrics, bool split = false)
      : sh_(&sh), clock_(&clock), seq_(&sequencer), driver_(&driver), log_(&log), cfg_(cfg), metrics_(&metrics),
        host_{this}, split_(split), work_(&clock) {
    pending_down_.reserve(cfg_.sessions.size() * 2);
    // Every session on both instances: a take-over plus a RESUME's own instances.
    seq_->reserve_first(cfg_.sessions.size() * 2);
  }
  BasicReplStage(const BasicReplStage&) = delete;
  BasicReplStage& operator=(const BasicReplStage&) = delete;

  // Opens the links and starts the paired day (both nodes hold the same day-start
  // records). `timers`, `snapshot_id`, `digest`: the sequencer's position.
  std::expected<void, std::string> start(std::uint64_t config_digest) {
    if (auto r = open_links(); !r) return r;
    live_ = true;
    digest_ = config_digest;
    timers_seen_ = seq_->next_timer();
    snapshot_next_ = seq_->next_snapshot_id();
    replica_ = std::make_unique<repl::Replica<Host>>(cfg_.repl, host_);
    replica_->start_paired(1, cfg_.initial_primary, cfg_.peer_incarnation, clock_->now_mono());
    publish();
    work_.finish();
    started_ = true;
    return {};
  }

  // A restart mid-day (10 §5): RECOVERING with this process's incarnation. The links
  // open now; poll_prestart() runs the handshake until handshake_done().
  std::expected<void, std::string> start_recovering(std::uint64_t config_digest, RejoinHooks hooks) {
    if (auto r = open_links(); !r) return r;
    hooks_ = std::move(hooks);
    digest_ = config_digest;
    replica_ = std::make_unique<repl::Replica<Host>>(cfg_.repl, host_);
    replica_->start_recovering(clock_->now_mono());
    publish();
    work_.finish();
    started_ = true;
    return {};
  }
  bool poll_prestart() {
    const Nanos now = clock_->now_mono();
    bool did = false;
    did |= poll_links(now);
    did |= replica_->poll(now);
    publish();
    work_.finish();
    return did;
  }
  // The engine was reloaded (rejoin: after the truncation; RESUME: at the tail).
  [[nodiscard]] bool handshake_done() const noexcept { return reloaded_; }
  // RESUME (10 §5): this node's own instances died with its old process. Their
  // InstanceDown records go first after the new epoch's EpochStart (ADR-032), like a
  // take-over's. Called after the handshake, before the stages run.
  void queue_instance_down(std::uint32_t session, std::uint16_t instance) {
    pending_down_.push_back(seq::SessionEventMsg{session, instance, journal::SessionEventKind::InstanceDown, 0});
  }
  // From here on the journal, engine and output log belong to the running stages.
  void go_live() noexcept { live_ = true; }
  [[nodiscard]] bool started() const noexcept { return started_; }

  bool poll() {
    const Nanos now = clock_->now_mono();
    bool did = false;
    if (split_) did |= drain_tee();
    did |= poll_links(now);
    StateHashMsg h;
    while (sh_->hashes.try_pop(h)) {
      work_.start();
      work_.add();
      replica_->on_state_hash(h.index, h.hash);
    }
    did |= replica_->poll(now);
    const repl::Role role = replica_->role();
    if (split_) {
      // The sequencer runs on the seq thread (SeqSide); this thread owns the replica.
      if (repl::is_primary(role)) {
        // InstanceDown goes to the sequencer when publish_split() allows sequencing
        // again (ADR-032); only what did not fit there goes through the input queue.
        if (published_allowed_) did |= push_instance_down();
        did |= reinject_staged();
      } else if (role == repl::Role::kBackup || role == repl::Role::kCandidate) {
        did |= forward_inbound(now);
      }
      publish();
      publish_split();
      work_.finish();
      return did;
    }
    if (repl::is_primary(role)) {
      if (resync_) {
        // Records the replica appended (replicated history, an EpochStart): the
        // sequencer continues after them.
        // Timer records and SnapshotMarks so far: replicated ones (counted on append) or
        // our own sequencer's (a primary that went solo), whichever this node holds.
        seq_->resume(log_->tail(), std::max(timers_seen_, seq_->next_timer()),
                     std::max(snapshot_next_, seq_->next_snapshot_id()), digest_);
        resync_ = false;
      }
      did |= deliver_instance_down();
      did |= push_instance_down();  // what did not fit in the first list
      did |= reinject_staged();
      work_.finish();  // the driver meters sequencing (seq)
      {
        const ScqConsumerScope consumer(sh_->scq_consumer, ScqConsumerGuard::kSeq);
        did |= driver_->step(replica_->sequencing_allowed());
      }
    } else {
      if (role == repl::Role::kBackup || role == repl::Role::kCandidate) did |= forward_inbound(now);
      work_.finish();
      did |= driver_->step(false);  // manual clock only
    }
    publish();
    return did;
  }

  [[nodiscard]] const repl::Replica<Host>& replica() const noexcept { return *replica_; }
  [[nodiscard]] const md::WorkStats& work() const noexcept { return work_.stats(); }
  void publish_metrics() {
    metrics_->set(Ctr::repl_role, static_cast<std::uint64_t>(replica_->role()));
    metrics_->set(Ctr::repl_epoch, replica_->epoch());
    metrics_->set(Ctr::repl_commit, replica_->commit_index());
    const std::uint64_t tail = log_->tail().last_index;
    metrics_->set(Ctr::repl_ack_lag, tail > replica_->backup_ack() ? tail - replica_->backup_ack() : 0);
    metrics_->set(Ctr::repl_forwards, replica_->stats().forwards_sent);
    metrics_->set(Ctr::repl_alarms, alarms_);
    metrics_->set(Ctr::release_index, replica_->release_watermark());
    metrics_->set_work(Ctr::repl_work_tsc, work_.stats());
  }

 private:
  // The data-plane and witness links.
  bool poll_links(Nanos now) {
    bool did = data_.poll_rx([&](const env::RxDatagram& d) {
      work_.start();
      work_.add();
      replica_->on_peer(d.data, now);
    }) != 0;
    did |= ctl_.poll_rx([&](const env::RxDatagram& d) {
      work_.start();
      work_.add();
      replica_->on_witness(d.data, now);
    }) != 0;
    return did;
  }

  // ---- split mode (the replica on its own thread) ----------------------------------------
  // The sequencer's committed records, into the record log (repl thread only).
  bool drain_tee() {
    bool did = false;
    std::uint32_t n = 0;
    while (const std::byte* p = sh_->split.tee.peek(n)) {
      const journal::RecordView v{std::span<const std::byte>(p, n)};
      work_.start();
      work_.add();
      if (v.index() == log_->tail().last_index + 1) {
        const bool ok = log_->append_from(p, n, sh_->l2.sealer());
        LLE_ASSERT(ok, "record log out of step with the sequencer's tee");
        note_record(v);
      }
      sh_->split.tee.release();
      did = true;
    }
    return did;
  }
  // True once the seq thread has begun a poll that saw sequencing disallowed.
  [[nodiscard]] bool seq_parked() const noexcept {
    return !published_allowed_ && sh_->split.parked.load(std::memory_order_acquire) == disallow_gen_;
  }
  void publish_split() {
    SplitRepl& sp = sh_->split;
    const bool want = replica_->sequencing_allowed();
    if (want && !published_allowed_) {
      if (resync_) {
        (void)drain_tee();
        sp.resync = SplitRepl::Resync{log_->tail(), timers_seen_, snapshot_next_, digest_};
        sp.resync_gen.fetch_add(1, std::memory_order_release);
        resync_ = false;
      }
      // While the seq thread is parked (InstanceDown comes with a grant's EpochStart,
      // appended once it parked, or from the handshake, before it ran) the sequencer's
      // first list is ours; allowing sequencing below publishes it with the resync slot.
      if (seq_parked()) (void)deliver_instance_down();
      sp.allowed.store(true, std::memory_order_release);
      published_allowed_ = true;
    } else if (!want && published_allowed_) {
      ++disallow_gen_;
      sp.disallow_gen.store(disallow_gen_, std::memory_order_relaxed);
      sp.allowed.store(false, std::memory_order_release);
      published_allowed_ = false;
    }
  }

  std::expected<void, std::string> open_links() {
    net::UdpConfig d;
    d.bind = cfg_.bind;
    d.dst_addr = false;
    if (auto r = data_.open(d); !r) return std::unexpected("repl: data link: " + net::to_string(r.error()));
    net::UdpConfig c;
    c.bind = env::Endpoint{cfg_.bind.ipv4, 0};
    c.dst_addr = false;
    if (auto r = ctl_.open(c); !r) return std::unexpected("repl: witness link: " + net::to_string(r.error()));
    return {};
  }

  void publish() {
    sh_->apply_limit.store(replica_->apply_limit());
    const std::uint64_t r = replica_->release_watermark();
    if (r > sh_->egress_state.release.load()) sh_->egress_state.release.store(r);
    sh_->role.store(static_cast<std::uint8_t>(replica_->role()), std::memory_order_release);
    sh_->epoch.store(replica_->epoch(), std::memory_order_release);
  }

  // ---- log ----------------------------------------------------------------------------
  bool append(std::span<const std::byte> rec) {
    if (split_) {
      if (!seq_parked()) return false;  // the sequencer may still be appending: retried
      (void)drain_tee();                // its last records first
    }
    const auto len = static_cast<std::uint32_t>(rec.size());
    std::byte* dst = sh_->l2.try_reserve(len);
    if (dst == nullptr) return false;  // L2 full: the io stage is behind
    std::memcpy(dst, rec.data(), len);
    (void)sh_->l2.sealer().reseal(dst, canonical_);
    if (!log_->append_canonical(rec)) {
      // Not the next record of our log: refuse it (the core validated the chain).
      return false;
    }
    sh_->l2.commit();
    work_.start();
    work_.add();
    const journal::RecordView v{rec};
    sh_->sequenced.store(v.index());
    note_record(v);
    resync_ = true;
    return true;
  }
  // Counters the sequencer continues from (Timer records, SnapshotMark ids, config digest).
  void note_record(const journal::RecordView& v) {
    switch (v.type()) {
      case journal::RecordType::Timer: ++timers_seen_; break;
      case journal::RecordType::SnapshotMark:
        if (const auto m = journal::decode_snapshot_mark(v)) snapshot_next_ = m->snapshot_id + 1;
        break;
      case journal::RecordType::EpochStart:
        if (const auto e = journal::decode_epoch_start(v)) digest_ = e->config_digest;
        break;
      default: break;
    }
  }

  repl::EpochEndInfo epoch_end(std::uint64_t e) const {
    repl::EpochEndInfo out;
    log_->scan(1, [&](const journal::RecordView& v) {
      if (v.epoch() > e) return false;
      out = repl::EpochEndInfo{v.index(), v.crc(), v.epoch()};
      return true;
    });
    return out;
  }
  repl::EpochEndInfo epoch_start(std::uint64_t e) const {
    repl::EpochEndInfo out;
    log_->scan(1, [&](const journal::RecordView& v) {
      if (v.epoch() < e) return true;
      if (v.epoch() == e) out = repl::EpochEndInfo{v.index(), v.crc(), v.epoch()};
      return false;
    });
    return out;
  }

  // 10 §5 step 2: drop the records after t (never committed in the primary's history).
  bool truncate(std::uint64_t t) {
    if (t >= log_->tail().last_index) return true;
    if (live_ || !hooks_.truncate) restart_rejoin("truncate the journal to", t);
    NLOG_INFO("repl: rejoin truncates the journal from {} to {}", log_->tail().last_index, t);
    return hooks_.truncate(t);
  }
  // 10 §5 step 3: engine state as of record t (replayed from the journal; no snapshots).
  void reload(std::uint64_t t) {
    if (live_ || !hooks_.reload) {
      // Running: the engine is a prefix of the log. If it has not passed t it simply
      // applies on up to t (the core's apply limit is then at least t); only an engine
      // ahead of t would need its state rebuilt.
      if (t >= sh_->egress_state.applied.load() && t <= log_->tail().last_index) return;
      restart_rejoin("reload the engine to", t);
    }
    const ReloadResult r = hooks_.reload(t);
    if (!r.ok) {
      std::fprintf(stderr, "exchanged: rejoin: engine reload to %llu failed\n", static_cast<unsigned long long>(t));
      Env::exit(2);
    }
    timers_seen_ = r.timers;
    snapshot_next_ = r.next_snapshot_id;
    if (r.config_digest != 0) digest_ = r.config_digest;
    resync_ = true;
    reloaded_ = true;
    NLOG_INFO("repl: engine reloaded to {} ({} timers)", t, r.timers);
  }
  [[noreturn]] void restart_rejoin(const char* what, std::uint64_t t) {
    NLOG_ERROR("repl: rejoin must {} {} while the node runs: restarting the handshake", std::string_view(what), t);
    std::fprintf(stderr, "exchanged: rejoin must %s %llu while running: exiting to restart the handshake\n", what,
                 static_cast<unsigned long long>(t));
    Env::exit(kExitRestartRejoin);
  }

  // ---- sequencer side -------------------------------------------------------------------
  bool inject(const repl::wire::Forward& f) {
    if (f.kind == repl::wire::ForwardKind::kSessionEvent) {
      return sh_->ouch.try_push(seq::session_event_inbound(seq::SessionEventMsg{
          f.session_id, f.instance, static_cast<journal::SessionEventKind>(f.event), f.requested_seq}));
    }
    seq::InboundMsg m;
    gw::make_inbound(m, f.session_id, f.account, f.instance, f.bytes, 0);
    // The backup's gateway flagged it (an over-long packet, truncated there): the record
    // carries exactly the flags a direct submission would have (wire::Forward::record_flags).
    m.flags = static_cast<std::uint16_t>(m.flags | f.record_flags);
    return sh_->ouch.try_push(m);
  }

  void instance_down(repl::NodeId peer) {
    // 10 §4 step 5: every instance the old partner had is gone. The engine treats an
    // InstanceDown for an instance that was not live as a no-op, so all sessions are
    // listed; the ones that were live get cancel-on-disconnect.
    for (std::uint32_t id : cfg_.sessions) pending_down_.push_back(seq::SessionEventMsg{id, peer, journal::SessionEventKind::InstanceDown, 0});
    NLOG_INFO("repl: instance {} down for {} sessions", static_cast<std::uint16_t>(peer), cfg_.sessions.size());
  }
  // ADR-032: the dead instances go down before any overdue Timer and any queued input,
  // so a cross that came due during the outage never executes their cancel-on-disconnect
  // orders: into the sequencer's first list, emitted right after the new epoch's
  // EpochStart. The sequencer must not be running: combined mode (this thread), or split
  // mode with the seq thread parked (publish_split).
  bool deliver_instance_down() {
    bool did = false;
    while (down_next_ < pending_down_.size() && seq_->inject_first(pending_down_[down_next_])) {
      work_.start();
      work_.add();
      ++down_next_;
      did = true;
    }
    if (down_next_ < pending_down_.size() && !down_overflow_noted_) {
      down_overflow_noted_ = true;
      NLOG_WARN("repl: {} InstanceDown records did not fit the sequencer's first list: queued behind due timers",
                pending_down_.size() - down_next_);
    }
    finish_down();
    return did;
  }
  // What did not fit in the first list (two take-overs before the sequencer emitted the
  // first one's): through the input queue, in order, behind any due Timer.
  bool push_instance_down() {
    bool did = false;
    while (down_next_ < pending_down_.size() &&
           sh_->ouch.try_push(seq::session_event_inbound(pending_down_[down_next_]))) {
      work_.start();
      work_.add();
      ++down_next_;
      did = true;
    }
    finish_down();
    return did;
  }
  void finish_down() noexcept {
    if (down_next_ == pending_down_.size() && down_next_ != 0) {
      pending_down_.clear();
      down_next_ = 0;
      down_overflow_noted_ = false;
    }
  }

  // Backup: mirror-session input goes to the primary (10 §3 step 5). In split mode the
  // replica pops the input SCQs only once the seq thread has parked (a demotion is
  // seen here before publish_split() turns sequencing off): one consumer at a time.
  bool forward_inbound(Nanos now) {
    if (split_ && !seq_parked()) return false;
    const ScqConsumerScope consumer(sh_->scq_consumer, ScqConsumerGuard::kRepl);
    bool did = false;
    for (int budget = 0; budget < 64; ++budget) {
      if (!staged_) {
        if (sh_->ouch.try_pop(staged_msg_)) {
          staged_ = true;
          staged_event_ = seq::is_session_event(staged_msg_);
          if (staged_event_) staged_ev_ = seq::session_event_of(staged_msg_);
        } else if (sh_->events.try_pop(staged_ev_)) {
          staged_ = true;
          staged_event_ = true;
        } else {
          break;
        }
      }
      repl::wire::Forward f;
      if (staged_event_) {
        f.session_id = staged_ev_.session_id;
        f.instance = staged_ev_.instance;
        f.kind = repl::wire::ForwardKind::kSessionEvent;
        f.event = static_cast<std::uint8_t>(staged_ev_.event);
        f.requested_seq = staged_ev_.requested_seq;
      } else {
        f.session_id = staged_msg_.session_id;
        f.account = staged_msg_.account;
        f.instance = staged_msg_.instance;
        f.kind = repl::wire::ForwardKind::kOuch;
        f.bytes = staged_msg_.payload();
        f.record_flags = staged_msg_.flags;  // kFlagMalformedInput if the gateway truncated it
      }
      if (staged_event_) f.account = 0;
      const auto st = replica_->forward(f, now);
      if (st == repl::Replica<Host>::ForwardStatus::kFull || st == repl::Replica<Host>::ForwardStatus::kNotForwarding)
        break;  // retried next poll (or re-injected after a promotion)
      if (st == repl::Replica<Host>::ForwardStatus::kTooLarge)
        NLOG_ERROR("repl: inbound message of {} bytes too large to forward: dropped", f.bytes.size());
      work_.start();
      work_.add();
      staged_ = false;
      did = true;
    }
    return did;
  }
  // After a promotion, a message popped but not yet forwarded goes to our own sequencer
  // behind whatever the core re-injects (its pending FORWARDs, in order).
  bool reinject_staged() {
    if (!staged_ || replica_->pending_forwards() != 0) return false;
    const bool ok = staged_event_ ? sh_->ouch.try_push(seq::session_event_inbound(staged_ev_))
                                  : sh_->ouch.try_push(staged_msg_);
    if (ok) {
      work_.start();
      work_.add();
      staged_ = false;
    }
    return ok;
  }

  // ---- notifications --------------------------------------------------------------------
  void on_role(repl::Role r, std::uint64_t e) {
    NLOG_INFO("repl: role {} epoch {}", std::string_view(repl::to_string(r)), e);
    switch (r) {
      case repl::Role::kPrimary:
        sh_->mirror.store(false, std::memory_order_release);
        sh_->lines.store(md::kLineA, std::memory_order_release);
        break;
      case repl::Role::kSoloPrimary:
      case repl::Role::kSoloCandidate:
        sh_->mirror.store(false, std::memory_order_release);
        sh_->lines.store(md::kLineA | md::kLineB, std::memory_order_release);  // 10 §4 step 4: both lines
        break;
      case repl::Role::kBackup:
      case repl::Role::kCandidate:
        sh_->mirror.store(true, std::memory_order_release);
        sh_->lines.store(md::kLineB, std::memory_order_release);
        break;
      default:
        sh_->mirror.store(true, std::memory_order_release);
        sh_->lines.store(0, std::memory_order_release);
        break;
    }
  }
  void on_deposed() {
    // 10 §4: a deposed node closes TCP without End of Session and exits. Exiting at once
    // closes every socket; nothing it holds can be released any more.
    NLOG_ERROR("repl: deposed in epoch {}: exiting without End of Session", replica_->epoch());
    std::fprintf(stderr, "exchanged: deposed (epoch %llu): exiting\n",
                 static_cast<unsigned long long>(replica_->epoch()));
    Env::exit(3);
  }
  void on_alarm(repl::Alarm a, std::uint64_t d) {
    ++alarms_;
    NLOG_ERROR("repl: ALARM {} at {}", std::string_view(repl::to_string(a)), d);
  }
  void on_trace(const repl::TraceEvent& e) {
    using K = repl::TraceKind;
    switch (e.kind) {
      case K::kFreeze: NLOG_INFO("repl: frozen at {}", e.a); break;
      case K::kRequestPromote: NLOG_INFO("repl: PROMOTE from epoch {} last {}", e.a, e.b); break;
      case K::kRequestSolo: NLOG_INFO("repl: SOLO from epoch {}", e.a); break;
      case K::kGrantApplied: NLOG_INFO("repl: granted epoch {} (request {}) EpochStart at {}", e.a, e.b, e.c); break;
      case K::kDeposed: NLOG_INFO("repl: deposed at epoch {}", e.a); break;
      case K::kSoloCancelled: NLOG_INFO("repl: backup back before SOLO"); break;
      case K::kRequestResume: NLOG_INFO("repl: RESUME from epoch {}", e.a); break;
      case K::kRequestJoin: NLOG_INFO("repl: JOIN relayed: epoch {} last {} joiner incarnation {}", e.a, e.b, e.c); break;
      case K::kTruncate: NLOG_INFO("repl: rejoin truncation point {}", e.a); break;
      case K::kRejoined: NLOG_INFO("repl: rejoined as the backup in epoch {}", e.a); break;
      case K::kAdoptEpoch: NLOG_INFO("repl: adopted epoch {} from the witness", e.a); break;
      case K::kEpochEndAnswer: NLOG_INFO("repl: EPOCH_END answered to incarnation {}", e.a); break;
      default: break;
    }
  }

  Shared* sh_;
  Clock* clock_;
  SequencerT* seq_;
  DriverT* driver_;
  Log* log_;
  ReplStageConfig cfg_;
  Metrics* metrics_;
  Host host_;
  std::unique_ptr<repl::Replica<Host>> replica_;
  typename Env::Udp data_;
  typename Env::Udp ctl_;
  journal::Sealer canonical_;
  bool resync_ = false;
  std::size_t timers_seen_ = 0;
  std::uint64_t snapshot_next_ = 1;
  std::uint64_t digest_ = 0;
  std::vector<seq::SessionEventMsg> pending_down_;
  std::size_t down_next_ = 0;
  bool down_overflow_noted_ = false;
  bool staged_ = false;
  bool staged_event_ = false;
  seq::InboundMsg staged_msg_{};
  seq::SessionEventMsg staged_ev_{};
  std::uint64_t alarms_ = 0;
  RejoinHooks hooks_;
  bool split_ = false;
  bool published_allowed_ = false;
  std::uint64_t disallow_gen_ = 0;
  bool started_ = false;
  bool live_ = false;
  bool reloaded_ = false;
  md::WorkMeter<Clock> work_;
};
using ReplStage = BasicReplStage<ReplEnv>;

// The seq thread's stage in split mode: sequences while the replica allows it, resuming
// from the replica's resync slot after records the replica appended; parks otherwise.
template <class Env>
class BasicSeqSide {
 public:
  BasicSeqSide(Shared& sh, typename Env::Sequencer& sequencer, typename Env::Driver& driver)
      : guard_(&sh.scq_consumer), sp_(&sh.split), seq_(&sequencer), driver_(&driver) {}
  bool poll() {
    if (!sp_->allowed.load(std::memory_order_acquire)) {
      sp_->parked.store(sp_->disallow_gen.load(std::memory_order_relaxed), std::memory_order_release);
      return driver_->step(false);  // the manual clock still walks
    }
    const std::uint64_t g = sp_->resync_gen.load(std::memory_order_acquire);
    if (g != seen_resync_) {
      const SplitRepl::Resync& r = sp_->resync;
      seq_->resume(r.chain, r.timers, r.next_snapshot_id, r.digest);
      seen_resync_ = g;
    }
    const ScqConsumerScope consumer(*guard_, ScqConsumerGuard::kSeq);
    return driver_->step(true);
  }

 private:
  ScqConsumerGuard* guard_;
  SplitRepl* sp_;
  typename Env::Sequencer* seq_;
  typename Env::Driver* driver_;
  std::uint64_t seen_resync_ = 0;
};
using SeqSide = BasicSeqSide<ReplEnv>;

}  // namespace lle::exch

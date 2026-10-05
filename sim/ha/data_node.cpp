#include "sim/ha/data_node.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "repl/journal_truncate.h"
#include "sim/dist.h"
#include "sim/rng.h"

namespace lle::sim::ha {

namespace {

constexpr std::uint32_t kQueueDepth = journal::kQueueDepth;
constexpr std::size_t kMaxTx = 64 * 1024;

journal::JournalWriterOptions writer_options() {
  journal::JournalWriterOptions o;
  o.day = kDay;
  o.queue_depth = kQueueDepth;
  return o;
}

bool frame(Bytes& tx, std::span<const std::byte> payload) {
  if (payload.size() > 0xFFFF) return false;
  const std::size_t at = tx.size();
  tx.resize(at + 2 + payload.size());
  store_le16(tx.data() + at, static_cast<std::uint16_t>(payload.size()));
  if (!payload.empty()) std::memcpy(tx.data() + at + 2, payload.data(), payload.size());
  return true;
}

}  // namespace

HaNode::HaNode(Node& n, Truth& t, const NodeParams& p, BootReason why)
    : node_(n),
      t_(t),
      store_(t.store[n.id()]),
      p_(p),
      self_(static_cast<NodeId>(n.id())),
      peer_(n.id() == kA ? kB : kA),
      inc_(n.incarnation()),
      dir_(t.store[n.id()].dir, gate_),
      data_port_(n, kDataPort),
      ctl_port_(n, kCtlPort),
      client_port_(n),
      host_{this} {
  World& w = n.world();
  const FaultConfig& f = w.faults();
  gate_.world = &w;
  gate_.rng = w.stream(Stream::Disk, (std::uint64_t{0x4A} << 40) | (std::uint64_t{self_} << 32) | inc_);
  gate_.write_min_ns = std::max<Nanos>(1'000, f[Param::DiskWriteMinNs]);
  gate_.write_mean_ns = std::max<Nanos>(5'000, f[Param::DiskWriteMeanNs]);
  gate_.stall_ppm = static_cast<std::uint32_t>(f.u(Param::DiskStallPpm));
  gate_.stall_max_ns = f[Param::DiskStallMaxNs];
  gate_.eio_ppm = static_cast<std::uint32_t>(f.u(Param::DiskEioWritePpm));
  gate_.may_fail = [this] { return !t_.may_fail || t_.may_fail(self_, false); };
  hash_interval_ = p.repl.hash_interval;
  boot(why);
}

HaNode::~HaNode() {
  // The dying process's write syscalls complete before it is gone: in-flight journal
  // writes settle (a host crash has already decided their fate, see crash_data_node).
  dir_.settle_all();
  if (t_.node[self_] == this) t_.node[self_] = nullptr;
}

void HaNode::boot(BootReason why) {
  ++store_.boots;
  t_.node[self_] = this;
  prep_ = std::make_unique<journal::SegmentPreparer<HaDir, Prng>>(dir_, store_.nonce_rng, kDay, kSegmentBytes);
  // 06 §7: recover L3, repairing a torn tail.
  journal::RecoveryOptions ro;
  ro.day = kDay;
  const journal::RecoveryResult rr = journal::recover(dir_, ro);
  if (!rr.usable() || (rr.torn_tail && !rr.repaired)) {
    t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": journal recovery refused: " + rr.detail);
    dead_ = true;
    return;
  }
  writer_ = std::make_unique<journal::JournalWriter<HaDevice>>(writer_options());
  LLE_ASSERT(journal::resume_writer(*writer_, dir_, rr), "resume_writer");
  ensure_spares();
  // 06 §5: L2 survives a process crash; restore the chain after the durable tail.
  ring_.init(store_.l2.get(), kL2Bytes, store_.l2_nonce);
  const journal::L2RestoreResult l2 = ring_.restore(rr.chain.last_index + 1, rr.chain.last_crc);
  const journal::ChainState tail = l2.found ? l2.chain : rr.chain;
  // Reconcile the harness mirror with what recovery found: L3 + L2 is exactly the
  // prefix the node held (all of it after a process crash).
  auto& h = store_.history;
  const bool host = store_.host_crashed;
  store_.host_crashed = false;
  std::string bad;
  if (tail.last_index > h.size()) {
    bad = "recovered index " + std::to_string(tail.last_index) + " beyond the " + std::to_string(h.size()) + " held";
  } else if (rr.chain.last_index != 0 && crc_of(h[rr.chain.last_index - 1]) != rr.chain.last_crc) {
    bad = "recovered L3 record " + std::to_string(rr.chain.last_index) + " differs from the one written";
  } else if (tail.last_index != 0 && crc_of(h[tail.last_index - 1]) != tail.last_crc) {
    bad = "restored L2 record " + std::to_string(tail.last_index) + " differs from the one written";
  } else if (!host && tail.last_index != h.size()) {
    bad = "after a process crash L3+L2 hold " + std::to_string(tail.last_index) + " of " + std::to_string(h.size()) +
          " records (L2 lost data)";
  }
  if (!bad.empty()) {
    t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": " + bad);
    dead_ = true;
    return;
  }
  h.resize(static_cast<std::size_t>(tail.last_index));
  tail_ = tail;
  max_urn_.clear();
  for (const Bytes& r : h) {
    const journal::RecordView v = view(r);
    if (v.type() != journal::RecordType::OuchInbound) continue;
    const auto in = journal::decode_ouch_inbound(v);
    const auto o = in ? decode_order(in->msg) : std::nullopt;
    if (o && o->urn > max_urn_[in->account]) max_urn_[in->account] = o->urn;
  }
  durable_seen_ = writer_->durable_index();
  t_.l3_max[self_] = durable_seen_;

  repl::Config c = p_.repl;
  c.self = static_cast<repl::NodeId>(self_);
  c.incarnation = inc_;
  repl_ = std::make_unique<repl::Replica<Host>>(c, host_);
  const Nanos now = node_.clock().now_mono();
  if (why == BootReason::Initial) {
    repl_->start_paired(1, static_cast<repl::NodeId>(p_.primary0), 0, now);
  } else {
    t_.tla.emit(t_.w->now(), "restart", "n", self_, "inc", inc_, "len", tail_.last_index, "durable", durable_seen_);
    repl_->start_recovering(now);
  }
  (void)client_port_.listen(env::Endpoint{node_ip(self_), kClientPort});
  node_.add_stage(s_repl_, "repl");
  node_.add_stage(s_seq_, "seq");
  node_.add_stage(s_io_, "io");
  node_.add_stage(s_app_, "app");
}

// ---- log ----------------------------------------------------------------------------------

bool HaNode::append_canonical(std::span<const std::byte> rec, Origin origin) {
  const auto len = static_cast<std::uint32_t>(rec.size());
  std::byte* dst = ring_.try_reserve(len);
  if (dst == nullptr) return false;  // L2 full: the journal writer is behind
  std::memcpy(dst, rec.data(), len);
  (void)ring_.sealer().reseal(dst, canonical_);
  ring_.commit();
  const journal::RecordView v{rec};
  LLE_ASSERT(v.index() == tail_.last_index + 1 && v.prev_crc() == tail_.last_crc, "log append out of chain");
  store_.history.emplace_back(rec.begin(), rec.end());
  tail_ = journal::ChainState{v.index(), v.crc(), v.ts_ns(), v.epoch()};
  t_.on_hold(self_, v.index(), v.crc());
  // Classification for the TLA+ trace: an order the engine will execute (first
  // UserRefNum above the account's maximum in this log), or a no-op record.
  std::string what = "rec";
  if (v.type() == journal::RecordType::OuchInbound) {
    const auto in = journal::decode_ouch_inbound(v);
    const auto o = in ? decode_order(in->msg) : std::nullopt;
    if (o && o->urn > max_urn_[in->account]) {
      max_urn_[in->account] = o->urn;
      what = "a" + std::to_string(in->account) + "u" + std::to_string(o->urn);
    }
  } else if (v.type() == journal::RecordType::EpochStart) {
    what = "es";
  }
  if (origin == Origin::kSequencer) {
    t_.tla.emit(t_.w->now(), "seq", "n", self_, "idx", v.index(), "crc", v.crc(), "ep", v.epoch(), "v", what);
  } else if (t_.tla.on()) {
    pending_value_ = what;  // reported with the replica's RecvAppend / EpochStart trace event
  }
  return true;
}

bool HaNode::sequence_one(const Inbound& in) {
  std::array<std::byte, 128> buf{};
  journal::RecordBuilder b(canonical_, tail_);
  b.set_epoch(static_cast<std::uint32_t>(repl_->epoch()));
  std::span<std::byte> r;
  const Nanos ts = node_.clock().now_real();
  if (in.event) {
    r = b.append(std::span<std::byte>(buf), ts,
                 journal::SessionEvent{in.session, in.instance, in.kind, in.requested_seq});
  } else {
    r = b.append(std::span<std::byte>(buf), ts,
                 journal::OuchInbound{in.session, in.account, in.instance,
                                      std::span<const std::byte>(in.msg.data(), in.len)},
                 in.flags);
  }
  LLE_ASSERT(!r.empty(), "sequencer record");
  return append_canonical(r, Origin::kSequencer);
}

std::uint32_t HaNode::read(std::uint64_t idx, std::span<std::byte> out) const {
  const auto& h = store_.history;
  if (idx == 0 || idx > h.size() || idx > tail_.last_index) return 0;
  const Bytes& r = h[idx - 1];
  std::memcpy(out.data(), r.data(), r.size());
  return static_cast<std::uint32_t>(r.size());
}

repl::EpochEndInfo HaNode::epoch_end(std::uint64_t e) const {
  const auto& h = store_.history;
  for (std::size_t i = std::min<std::size_t>(h.size(), tail_.last_index); i > 0; --i) {
    const journal::RecordView v = view(h[i - 1]);
    if (v.epoch() <= e) return repl::EpochEndInfo{v.index(), v.crc(), v.epoch()};
  }
  return {};
}

repl::EpochEndInfo HaNode::epoch_start(std::uint64_t e) const {
  const auto& h = store_.history;
  const std::size_t n = std::min<std::size_t>(h.size(), tail_.last_index);
  for (std::size_t i = 0; i < n; ++i) {
    const journal::RecordView v = view(h[i]);
    if (v.epoch() == e) return repl::EpochEndInfo{v.index(), v.crc(), v.epoch()};
    if (v.epoch() > e) break;
  }
  return {};
}

// Everything in L2 into the journal and durable now (cold path: the writer is quiesced).
void HaNode::drain_journal() {
  for (int spins = 0; spins < 1'000'000; ++spins) {
    (void)writer_->poll();
    if (writer_->failed()) return;
    for (;;) {
      const journal::RecordView v = ring_.peek(0);
      if (v.empty()) break;
      const auto st = writer_->append(v.bytes(), ring_.sealer());
      if (st == journal::JournalWriter<HaDevice>::Status::Ok) {
        ring_.release(0);
        continue;
      }
      if (st == journal::JournalWriter<HaDevice>::Status::NeedSegment) {
        ensure_spares();
        continue;
      }
      break;
    }
    (void)writer_->flush();
    dir_.expedite_all();
    (void)writer_->poll();
    if (ring_.peek(0).empty() && writer_->batch_used() == 0 && writer_->in_flight() == 0) break;
  }
  note_durable();
}

void HaNode::reset_l2(bool fresh_nonce) {
  if (fresh_nonce) {
    std::uint64_t nonce = 0;
    do {
      nonce = store_.nonce_rng.next_u64();
    } while (!journal::usable_nonce(nonce) || nonce == store_.l2_nonce);
    store_.l2_nonce = nonce;
  }
  std::memset(store_.l2.get(), 0, kL2Bytes);
  ring_.init(store_.l2.get(), kL2Bytes, store_.l2_nonce);
}

// 10 §5 step 2: the divergent tail goes from L2 and L3. L2 is drained to L3 first so
// every record up to t is durable, then L3 is truncated and the ring re-nonced: a
// stale record t+1 still in the ring's storage would otherwise chain to t and come
// back at the next L2 restore.
bool HaNode::truncate(std::uint64_t t) {
  drain_journal();
  if (writer_->failed()) return false;
  const repl::TruncateResult tr = repl::truncate_journal(dir_, *prep_, kDay, t);
  if (!tr.ok) {
    t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": truncate_journal: " + tr.detail);
    return false;
  }
  journal::RecoveryOptions ro;
  ro.day = kDay;
  const journal::RecoveryResult rr = journal::recover(dir_, ro);
  if (!rr.usable() || rr.chain.last_index != t) {
    t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": recovery after truncation to " + std::to_string(t) +
                               " found " + std::to_string(rr.chain.last_index) + ": " + rr.detail);
    return false;
  }
  writer_ = std::make_unique<journal::JournalWriter<HaDevice>>(writer_options());
  LLE_ASSERT(journal::resume_writer(*writer_, dir_, rr), "resume after truncation");
  ensure_spares();
  reset_l2(true);
  store_.history.resize(static_cast<std::size_t>(t));
  tail_ = rr.chain;
  max_urn_.clear();
  for (const Bytes& r : store_.history) {
    const journal::RecordView v = view(r);
    if (v.type() != journal::RecordType::OuchInbound) continue;
    const auto in = journal::decode_ouch_inbound(v);
    const auto o = in ? decode_order(in->msg) : std::nullopt;
    if (o && o->urn > max_urn_[in->account]) max_urn_[in->account] = o->urn;
  }
  durable_seen_ = writer_->durable_index();
  ++t_.truncations;
  return true;
}

void HaNode::reload(std::uint64_t t) {
  engine_ = ToyEngine{};
  regen_.reset();
  snap_base_index_ = 0;
  for (std::uint64_t i = 1; i <= t && i <= store_.history.size(); ++i) (void)engine_.apply(view(store_.history[i - 1]));
  snap_rx_.clear();
}

bool HaNode::inject(const repl::wire::Forward& f) {
  if (inbound_.size() >= p_.inbound_cap) return false;
  Inbound in;
  in.session = f.session_id;
  in.instance = f.instance;
  in.account = f.account;
  if (f.kind == repl::wire::ForwardKind::kSessionEvent) {
    in.event = true;
    in.kind = static_cast<journal::SessionEventKind>(f.event);
    in.requested_seq = f.requested_seq;
  } else {
    if (f.bytes.size() > in.msg.size()) return true;  // not a toy order: dropped (never sequenced)
    std::memcpy(in.msg.data(), f.bytes.data(), f.bytes.size());
    in.len = static_cast<std::uint16_t>(f.bytes.size());
    in.flags = f.record_flags;
  }
  inbound_.push_back(in);
  return true;
}

// ---- repl hooks ---------------------------------------------------------------------------

void HaNode::on_role(repl::Role r, std::uint64_t e) {
  t_.log("n%u inc %llu role %s epoch %llu", self_, static_cast<unsigned long long>(inc_), repl::to_string(r),
         static_cast<unsigned long long>(e));
  role_seen_ = r;
}

void HaNode::on_deposed() {
  ++t_.deposed;
  t_.log("n%u deposed: exits without End of Session", self_);
  t_.tla.emit(t_.w->now(), "crash", "n", self_, "kind", "deposed", "len", tail_.last_index);
  dead_ = true;
  node_.request_crash();
}

void HaNode::on_alarm(repl::Alarm a, std::uint64_t d) {
  ++t_.alarms;
  t_.log("n%u ALARM %s %llu", self_, repl::to_string(a), static_cast<unsigned long long>(d));
  switch (a) {
    case repl::Alarm::kStateHashMismatch:
    case repl::Alarm::kBuildMismatch:
      t_.fail(t_.o_replay, "n" + std::to_string(self_) + ": determinism alarm " + repl::to_string(a) + " at " +
                               std::to_string(d));
      break;
    case repl::Alarm::kBadRecord:
    case repl::Alarm::kDiverged:
    case repl::Alarm::kSnapshotInvalid:
    case repl::Alarm::kIncarnationRegressed:
      t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": alarm " + repl::to_string(a) + " at " + std::to_string(d));
      break;
    case repl::Alarm::kUnpromotableSuspect:
      break;
  }
}

void HaNode::on_trace(const repl::TraceEvent& e) {
  const Nanos now = t_.w->now();
  using K = repl::TraceKind;
  switch (e.kind) {
    case K::kSendAppend:
      t_.tla.emit(now, "send_append", "n", self_, "idx", e.a, "ep", repl_->epoch());
      break;
    case K::kRecvAppend:
      t_.tla.emit(now, "recv_append", "n", self_, "idx", e.a, "crc", e.b, "ep", repl_->epoch(), "v", pending_value_);
      break;
    case K::kCatchupAppend:
      t_.tla.emit(now, "catchup_append", "n", self_, "idx", e.a, "crc", e.b, "v", pending_value_);
      break;
    case K::kRecvAck:
      t_.tla.emit(now, "recv_ack", "n", self_, "len", e.a, "ep", repl_->epoch());
      break;
    case K::kRelease: {
      const bool solo = e.b == 1;
      t_.on_release(self_, release_seen_, e.a, solo, repl_->epoch(), writer_->durable_index());
      t_.tla.emit(now, "release", "n", self_, "w", e.a, "mode", solo ? "solo" : "paired", "ep", repl_->epoch());
      release_seen_ = e.a;
      break;
    }
    case K::kFreeze:
      t_.tla.emit(now, "freeze", "n", self_, "last", e.a);
      break;
    case K::kRequestPromote:
      t_.tla.emit(now, "req_promote", "n", self_, "fe", e.a, "last", e.b, "inc", inc_);
      break;
    case K::kRequestSolo:
      t_.tla.emit(now, "req_solo", "n", self_, "fe", e.a, "inc", inc_);
      break;
    case K::kRequestResume:
      t_.tla.emit(now, "req_resume", "n", self_, "fe", e.a, "inc", inc_);
      break;
    case K::kRequestJoin:
      t_.pending_join = Truth::PendingJoin{true, e.a, self_, e.c, inc_};
      t_.tla.emit(now, "req_join", "n", self_, "fe", e.a, "last", e.b, "jinc", e.c);
      break;
    case K::kGrantApplied: {
      const auto type = static_cast<witness::MsgType>(e.b);
      switch (type) {
        case witness::MsgType::kPromote:
          ++t_.takeovers;
          if (engine_.has_partial_fill()) SIM_PROBE("ha.failover_during_partial_fill");
          break;
        case witness::MsgType::kSolo: ++t_.solos; break;
        case witness::MsgType::kResume: ++t_.resumes; break;
        case witness::MsgType::kJoin: ++t_.joins; break;
        default: break;
      }
      t_.log("n%u %s granted: epoch %llu, EpochStart at %llu", self_, witness::to_string(type),
             static_cast<unsigned long long>(e.a), static_cast<unsigned long long>(e.c));
      t_.tla.emit(now, "grant_applied", "n", self_, "type", witness::to_string(type), "epoch", e.a, "es_idx", e.c,
                  "es_crc", crc_of(store_.history[e.c - 1]), "inc", inc_);
      t_.on_primary(self_, e.a);
      break;
    }
    case K::kRejoined:
      t_.tla.emit(now, "rejoined", "n", self_, "epoch", e.a, "inc", inc_);
      break;
    case K::kTruncate:
      t_.tla.emit(now, "truncate", "n", self_, "to", e.a);
      break;
    case K::kAdoptEpoch:
      t_.tla.emit(now, "adopt_epoch", "n", self_, "epoch", e.a);
      break;
    case K::kDeposed:
      break;
    case K::kSoloCancelled:
      t_.tla.emit(now, "solo_cancelled", "n", self_);
      break;
    case K::kEpochEndAnswer:
      t_.tla.emit(now, "ee_answer", "n", self_, "jinc", e.a);
      break;
    case K::kSendCatchup:
      t_.tla.emit(now, "catchup_send", "n", self_, "idx", e.a);
      break;
    case K::kJoinAbandoned:
      t_.tla.emit(now, "join_abandoned", "n", self_, "last", e.a);
      break;
    case K::kRejoinEpochStart:
      t_.log("n%u joins epoch %llu: appends its EpochStart at %llu", self_, static_cast<unsigned long long>(e.c),
             static_cast<unsigned long long>(e.a));
      t_.tla.emit(now, "rejoin_es", "n", self_, "idx", e.a, "crc", e.b, "epoch", e.c);
      break;
  }
}

// ---- snapshots ----------------------------------------------------------------------------

repl::SnapshotOffer HaNode::snapshot_offer() {
  snap_tx_ = engine_.snapshot_image(static_cast<std::uint32_t>(repl_->epoch()));
  if (snap_tx_.empty()) return {};
  return repl::SnapshotOffer{engine_.applied(), snap_tx_.size()};
}

std::uint32_t HaNode::snapshot_read(std::uint64_t off, std::span<std::byte> out) {
  if (off >= snap_tx_.size()) return 0;
  const std::size_t n = std::min<std::size_t>(out.size(), snap_tx_.size() - static_cast<std::size_t>(off));
  std::memcpy(out.data(), snap_tx_.data() + off, n);
  return static_cast<std::uint32_t>(n);
}

bool HaNode::snapshot_receive(std::uint64_t idx, std::uint64_t total, std::uint64_t off, std::span<const std::byte> b) {
  if (off == 0) {
    if (total > (std::uint64_t{64} << 20)) return false;
    snap_rx_.assign(static_cast<std::size_t>(total), std::byte{0});
    snap_rx_index_ = idx;
  }
  if (snap_rx_index_ != idx || off + b.size() > snap_rx_.size()) return false;
  std::memcpy(snap_rx_.data() + off, b.data(), b.size());
  return true;
}

bool HaNode::snapshot_install() {
  ToyEngine e;
  if (!e.restore(snap_rx_) || e.applied() != snap_rx_index_) return false;  // invalid
  // Catch-up records and snapshot chunks race on the network: the engine may already
  // have applied past the snapshot. The snapshot is then simply not needed.
  if (e.applied() <= engine_.applied()) {
    SIM_PROBE("ha.snapshot_not_needed");
    return true;
  }
  engine_ = std::move(e);
  snap_base_index_ = engine_.applied();
  regen_.reset();
  SIM_PROBE("ha.snapshot_installed");
  return true;
}

// ---- stages -------------------------------------------------------------------------------

void HaNode::ensure_spares() {
  while (writer_->prepared_count() < 2) {
    auto p = prep_->create();
    if (!p) {
      t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": segment preparation failed");
      return;
    }
    if (!writer_->add_prepared(dir_.device(p->handle), p->handle, p->header)) return;
  }
}

void HaNode::note_durable() {
  const std::uint64_t d = writer_->durable_index();
  if (d > durable_seen_) {
    durable_seen_ = d;
    t_.l3_max[self_] = d;
    t_.tla.emit(t_.w->now(), "durable", "n", self_, "len", d);
  }
}

bool HaNode::poll_repl() {
  if (dead_) return false;
  const Nanos now = node_.clock().now_mono();
  bool did = false;
  did |= data_port_.poll_rx([&](const env::RxDatagram& d) {
           if (!dead_) repl_->on_peer(d.data, now);
         }) != 0;
  did |= ctl_port_.poll_rx([&](const env::RxDatagram& d) {
           if (!dead_) repl_->on_witness(d.data, now);
         }) != 0;
  if (dead_) return did;
  did |= repl_->poll(now);
  if (!repl::is_primary(repl_->role())) release_seen_ = repl_->release_watermark();
  return did;
}

bool HaNode::poll_seq() {
  if (dead_ || !repl_->sequencing_allowed()) return false;
  bool did = false;
  if (pending_instance_down_ >= 0 && engine_.applied() == tail_.last_index) {
    // 10 §4 step 5: the old partner's session instances are down.
    const auto inst = engine_.live_instances(static_cast<std::uint32_t>(pending_instance_down_));
    for (auto it = inst.rbegin(); it != inst.rend(); ++it) {
      Inbound in;
      in.event = true;
      in.session = it->first;
      in.instance = it->second;
      in.kind = journal::SessionEventKind::InstanceDown;
      inbound_.push_front(in);
    }
    pending_instance_down_ = -1;
  }
  int budget = 64;
  while (!inbound_.empty() && repl_->sequencing_allowed() && budget-- > 0) {
    if (!sequence_one(inbound_.front())) break;
    inbound_.pop_front();
    did = true;
  }
  return did;
}

bool HaNode::poll_io() {
  if (dead_) return false;
  bool did = writer_->poll() != 0;
  using W = journal::JournalWriter<HaDevice>;
  // A record leaves the L2 ring (its cursor is released) only into a batch that is
  // submitted in this same poll: the open batch is process memory, so a record copied
  // into it and then overwritten in the ring would be lost at a process crash although
  // the node had acknowledged it as L2-held. Keep one queue slot for the final flush.
  while (writer_->in_flight() + 1 < kQueueDepth) {
    const journal::RecordView v = ring_.peek(0);
    if (v.empty()) break;
    const W::Status st = writer_->append(v.bytes(), ring_.sealer());
    if (st == W::Status::Ok) {
      ring_.release(0);
      did = true;
      continue;
    }
    if (st == W::Status::NeedSegment) {
      ensure_spares();
      if (writer_->prepared_count() == 0) break;
      continue;
    }
    if (st == W::Status::BadRecord) t_.fail(t_.o_internal, "n" + std::to_string(self_) + ": writer refused a record");
    break;
  }
  if (writer_->flush()) did = true;
  if (writer_->failed()) {
    // 06 §6: any EIO or short write is fatal: intake halts, the node fails over.
    SIM_PROBE("ha.journal_eio_abort");
    t_.log("n%u journal write failed: process aborts", self_);
    t_.tla.emit(t_.w->now(), "crash", "n", self_, "kind", "abort", "len", tail_.last_index);
    dead_ = true;
    node_.request_crash();
    return true;
  }
  ensure_spares();
  note_durable();
  return did;
}

bool HaNode::poll_app() {
  if (dead_) return false;
  bool did = false;
  const std::uint64_t limit = std::min(repl_->apply_limit(), tail_.last_index);
  for (int budget = 256; engine_.applied() < limit && budget > 0; --budget) {
    const std::uint64_t i = engine_.applied() + 1;
    if (i > store_.history.size()) break;
    (void)engine_.apply(view(store_.history[i - 1]));
    if (hash_interval_ != 0 && i % hash_interval_ == 0) repl_->on_state_hash(i, engine_.hash());
    did = true;
  }
  did |= poll_gateway();
  return did;
}

// ---- gateway ------------------------------------------------------------------------------

bool HaNode::poll_gateway() {
  bool did = false;
  client_port_.poll([&](const env::StreamEvent& ev) {
    did = true;
    switch (ev.kind) {
      case env::StreamEventKind::Accepted:
        conns_[ev.conn] = Conn{};
        break;
      case env::StreamEventKind::Connected:
        break;
      case env::StreamEventKind::Data: {
        auto it = conns_.find(ev.conn);
        if (it == conns_.end()) break;
        it->second.rx.insert(it->second.rx.end(), ev.data.begin(), ev.data.end());
        break;
      }
      case env::StreamEventKind::Closed: {
        auto it = conns_.find(ev.conn);
        if (it == conns_.end()) break;
        Conn& c = it->second;
        if (c.logged_in) {
          Inbound in;
          in.event = true;
          in.session = c.session;
          in.instance = c.instance;
          in.kind = journal::SessionEventKind::Disconnect;
          const repl::Role r = repl_->role();
          if (repl::is_primary(r) || r == repl::Role::kSoloCandidate) {
            if (inbound_.size() < p_.inbound_cap) inbound_.push_back(in);
          } else if (r == repl::Role::kBackup || r == repl::Role::kCandidate) {
            repl::wire::Forward f;
            f.session_id = c.session;
            f.instance = c.instance;
            f.account = c.session;
            f.kind = repl::wire::ForwardKind::kSessionEvent;
            f.event = static_cast<std::uint8_t>(journal::SessionEventKind::Disconnect);
            (void)repl_->forward(f, node_.clock().now_mono());
          }
        }
        conns_.erase(it);
        break;
      }
    }
  });
  for (auto it = conns_.begin(); it != conns_.end();) {
    const env::ConnId id = it->first;
    Conn& c = it->second;
    // Inbound frames, in order; stop at backpressure.
    std::size_t off = 0;
    bool stop = false;
    bool closed = false;
    while (!stop && c.rx.size() - off >= 2) {
      const std::size_t len = load_le16(c.rx.data() + off);
      if (c.rx.size() - off < 2 + len) break;
      const std::size_t before = off;
      on_frame(id, c, std::span<const std::byte>(c.rx.data() + off + 2, len), stop);
      if (!stop) off += 2 + len;
      if (conns_.find(id) == conns_.end()) {
        closed = true;
        break;
      }
      (void)before;
    }
    if (closed) {
      it = conns_.lower_bound(id);
      continue;
    }
    if (off != 0) {
      c.rx.erase(c.rx.begin(), c.rx.begin() + static_cast<std::ptrdiff_t>(off));
      did = true;
    }
    send_outputs(id, c);
    if (!c.tx.empty()) {
      const std::size_t n = client_port_.write(id, c.tx);
      if (n != 0) {
        c.tx.erase(c.tx.begin(), c.tx.begin() + static_cast<std::ptrdiff_t>(n));
        did = true;
      }
    }
    ++it;
  }
  return did;
}

void HaNode::on_frame(env::ConnId id, Conn& c, std::span<const std::byte> f, bool& stop) {
  if (f.empty()) return;
  const repl::Role r = repl_->role();
  const Nanos now = node_.clock().now_mono();
  const bool primary = repl::is_primary(r) || r == repl::Role::kSoloCandidate;
  const bool mirror = r == repl::Role::kBackup || r == repl::Role::kCandidate;
  if (f[0] == std::byte{'L'} && f.size() == 13) {
    if (c.logged_in) return;
    const std::uint32_t account = load_le32(f.data() + 1);
    const std::uint64_t next = std::max<std::uint64_t>(1, load_le64(f.data() + 5));
    const std::uint16_t inst = new_instance();
    bool ok = false;
    if (primary && r != repl::Role::kSoloCandidate) {
      if (inbound_.size() < p_.inbound_cap) {
        Inbound in;
        in.event = true;
        in.session = account;
        in.instance = inst;
        in.kind = journal::SessionEventKind::Login;
        in.requested_seq = next;
        inbound_.push_back(in);
        ok = true;
      }
    } else if (r == repl::Role::kBackup) {
      // 10 §3 step 5: a login on the mirror port is a second instance (mirror-attach),
      // forwarded to the primary like any inbound.
      repl::wire::Forward fw;
      fw.session_id = account;
      fw.instance = inst;
      fw.account = account;
      fw.kind = repl::wire::ForwardKind::kSessionEvent;
      fw.event = static_cast<std::uint8_t>(journal::SessionEventKind::MirrorAttach);
      fw.requested_seq = next;
      ok = repl_->forward(fw, now) == repl::Replica<Host>::ForwardStatus::kAccepted;
    }
    if (!ok) {
      const std::byte j[] = {std::byte{'J'}};
      (void)frame(c.tx, j);
      (void)client_port_.write(id, c.tx);
      c.tx.clear();
      close_conn(id, c);
      return;
    }
    c.logged_in = true;
    c.session = account;
    c.instance = inst;
    c.next_seq = next;
    return;
  }
  if (f[0] == std::byte{'O'} && f.size() == kToyOrderBytes && c.logged_in) {
    if (primary) {
      if (inbound_.size() >= p_.inbound_cap) {
        stop = true;
        return;
      }
      Inbound in;
      in.session = c.session;
      in.instance = c.instance;
      in.account = c.session;
      std::memcpy(in.msg.data(), f.data(), kToyOrderBytes);
      in.len = static_cast<std::uint16_t>(kToyOrderBytes);
      inbound_.push_back(in);
    } else if (mirror) {
      repl::wire::Forward fw;
      fw.session_id = c.session;
      fw.instance = c.instance;
      fw.account = c.session;
      fw.kind = repl::wire::ForwardKind::kOuch;
      fw.bytes = f;
      const auto st = repl_->forward(fw, now);
      if (st == repl::Replica<Host>::ForwardStatus::kFull) stop = true;
    }
  }
}

void HaNode::send_outputs(env::ConnId id, Conn& c) {
  (void)id;
  if (!c.logged_in) return;
  const SessionStream* s = engine_.session(c.session);
  if (s == nullptr) return;
  const std::uint64_t release = repl_->release_watermark();
  while (c.tx.size() < kMaxTx && c.next_seq < s->next_seq()) {
    const Output* o = s->at(c.next_seq);
    if (o == nullptr && c.next_seq < s->base && snap_base_index_ != 0) {
      // Before the snapshot this engine was loaded from: regenerate from the journal.
      if (!regen_) {
        regen_ = std::make_unique<ToyEngine>();
        for (std::uint64_t i = 1; i <= snap_base_index_ && i <= store_.history.size(); ++i) {
          (void)regen_->apply(view(store_.history[i - 1]));
        }
      }
      const SessionStream* rs = regen_->session(c.session);
      o = rs == nullptr ? nullptr : rs->at(c.next_seq);
    }
    if (o == nullptr || o->source > release) break;
    // Egress ground truth (O-OUTPUT-COMMIT): every output a client can receive derives
    // from a record some primary released under the Output Rule.
    const std::uint32_t crc = crc_of(store_.history[o->source - 1]);
    if (o->source > t_.released.size() || t_.released[o->source - 1] != crc) {
      t_.fail(t_.o_commit, "n" + std::to_string(self_) + " (" + repl::to_string(repl_->role()) +
                               ") sends an output of record " + std::to_string(o->source) +
                               " that no primary released (release watermark " + std::to_string(release) + ")");
      return;
    }
    Bytes payload(9 + o->bytes.size());
    payload[0] = std::byte{'S'};
    store_le64(payload.data() + 1, c.next_seq);
    std::memcpy(payload.data() + 9, o->bytes.data(), o->bytes.size());
    (void)frame(c.tx, payload);
    ++c.next_seq;
  }
}

void HaNode::close_conn(env::ConnId id, Conn& c) {
  (void)c;
  client_port_.close(id);
  conns_.erase(id);
}

}  // namespace lle::sim::ha

#pragma once
// Replica: the hot-standby replication core of one data node (10 §2–§5), sans-I/O.
//
// Inputs are decoded-able datagrams from the peer (data link) and from the witness
// (control), plus poll(now) for timers and sending; every side effect goes through the
// Host (types.h). The core never reads a clock, allocates after construction on the
// hot path, or blocks. It refines verify/tla/HotStandby.tla; the mapping from each
// transition to a spec action is in docs/design/replication.md, and every action is
// reported through Host::trace() for trace validation.
//
// Roles and the rules the model checking established (docs/verification/tla-results.md):
//  P   paired primary. Sequences; streams APPENDs; commit = min(L2 tail, backup ACK);
//      releases at commit. With no ACK progress for T_ack it stops sequencing and
//      releasing, flushes its whole log to L3 and only then sends SOLO (-> SC).
//  SC  waits for the SOLO grant (REJECT: deposed). On GRANT appends EpochStart -> SP.
//  SP  solo primary. Releases at durable_index (L3), once its EpochStart is durable.
//      Serves rejoin: EPOCH_END, catch-up, and relays JOIN at zero lag with sequencing
//      and release paused.
//  B   backup. Validates epoch, index continuity and the CRC chain; appends to its L2;
//      ACKs cumulatively; applies and releases (mirror sessions) up to the announced
//      commit; forwards mirror-session inbound (FORWARD). Without the primary for T_d
//      it freezes (-> C).
//  C   frozen candidate: never ACKs, appends, applies or forwards again. Flushes its
//      whole log to L3, then sends PROMOTE{last_index}. On GRANT (matching incarnation)
//      appends EpochStart right after last_index -> SP.
//  R   recovering after a restart, new incarnation. RESUME is granted only to the solo
//      primary of record; otherwise the witness's REJECT names the primary, and the
//      node rejoins: EPOCH_END truncation by epoch, state reload, catch-up, JOIN.
// A node acts on a GRANT only if the grant's incarnation equals its own. A node that
// learns it was deposed (stale-epoch REJECT, a peer primary in a newer epoch) exits.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "journal/record.h"
#include "repl/types.h"
#include "repl/window.h"
#include "repl/wire.h"
#include "witness/control.h"

namespace lle::repl {

inline constexpr std::size_t kMaxForwardInline = 512;

template <Host H>
class Replica {
 public:
  struct Stats {
    std::uint64_t appends_sent = 0;
    std::uint64_t retransmits = 0;
    std::uint64_t records_received = 0;
    std::uint64_t duplicates = 0;
    std::uint64_t gaps = 0;
    std::uint64_t stale_dropped = 0;
    std::uint64_t frozen_dropped = 0;  // epoch-e APPENDs a candidate refused
    std::uint64_t bad_records = 0;
    std::uint64_t no_room = 0;
    std::uint64_t acks_sent = 0;
    std::uint64_t nacks_sent = 0;
    std::uint64_t witness_requests = 0;
    std::uint64_t grants = 0;
    std::uint64_t rejects = 0;
    std::uint64_t ignored_grants = 0;  // wrong incarnation, request or epoch
    std::uint64_t forwards_sent = 0;
    std::uint64_t forwards_injected = 0;
    std::uint64_t forwards_duplicate = 0;
    std::uint64_t forwards_reinjected = 0;
    std::uint64_t solo_cancelled = 0;
    std::uint64_t truncations = 0;
    std::uint64_t joins = 0;
    std::uint64_t snapshot_chunks = 0;
    std::uint64_t hash_checks = 0;
  };

  enum class ForwardStatus : std::uint8_t { kAccepted, kFull, kNotForwarding, kTooLarge };

  Replica(const Config& cfg, H& host) : cfg_(cfg), h_(host), self_(cfg.self), peer_(cfg.self == 0 ? 1 : 0) {
    LLE_ASSERT(witness::valid_node(cfg.self), "node id");
    LLE_ASSERT(cfg.t_ack < cfg.t_d, "T_ack < T_d (10 §4)");
    stream_.win.init(cfg.window_bytes, cfg.window_records);
    scratch_ = std::make_unique<std::byte[]>(journal::kMaxRecordBytes);
    reasm_ = std::make_unique<std::byte[]>(journal::kMaxRecordBytes);
    dgram_ = std::make_unique<std::byte[]>(wire::kMaxDatagram);
    pack_ = std::make_unique<std::byte[]>(wire::kMaxDatagram);
    fwd_bytes_ = std::make_unique<std::byte[]>(cfg.forward_slots * kMaxForwardInline);
    fwd_q_.resize(cfg.forward_slots);
    canonical_ = std::make_unique<journal::Sealer>();
  }
  Replica(const Replica&) = delete;
  Replica& operator=(const Replica&) = delete;

  // ---- start ------------------------------------------------------------------------

  // Day start (06 §10): both nodes hold the same journal, ending with EpochStart(epoch),
  // and the witness was initialized with {epoch, primary, members {A, B}}.
  void start_paired(std::uint64_t epoch, NodeId primary, std::uint64_t backup_inc, Nanos now) {
    epoch_ = epoch;
    members_ = 0b11;
    primary_ = primary;
    const journal::ChainState t = h_.log_tail();
    last_peer_heard_ = now;
    last_ack_progress_ = now;
    if (primary == self_) {
      peer_inc_ = backup_inc;
      ack_ = t.last_index;
      stream_.reset(ack_, epoch_, peer_inc_, false, now);
      set_role(Role::kPrimary);
    } else {
      // Nothing is mirrored or applied, not even the day-start EpochStart, before the
      // primary announces it has released it: a backup never runs ahead of its primary's
      // releases (a primary that dies before its first release leaves index 1 unreleased,
      // and the new primary releases it first).
      commit_ann_ = 0;
      set_role(Role::kBackup);
    }
  }

  // After a restart and local recovery (06 §7): RECOVERING with this process's incarnation.
  void start_recovering(Nanos now) {
    // Query ids carry the incarnation, so a late EPOCH_END for an earlier process is
    // never taken for an answer to this one's query.
    query_id_ = cfg_.incarnation << 32;
    epoch_ = h_.log_tail().epoch;
    resume_epoch_ = epoch_;
    members_ = 0;
    set_role(Role::kRecovering);
    phase_ = Phase::kAskWitness;
    request_resume(now);
  }

  // ---- inputs -----------------------------------------------------------------------

  void on_peer(std::span<const std::byte> datagram, Nanos now) {
    const auto m = wire::decode(datagram);
    if (!m || role_ == Role::kDeposed || role_ == Role::kNone) return;
    std::visit(
        [&](const auto& x) {
          if (x.from != peer_) return;
          handle(x, now);
        },
        *m);
  }

  void on_witness(std::span<const std::byte> datagram, Nanos now) {
    const auto m = witness::decode(datagram);
    if (!m || role_ == Role::kDeposed || role_ == Role::kNone) return;
    if (const auto* g = std::get_if<witness::Grant>(&*m)) on_grant(*g, now);
    else if (const auto* r = std::get_if<witness::Reject>(&*m)) on_reject(*r, now);
  }

  // Timers and sending. Returns true if anything was done.
  bool poll(Nanos now) {
    if (role_ == Role::kDeposed || role_ == Role::kNone) return false;
    bool did = false;
    if (now >= next_hb_w_) {
      send_witness(witness::Heartbeat{self_, witness_role(), cfg_.incarnation, epoch_});
      next_hb_w_ = now + cfg_.heartbeat_ns;
      did = true;
    }
    if (req_.active && now >= req_.next_at) {
      resend_request(now);
      did = true;
    }
    if (fwd_reinject_ && is_primary(role_) && !es_pending_) reinject_forwards();
    switch (role_) {
      case Role::kPrimary: did |= poll_primary(now); break;
      case Role::kSoloPrimary: did |= poll_solo(now); break;
      case Role::kBackup: did |= poll_backup(now); break;
      case Role::kCandidate: did |= poll_candidate(now); break;
      case Role::kRecovering: did |= poll_recovering(now); break;
      case Role::kSoloCandidate:
      case Role::kDeposed:
      case Role::kNone: break;
    }
    if (role_ != Role::kDeposed) update_release();
    return did;
  }

  // Backup gateway: inbound OUCH bytes or a session event of a mirror-session instance
  // (10 §3). The core numbers it per (session, instance), sends FORWARD and retransmits
  // until the record shows up in the replicated journal. On promotion, whatever is
  // still pending is injected into this node's own sequencer, in order.
  ForwardStatus forward(const wire::Forward& in, Nanos now) {
    if (role_ != Role::kBackup && role_ != Role::kCandidate) return ForwardStatus::kNotForwarding;
    if (in.bytes.size() > kMaxForwardInline) return ForwardStatus::kTooLarge;
    if (fwd_count_ == fwd_q_.size()) return ForwardStatus::kFull;
    const std::uint64_t key = fwd_key(in.session_id, in.instance);
    const std::size_t slot = (fwd_head_ + fwd_count_) % fwd_q_.size();
    FwdEntry& e = fwd_q_[slot];
    e.f = in;
    e.f.from = self_;
    e.f.seq = ++fwd_assigned_[key];
    e.key = key;
    e.done = false;
    e.sent_at = 0;
    e.sent = false;
    std::byte* store = fwd_bytes_.get() + slot * kMaxForwardInline;
    if (!in.bytes.empty()) std::memcpy(store, in.bytes.data(), in.bytes.size());
    e.f.bytes = std::span<const std::byte>(store, in.bytes.size());
    ++fwd_count_;
    if (role_ == Role::kBackup) send_forward(e, now);
    return ForwardStatus::kAccepted;
  }

  // Applier checkpoint: the state hash after applying records 1..index (10 §3, R-07).
  void on_state_hash(std::uint64_t index, std::uint64_t hash) {
    own_hashes_[own_hash_n_++ % own_hashes_.size()] = wire::StateHash{index, hash};
    latest_hash_ = wire::StateHash{index, hash};
    hash_unsent_ = true;
    for (auto& p : peer_hashes_) {
      if (p.index == index && p.index != 0) {
        compare_hash(p);
        p = {};
      }
    }
  }

  // ---- queries (egress, sequencer, applier, gateways) -------------------------------
  [[nodiscard]] Role role() const noexcept { return role_; }
  [[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }
  [[nodiscard]] witness::Members members() const noexcept { return members_; }
  [[nodiscard]] NodeId primary() const noexcept { return primary_; }
  [[nodiscard]] std::uint64_t incarnation() const noexcept { return cfg_.incarnation; }
  // Output Rule: outputs derived from index i may be released iff i <= release_watermark().
  [[nodiscard]] std::uint64_t release_watermark() const noexcept { return release_; }
  [[nodiscard]] std::uint64_t commit_index() const noexcept {
    return role_ == Role::kPrimary ? std::min(h_.log_tail().last_index, ack_) : commit_ann_;
  }
  [[nodiscard]] std::uint64_t backup_ack() const noexcept { return ack_; }
  [[nodiscard]] std::uint64_t frozen_last() const noexcept { return frozen_last_; }
  [[nodiscard]] bool unpromotable() const noexcept { return unpromotable_; }
  // The applier may apply records up to this index.
  [[nodiscard]] std::uint64_t apply_limit() const noexcept {
    const std::uint64_t tail = h_.log_tail().last_index;
    switch (role_) {
      case Role::kPrimary:
      case Role::kSoloPrimary:
      case Role::kSoloCandidate: return tail;
      case Role::kBackup: return std::min(tail, commit_ann_);
      case Role::kCandidate: return apply_frozen_;
      case Role::kRecovering:
        if (!reloaded_) return 0;
        if (snap_rx_.active && !snap_rx_.installed) return base_;
        return std::max(base_, std::min(tail, commit_ann_));
      case Role::kDeposed:
      case Role::kNone: return 0;
    }
    return 0;
  }
  // The sequencer may append new records (10 §4–§5: stopped while losing the backup,
  // until the EpochStart of a new epoch is in the log, and during the JOIN window).
  [[nodiscard]] bool sequencing_allowed() const noexcept {
    if (es_pending_) return false;
    if (role_ == Role::kPrimary) return !losing_;
    if (role_ == Role::kSoloPrimary) return !join_window_;
    return false;
  }
  [[nodiscard]] bool joining() const noexcept { return join_.active; }
  // True during the Host::reload_state call of a RESUME: the node resumes as the solo
  // primary of record, whose journal is the day's history (a joiner's reload instead may
  // hold records its primary has not released, DST-013).
  [[nodiscard]] bool reload_is_resume() const noexcept { return resume_reload_; }
  // The solo primary has relayed a JOIN that the witness may grant (failure-model gating).
  [[nodiscard]] bool join_sent() const noexcept { return join_.active && join_.join_sent; }
  struct JoinView {
    bool active = false;
    bool sent = false;
    bool window = false;
    std::uint64_t acked = 0;
    std::uint64_t inc = 0;
    bool snap_active = false;
    bool snap_done = false;
    std::uint64_t snap_acked = 0;
    std::uint64_t snap_total = 0;
  };
  [[nodiscard]] JoinView join_view() const noexcept {
    return JoinView{join_.active,     join_.join_sent, join_window_,     join_.acked,        join_.inc,
                    join_.snap.active, join_.snap.done, join_.snap.acked, join_.snap.total};
  }
  [[nodiscard]] bool join_window() const noexcept { return join_window_; }
  [[nodiscard]] std::size_t pending_forwards() const noexcept { return fwd_count_; }
  [[nodiscard]] const Stats& stats() const noexcept { return stats_; }

 private:
  enum class Phase : std::uint8_t { kAskWitness, kQueryEpochEnd, kCatchingUp };

  struct Stream {
    RecordWindow win;
    std::uint64_t acked = 0;
    std::uint64_t loaded = 0;
    std::uint64_t send_index = 1;
    std::uint32_t send_offset = 0;
    std::uint64_t traced = 0;  // highest index whose first byte was sent in this stream
    std::uint64_t epoch = 0;
    std::uint64_t target_inc = 0;
    bool catchup = false;
    Nanos last_progress = 0;
    Nanos last_rewind = 0;

    void reset(std::uint64_t base, std::uint64_t ep, std::uint64_t inc, bool cu, Nanos now) {
      win.clear(base + 1);
      acked = base;
      loaded = base;
      send_index = base + 1;
      send_offset = 0;
      traced = base;
      epoch = ep;
      target_inc = inc;
      catchup = cu;
      last_progress = now;
      last_rewind = now;
    }
    void on_ack(std::uint64_t idx, Nanos now) {
      if (idx <= acked) return;
      if (idx > loaded) {
        win.clear(idx + 1);
        loaded = idx;
      } else {
        win.pop_through(idx);
      }
      acked = idx;
      last_progress = now;
      if (send_index <= acked) {
        send_index = acked + 1;
        send_offset = 0;
      }
    }
    void rewind(std::uint64_t idx, Nanos now) {
      idx = std::max(idx, acked + 1);
      if (idx > loaded + 1) return;
      if (idx < send_index || (idx == send_index && send_offset != 0)) {
        send_index = idx;
        send_offset = 0;
      }
      last_rewind = now;
    }
    [[nodiscard]] bool outstanding() const noexcept { return send_index > acked + 1 || send_offset != 0; }
  };

  struct Request {
    bool active = false;
    witness::MsgType type = witness::MsgType::kPromote;
    witness::Message msg;
    std::uint64_t from_epoch = 0;
    Nanos next_at = 0;
    std::uint64_t sends = 0;
  };

  struct SnapTx {
    bool active = false;
    bool done = false;
    std::uint64_t index = 0;
    std::uint64_t total = 0;
    std::uint64_t acked = 0;
    std::uint64_t next = 0;
    Nanos last_progress = 0;
  };

  static constexpr std::uint64_t kNoPartner = ~std::uint64_t{0};

  struct Joiner {
    bool active = false;
    std::uint64_t inc = 0;
    std::uint32_t attempt = 0;
    std::uint64_t acked = 0;
    Nanos last_heard = 0;
    bool join_sent = false;
    std::uint64_t join_last = 0;
    SnapTx snap;
  };

  struct SnapRx {
    bool active = false;
    bool installed = false;
    bool abandoned = false;
    std::uint64_t index = 0;
    std::uint64_t total = 0;
    std::uint64_t have = 0;
  };

  struct FwdEntry {
    wire::Forward f;
    std::uint64_t key = 0;
    bool done = false;
    bool sent = false;
    Nanos sent_at = 0;
  };

  static std::uint64_t fwd_key(std::uint32_t session, std::uint16_t instance) noexcept {
    return (static_cast<std::uint64_t>(session) << 16) | instance;
  }

  // ---- small helpers ----------------------------------------------------------------

  void set_role(Role r) {
    role_ = r;
    // A peer's state hashes are comparable only while both logs are the same history:
    // within one pairing. Any role change may start a different history (a takeover
    // appends its own EpochStart where the old primary had other records).
    peer_hashes_ = {};
    h_.on_role(r, epoch_);
  }

  // Our own checkpoints describe the applier before a reload: forget them.
  void reload_state(std::uint64_t t) {
    own_hashes_ = {};
    latest_hash_ = {};
    hash_unsent_ = false;
    h_.reload_state(t);
  }

  [[nodiscard]] witness::Role witness_role() const noexcept {
    switch (role_) {
      case Role::kPrimary:
      case Role::kSoloCandidate: return witness::Role::kPrimary;
      case Role::kSoloPrimary: return witness::Role::kSoloPrimary;
      case Role::kBackup: return witness::Role::kBackup;
      case Role::kCandidate: return witness::Role::kCandidate;
      default: return witness::Role::kRecovering;
    }
  }

  void trace(TraceKind k, std::uint64_t a = 0, std::uint64_t b = 0, std::uint64_t c = 0) {
    h_.trace(TraceEvent{k, a, b, c});
  }

  void send(const wire::Message& m) {
    const std::size_t n = wire::encode(m, std::span<std::byte>(dgram_.get(), wire::kMaxDatagram));
    LLE_ASSERT(n != 0, "repl: message did not encode");
    h_.send_peer(std::span<const std::byte>(dgram_.get(), n));
  }

  void send_witness(const witness::Message& m) {
    const witness::Encoded e = witness::encode(m);
    h_.send_witness(e.span());
  }

  void request(const witness::Message& m, witness::MsgType type, std::uint64_t from_epoch, Nanos now) {
    req_.active = true;
    req_.type = type;
    req_.msg = m;
    req_.from_epoch = from_epoch;
    req_.sends = 0;
    resend_request(now);
  }

  void resend_request(Nanos now) {
    ++stats_.witness_requests;
    ++req_.sends;
    if (req_.sends == 4 && req_.type == witness::MsgType::kPromote) SIM_PROBE("repl.witness_unreachable_during_promotion", rare);
    send_witness(req_.msg);
    req_.next_at = now + cfg_.witness_retry_ns;
  }

  void depose() {
    if (role_ == Role::kDeposed) return;
    trace(TraceKind::kDeposed, epoch_);
    req_.active = false;
    join_ = {};
    join_window_ = false;
    fwd_count_ = 0;
    set_role(Role::kDeposed);
    h_.deposed();
  }

  void alarm(Alarm a, std::uint64_t detail) { h_.alarm(a, detail); }

  void note_peer_inc(std::uint64_t inc) noexcept {
    if (!peer_inc_seen_ || inc > peer_inc_max_) peer_inc_max_ = inc;
    peer_inc_seen_ = true;
  }

  bool read_record(std::uint64_t index, std::span<const std::byte>& out) {
    const std::uint32_t n = h_.log_read(index, std::span<std::byte>(scratch_.get(), journal::kMaxRecordBytes));
    if (n == 0) return false;
    out = std::span<const std::byte>(scratch_.get(), n);
    return true;
  }

  // Builds and appends EpochStart(epoch, primary) right after the current tail
  // (RecvGrant / Rejoin in the spec). The record is a pure function of the log tail, the
  // epoch, the primary and the configuration (its timestamp is last_ts + 1), so a
  // joiner can reconstruct the EpochStart its primary appends after a JOIN grant
  // byte for byte. Returns false if the log has no room yet.
  bool append_epoch_start(std::uint64_t epoch, NodeId primary) {
    const journal::ChainState t = h_.log_tail();
    LLE_ASSERT(epoch <= 0xFFFF'FFFFu, "epoch exceeds the record field");
    std::array<std::byte, journal::record_bytes_for_payload(16)> buf{};
    const journal::Stamp st{t.last_index + 1, t.last_ts + 1, static_cast<std::uint32_t>(epoch), t.last_crc, 0};
    const journal::EpochStart es{static_cast<std::uint32_t>(epoch), primary, cfg_.config_digest};
    (void)journal::build_record(buf.data(), st, es, *canonical_);
    if (!h_.log_append(std::span<const std::byte>(buf.data(), buf.size()))) return false;
    es_index_ = t.last_index + 1;
    es_crc_ = load_le32(buf.data() + journal::hdr::kCrc);
    return true;
  }

  // ---- witness replies ----------------------------------------------------------------

  void on_grant(const witness::Grant& g, Nanos now) {
    if (g.request == witness::MsgType::kJoin && g.to_node == self_ && g.primary != self_) {
      on_join_admission(g, now);  // W's copy of a JOIN grant, addressed to the joiner
      return;
    }
    if (g.request == witness::MsgType::kJoin && g.to_node == self_) {
      on_join_granted(g.epoch, g.members, g.from_epoch, g.incarnation, now);
      return;
    }
    if (g.to_node != self_ || !req_.active || g.request != req_.type || g.from_epoch != req_.from_epoch) {
      ++stats_.ignored_grants;
      return;
    }
    // A node acts on a GRANT only if it was issued to its own incarnation (10 §2;
    // mutant NoIncarnation).
    if (g.incarnation != cfg_.incarnation) {
      ++stats_.ignored_grants;
      return;
    }
    ++stats_.grants;
    req_.active = false;
    switch (g.request) {
      case witness::MsgType::kPromote:
        if (role_ != Role::kCandidate) return;
        LLE_ASSERT(h_.log_tail().last_index == frozen_last_, "a candidate's log never grows after freezing");
        enter_solo(g, now);
        break;
      case witness::MsgType::kSolo:
        if (role_ != Role::kSoloCandidate) return;
        enter_solo(g, now);
        break;
      case witness::MsgType::kResume:
        if (role_ != Role::kRecovering) return;
        resume_reload_ = true;  // the host's reload is the solo primary of record's
        reload_state(h_.log_tail().last_index);
        resume_reload_ = false;
        reloaded_ = true;
        enter_solo(g, now);
        break;
      default:
        break;
    }
  }

  // W granted one of the JOINs we relayed in this epoch. Its GRANT does not say which,
  // so it is accepted while the JOIN is pending and also after we gave it up: W is in
  // epoch + 1 either way, and only learning that epoch is safe (resuming solo service
  // in the old one could release records a promoted joiner would not have). The partner
  // is the joiner of our only JOIN of the epoch. After a second JOIN in one epoch it is
  // unknown until the backup proves that W's own copy of the grant admitted it (an
  // admitted HEARTBEAT); without that proof we hear no ACK and go solo.
  void on_join_granted(std::uint64_t epoch, witness::Members members, std::uint64_t from_epoch, std::uint64_t inc,
                       Nanos now) {
    if (inc != cfg_.incarnation || role_ != Role::kSoloPrimary || relays_.count == 0 || relays_.epoch != epoch_ ||
        from_epoch != epoch_ || epoch != epoch_ + 1 || members != 0b11) {
      ++stats_.ignored_grants;
      return;
    }
    ++stats_.grants;
    if (!relays_.pending) SIM_PROBE("repl.join_grant_applied_after_giving_up");
    if (req_.active && req_.type == witness::MsgType::kJoin) req_.active = false;
    const std::uint64_t partner = relays_.count == 1 && relays_.pending ? relays_.last_inc : kNoPartner;
    enter_paired_after_join(epoch, members, partner, relays_.last_index, now);
  }

  // A REJECT of a JOIN we relayed in this epoch (10 §5).
  void on_join_rejected(const witness::Reject& r, Nanos now) {
    if (r.incarnation != cfg_.incarnation || role_ != Role::kSoloPrimary || relays_.count == 0 ||
        relays_.epoch != epoch_ || r.from_epoch != epoch_) {
      return;  // not about a JOIN of ours in this epoch
    }
    ++stats_.rejects;
    if (r.epoch == epoch_ && r.primary == self_ && r.members == witness::member_bit(self_)) {
      // W refused a JOIN of ours and has granted none. In this configuration the only
      // reason is a joiner incarnation W knows to be superseded (dead). With one JOIN in
      // the epoch the refusal is its own: give it up and resume solo service. After a
      // second JOIN it may be a late answer to the first, so the latest stays pending
      // (retransmitted, paused) unless its joiner is known dead too: then any grant still
      // to come pairs W with a dead incarnation, which can never take over.
      if (!relays_.pending) return;
      if (relays_.count == 1 || (peer_inc_seen_ && peer_inc_max_ > relays_.last_inc)) {
        relays_.pending = false;
        if (req_.active && req_.type == witness::MsgType::kJoin) req_.active = false;
        abandon_joiner();
        trace(TraceKind::kJoinAbandoned, relays_.last_index);
      }
      return;
    }
    if (r.epoch == epoch_ + 1 && r.primary == self_ && r.members == 0b11) {
      // W moved to epoch + 1 by granting one of our JOINs (as its live solo primary of
      // record, nothing else could) and this is its answer to a later, stale request.
      on_join_granted(r.epoch, r.members, r.from_epoch, r.incarnation, now);
      return;
    }
    depose();  // W moved on without us
  }

  void on_reject(const witness::Reject& r, Nanos now) {
    if (r.to_node == self_ && r.request == witness::MsgType::kJoin) {
      on_join_rejected(r, now);
      return;
    }
    if (r.to_node != self_ || !req_.active || r.request != req_.type || r.from_epoch != req_.from_epoch ||
        r.incarnation != cfg_.incarnation) {
      return;
    }
    ++stats_.rejects;
    switch (r.request) {
      case witness::MsgType::kPromote:
        // The tie-break (W still hears the primary) is the only reason to keep trying:
        // the candidate cannot unfreeze, so it retries until the primary goes solo
        // (stale epoch: deposed) or falls silent (granted).
        if (r.reason == witness::RejectReason::kPrimaryAlive) return;
        depose();
        break;
      case witness::MsgType::kSolo:
        depose();
        break;
      case witness::MsgType::kResume:
        on_resume_rejected(r, now);
        break;
      default:
        break;
    }
  }

  void on_resume_rejected(const witness::Reject& r, Nanos now) {
    if (role_ != Role::kRecovering) return;
    if (phase_ == Phase::kCatchingUp) {
      // A probe after the primary we are joining fell silent (poll_recovering).
      req_.active = false;
      if (r.primary == primary_ && r.epoch == catchup_epoch_ + 1 && r.members == 0b11) {
        // W has paired us with the primary we were joining: its JOIN for us was granted
        // and neither the primary's relay nor W's copy of the grant reached us. If it
        // named an earlier incarnation of ours instead, our PROMOTE will be refused for
        // the wrong incarnation and we exit (the witness, not this guess, is the safety).
        SIM_PROBE("repl.joiner_learns_admission_from_reject");
        become_backup_after_join(r.epoch, now);
        return;
      }
      if (r.primary == primary_ && r.epoch == catchup_epoch_) {
        last_primary_heard_ = now;  // no JOIN yet: keep catching up
        return;
      }
    }
    if (r.primary == self_) {
      if (r.members == witness::member_bit(self_)) {
        if (r.reason == witness::RejectReason::kStaleEpoch && r.epoch != resume_epoch_) {
          // The solo primary of record restarted with a stale view of the epoch (its
          // GRANT was lost, or the EpochStart did not reach L3). Only it can be granted
          // anything in this configuration, so it adopts W's epoch and asks again.
          SIM_PROBE("repl.resume_adopted_epoch");
          resume_epoch_ = r.epoch;
          epoch_ = r.epoch;
          trace(TraceKind::kAdoptEpoch, r.epoch);
          request_resume(now);
          return;
        }
        if (r.reason == witness::RejectReason::kWrongIncarnation) alarm(Alarm::kIncarnationRegressed, r.epoch);
      }
      // A paired configuration whose primary restarted: the backup takes over once W no
      // longer hears our old incarnation (tie-break); keep asking to learn the outcome.
      req_.active = true;
      return;
    }
    primary_ = r.primary;
    req_.active = false;
    start_rejoin(now);
  }

  void request_resume(Nanos now) {
    trace(TraceKind::kRequestResume, resume_epoch_);
    request(witness::Resume{resume_epoch_, self_, cfg_.incarnation}, witness::MsgType::kResume, resume_epoch_, now);
  }

  // PROMOTE, SOLO and RESUME grants make this node the solo primary of a new epoch.
  void enter_solo(const witness::Grant& g, Nanos now) {
    epoch_ = g.epoch;
    members_ = g.members;
    primary_ = self_;
    grant_type_ = g.request;
    es_pending_ = true;
    losing_ = false;
    join_ = {};
    join_window_ = false;
    relays_ = {};
    fwd_next_.clear();
    last_peer_heard_ = now;
    set_role(Role::kSoloPrimary);
    try_finish_grant();
  }

  void enter_paired_after_join(std::uint64_t epoch, witness::Members members, std::uint64_t partner,
                               std::uint64_t acked, Nanos now) {
    ++stats_.joins;
    epoch_ = epoch;
    members_ = members;
    primary_ = self_;
    grant_type_ = witness::MsgType::kJoin;
    peer_inc_ = partner;
    ack_ = acked;
    es_pending_ = true;
    losing_ = false;
    abandon_joiner();  // a catch-up session of another joiner, if any, ends with the epoch
    relays_ = {};
    fwd_next_.clear();
    last_peer_heard_ = now;
    last_ack_progress_ = now;
    stream_.reset(ack_, epoch_, peer_inc_, false, now);
    set_role(Role::kPrimary);
    try_finish_grant();
  }

  // Appends the epoch's EpochStart record (retried by poll while the log is full).
  void try_finish_grant() {
    if (!es_pending_ || !append_epoch_start(epoch_, self_)) return;
    es_pending_ = false;
    release_gate_ = es_index_;
    trace(TraceKind::kGrantApplied, epoch_, static_cast<std::uint64_t>(grant_type_), es_index_);
    h_.request_flush();
    if (grant_type_ == witness::MsgType::kPromote || grant_type_ == witness::MsgType::kSolo) {
      // 10 §4 step 5: the old partner's session instances are down.
      h_.instance_down(peer_);
    }
    if (grant_type_ == witness::MsgType::kPromote) {
      fwd_reinject_ = true;  // our own mirror-session input that the old primary never committed
    } else {
      fwd_count_ = 0;
    }
  }

  // ---- data-plane handlers ------------------------------------------------------------

  void handle(const wire::Append& a, Nanos now) {
    if (a.catchup) {
      if (role_ != Role::kRecovering || phase_ != Phase::kCatchingUp || a.target_inc != cfg_.incarnation ||
          a.epoch != catchup_epoch_) {
        ++stats_.stale_dropped;
        return;
      }
      last_primary_heard_ = now;
      commit_ann_ = std::max(commit_ann_, a.commit_index);
      receive_records(a, true, now);
      return;
    }
    switch (role_) {
      case Role::kBackup:
        if (a.epoch < epoch_) {
          ++stats_.stale_dropped;
          return;
        }
        if (a.epoch > epoch_) {
          depose();
          return;
        }
        if (a.target_inc != cfg_.incarnation) {
          ++stats_.stale_dropped;
          return;
        }
        last_peer_heard_ = now;
        note_commit(a.commit_index);
        if (a.has_hash) peer_hash(a.hash);
        receive_records(a, false, now);
        return;
      case Role::kCandidate:
        if (a.epoch == epoch_) {
          // 10 §4 step 1: frozen. Never accepted, never acknowledged (mutant AckWhileCandidate).
          SIM_PROBE("repl.candidate_append_after_freeze");
          ++stats_.frozen_dropped;
        } else if (a.epoch > epoch_) {
          depose();
        }
        return;
      case Role::kRecovering:
        if (joinable() && a.epoch == catchup_epoch_ + 1 && a.target_inc == cfg_.incarnation) {
          if (!become_backup_after_join(a.epoch, now)) return;
          note_commit(a.commit_index);
          receive_records(a, false, now);
        } else {
          ++stats_.stale_dropped;
        }
        return;
      case Role::kPrimary:
      case Role::kSoloPrimary:
      case Role::kSoloCandidate:
        if (a.epoch > epoch_) depose();
        else ++stats_.stale_dropped;
        return;
      default:
        return;
    }
  }

  void handle(const wire::Ack& k, Nanos now) {
    note_peer_inc(k.inc);
    if (k.catchup) {
      if (role_ != Role::kSoloPrimary || !join_.active || k.inc != join_.inc || k.epoch != epoch_) return;
      join_.last_heard = now;
      if (k.l2_index > join_.acked && k.l2_index <= h_.log_tail().last_index) {
        join_.acked = k.l2_index;
        stream_.on_ack(k.l2_index, now);
      }
      SnapTx& s = join_.snap;
      if (s.active && k.snap_index == s.index && k.snap_offset > s.acked && k.snap_offset <= s.total) {
        s.acked = k.snap_offset;
        s.last_progress = now;
        if (s.next < s.acked) s.next = s.acked;
        if (s.acked == s.total && !s.done) {
          s.done = true;
          h_.snapshot_release();
        }
      }
      return;
    }
    if (role_ != Role::kPrimary || k.epoch != epoch_ || k.inc != peer_inc_) {
      ++stats_.stale_dropped;
      return;
    }
    last_peer_heard_ = now;
    if (k.l2_index <= ack_ || k.l2_index > h_.log_tail().last_index) return;
    ack_ = k.l2_index;
    last_ack_progress_ = now;
    stream_.on_ack(ack_, now);
    trace(TraceKind::kRecvAck, ack_);
    if (losing_) {
      // The backup came back before SOLO was sent: resume paired service (the spec's P
      // may still RecvAck; only RequestSolo is irrevocable).
      losing_ = false;
      ++stats_.solo_cancelled;
      SIM_PROBE("repl.solo_cancelled");
      trace(TraceKind::kSoloCancelled);
    }
  }

  void handle(const wire::Nack& n, Nanos now) {
    if (n.catchup) {
      if (role_ == Role::kSoloPrimary && join_.active && n.inc == join_.inc && n.epoch == epoch_) {
        join_.last_heard = now;
        maybe_rewind(n.expected_index, now);
      }
      return;
    }
    if (role_ != Role::kPrimary || n.epoch != epoch_ || n.inc != peer_inc_) return;
    last_peer_heard_ = now;
    maybe_rewind(n.expected_index, now);
  }

  void maybe_rewind(std::uint64_t expected, Nanos now) {
    if (now - stream_.last_rewind < cfg_.rto_ns / 4) return;
    if (expected > stream_.acked && expected <= stream_.loaded + 1) {
      ++stats_.retransmits;
      stream_.rewind(expected, now);
    }
  }

  void handle(const wire::Heartbeat& hb, Nanos now) {
    if (hb.build_id != cfg_.build_id) {
      // Build-ID handshake (10 §3, R-07): the nodes must run the same artifact.
      if (!build_alarmed_) alarm(Alarm::kBuildMismatch, hb.build_id);
      build_alarmed_ = true;
      if (role_ == Role::kBackup || role_ == Role::kCandidate || role_ == Role::kRecovering) unpromotable_ = true;
    }
    note_peer_inc(hb.inc);
    const bool peer_primary = hb.role == static_cast<std::uint8_t>(Role::kPrimary) ||
                              hb.role == static_cast<std::uint8_t>(Role::kSoloPrimary);
    switch (role_) {
      case Role::kPrimary:
        if (peer_inc_ == kNoPartner && hb.admitted && hb.epoch == epoch_ &&
            hb.role == static_cast<std::uint8_t>(Role::kBackup) && !losing_) {
          // We could not tell which of our JOINs W granted; W's own copy of the grant
          // admitted this backup incarnation, so it is the one W recorded.
          SIM_PROBE("repl.primary_pairs_on_admission_proof");
          peer_inc_ = hb.inc;
          stream_.reset(ack_, epoch_, peer_inc_, false, now);
          last_ack_progress_ = now;
        }
        if (hb.epoch == epoch_ && hb.inc == peer_inc_) {
          last_peer_heard_ = now;
          if (hb.hash.index != 0) peer_hash(hb.hash);
        } else if (hb.epoch > epoch_ && peer_primary) {
          depose();
        }
        return;
      case Role::kBackup:
        if (hb.epoch == epoch_ && peer_primary && hb.partner_inc == cfg_.incarnation) {
          last_peer_heard_ = now;
          note_commit(hb.commit);
          if (hb.hash.index != 0) peer_hash(hb.hash);
        } else if (hb.epoch > epoch_ && peer_primary) {
          depose();
        }
        return;
      case Role::kRecovering:
        if (joinable() && peer_primary) {
          if (hb.epoch == catchup_epoch_ + 1 && hb.role == static_cast<std::uint8_t>(Role::kPrimary) &&
              hb.partner_inc == cfg_.incarnation) {
            become_backup_after_join(hb.epoch, now);
            note_commit(hb.commit);
          } else if (hb.epoch == catchup_epoch_) {
            last_primary_heard_ = now;
          }
        }
        return;
      case Role::kCandidate:
      case Role::kSoloCandidate:
      case Role::kSoloPrimary:
        if (hb.epoch > epoch_ && peer_primary) depose();
        return;
      default:
        return;
    }
  }

  void handle(const wire::Forward& f, Nanos now) {
    if (role_ != Role::kPrimary || f.epoch != epoch_ || f.inc != peer_inc_) {
      ++stats_.stale_dropped;
      return;
    }
    last_peer_heard_ = now;
    std::uint64_t& next = fwd_next_.try_emplace(fwd_key(f.session_id, f.instance), 1).first->second;
    if (f.seq < next) {
      ++stats_.forwards_duplicate;
      return;
    }
    // In order only: a gap waits for the backup's retransmission.
    if (f.seq > next || !sequencing_allowed()) return;
    if (h_.inject_inbound(f)) {
      ++next;
      ++stats_.forwards_injected;
    }
  }

  void handle(const wire::EpochEndQuery& q, Nanos now) {
    (void)now;
    note_peer_inc(q.inc);
    wire::EpochEnd r;
    r.from = self_;
    r.query_epoch = q.epoch;
    r.query_id = q.query_id;
    r.primary_epoch = epoch_;
    r.tail = h_.log_tail().last_index;
    if (!is_primary(role_) || es_pending_ || q.build_id != cfg_.build_id) {
      if (q.build_id != cfg_.build_id) alarm(Alarm::kBuildMismatch, q.build_id);
      r.refused = true;
    } else {
      const EpochEndInfo info = h_.log_epoch_end(q.epoch);
      r.end_index = info.index;
      r.end_crc = info.crc;
      r.end_epoch = info.epoch;
      const EpochEndInfo start = h_.log_epoch_start(info.epoch);
      r.start_index = start.index;
      r.start_crc = start.crc;
      trace(TraceKind::kEpochEndAnswer, q.inc);
    }
    send(r);
  }

  void handle(const wire::EpochEnd& e, Nanos now) {
    if (role_ != Role::kRecovering) return;
    if (phase_ == Phase::kCatchingUp && e.refused && e.query_id == 0) {
      // A refused CATCHUP_REQ. query_epoch names the session it refused.
      if (e.query_epoch != catchup_epoch_) return;  // an earlier session's, delivered late
      if (e.primary_epoch != catchup_epoch_) {
        // Our session belongs to a handshake with an earlier epoch of the primary (it
        // restarted or moved on): hand-shake again.
        start_rejoin(now);
        return;
      }
      // The primary could not find our catch-up point on its history although the
      // epoch-based truncation point verified: resynchronize from the beginning.
      alarm(Alarm::kDiverged, h_.log_tail().last_index);
      if (!h_.log_truncate(0)) {
        depose();
        return;
      }
      ++stats_.truncations;
      trace(TraceKind::kTruncate, 0);
      reload_state(0);
      base_ = 0;
      ++attempt_;
      commit_ann_ = 0;
      snap_rx_ = {};
      send_catchup_req(now);
      return;
    }
    if (phase_ != Phase::kQueryEpochEnd || e.query_id != query_id_) return;
    if (e.refused) {
      phase_ = Phase::kAskWitness;
      request_resume(now);
      return;
    }
    const journal::ChainState tail = h_.log_tail();
    if (e.end_index != 0 && e.end_epoch < e.query_epoch) {
      // KIP-279: the primary holds no record of our last epoch, so none of our records
      // with an epoch above end_epoch is in its history. Drop them and ask again with
      // the epoch we are left with.
      const EpochEndInfo mine = h_.log_epoch_end(e.end_epoch);
      if (mine.index < tail.last_index) {
        SIM_PROBE("repl.rejoin_truncates_newer_epochs");
        ++stats_.truncations;
        if (!h_.log_truncate(mine.index)) {
          depose();
          return;
        }
        trace(TraceKind::kTruncate, mine.index);
      }
      send_epoch_end_query(now);
      return;
    }
    if (e.end_index != 0) {
      // Records of one epoch form one run, written by that epoch's primary from its
      // EpochStart on. If our run of this epoch does not start where the primary's does
      // (a reconstructed EpochStart that no grant made real), none of it is the
      // primary's: drop it and ask again.
      const EpochEndInfo mine = h_.log_epoch_start(e.end_epoch);
      if (mine.index != 0 && (mine.index != e.start_index || mine.crc != e.start_crc)) {
        SIM_PROBE("repl.rejoin_drops_foreign_epoch_run");
        ++stats_.truncations;
        if (!h_.log_truncate(mine.index - 1)) {
          depose();
          return;
        }
        trace(TraceKind::kTruncate, mine.index - 1);
        send_epoch_end_query(now);
        return;
      }
    }
    std::uint64_t t = std::min(tail.last_index, e.end_index);
    if (t == e.end_index && t != 0) {
      // Verify the epoch-based truncation point: the record there must be the primary's.
      std::span<const std::byte> rec;
      if (!read_record(t, rec) || load_le32(rec.data() + journal::hdr::kCrc) != e.end_crc) {
        alarm(Alarm::kDiverged, t);
        t = 0;
      }
    }
    if (t < tail.last_index) {
      // 10 §5 step 2: drop the divergent tail (epoch-based, KIP-101), L2 and L3.
      SIM_PROBE("repl.rejoin_truncates_divergent_tail", rare);
      ++stats_.truncations;
      if (!h_.log_truncate(t)) {
        depose();
        return;
      }
      trace(TraceKind::kTruncate, t);
    }
    // 10 §5 step 3: engine state from a snapshot at or below t, replayed to t.
    reload_state(t);
    reloaded_ = true;
    base_ = t;
    ++attempt_;
    catchup_epoch_ = e.primary_epoch;
    commit_ann_ = 0;
    snap_rx_ = {};
    phase_ = Phase::kCatchingUp;
    last_primary_heard_ = now;
    send_catchup_req(now);
  }

  void handle(const wire::CatchupReq& c, Nanos now) {
    note_peer_inc(c.inc);
    if (role_ != Role::kSoloPrimary || es_pending_) return;
    if (c.build_id != cfg_.build_id) {
      alarm(Alarm::kBuildMismatch, c.build_id);
      return;
    }
    if (c.epoch != epoch_) {
      // A session opened by a handshake with another epoch of ours: we restarted (a host
      // crash may have taken records the joiner already copied) or moved on (a JOIN, a
      // SOLO). Our history since then is not what the joiner's handshake saw, so it
      // must hand-shake again; this is not a divergence. The refusal names the session
      // (query_epoch), so a late one cannot be taken for a refusal of a newer session.
      wire::EpochEnd r;
      r.from = self_;
      r.refused = true;
      r.query_epoch = c.epoch;
      r.primary_epoch = epoch_;
      send(r);
      return;
    }
    const journal::ChainState tail = h_.log_tail();
    if (c.from_index == 0 || c.from_index - 1 > tail.last_index) return;
    const std::uint64_t prev = c.from_index - 1;
    std::uint32_t crc = 0;
    if (prev != 0) {
      std::span<const std::byte> rec;
      if (!read_record(prev, rec)) return;
      crc = load_le32(rec.data() + journal::hdr::kCrc);
    }
    if (crc != c.prev_crc) {
      // The joiner's truncation point is not on our history: make it start over.
      alarm(Alarm::kDiverged, prev);
      wire::EpochEnd r;
      r.from = self_;
      r.refused = true;
      r.query_epoch = c.epoch;
      r.primary_epoch = epoch_;
      send(r);
      return;
    }
    // One session per joiner attempt: a reordered, older CATCHUP_REQ of the same attempt
    // only reports progress; a new attempt (after a reload or resync) starts over.
    if (join_.active && join_.inc == c.inc && (join_.join_sent || c.attempt <= join_.attempt)) {
      join_.last_heard = now;
      if (prev > join_.acked) {
        join_.acked = prev;
        stream_.on_ack(prev, now);
      }
      if (!join_.join_sent) maybe_rewind(c.from_index, now);
      return;
    }
    if (join_.active && join_.join_sent) return;  // a JOIN is in flight for another incarnation
    // A new joiner, or ours starting over from an earlier point.
    abandon_joiner();
    join_.active = true;
    join_.inc = c.inc;
    join_.attempt = c.attempt;
    join_.acked = prev;
    join_.last_heard = now;
    stream_.reset(prev, epoch_, c.inc, true, now);
    if (tail.last_index - prev > cfg_.snapshot_threshold) {
      const SnapshotOffer offer = h_.snapshot_offer();
      if (offer.bytes != 0 && offer.index > prev) {
        SIM_PROBE("repl.snapshot_catchup");
        join_.snap = SnapTx{true, false, offer.index, offer.bytes, 0, 0, now};
      }
    }
  }

  void handle(const wire::SnapshotChunk& s, Nanos now) {
    if (role_ != Role::kRecovering || phase_ != Phase::kCatchingUp || s.inc != cfg_.incarnation ||
        s.epoch != catchup_epoch_) {
      return;
    }
    last_primary_heard_ = now;
    if (!snap_rx_.active || snap_rx_.index != s.snap_index) {
      if (snap_rx_.installed) {
        // Already loaded a snapshot in this attempt: tell the primary this one is done.
        wire::Ack k;
        k.from = self_;
        k.catchup = true;
        k.epoch = catchup_epoch_;
        k.l2_index = h_.log_tail().last_index;
        k.inc = cfg_.incarnation;
        k.snap_index = s.snap_index;
        k.snap_offset = s.total;
        send(k);
        return;
      }
      if (s.offset != 0) return;
      snap_rx_ = SnapRx{true, false, false, s.snap_index, s.total, 0};
    }
    if (!snap_rx_.abandoned && !snap_rx_.installed && s.offset == snap_rx_.have) {
      ++stats_.snapshot_chunks;
      if (h_.snapshot_receive(s.snap_index, s.total, s.offset, s.bytes)) {
        snap_rx_.have += s.bytes.size();
      } else {
        snap_rx_.abandoned = true;
      }
      if (snap_rx_.have == snap_rx_.total) {
        if (h_.snapshot_install()) {
          snap_rx_.installed = true;
        } else {
          alarm(Alarm::kSnapshotInvalid, s.snap_index);
          snap_rx_.abandoned = true;
        }
      }
    }
    if (snap_rx_.abandoned) {
      // Fall back to replaying the (complete) journal; tell the primary to stop.
      snap_rx_.installed = true;
      snap_rx_.have = snap_rx_.total;
    }
    send_ack(true);
  }

  // ---- record reception ----------------------------------------------------------------

  void receive_records(const wire::Append& a, bool catchup, Nanos now) {
    std::uint64_t next = h_.log_tail().last_index + 1;
    bool appended = false;
    bool dup = false;
    bool gap = false;
    const bool fragment = a.first_offset != 0 || a.records.size() < a.first_len;
    if (fragment) {
      if (a.first_index < next) {
        dup = true;
      } else if (a.first_index > next) {
        gap = true;
      } else {
        if (reasm_index_ != next || a.first_offset == 0) {
          reasm_index_ = next;
          reasm_have_ = 0;
        }
        if (a.first_offset == reasm_have_) {
          std::memcpy(reasm_.get() + reasm_have_, a.records.data(), a.records.size());
          reasm_have_ += static_cast<std::uint32_t>(a.records.size());
          if (reasm_have_ == a.first_len) {
            appended = accept_record(std::span<const std::byte>(reasm_.get(), a.first_len), a.epoch, catchup);
            reasm_have_ = 0;
            reasm_index_ = 0;
          }
        } else if (a.first_offset < reasm_have_) {
          dup = true;
        } else {
          gap = true;
        }
      }
    } else {
      std::uint64_t idx = a.first_index;
      for (std::size_t off = 0; off < a.records.size(); ++idx) {
        const std::uint32_t len = load_le32(a.records.data() + off + journal::hdr::kLen);
        const std::span<const std::byte> rec = a.records.subspan(off, len);
        off += len;
        if (idx < next) {
          dup = true;
          continue;
        }
        if (idx > next) {
          gap = true;
          break;
        }
        reasm_have_ = 0;
        reasm_index_ = 0;
        if (!accept_record(rec, a.epoch, catchup)) break;
        appended = true;
        ++next;
      }
    }
    if (dup) ++stats_.duplicates;
    if (appended || (dup && now - last_ack_sent_ >= cfg_.rto_ns / 4)) {
      send_ack(catchup);
      last_ack_sent_ = now;
    }
    if (gap) {
      ++stats_.gaps;
      if (now - last_nack_sent_ >= cfg_.rto_ns / 4) {
        ++stats_.nacks_sent;
        send(wire::Nack{self_, catchup, catchup ? catchup_epoch_ : epoch_, h_.log_tail().last_index + 1,
                        cfg_.incarnation});
        last_nack_sent_ = now;
      }
    }
  }

  // Validates one replicated record against the local chain and appends it to L2
  // (10 §3 step 2): structure, canonical seal, index continuity, prev_crc, epochs.
  bool accept_record(std::span<const std::byte> rec, std::uint64_t msg_epoch, bool catchup) {
    const journal::ChainState t = h_.log_tail();
    const auto v = journal::parse_record(rec);
    const bool ok = v && v->len() == rec.size() && v->type() != journal::RecordType::Pad &&
                    v->index() == t.last_index + 1 && v->crc() == v->content() && v->prev_crc() == t.last_crc &&
                    v->epoch() >= t.epoch && v->epoch() <= msg_epoch;
    if (!ok) {
      ++stats_.bad_records;
      alarm(Alarm::kBadRecord, t.last_index + 1);
      return false;
    }
    if (!h_.log_append(rec)) {
      ++stats_.no_room;
      return false;
    }
    ++stats_.records_received;
    trace(catchup ? TraceKind::kCatchupAppend : TraceKind::kRecvAppend, v->index(), v->crc());
    if (!catchup && role_ == Role::kBackup) note_sequenced(*v);
    return true;
  }

  void send_ack(bool catchup) {
    ++stats_.acks_sent;
    wire::Ack k;
    k.from = self_;
    k.catchup = catchup;
    k.epoch = catchup ? catchup_epoch_ : epoch_;
    k.l2_index = h_.log_tail().last_index;
    k.inc = cfg_.incarnation;
    if (catchup && snap_rx_.active) {
      k.snap_index = snap_rx_.index;
      k.snap_offset = snap_rx_.have;
    }
    send(k);
  }

  void note_commit(std::uint64_t c) {
    const std::uint64_t tail = h_.log_tail().last_index;
    c = std::min(c, tail);
    if (c > commit_ann_) commit_ann_ = c;
  }

  // ---- forwarding bookkeeping (backup side) -------------------------------------------

  void send_forward(FwdEntry& e, Nanos now) {
    e.f.epoch = epoch_;
    e.f.inc = cfg_.incarnation;
    e.sent = true;
    e.sent_at = now;
    ++stats_.forwards_sent;
    send(e.f);
  }

  // A replicated record for one of our forwarded (session, instance) streams: the k-th
  // such record is our k-th FORWARD, because the primary sequences each stream in order.
  void note_sequenced(const journal::RecordView& v) {
    if (fwd_assigned_.empty()) return;
    std::uint32_t session = 0;
    std::uint16_t instance = 0;
    if (v.type() == journal::RecordType::OuchInbound && v.payload().size() >= journal::OuchInbound::kHeadBytes) {
      session = load_le32(v.payload().data());
      instance = load_le16(v.payload().data() + 8);
    } else if (v.type() == journal::RecordType::SessionEvent && v.payload().size() >= 16) {
      session = load_le32(v.payload().data());
      instance = load_le16(v.payload().data() + 4);
    } else {
      return;
    }
    const std::uint64_t key = fwd_key(session, instance);
    if (fwd_assigned_.find(key) == fwd_assigned_.end()) return;
    const std::uint64_t seen = ++fwd_seen_[key];
    for (std::size_t i = 0; i < fwd_count_; ++i) {
      FwdEntry& e = fwd_q_[(fwd_head_ + i) % fwd_q_.size()];
      if (!e.done && e.key == key && e.f.seq <= seen) e.done = true;
    }
    pop_done_forwards();
  }

  void pop_done_forwards() {
    while (fwd_count_ != 0 && fwd_q_[fwd_head_].done) {
      fwd_head_ = (fwd_head_ + 1) % fwd_q_.size();
      --fwd_count_;
    }
  }

  // After a promotion: our own pending mirror-session input goes straight to our
  // sequencer, in order. Retried while the sequencer queue is full.
  void reinject_forwards() {
    while (fwd_count_ != 0) {
      FwdEntry& e = fwd_q_[fwd_head_];
      if (!e.done) {
        if (!h_.inject_inbound(e.f)) return;
        ++stats_.forwards_reinjected;
      }
      fwd_head_ = (fwd_head_ + 1) % fwd_q_.size();
      --fwd_count_;
    }
    fwd_reinject_ = false;
  }

  // ---- state hashes (R-07) --------------------------------------------------------------

  void peer_hash(const wire::StateHash& p) {
    for (const auto& o : own_hashes_) {
      if (o.index == p.index && o.index != 0) {
        compare_hash(p);
        return;
      }
    }
    peer_hashes_[peer_hash_n_++ % peer_hashes_.size()] = p;
  }

  void compare_hash(const wire::StateHash& p) {
    for (const auto& o : own_hashes_) {
      if (o.index != p.index || o.index == 0) continue;
      ++stats_.hash_checks;
      if (o.hash != p.hash) {
        if (!unpromotable_ && role_ != Role::kPrimary && role_ != Role::kSoloPrimary) unpromotable_ = true;
        alarm(Alarm::kStateHashMismatch, p.index);
      }
      return;
    }
  }

  // ---- role pollers ---------------------------------------------------------------------

  bool poll_primary(Nanos now) {
    bool did = false;
    if (es_pending_) try_finish_grant();
    const journal::ChainState tail = h_.log_tail();
    if (ack_ >= tail.last_index) last_ack_progress_ = now;
    if (!losing_ && !es_pending_ &&
        (now - last_peer_heard_ > cfg_.t_ack || now - last_ack_progress_ > cfg_.t_ack)) {
      // 10 §4 backup loss: stop releasing and sequencing, flush everything to L3.
      losing_ = true;
      h_.request_flush();
      did = true;
    }
    if (losing_) {
      if (h_.durable_index() >= tail.last_index) {
        set_role(Role::kSoloCandidate);
        trace(TraceKind::kRequestSolo, epoch_);
        request(witness::Solo{epoch_, self_, cfg_.incarnation}, witness::MsgType::kSolo, epoch_, now);
        return true;
      }
      h_.request_flush();
    }
    // Announce what is released, not just committed: the backup's mirror sessions and
    // its applier then never run ahead of the primary's own Output Rule.
    update_release();
    if (peer_inc_ != kNoPartner) did |= pump_stream(now, release_);
    if (now >= next_hb_) {
      send_heartbeat(peer_inc_);
      next_hb_ = now + cfg_.heartbeat_ns;
      did = true;
    }
    return did;
  }

  bool poll_solo(Nanos now) {
    bool did = false;
    if (es_pending_) {
      try_finish_grant();
      if (es_pending_) return false;
      did = true;
    }
    if (!join_.active) return did;
    const journal::ChainState tail = h_.log_tail();
    if (!join_.join_sent && now - join_.last_heard > cfg_.t_ack) {
      abandon_joiner();
      return true;
    }
    did |= pump_snapshot(now);
    did |= pump_stream(now, release_);
    if (now >= next_hb_) {
      send_heartbeat(0);
      next_hb_ = now + cfg_.heartbeat_ns;
      did = true;
    }
    const bool snap_ready = !join_.snap.active || join_.snap.done;
    if (!join_window_ && snap_ready && tail.last_index - join_.acked <= cfg_.join_lag_records) {
      // 10 §5 step 5: pause sequencing and drain the joiner to zero lag. Release goes on
      // until it reaches the tail: a joiner applies only what we have released, so its
      // L2 must otherwise hold everything between our release and our tail, and a disk
      // stall that holds our durable index back while we sequence can make that more
      // than its L2 holds. Frozen there, it never reached zero lag (DST-009).
      join_window_ = true;
      did = true;
    }
    // The JOIN leaves only when the joiner holds our whole log and everything in it is
    // released: from the JOIN on we neither sequence nor release (HotStandby's atomic
    // Rejoin, with the primary paused), and nothing is left that we would have to.
    if (join_window_ && !join_.join_sent && release_ < tail.last_index && h_.durable_index() < tail.last_index) {
      h_.request_flush();  // the tail must be durable to be released before the JOIN
    }
    if (join_window_ && !join_.join_sent && join_.acked == tail.last_index && release_ == tail.last_index) {
      join_.join_sent = true;
      join_.join_last = tail.last_index;
      if (relays_.epoch != epoch_) relays_ = Relays{epoch_, 0, 0, 0, false};
      ++relays_.count;
      relays_.last_inc = join_.inc;
      relays_.last_index = tail.last_index;
      relays_.pending = true;
      trace(TraceKind::kRequestJoin, epoch_, tail.last_index, join_.inc);
      request(witness::Join{epoch_, self_, peer_, cfg_.incarnation, join_.inc, tail.last_index}, witness::MsgType::kJoin,
              epoch_, now);
      did = true;
    }
    return did;
  }

  bool poll_backup(Nanos now) {
    bool did = false;
    if (now - last_peer_heard_ > cfg_.t_d) {
      if (unpromotable_) {
        if (!suspect_alarmed_) alarm(Alarm::kUnpromotableSuspect, epoch_);
        suspect_alarmed_ = true;
      } else {
        freeze();
        return true;
      }
    }
    for (std::size_t i = 0; i < fwd_count_; ++i) {
      FwdEntry& e = fwd_q_[(fwd_head_ + i) % fwd_q_.size()];
      if (!e.done && (!e.sent || now - e.sent_at >= cfg_.forward_retry_ns)) {
        if (e.sent) SIM_PROBE("repl.forward_retransmit");
        send_forward(e, now);
        did = true;
      }
    }
    if (now >= next_hb_) {
      send_heartbeat(0);
      next_hb_ = now + cfg_.heartbeat_ns;
      did = true;
    }
    return did;
  }

  // 10 §4 step 1: stop accepting and acknowledging epoch-e APPENDs, stop applying and
  // forwarding; last_index is fixed from here on.
  void freeze() {
    frozen_last_ = h_.log_tail().last_index;
    apply_frozen_ = std::min(frozen_last_, commit_ann_);
    promote_sent_ = false;
    set_role(Role::kCandidate);
    trace(TraceKind::kFreeze, frozen_last_);
    h_.request_flush();
  }

  bool poll_candidate(Nanos now) {
    if (promote_sent_) return false;
    // 10 §4 step 2: the whole log on L3 before PROMOTE.
    if (h_.durable_index() >= frozen_last_) {
      promote_sent_ = true;
      trace(TraceKind::kRequestPromote, epoch_, frozen_last_);
      request(witness::Promote{epoch_, self_, cfg_.incarnation, frozen_last_}, witness::MsgType::kPromote, epoch_, now);
      return true;
    }
    h_.request_flush();
    return false;
  }

  bool poll_recovering(Nanos now) {
    switch (phase_) {
      case Phase::kAskWitness:
        return false;
      case Phase::kQueryEpochEnd:
        if (now >= next_rejoin_at_) {
          resend_epoch_end_query(now);
          return true;
        }
        return false;
      case Phase::kCatchingUp:
        if (now - last_primary_heard_ > cfg_.t_d && !req_.active) {
          // Silent primary: ask the witness what happened (its REJECT names the
          // configuration). A JOIN for us may have been granted.
          request_resume(now);
          return true;
        }
        if (now >= next_rejoin_at_) {
          send_catchup_req(now);
          return true;
        }
        if (now >= next_hb_) {
          send_ack(true);  // keepalive: the primary drops a silent joiner after T_ack
          next_hb_ = now + cfg_.heartbeat_ns;
          return true;
        }
        return false;
    }
    return false;
  }

  void start_rejoin(Nanos now) {
    phase_ = Phase::kQueryEpochEnd;
    send_epoch_end_query(now);
  }

  // A new EPOCH_END question (a new handshake, or the next step of one after a
  // truncation) gets a new query id; its retransmissions keep it, so an answer to any
  // copy is accepted however long the round trip, and an answer to an earlier question
  // never is. Ids start at incarnation << 32, so they never repeat across incarnations.
  void send_epoch_end_query(Nanos now) {
    ++query_id_;
    resend_epoch_end_query(now);
  }

  void resend_epoch_end_query(Nanos now) {
    // The question does not change between copies: the log is not touched until the answer.
    send(wire::EpochEndQuery{self_, h_.log_tail().epoch, cfg_.incarnation, cfg_.build_id, query_id_});
    next_rejoin_at_ = now + cfg_.rejoin_retry_ns;
  }

  void send_catchup_req(Nanos now) {
    const journal::ChainState t = h_.log_tail();
    send(wire::CatchupReq{self_, t.last_index + 1, t.last_crc, attempt_, cfg_.incarnation, cfg_.build_id, catchup_epoch_});
    next_rejoin_at_ = now + cfg_.rejoin_retry_ns;
  }

  [[nodiscard]] bool joinable() const noexcept { return phase_ == Phase::kCatchingUp; }

  // W granted the JOIN our primary relayed for us (10 §5): its copy of the grant came to
  // us with our recorded incarnation. Accepted only for the JOIN of the catch-up session
  // we are in (the primary's epoch + 1), like the relay and a REJECT: that JOIN was sent
  // at zero lag with the primary paused, so our log is exactly its last_index. A copy
  // that arrives after we re-handshook with a newer epoch of the primary (it went solo
  // while the copy was in flight) is stale and ignored.
  void on_join_admission(const witness::Grant& g, Nanos now) {
    if (role_ == Role::kBackup && g.incarnation == cfg_.incarnation && g.epoch == epoch_ && g.primary == primary_ &&
        witness::is_member(g.members, self_)) {
      // Admitted already (relay or REJECT); W's copy now proves it recorded us.
      w_admitted_epoch_ = g.epoch;
      return;
    }
    if (g.incarnation != cfg_.incarnation || role_ != Role::kRecovering || !reloaded_ || !joinable() ||
        !witness::is_member(g.members, self_) || g.primary != peer_ || g.from_epoch != catchup_epoch_ ||
        g.epoch != catchup_epoch_ + 1) {
      ++stats_.ignored_grants;
      return;
    }
    ++stats_.grants;
    SIM_PROBE("repl.joiner_adopts_join_grant");
    if (become_backup_after_join(g.epoch, now)) w_admitted_epoch_ = g.epoch;
  }

  // The joiner becomes the backup of `epoch`. HotStandby's Rejoin gives both logs the
  // epoch's EpochStart in the same step; the primary appends it once its GRANT arrives,
  // and the joiner appends the identical record itself (EpochStart is a pure function of
  // the log tail, the epoch, the primary and the configuration), so a primary that dies
  // right after the grant leaves its backup with the same log the model has. The
  // primary's own copy, when it arrives in an APPEND, is then a duplicate.
  bool become_backup_after_join(std::uint64_t epoch, Nanos now) {
    if (h_.log_tail().epoch < epoch) {
      if (!append_epoch_start(epoch, peer_)) return false;  // L2 full: the next evidence retries
      trace(TraceKind::kRejoinEpochStart, es_index_, es_crc_, epoch);
    }
    phase_ = Phase::kCatchingUp;
    epoch_ = epoch;
    members_ = 0b11;
    primary_ = peer_;
    last_peer_heard_ = now;
    fwd_assigned_.clear();
    fwd_seen_.clear();
    fwd_count_ = 0;
    snap_rx_ = {};
    set_role(Role::kBackup);
    trace(TraceKind::kRejoined, epoch);
    // The primary counts our ACKs of the new epoch from the catch-up position, and its
    // T_ack runs from the grant. Acknowledge the EpochStart we hold now: when nothing
    // follows it (after the close), its APPEND reaches us as a duplicate inside the ACK
    // rate limit, and the retransmission can come after T_ack (DST-010).
    send_ack(false);
    last_ack_sent_ = now;
    return true;
  }

  void abandon_joiner() {
    if (join_.snap.active && !join_.snap.done) h_.snapshot_release();
    join_ = {};
    join_window_ = false;
  }

  void send_heartbeat(std::uint64_t partner_inc) {
    wire::Heartbeat hb;
    hb.from = self_;
    hb.epoch = epoch_;
    hb.last = h_.log_tail().last_index;
    hb.commit = role_ == Role::kPrimary ? release_ : commit_index();
    hb.applied = h_.applied_index();
    hb.released = release_;
    hb.durable = h_.durable_index();
    hb.inc = cfg_.incarnation;
    hb.build_id = cfg_.build_id;
    hb.hash = latest_hash_;
    hb.partner_inc = partner_inc;
    hb.role = static_cast<std::uint8_t>(role_);
    hb.members = members_;
    hb.primary = primary_;
    hb.admitted = role_ == Role::kBackup && w_admitted_epoch_ != 0 && w_admitted_epoch_ == epoch_;
    send(hb);
  }

  // Loads new records into the window and sends APPENDs: whole records packed up to the
  // datagram limit, or fragments of a record that does not fit an empty datagram.
  bool pump_stream(Nanos now, std::uint64_t commit) {
    bool did = false;
    const std::uint64_t tail = h_.log_tail().last_index;
    while (stream_.loaded < tail) {
      std::span<const std::byte> rec;
      if (!read_record(stream_.loaded + 1, rec) || !stream_.win.has_room(rec.size())) break;
      (void)stream_.win.push(rec);
      ++stream_.loaded;
    }
    if (!stream_.outstanding()) {
      stream_.last_progress = now;
    } else if (now - stream_.last_progress > cfg_.rto_ns && now - stream_.last_rewind > cfg_.rto_ns) {
      // Go-back-N after a lost APPEND or ACK.
      SIM_PROBE("repl.append_retransmit_timeout");
      ++stats_.retransmits;
      stream_.rewind(stream_.acked + 1, now);
      stream_.last_progress = now;
    }
    for (std::size_t n = 0; n < cfg_.max_datagrams_per_poll && stream_.send_index <= stream_.loaded; ++n) {
      send_one_append(commit);
      did = true;
    }
    return did;
  }

  void send_one_append(std::uint64_t commit) {
    wire::Append a;
    a.from = self_;
    a.catchup = stream_.catchup;
    a.epoch = stream_.epoch;
    a.commit_index = commit;
    a.target_inc = stream_.target_inc;
    if (!stream_.catchup && hash_unsent_ && latest_hash_.index != 0) {
      a.has_hash = true;
      a.hash = latest_hash_;
      hash_unsent_ = false;
    }
    const std::size_t cap = wire::append_capacity(a.has_hash, 0);
    const std::span<const std::byte> first = stream_.win.get(stream_.send_index);
    LLE_ASSERT(!first.empty(), "send window lost a record");
    a.first_index = stream_.send_index;
    a.first_len = static_cast<std::uint32_t>(first.size());
    if (stream_.send_offset != 0 || first.size() > cap) {
      const std::size_t n = std::min<std::size_t>(first.size() - stream_.send_offset, cap);
      a.first_offset = stream_.send_offset;
      a.records = first.subspan(stream_.send_offset, n);
      if (stream_.send_offset == 0) note_first_send(stream_.send_index);
      stream_.send_offset += static_cast<std::uint32_t>(n);
      if (stream_.send_offset == first.size()) {
        ++stream_.send_index;
        stream_.send_offset = 0;
      }
    } else {
      std::size_t used = 0;
      while (stream_.send_index <= stream_.loaded) {
        const std::span<const std::byte> r = stream_.win.get(stream_.send_index);
        if (used + r.size() > cap) break;
        std::memcpy(pack_.get() + used, r.data(), r.size());
        used += r.size();
        note_first_send(stream_.send_index);
        ++stream_.send_index;
      }
      a.records = std::span<const std::byte>(pack_.get(), used);
    }
    ++stats_.appends_sent;
    send(a);
  }

  void note_first_send(std::uint64_t index) {
    if (index <= stream_.traced) return;
    stream_.traced = index;
    trace(stream_.catchup ? TraceKind::kSendCatchup : TraceKind::kSendAppend, index);
  }

  bool pump_snapshot(Nanos now) {
    SnapTx& s = join_.snap;
    if (!s.active || s.done) return false;
    bool did = false;
    if (s.next > s.acked && now - s.last_progress > cfg_.rto_ns) {
      s.next = s.acked;
      s.last_progress = now;
    }
    for (std::size_t n = 0; n < cfg_.max_datagrams_per_poll && s.next < s.total &&
                            s.next < s.acked + cfg_.snapshot_window_bytes;
         ++n) {
      const std::size_t want = std::min<std::uint64_t>(wire::kMaxSnapshotChunk, s.total - s.next);
      const std::uint32_t got = h_.snapshot_read(s.next, std::span<std::byte>(scratch_.get(), want));
      if (got == 0) break;
      wire::SnapshotChunk c;
      c.from = self_;
      c.snap_index = s.index;
      c.total = s.total;
      c.offset = s.next;
      c.inc = join_.inc;
      c.epoch = epoch_;
      c.bytes = std::span<const std::byte>(scratch_.get(), got);
      send(c);
      s.next += got;
      did = true;
    }
    return did;
  }

  // ---- the Output Rule -------------------------------------------------------------------

  void update_release() {
    std::uint64_t w = release_;
    const std::uint64_t tail = h_.log_tail().last_index;
    switch (role_) {
      case Role::kPrimary:
        if (!losing_ && !es_pending_) w = std::min(tail, ack_);
        break;
      case Role::kSoloPrimary: {
        const std::uint64_t durable = h_.durable_index();
        // Solo mode releases only L3-durable records, and nothing before its own
        // EpochStart is durable (10 §4 step 4; mutant SoloReleaseFromL2). Release goes on
        // while a joiner drains (sequencing is paused, so it can only catch up with the
        // tail) and stops from the JOIN on (DST-009).
        const bool join_pending = relays_.pending && relays_.epoch == epoch_;
        if (!es_pending_ && !join_pending && durable >= release_gate_) w = std::min(tail, durable);
        break;
      }
      case Role::kBackup:
        w = std::min(tail, commit_ann_);
        break;
      case Role::kRecovering:
        // A catching-up joiner applies what the primary has released, and its node holds
        // every output in its egress ring until release covers it (it transmits nothing:
        // no line, mirror gateways). Held at 0, a catch-up longer than the egress ring and
        // L2 together stopped the applier, then L2, then the catch-up (DST-011).
        if (reloaded_ && !(snap_rx_.active && !snap_rx_.installed)) w = std::min(tail, commit_ann_);
        break;
      default:
        break;
    }
    if (w > release_) {
      release_ = w;
      if (is_primary(role_)) trace(TraceKind::kRelease, w, role_ == Role::kSoloPrimary ? 1 : 0);
    }
  }

  // ---- state ----------------------------------------------------------------------------
  Config cfg_;
  H& h_;
  NodeId self_;
  NodeId peer_;
  Role role_ = Role::kNone;
  std::uint64_t epoch_ = 0;
  witness::Members members_ = 0;
  NodeId primary_ = 0;

  // Primary.
  std::uint64_t peer_inc_ = 0;  // backup incarnation we are paired with (kNoPartner: none yet)
  std::uint64_t ack_ = 0;
  bool losing_ = false;
  Nanos last_ack_progress_ = 0;
  Stream stream_;
  std::map<std::uint64_t, std::uint64_t> fwd_next_;  // (session, instance) -> next FORWARD seq

  // Grants.
  bool es_pending_ = false;
  std::uint64_t es_index_ = 0;
  std::uint64_t release_gate_ = 0;
  witness::MsgType grant_type_ = witness::MsgType::kPromote;
  Request req_;

  // Backup / candidate.
  std::uint64_t commit_ann_ = 0;
  bool resume_reload_ = false;  // reload_is_resume()
  std::uint64_t frozen_last_ = 0;
  std::uint64_t apply_frozen_ = 0;
  bool promote_sent_ = false;
  std::uint32_t es_crc_ = 0;
  bool unpromotable_ = false;
  bool suspect_alarmed_ = false;
  bool build_alarmed_ = false;
  std::uint64_t reasm_index_ = 0;
  std::uint32_t reasm_have_ = 0;
  Nanos last_ack_sent_ = 0;
  Nanos last_nack_sent_ = 0;

  // Forwarding (backup side).
  std::vector<FwdEntry> fwd_q_;
  std::size_t fwd_head_ = 0;
  std::size_t fwd_count_ = 0;
  bool fwd_reinject_ = false;
  std::map<std::uint64_t, std::uint64_t> fwd_assigned_;
  std::map<std::uint64_t, std::uint64_t> fwd_seen_;

  // Recovering / rejoin.
  Phase phase_ = Phase::kAskWitness;
  std::uint64_t resume_epoch_ = 0;
  std::uint64_t query_id_ = 0;
  std::uint32_t attempt_ = 0;
  std::uint64_t catchup_epoch_ = 0;
  std::uint64_t base_ = 0;
  bool reloaded_ = false;
  Nanos next_rejoin_at_ = 0;
  Nanos last_primary_heard_ = 0;
  SnapRx snap_rx_;

  // Solo primary: the joiner it serves.
  Joiner join_;
  // The JOINs this solo primary relayed in its current epoch (10 §5). W grants at most
  // one JOIN per epoch, but neither its GRANT nor its REJECT names the joiner or its
  // incarnation, so once a second JOIN is relayed in one epoch an answer cannot be
  // matched to a JOIN.
  struct Relays {
    std::uint64_t epoch = 0;       // our epoch when relayed: the JOINs' from_epoch
    std::uint32_t count = 0;       // JOINs relayed in that epoch
    std::uint64_t last_inc = 0;    // the latest one's joiner incarnation
    std::uint64_t last_index = 0;  // and its last_index
    bool pending = false;          // the latest is unanswered: sequencing and release stay paused
  } relays_;
  // The newest incarnation the peer has shown (ACK, HEARTBEAT, EPOCH_END_QUERY,
  // CATCHUP_REQ): every older incarnation of it is dead.
  bool peer_inc_seen_ = false;
  std::uint64_t peer_inc_max_ = 0;
  // Joiner: the epoch that W's own copy of a JOIN grant admitted this process to.
  std::uint64_t w_admitted_epoch_ = 0;
  bool join_window_ = false;

  // Common.
  std::uint64_t release_ = 0;
  Nanos last_peer_heard_ = 0;
  Nanos next_hb_ = 0;
  Nanos next_hb_w_ = 0;
  std::array<wire::StateHash, 8> own_hashes_{};
  std::size_t own_hash_n_ = 0;
  std::array<wire::StateHash, 8> peer_hashes_{};
  std::size_t peer_hash_n_ = 0;
  wire::StateHash latest_hash_{};
  bool hash_unsent_ = false;

  std::unique_ptr<std::byte[]> scratch_;
  std::unique_ptr<std::byte[]> reasm_;
  std::unique_ptr<std::byte[]> dgram_;
  std::unique_ptr<std::byte[]> pack_;
  std::unique_ptr<std::byte[]> fwd_bytes_;
  std::unique_ptr<journal::Sealer> canonical_;
  Stats stats_;
};

}  // namespace lle::repl

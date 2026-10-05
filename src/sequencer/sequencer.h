#pragma once
// The sequencer stage (06 §2, 01 §4 step 2): the single writer of the journal.
//
// Inputs, polled in a fixed priority order on every poll():
//   0. the session events injected to go first (inject_first, ADR-032): the
//      InstanceDown records of the instances that died with the old process or the old
//      partner, emitted ahead of every due Timer and every queued input, so they are
//      the first records after the recovered prefix or the new epoch's EpochStart;
//   1. raw inbound OUCH messages: first the input re-injected ahead of the queue
//      (inject_ahead: after a promotion, the backup's own mirror-session input the old
//      primary never committed, which is older than anything still queued), then the
//      gateways' SCQ MPSC (the backup's repl stage FORWARDs mirror-session input into the
//      same queue), and the session events of
//      the same producers, tagged (session_event_inbound): one ordered channel per
//      producer, so a connection's Disconnect follows every OUCH it sent before it and
//      the next connection's Login precedes its orders (cancel-on-disconnect; DST-004);
//   2. session events from the separate queue (tools and harnesses that push there;
//      exchanged's producers use the tagged path);
//   3. admin commands (the authenticated lle-admin channel);
//   4. the schedule: a Timer record when the clock passes an entry's time.
// Timers are also checked before every record is stamped, with the same clock reading
// that stamps it, so a record stamped at or after a scheduled time always follows that
// Timer in the journal (05: auctions and phase changes happen at journal positions).
// SequencerConfig::timer_batch bounds the Timer records one poll emits (a node started
// late finds thousands of 1 Hz timers due at once); an input record never overtakes a
// due Timer: it waits, staged, for the polls that emit the rest. The one exception is
// input 0: a dead connection's disconnect happened at the crash or the takeover, before
// any timer that came due during the outage (cancel-on-disconnect, ADR-032).
//
// Per record: index = last + 1, the current epoch, ts_ns = max(last_ts + 1,
// clock.now_real()) (strictly increasing: ITCH timestamps never decrease), prev_crc =
// the previous record's content crc, sealed with the L2 ring's nonce, built in place in
// the ring and published to every cursor.
//
// Back-pressure: when the ring has no room (its slowest cursor lags by the capacity)
// the record stays staged and the source is not popped again until it is published, so
// gateways see a full MPSC and apply TCP flow control. Nothing is dropped.
//
// Environment (ADR-003): `Env` provides the clock, the three input queue types and
// the ring type; the core never touches a system clock, allocates, or blocks (the list
// of input 0 is sized once, by reserve_first, before the stage runs).
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "common/hash.h"
#include "common/types.h"
#include "env/concepts.h"
#include "journal/record.h"

namespace lle::seq {

// ---- inputs ------------------------------------------------------------------------

// A raw inbound OUCH message with its routing metadata (01 §4 step 1). The gateway
// checks framing only; `bytes` are the original wire bytes. kMaxBytes covers the
// largest legal inbound OUCH message (specgen's kMaxInboundOuchLen is 140); longer
// packets arrive truncated with kFlagMalformedInput set.
template <std::size_t MaxBytes>
struct alignas(64) BasicInboundMsg {
  static constexpr std::size_t kMaxBytes = MaxBytes;
  std::uint32_t session_id = 0;
  std::uint32_t account = 0;
  std::uint16_t instance = 0;
  std::uint16_t len = 0;
  std::uint16_t flags = 0;  // journal record flags (kFlagMalformedInput)
  std::uint16_t reserved = 0;
  std::uint64_t rx_tsc = 0;  // latency probes only; never journaled (not deterministic)
  std::byte bytes[MaxBytes]{};

  [[nodiscard]] std::span<const std::byte> payload() const noexcept { return {bytes, len <= MaxBytes ? len : MaxBytes}; }
};
using InboundMsg = BasicInboundMsg<168>;
static_assert(sizeof(InboundMsg) == 192);

struct SessionEventMsg {
  std::uint32_t session_id = 0;
  std::uint16_t instance = 0;
  journal::SessionEventKind event = journal::SessionEventKind::Login;
  std::uint64_t requested_seq = 0;
};

// A session event carried in the OUCH queue. Producers (the gateways, the replication
// stage, start-up) push a connection's session events into the same SCQ as its OUCH
// messages, so the journal keeps each producer's order: a Disconnect after every OUCH
// the connection sent before it, the next connection's Login before its orders
// (cancel-on-disconnect, 05 §4 step 8; DST-004). Tag: InboundMsg::reserved; payload:
// u8 event, u64 requested sequence (little-endian).
inline constexpr std::uint16_t kInboundSessionEvent = 1;
template <class Msg = InboundMsg>
[[nodiscard]] inline Msg session_event_inbound(const SessionEventMsg& e) noexcept {
  static_assert(Msg::kMaxBytes >= 9);
  Msg m;
  m.session_id = e.session_id;
  m.instance = e.instance;
  m.reserved = kInboundSessionEvent;
  m.len = 9;
  m.bytes[0] = static_cast<std::byte>(e.event);
  store_le64(m.bytes + 1, e.requested_seq);
  return m;
}
template <std::size_t N>
[[nodiscard]] inline bool is_session_event(const BasicInboundMsg<N>& m) noexcept {
  return m.reserved == kInboundSessionEvent;
}
template <std::size_t N>
[[nodiscard]] inline SessionEventMsg session_event_of(const BasicInboundMsg<N>& m) noexcept {
  SessionEventMsg e;
  e.session_id = m.session_id;
  e.instance = m.instance;
  e.event = static_cast<journal::SessionEventKind>(std::to_integer<std::uint8_t>(m.bytes[0]));
  e.requested_seq = load_le64(m.bytes + 1);
  return e;
}

template <std::size_t MaxArgs>
struct BasicAdminMsg {
  static constexpr std::size_t kMaxArgs = MaxArgs;
  std::uint16_t command = 0;
  std::uint16_t tlv_version = 1;
  std::uint32_t operator_id = 0;
  std::uint32_t len = 0;
  std::byte args[MaxArgs]{};

  [[nodiscard]] std::span<const std::byte> payload() const noexcept { return {args, len <= MaxArgs ? len : MaxArgs}; }
};
using AdminMsg = BasicAdminMsg<240>;

// One schedule entry (05, trading schedule: 04:00, 09:25 EOII, 09:28 NOII, 09:30 cross). The
// schedule is sorted by (time, id); `time` is exchange time (UNIX ns).
struct ScheduleEntry {
  Nanos time = 0;
  journal::TimerKind kind = journal::TimerKind::SystemEvent;
  std::uint32_t id = 0;
};

// One serialized configuration table (ADR-028); journaled as Config chunks.
struct ConfigBlob {
  journal::ConfigTable table = journal::ConfigTable::Symbols;
  std::span<const std::byte> bytes;
};

// The configuration digest the day start stamps into EpochStart (ADR-028): FNV-1a 64 over
// each table's id, size and bytes, in order. A paired node that restarts on an empty
// journal joins under the digest of its configuration file (DST-006).
[[nodiscard]] inline std::uint64_t config_digest(std::span<const ConfigBlob> config) noexcept {
  Fnv1a64 digest;
  for (const auto& c : config) {
    digest.u(static_cast<std::uint16_t>(c.table));
    digest.u(static_cast<std::uint64_t>(c.bytes.size()));
    digest.bytes(c.bytes);
  }
  return digest.value();
}

// ---- environment ---------------------------------------------------------------------

template <class Q>
concept PopQueue = requires(Q& q, typename Q::value_type& v) {
  { q.try_pop(v) } -> std::same_as<bool>;
};

template <class R>
concept JournalRing = requires(R& r, const R& cr, std::uint32_t n) {
  { r.try_reserve(n) } -> std::same_as<std::byte*>;
  r.commit();
  { cr.sealer() } -> std::same_as<const journal::Sealer&>;
};

template <class E>
concept SequencerEnv = requires {
  typename E::Clock;
  typename E::OuchQueue;
  typename E::SessionQueue;
  typename E::AdminQueue;
  typename E::Ring;
} && env::ClockLike<typename E::Clock> && PopQueue<typename E::OuchQueue> && PopQueue<typename E::SessionQueue> &&
                       PopQueue<typename E::AdminQueue> && JournalRing<typename E::Ring> &&
                       std::same_as<typename E::SessionQueue::value_type, SessionEventMsg>;

struct SequencerConfig {
  std::uint32_t ouch_batch = 64;     // per poll, per source: bounds the time spent on one
  std::uint32_t session_batch = 16;  // source so lower priorities are never starved
  std::uint32_t admin_batch = 16;
  std::uint64_t snapshot_every = 10'000'000;  // SnapshotMark after every Nth index (0: never)
  std::uint32_t timer_batch = 0;              // Timer records per poll (0: no bound)
};

enum class SeqError : std::uint8_t {
  RingFull,       // day start / epoch start / day end found no room in the ring
  ConfigTooLarge, // a config table needs more than 65535 chunks
  NotStarted,
};

struct SequencerStats {
  std::uint64_t records = 0;
  std::uint64_t ouch = 0;
  std::uint64_t session_events = 0;
  std::uint64_t first = 0;  // of session_events: injected to go first (ADR-032)
  std::uint64_t ahead = 0;  // OUCH input (and tagged events) taken from the re-injected list
  std::uint64_t admin = 0;
  std::uint64_t timers = 0;
  std::uint64_t snapshot_marks = 0;
  std::uint64_t backpressure = 0;  // polls that stopped because the ring was full
  std::uint64_t timer_bounded = 0;  // polls that stopped at timer_batch with timers still due
};

template <SequencerEnv Env>
class Sequencer {
 public:
  using Clock = typename Env::Clock;
  using OuchQueue = typename Env::OuchQueue;
  using SessionQueue = typename Env::SessionQueue;
  using AdminQueue = typename Env::AdminQueue;
  using Ring = typename Env::Ring;
  using OuchMsg = typename OuchQueue::value_type;
  using AdminMessage = typename AdminQueue::value_type;

  Sequencer(Clock& clock, OuchQueue& ouch, SessionQueue& sessions, AdminQueue& admin, Ring& ring,
            std::span<const ScheduleEntry> schedule, SequencerConfig cfg = {}) noexcept
      : clock_(&clock), ouch_q_(&ouch), session_q_(&sessions), admin_q_(&admin), ring_(&ring), schedule_(schedule),
        cfg_(cfg) {
    for (std::size_t i = 1; i < schedule_.size(); ++i) {
      LLE_ASSERT(schedule_[i - 1].time < schedule_[i].time ||
                     (schedule_[i - 1].time == schedule_[i].time && schedule_[i - 1].id < schedule_[i].id),
                 "schedule must be sorted by (time, id)");
    }
  }

  // ---- lifecycle (cold) ---------------------------------------------------------------

  // Day start (06 §10, ADR-028): DayStart, the config tables as Config records, then
  // EpochStart carrying the config digest. Indices restart at 1. The ring must have
  // room for all of them (it is empty at day start).
  std::expected<void, SeqError> start_day(const journal::DayStart& ds, std::span<const ConfigBlob> config,
                                          std::uint32_t epoch, std::uint32_t primary_node) {
    for (const auto& c : config) {
      if (chunks_of(c) > 0xFFFF) return std::unexpected(SeqError::ConfigTooLarge);
    }
    chain_ = journal::ChainState{0, 0, chain_.last_ts, epoch};
    next_timer_ = 0;
    next_snapshot_id_ = 1;
    pending_mark_ = false;
    started_ = true;
    if (!emit_now(ds)) return std::unexpected(SeqError::RingFull);
    for (const auto& c : config) {
      const std::uint32_t n = chunks_of(c);
      for (std::uint32_t k = 0; k < n; ++k) {
        const std::size_t off = std::size_t{k} * journal::ConfigChunk::kMaxChunkBytes;
        const std::size_t len = std::min<std::size_t>(journal::ConfigChunk::kMaxChunkBytes, c.bytes.size() - off);
        const journal::ConfigChunk chunk{c.table, static_cast<std::uint16_t>(k), static_cast<std::uint16_t>(n),
                                         static_cast<std::uint32_t>(c.bytes.size()), c.bytes.subspan(off, len)};
        if (!emit_now(chunk)) return std::unexpected(SeqError::RingFull);
      }
    }
    config_digest_ = seq::config_digest(config);
    if (!emit_now(journal::EpochStart{epoch, primary_node, config_digest_})) return std::unexpected(SeqError::RingFull);
    return {};
  }

  // Continue after a restart from the last journaled record (L2 restore / L3
  // recovery). `next_timer`: schedule entries already journaled; `next_snapshot_id`:
  // one past the last SnapshotMark id.
  void resume(const journal::ChainState& chain, std::size_t next_timer, std::uint64_t next_snapshot_id,
              std::uint64_t config_digest = 0) noexcept {
    chain_ = chain;
    next_timer_ = next_timer;
    next_snapshot_id_ = next_snapshot_id;
    config_digest_ = config_digest;
    pending_mark_ = false;
    started_ = true;
  }

  // First record of a new epoch after promotion (10 §4).
  std::expected<void, SeqError> start_epoch(std::uint32_t epoch, std::uint32_t primary_node) {
    if (!started_) return std::unexpected(SeqError::NotStarted);
    LLE_ASSERT(epoch >= chain_.epoch, "epochs only increase");
    const std::uint32_t old = chain_.epoch;
    chain_.epoch = epoch;
    if (!emit_now(journal::EpochStart{epoch, primary_node, config_digest_})) {
      chain_.epoch = old;
      return std::unexpected(SeqError::RingFull);
    }
    return {};
  }

  // The last record of the day (06 §10).
  std::expected<void, SeqError> end_day(std::uint64_t itch_messages, std::uint64_t soup_messages) {
    if (!started_) return std::unexpected(SeqError::NotStarted);
    if (!emit_now(journal::DayEnd{chain_.last_index + 1, itch_messages, soup_messages})) {
      return std::unexpected(SeqError::RingFull);
    }
    started_ = false;
    return {};
  }

  // ---- session events that go first (ADR-032) -----------------------------------------
  // After a restart, a promotion or a rejoin, the InstanceDown records of the dead
  // instances are sequenced before any overdue Timer and any queued input: they are the
  // first records after the recovered prefix or the new epoch's EpochStart (the next
  // polls emit them, waiting out back-pressure like any record). resume() keeps them.
  // reserve_first sizes the list (cold: it allocates); inject_first never allocates and
  // returns false when the list is full.
  void reserve_first(std::size_t n) { first_.reserve(first_.size() + n); }
  [[nodiscard]] bool inject_first(const SessionEventMsg& e) noexcept {
    if (first_.size() == first_.capacity()) {
      if (first_next_ == 0) return false;
      first_.erase(first_.begin(), first_.begin() + static_cast<std::ptrdiff_t>(first_next_));  // no allocation
      first_next_ = 0;
    }
    first_.push_back(e);  // within the capacity: no allocation
    return true;
  }
  [[nodiscard]] std::size_t first_pending() const noexcept { return first_.size() - first_next_; }
  [[nodiscard]] std::size_t first_capacity() const noexcept { return first_.capacity(); }

  // ---- input re-injected ahead of the queue -------------------------------------------
  // After a promotion the replica re-injects the backup's own mirror-session input that
  // the old primary never committed (its pending FORWARDs), and the stage the message it
  // had popped but not forwarded. Input a gateway queued meanwhile is newer: re-injected
  // behind it, the older orders would carry lower UserRefNums than ones already taken and
  // be ignored as resends (05 §4). So the re-injected input is OUCH input emitted before
  // the queue (after any due Timer, as all input). reserve_ahead sizes the list (cold);
  // inject_ahead never allocates and returns false when it is full.
  void reserve_ahead(std::size_t n) { ahead_.reserve(ahead_.size() + n); }
  [[nodiscard]] bool inject_ahead(const OuchMsg& m) noexcept {
    if (ahead_.size() == ahead_.capacity()) {
      if (ahead_next_ == 0) return false;
      ahead_.erase(ahead_.begin(), ahead_.begin() + static_cast<std::ptrdiff_t>(ahead_next_));  // no allocation
      ahead_next_ = 0;
    }
    ahead_.push_back(m);  // within the capacity: no allocation
    return true;
  }
  [[nodiscard]] std::size_t ahead_pending() const noexcept { return ahead_.size() - ahead_next_; }
  [[nodiscard]] std::size_t ahead_capacity() const noexcept { return ahead_.capacity(); }

  // ---- the stage body -------------------------------------------------------------------
  bool poll() noexcept {
    if (!started_) return false;
    timers_this_poll_ = 0;
    timer_budget_hit_ = false;
    bool did = false;
    if (!flush_mark(did)) return did;
    // 0. Session events that go first: no due Timer and no queued input before them.
    if (first_next_ < first_.size()) {
      for (std::uint32_t i = 0; i < cfg_.ouch_batch && first_next_ < first_.size(); ++i) {
        const SessionEventMsg& e = first_[first_next_];
        const journal::SessionEvent p{e.session_id, e.instance, e.event, e.requested_seq};
        if (!append(p, 0, clock_->now_real())) return stalled(did);
        ++first_next_;
        ++stats_.session_events;
        ++stats_.first;
        did = true;
        if (!flush_mark(did)) return did;
      }
      if (first_next_ < first_.size()) return did;  // the rest next poll, still first
      first_.clear();
      first_next_ = 0;
    }
    // 1. OUCH: the re-injected input, then the queue.
    for (std::uint32_t i = 0; i < cfg_.ouch_batch; ++i) {
      if (!have_ouch_ && !next_ouch()) break;
      have_ouch_ = true;
      if (is_session_event(ouch_)) {  // in order with the producer's OUCH (DST-004)
        const SessionEventMsg e = session_event_of(ouch_);
        const journal::SessionEvent p{e.session_id, e.instance, e.event, e.requested_seq};
        if (!emit(p, 0)) return stalled(did || timers_this_poll_ != 0);
        have_ouch_ = false;
        ++stats_.session_events;
        did = true;
        if (!flush_mark(did)) return did;
        continue;
      }
      const journal::OuchInbound p{ouch_.session_id, ouch_.account, ouch_.instance, ouch_.payload()};
      if (!emit(p, ouch_.flags)) return stalled(did || timers_this_poll_ != 0);
      have_ouch_ = false;
      ++stats_.ouch;
      did = true;
      if (!flush_mark(did)) return did;
    }
    // 2. Session events.
    for (std::uint32_t i = 0; i < cfg_.session_batch; ++i) {
      if (!have_session_ && !session_q_->try_pop(session_)) break;
      have_session_ = true;
      const journal::SessionEvent p{session_.session_id, session_.instance, session_.event, session_.requested_seq};
      if (!emit(p, 0)) return stalled(did || timers_this_poll_ != 0);
      have_session_ = false;
      ++stats_.session_events;
      did = true;
      if (!flush_mark(did)) return did;
    }
    // 3. Admin.
    for (std::uint32_t i = 0; i < cfg_.admin_batch; ++i) {
      if (!have_admin_ && !admin_q_->try_pop(admin_)) break;
      have_admin_ = true;
      const journal::Admin p{admin_.command, admin_.tlv_version, admin_.operator_id, admin_.payload()};
      if (!emit(p, 0)) return stalled(did || timers_this_poll_ != 0);
      have_admin_ = false;
      ++stats_.admin;
      did = true;
      if (!flush_mark(did)) return did;
    }
    // 4. The schedule.
    const std::uint64_t before = stats_.timers;
    if (!emit_due_timers(clock_->now_real())) return stalled(did || stats_.timers != before);
    return did || stats_.timers != before;
  }

  // ---- state ------------------------------------------------------------------------------
  [[nodiscard]] const journal::ChainState& chain() const noexcept { return chain_; }
  [[nodiscard]] std::size_t next_timer() const noexcept { return next_timer_; }
  [[nodiscard]] std::uint64_t next_snapshot_id() const noexcept { return next_snapshot_id_; }
  [[nodiscard]] std::uint64_t config_digest() const noexcept { return config_digest_; }
  [[nodiscard]] const SequencerStats& stats() const noexcept { return stats_; }
  [[nodiscard]] bool started() const noexcept { return started_; }

 private:
  static std::uint32_t chunks_of(const ConfigBlob& c) noexcept {
    const std::size_t n = (c.bytes.size() + journal::ConfigChunk::kMaxChunkBytes - 1) / journal::ConfigChunk::kMaxChunkBytes;
    return n == 0 ? 1u : static_cast<std::uint32_t>(n > 0x10000 ? 0x10000 : n);
  }

  // The next OUCH input into ouch_: the re-injected list first, then the queue.
  bool next_ouch() noexcept {
    if (ahead_next_ < ahead_.size()) {
      ouch_ = ahead_[ahead_next_++];
      ++stats_.ahead;
      if (ahead_next_ == ahead_.size()) {
        ahead_.clear();
        ahead_next_ = 0;
      }
      return true;
    }
    return ouch_q_->try_pop(ouch_);
  }

  // A poll stops: the ring is full, or this poll's timer budget is spent (not
  // back-pressure: the next poll goes on).
  bool stalled(bool did) noexcept {
    if (timer_budget_hit_) {
      ++stats_.timer_bounded;
    } else {
      ++stats_.backpressure;
    }
    return did;
  }

  // Timers due at `now`, in schedule order. False if the ring is full or this poll
  // already emitted timer_batch of them with more due (timer_budget_hit_).
  bool emit_due_timers(Nanos now) noexcept {
    while (next_timer_ < schedule_.size() && schedule_[next_timer_].time <= now) {
      if (cfg_.timer_batch != 0 && timers_this_poll_ >= cfg_.timer_batch) {
        timer_budget_hit_ = true;
        return false;
      }
      const ScheduleEntry& e = schedule_[next_timer_];
      if (!append(journal::Timer{e.id, e.kind, e.time}, 0, now)) return false;
      ++next_timer_;
      ++stats_.timers;
      ++timers_this_poll_;
      if (!flush_pending_mark()) return false;
    }
    return true;
  }

  // One input record, preceded by any timer due at the same clock reading.
  template <journal::PayloadLike P>
  bool emit(const P& p, std::uint16_t flags) noexcept {
    const Nanos now = clock_->now_real();
    if (!emit_due_timers(now)) return false;
    return append(p, flags, now);
  }

  // Cold-path records (day start, epoch start, day end): no timer interleaving.
  template <journal::PayloadLike P>
  bool emit_now(const P& p) noexcept {
    return append(p, 0, clock_->now_real());
  }

  template <journal::PayloadLike P>
  bool append(const P& p, std::uint16_t flags, Nanos now) noexcept {
    const std::uint32_t len = journal::record_size(p);
    std::byte* dst = ring_->try_reserve(len);
    if (dst == nullptr) return false;
    const Nanos ts = now > chain_.last_ts ? now : chain_.last_ts + 1;
    const journal::Stamp s{chain_.last_index + 1, ts, chain_.epoch, chain_.last_crc, flags};
    const std::uint32_t content = journal::build_record(dst, s, p, ring_->sealer());
    ring_->commit();
    chain_.last_index = s.index;
    chain_.last_crc = content;
    chain_.last_ts = ts;
    ++stats_.records;
    if (cfg_.snapshot_every != 0 && s.index % cfg_.snapshot_every == 0 && P::kType != journal::RecordType::SnapshotMark) {
      pending_mark_ = true;
    }
    return true;
  }

  // A SnapshotMark follows the record whose index is a multiple of snapshot_every
  // (a deterministic journal position, 06 §9).
  bool flush_pending_mark() noexcept {
    if (!pending_mark_) return true;
    if (!append(journal::SnapshotMark{next_snapshot_id_}, 0, clock_->now_real())) return false;
    pending_mark_ = false;
    ++next_snapshot_id_;
    ++stats_.snapshot_marks;
    return true;
  }
  bool flush_mark(bool& did) noexcept {
    const bool had = pending_mark_;
    if (!flush_pending_mark()) {
      ++stats_.backpressure;
      return false;
    }
    did = did || had;
    return true;
  }

  Clock* clock_;
  OuchQueue* ouch_q_;
  SessionQueue* session_q_;
  AdminQueue* admin_q_;
  Ring* ring_;
  std::span<const ScheduleEntry> schedule_;
  SequencerConfig cfg_;

  journal::ChainState chain_{};
  std::size_t next_timer_ = 0;
  std::uint64_t next_snapshot_id_ = 1;
  std::uint64_t config_digest_ = 0;
  bool pending_mark_ = false;
  bool started_ = false;
  std::uint32_t timers_this_poll_ = 0;
  bool timer_budget_hit_ = false;

  // Input 0 (ADR-032): emitted from first_next_ on; cleared once all are out.
  std::vector<SessionEventMsg> first_;
  std::size_t first_next_ = 0;
  // Re-injected input ahead of the OUCH queue: taken from ahead_next_ on.
  std::vector<OuchMsg> ahead_;
  std::size_t ahead_next_ = 0;

  // At most one staged (popped, not yet published) message per source.
  OuchMsg ouch_{};
  bool have_ouch_ = false;
  SessionEventMsg session_{};
  bool have_session_ = false;
  AdminMessage admin_{};
  bool have_admin_ = false;

  SequencerStats stats_{};
};

}  // namespace lle::seq

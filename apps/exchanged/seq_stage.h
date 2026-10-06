#pragma once
// The seq stage (01 §7 CPU 10; 06 §2): runs seq::Sequencer over the SCQ queues and the
// L2 ring, plus the node-level duties around it:
//   - the manual clock (tests): walks exchange time to the control port's target,
//     stopping at every scheduled time so each Timer record is stamped when it is due;
//   - the `sync` barrier of the control port: the first idle sequencer poll after a
//     request records the last index;
//   - day end (06 §10): inputs freeze, the engine catches up, then DayEnd carries the
//     day's ITCH and OUCH totals.
// In paired mode the replication core shares this thread (repl_stage.h): both write
// the L2 ring and the replica gates sequencing (10 §4), so one thread owns L2.
//
// The environment, the driver and the stage are generic over the clock and the
// sequencer (BasicSeqEnv, BasicSeqDriver, BasicSeqStage), so the simulator runs them
// on its virtual clock; SeqEnv, Sequencer, SeqDriver and SeqStage are the production
// bindings. The clock is env::ClockLike plus mode(), manual() and set_manual() (clock.h).
//
// Work time (T32, md/work_meter.h): the driver's meter, started by the ring when a poll
// reserves its first record; items are the records sequenced.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "exchanged/clock.h"
#include "exchanged/record_log.h"
#include "exchanged/shared.h"
#include "journal/record.h"
#include "log/nlog.h"
#include "md/work_meter.h"
#include "sequencer/sequencer.h"

namespace lle::exch {

// The sequencer's ring: the L2 ring, optionally teeing every committed record into the
// replication record log (paired mode): directly when the replica shares this thread,
// through an SPSC byte ring when it has its own (split mode; a full tee is back-pressure).
// A reserved record starts the driver's work meter (set_meter; none: not metered).
template <class ClockT, class LogT = RecordLog>
class BasicSeqRing {
 public:
  BasicSeqRing(L2& ring, LogT* log, conc::SpscByteRing* tee = nullptr) noexcept
      : ring_(&ring), log_(log), tee_(tee) {}
  void set_meter(md::WorkMeter<ClockT>* m) noexcept { meter_ = m; }
  std::byte* try_reserve(std::uint32_t n) noexcept {
    if (tee_ != nullptr) {
      t_ = tee_->try_reserve(n);
      if (t_ == nullptr) return nullptr;
    }
    p_ = ring_->try_reserve_keeping_reserve(n);  // a replica's EpochStart always fits (DST-016)
    n_ = n;
    if (p_ != nullptr && meter_ != nullptr) {
      meter_->start();
      meter_->add();
    }
    return p_;
  }
  void commit() noexcept {
    if (tee_ != nullptr) {
      std::memcpy(t_, p_, n_);
      tee_->commit();
    } else if (log_ != nullptr) {
      const bool ok = log_->append_from(p_, n_, ring_->sealer());
      LLE_ASSERT(ok, "record log out of step with L2");
    }
    ring_->commit();
  }
  [[nodiscard]] const journal::Sealer& sealer() const noexcept { return ring_->sealer(); }

 private:
  L2* ring_;
  LogT* log_;
  conc::SpscByteRing* tee_;
  md::WorkMeter<ClockT>* meter_ = nullptr;
  std::byte* p_ = nullptr;
  std::byte* t_ = nullptr;
  std::uint32_t n_ = 0;
};
using SeqRing = BasicSeqRing<NodeClock>;

template <class ClockT, class LogT = RecordLog>
struct BasicSeqEnv {
  using Clock = ClockT;
  using OuchQueue = exch::OuchQueue;
  using SessionQueue = exch::SessionQueue;
  using AdminQueue = exch::AdminQueue;
  using Ring = BasicSeqRing<ClockT, LogT>;
};
using SeqEnv = BasicSeqEnv<NodeClock>;
using Sequencer = seq::Sequencer<SeqEnv>;

// Node-level duties shared by the solo and paired seq stages.
template <class ClockT, class SequencerT>
class BasicSeqDriver {
 public:
  BasicSeqDriver(Shared& sh, ClockT& clock, SequencerT& sequencer, std::span<const seq::ScheduleEntry> timers,
                 bool auto_end) noexcept
      : sh_(&sh), clock_(&clock), seq_(&sequencer), timers_(timers), auto_end_(auto_end), work_(&clock) {}

  // One step of sequencing with the node duties. `allowed`: the replica lets this node
  // sequence (always true in solo mode).
  bool step(bool allowed) {
    const bool did = run(allowed);
    work_.finish();
    return did;
  }

  // The meter the sequencer's ring starts (BasicSeqRing::set_meter), and its totals.
  [[nodiscard]] md::WorkMeter<ClockT>& meter() noexcept { return work_; }
  [[nodiscard]] const md::WorkStats& work() const noexcept { return work_.stats(); }

 private:
  bool run(bool allowed) {
    bool did = false;
    if (!seq_->started()) return false;
    // The day ends after the session events that go first (ADR-032: a restart's
    // InstanceDown records), which the poll below emits.
    if (allowed && seq_->first_pending() == 0 &&
        (sh_->end_day_req.load() || (auto_end_ && !timers_.empty() && seq_->next_timer() >= timers_.size()))) {
      return try_end_day();
    }
    if (clock_->mode() == ClockMode::Manual) did |= walk_clock(allowed);
    if (allowed) {
      const bool busy = seq_->poll();
      did |= busy;
      sh_->sequenced.store(seq_->chain().last_index);
      observe();
      const std::uint64_t req = sh_->sync_req.load(std::memory_order_acquire);
      if (!busy && req != sh_->sync_ack.load()) {
        sh_->sync_index.store(seq_->chain().last_index);
        sh_->sync_ack.store(req);
      }
    }
    return did;
  }

  // Manual clock: move to the next scheduled time or the target, one step per call, so
  // every due Timer is stamped at its own time (as with a running clock).
  bool walk_clock(bool allowed) {
    const Nanos target = sh_->clock_target.load(std::memory_order_acquire);
    const Nanos now = clock_->manual();
    if (target <= now) {
      if (sh_->clock_reached.load() < static_cast<std::uint64_t>(now) && (!allowed || timers_due(now) == 0))
        sh_->clock_reached.store(static_cast<std::uint64_t>(now));
      return false;
    }
    if (allowed && timers_due(now) != 0) return false;  // the sequencer emits them first
    Nanos next = target;
    const std::size_t k = seq_->next_timer();
    if (allowed && k < timers_.size() && timers_[k].time < next) next = timers_[k].time;
    if (next < now) next = now;
    clock_->set_manual(next);
    return true;
  }
  [[nodiscard]] std::size_t timers_due(Nanos now) const noexcept {
    const std::size_t k = seq_->next_timer();
    return k < timers_.size() && timers_[k].time <= now ? 1 : 0;
  }

  // nlog (11 §3): timer injections and back-pressure episodes.
  void observe() {
    const seq::SequencerStats& st = seq_->stats();
    if (st.timers != timers_seen_) {
      NLOG_INFO("seq timers injected {} (schedule position {}, last index {})", st.timers - timers_seen_,
                seq_->next_timer(), seq_->chain().last_index);
      timers_seen_ = st.timers;
    }
    if (st.backpressure != bp_seen_) {
      if (!in_bp_) NLOG_WARN("seq back-pressure: L2 ring full at index {}", seq_->chain().last_index);
      in_bp_ = true;
      bp_seen_ = st.backpressure;
    } else if (in_bp_) {
      in_bp_ = false;
      NLOG_INFO("seq back-pressure over at index {}", seq_->chain().last_index);
    }
  }

  bool try_end_day() {
    const std::uint64_t last = seq_->chain().last_index;
    if (sh_->egress_state.applied.load() < last) return false;  // the engine catches up first
    if (!seq_->end_day(sh_->itch_total.load(), sh_->soup_total.load())) return false;
    sh_->sequenced.store(seq_->chain().last_index);
    sh_->end_day_req.store(false);
    NLOG_INFO("seq day end at index {}", seq_->chain().last_index);
    return true;
  }

  Shared* sh_;
  ClockT* clock_;
  SequencerT* seq_;
  std::span<const seq::ScheduleEntry> timers_;
  bool auto_end_;
  std::uint64_t timers_seen_ = 0;
  std::uint64_t bp_seen_ = 0;
  bool in_bp_ = false;
  md::WorkMeter<ClockT> work_;
};

using SeqDriver = BasicSeqDriver<NodeClock, Sequencer>;

// Solo mode: the sequencer alone.
template <class DriverT>
class BasicSeqStage {
 public:
  BasicSeqStage(DriverT& driver) noexcept : d_(&driver) {}
  bool poll() { return d_->step(true); }

 private:
  DriverT* d_;
};
using SeqStage = BasicSeqStage<SeqDriver>;

}  // namespace lle::exch

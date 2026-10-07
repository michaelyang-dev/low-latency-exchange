#pragma once
// The io stage (01 §7 CPU 14; 06 §6, §8): the L3 journal writer and the output log.
//
// Journal: records leave the L2 ring (cursor kL2Io) into the writer's open batch and
// the batch is submitted in the same poll (natural group commit, 06 §6). A record is
// released from the ring only into a batch that is submitted in this same poll: the
// open batch is process memory, and a record copied there whose ring slot is then
// reused would be lost at a process crash although it was acknowledged as L2-held.
// One queue slot is therefore always kept for the final flush. durable_index advances
// as contiguous writes complete; in solo mode it is the release watermark (ADR-005).
// A failed write is fatal (06 §6: never retried): intake stops and the process exits.
//
// Output log: every released ITCH and OUCH message is appended to the day's files
// (outlog/<day>/itch.bin, soup-<session>.bin), asynchronously and without fsync: the
// log is derived data, regenerated from the journal at recovery (06 §8). The writers
// buffer in user space and are flushed whenever the stage runs out of released input.
//
// Generic over the journal directory, writer and segment preparer, the output-log day
// and the clock its work meter reads (BasicIoStage), so the simulator runs this stage
// on its disk and virtual time; IoStage is the production binding.
//
// Work time (T32, md/work_meter.h): items are the records journaled, the output-log
// messages written and the output-log flushes. The meter starts once a poll's first
// record is in the writer's batch (a poll that only reaps completions is not metered).
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "env/entropy.h"
#include "exchanged/clock.h"
#include "exchanged/shared.h"
#include "journal/journal_writer.h"
#include "journal/posix_segment_dir.h"
#include "journal/uring_segment_dir.h"
#include "journal/segment.h"
#include "journal/segment_preparer.h"
#include "log/nlog.h"
#include "md/egress.h"
#include "md/work_meter.h"
#include "outlog/day.h"

namespace lle::exch {

// The production L3 path (06 §6): io_uring per segment where the platform allows it,
// pwrite + fdatasync otherwise (journal/uring_segment_dir.h; [journal] device).
using SegDir = journal::UringSegmentDir;
using Device = SegDir::Device;
using Writer = journal::JournalWriter<Device>;
using Preparer = journal::SegmentPreparer<SegDir, env::ProdRng>;

struct IoStats {
  std::uint64_t appended = 0;
  std::uint64_t outlog_itch = 0, outlog_soup = 0;
  std::uint64_t outlog_flushes = 0;
  std::uint64_t outlog_errors = 0;
  std::uint64_t segments_prepared = 0;
  std::uint64_t stall_prepares = 0;  // a segment had to be prepared on the write path
  std::uint64_t batches = 0;         // journal batches submitted
};

template <class DirT, class WriterT, class PreparerT, class OutDayT, class ClockT>
class BasicIoStage {
 public:
  BasicIoStage(Shared& sh, DirT& dir, PreparerT& prep, WriterT& writer, OutDayT& outlog, std::size_t spares,
               bool owns_release, const ClockT& clock)
      : sh_(&sh),
        dir_(&dir),
        prep_(&prep),
        w_(&writer),
        out_(&outlog),
        spares_(spares),
        owns_release_(owns_release),
        clock_(&clock),
        work_(&clock) {}

  bool poll() {
    const bool did = run();
    work_.finish();
    return did;
  }

  // Everything sequenced into L3 and the output log flushed (shutdown; cold).
  void drain(int max_spins = 1'000'000) {
    for (int i = 0; i < max_spins; ++i) {
      (void)poll();
      if (sh_->l2.peek(kL2Io).empty() && w_->batch_used() == 0 && w_->in_flight() == 0) break;
    }
    (void)out_->flush_all();
  }

  [[nodiscard]] const IoStats& stats() const noexcept { return stats_; }
  [[nodiscard]] std::uint64_t durable() const noexcept { return durable_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] const md::WorkStats& work() const noexcept { return work_.stats(); }
  // Batch commit times (11 §3): submission to durability, one sample per batch. Samples
  // k with count - kCommitSamples <= k < count are still held.
  static constexpr std::size_t kCommitSamples = 256;
  [[nodiscard]] std::uint64_t commit_count() const noexcept { return commit_count_; }
  [[nodiscard]] Nanos commit_sample(std::uint64_t k) const noexcept { return commit_ring_[k % kCommitSamples]; }

 private:
  bool run() {
    bool did = w_->poll() != 0;
    while (w_->in_flight() + 1 < journal::kQueueDepth) {
      const journal::RecordView v = sh_->l2.peek(kL2Io);
      if (v.empty() || sh_->io_hold.load(std::memory_order_relaxed)) break;
      const typename WriterT::Status st = w_->append(v.bytes(), sh_->l2.sealer());
      if (st == WriterT::Status::Ok) {
        work_.start();
        work_.add();
        sh_->l2.release(kL2Io);
        ++stats_.appended;
        note_submitted();  // a full batch went out with this append
        did = true;
        continue;
      }
      if (st == WriterT::Status::NeedSegment) {
        ++stats_.stall_prepares;
        NLOG_WARN("io: no prepared journal segment at index {}: preparing on the write path", v.index());
        if (!prepare_one()) return fatal("segment preparation failed");
        continue;
      }
      if (st == WriterT::Status::BadRecord) return fatal("journal writer refused a record");
      if (st == WriterT::Status::Failed) return fatal("journal write failed");
      break;  // Busy
    }
    if (w_->flush()) did = true;
    note_submitted();
    if (w_->failed()) return fatal("journal write failed");
    const std::uint64_t d = w_->durable_index();
    if (d != durable_) {
      durable_ = d;
      sh_->durable.store(d);
      if (owns_release_) sh_->egress_state.release.store(d);
      note_durable(d);
    }
    typename WriterT::AssignedSegment a;
    while (w_->take_assigned(a)) rename_assigned(a);
    did |= drain_outlog();
    if (w_->prepared_count() < spares_ && w_->in_flight() == 0 && idle_polls_ > 1024) {
      // Housekeeping when idle: keep spares ready so appends never wait for a zero-fill.
      if (!prepare_one()) return fatal("segment preparation failed");
      did = true;
    }
    idle_polls_ = did ? 0 : idle_polls_ + 1;
    return did;
  }

  bool fatal(const char* what) {
    if (!failed_) {
      failed_ = true;
      NLOG_ERROR("io: {}: the node stops (06 §6: never retried)", std::string_view(what));
      sh_->exit_code.store(4);
      sh_->stop.store(true);
    }
    return false;
  }

  bool prepare_one() {
    auto p = prep_->create();
    if (!p) return false;
    ++stats_.segments_prepared;
    return w_->add_prepared(dir_->device(p->handle), p->handle, p->header);
  }

  void rename_assigned(const typename WriterT::AssignedSegment& a) {
    NLOG_INFO("io: journal segment assigned: epoch {} first index {}", a.header.epoch, a.header.first_index);
    if (!dir_->rename(a.handle, journal::segment_file_name(a.header.epoch, a.header.first_index)) || !dir_->sync_dir()) {
      NLOG_WARN("io: could not rename journal segment {} (recovery reads headers, not names)", a.header.first_index);
    }
  }

  bool drain_outlog() {
    const std::size_t n = md::drain_released(sh_->egress, sh_->egress_state, md::kIo, 1024, [&](const md::OutEntry& e) {
      work_.start();
      work_.add();
      if (e.kind == md::OutKind::Itch) {
        if (!out_->itch().append(e.msg)) ++stats_.outlog_errors;
        ++stats_.outlog_itch;
      } else if (e.kind == md::OutKind::Ouch) {
        auto* w = out_->soup(e.session);
        if (w == nullptr || !w->append(e.msg)) ++stats_.outlog_errors;
        ++stats_.outlog_soup;
      } else if (e.kind == md::OutKind::DayEnd) {
        (void)out_->flush_all();
      }
      dirty_ = true;
      return true;
    });
    if (n == 0 && dirty_) {
      // No released input left: make the log readable for replay and re-requests.
      work_.start();
      work_.add();
      if (!out_->flush_all()) ++stats_.outlog_errors;
      ++stats_.outlog_flushes;
      dirty_ = false;
      return true;
    }
    if (stats_.outlog_errors != 0 && !outlog_alarm_) {
      outlog_alarm_ = true;
      NLOG_ERROR("io: output log write failed (derived data: regenerated from the journal at restart)");
    }
    return n != 0;
  }

  // A batch the writer submitted since the last look: its commit is timed from now.
  void note_submitted() {
    const std::uint64_t s = w_->submitted_index();
    if (s == last_submitted_) return;
    if (s < last_submitted_) {  // the writer was repositioned: nothing outstanding
      pending_n_ = 0;
    } else if (pending_n_ < pending_.size()) {
      pending_[(pending_head_ + pending_n_) % pending_.size()] = Pending{s, clock_->now_mono()};
      ++pending_n_;
    }
    last_submitted_ = s;
    ++stats_.batches;
  }

  // Batches up to `d` are durable: their commit times, and once a second a line with the
  // batches, their records and commit times since the last one (11 §3: batch size,
  // commit µs).
  void note_durable(std::uint64_t d) {
    if (pending_n_ == 0) return;
    const Nanos now = clock_->now_mono();
    while (pending_n_ != 0 && pending_[pending_head_].index <= d) {
      const Nanos t = now - pending_[pending_head_].at;
      commit_ring_[commit_count_ % kCommitSamples] = t;
      ++commit_count_;
      sum_commit_ += t;
      max_commit_ = std::max(max_commit_, t);
      ++summary_batches_;
      pending_head_ = (pending_head_ + 1) % pending_.size();
      --pending_n_;
    }
    if (now >= next_summary_) {
      if (summary_batches_ != 0) {
        const std::uint64_t records = stats_.appended - summary_records_;
        NLOG_INFO("io: journal: {} batches, {} records ({} per batch), commit mean {} us max {} us", summary_batches_,
                  records, records / summary_batches_, sum_commit_ / static_cast<Nanos>(summary_batches_) / 1000,
                  max_commit_ / 1000);
      }
      next_summary_ = now + kSummaryEvery;
      summary_batches_ = 0;
      summary_records_ = stats_.appended;
      sum_commit_ = 0;
      max_commit_ = 0;
    }
  }

  struct Pending {
    std::uint64_t index = 0;
    Nanos at = 0;
  };
  static constexpr Nanos kSummaryEvery = 1'000'000'000;

  Shared* sh_;
  DirT* dir_;
  PreparerT* prep_;
  WriterT* w_;
  OutDayT* out_;
  std::size_t spares_;
  bool owns_release_;
  std::uint64_t durable_ = 0;
  bool dirty_ = false;
  bool failed_ = false;
  bool outlog_alarm_ = false;
  std::uint64_t idle_polls_ = 0;
  IoStats stats_{};
  const ClockT* clock_;
  std::array<Pending, 32> pending_{};  // submitted batches not yet durable (the writer's queue depth is at most 16)
  std::size_t pending_head_ = 0, pending_n_ = 0;
  std::uint64_t last_submitted_ = 0;
  std::array<Nanos, kCommitSamples> commit_ring_{};
  std::uint64_t commit_count_ = 0;
  Nanos next_summary_ = 0, sum_commit_ = 0, max_commit_ = 0;
  std::uint64_t summary_batches_ = 0, summary_records_ = 0;
  md::WorkMeter<ClockT> work_;
};

// The production io stage.
using IoStage = BasicIoStage<SegDir, Writer, Preparer, outlog::OutlogDay, NodeClock>;

}  // namespace lle::exch

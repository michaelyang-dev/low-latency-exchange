#pragma once
// Work time of a stage (docs/perf/METHODOLOGY.md §16, T32): the cycle-counter time of
// each poll that processed at least one item, from the start of that poll's first item
// to the end of the poll, and the items processed. The stage threads busy-poll, so
// their CPU time says nothing about work; this does.
//
// Cost: one counter read when a poll starts its first item and one at its end, i.e.
// two reads on a non-empty poll and none on an empty one. The counter is the stage's
// Clock::tsc() (env::ClockLike) and nothing else, so a simulated clock drives it in the
// simulator and the meter never reads a hardware counter there.
//
//   meter.start();          // at an item (only the first call of a poll reads)
//   meter.add(n);           // items processed
//   meter.finish();         // end of poll: a batch with items adds its time
//
// The time before a poll's first item (the empty checks and the receive call that
// produced it) is not counted: it is the price of not reading the counter on empty
// polls. Which units count as items is the stage's (apps/exchanged/metrics.h).
// One thread: a meter belongs to the stage that owns it.
#include <cstdint>

namespace lle::md {

struct WorkStats {
  std::uint64_t tsc = 0;      // counter ticks spent in non-empty batches
  std::uint64_t items = 0;    // items processed in them
  std::uint64_t batches = 0;  // non-empty polls
};

template <class Clock>
class WorkMeter {
 public:
  explicit WorkMeter(const Clock* clock) noexcept : clock_(clock) {}

  void start() noexcept {
    if (open_) return;
    open_ = true;
    t0_ = clock_->tsc();
  }
  void add(std::uint64_t n = 1) noexcept { pending_ += n; }
  void finish() noexcept {
    if (open_) {
      open_ = false;
      if (pending_ != 0) {  // a started poll that processed nothing is not a work batch
        s_.tsc += clock_->tsc() - t0_;
        s_.items += pending_;
        ++s_.batches;
      }
    }
    pending_ = 0;
  }
  [[nodiscard]] const WorkStats& stats() const noexcept { return s_; }

 private:
  const Clock* clock_;
  std::uint64_t t0_ = 0;
  std::uint64_t pending_ = 0;
  bool open_ = false;
  WorkStats s_{};
};

}  // namespace lle::md

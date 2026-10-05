#pragma once
// Ring occupancy for the metrics segment (T20 validity checks, METHODOLOGY §15):
// ring_<R>_{cap,used,hwm,peak,window} for the L2 ring, the egress ring, the two input
// SCQs and (split paired mode) the sequencer's tee.
//
// The ring's owning stage samples it when it publishes its counters (every 1,024 polls
// and at the end of every burst, hosted.h), never on the hot path; hwm and peak are the
// largest samples, not an exact maximum. Windows are 1 s of the node's monotonic clock:
// `peak` is the largest sample of the last completed window and `window` the number of
// completed windows. A reader sampling at least once a second sees every window; a jump
// of more than one between two of its samples means it missed one (or the stage
// published nothing for over a second).
#include <cstdint>

#include "common/types.h"

namespace lle::exch {

struct RingGauge {
  static constexpr Nanos kWindow = 1'000'000'000;

  std::uint64_t cap = 0;     // capacity in the ring's unit (0: the ring is absent)
  std::uint64_t used = 0;    // the last sample
  std::uint64_t hwm = 0;     // largest sample since the node started
  std::uint64_t peak = 0;    // largest sample of the last completed window
  std::uint64_t window = 0;  // completed windows

  void sample(std::uint64_t u, Nanos now) noexcept {
    if (start_ == 0) start_ = now;
    if (now - start_ >= kWindow) {
      const auto n = static_cast<std::uint64_t>((now - start_) / kWindow);
      peak = open_peak_;
      window += n;
      start_ += static_cast<Nanos>(n) * kWindow;
      open_peak_ = 0;
    }
    used = u;
    if (u > hwm) hwm = u;
    if (u > open_peak_) open_peak_ = u;
  }

 private:
  Nanos start_ = 0;
  std::uint64_t open_peak_ = 0;
};

}  // namespace lle::exch

#pragma once
// The node's clock (env::ClockLike). now_real() is exchange time and is read by the
// sequencer only (01 §6: ts_ns is assigned at sequencing; the engine never reads a
// clock). Three modes (config day.clock):
//   Real    CLOCK_REALTIME: production.
//   Offset  CLOCK_REALTIME shifted so the process starts at a chosen time of day:
//           demos of a full day at real speed.
//   Manual  exchange time moves only when the control port's `clock` command walks it
//           forward (the seq stage stamps every due Timer at its scheduled time on the
//           way). Tests use it: with inputs fed in a fixed order, the journal, and with
//           it every output byte, is reproducible run to run (T05).
// now_mono() (timeouts) and tsc() (probes) always follow the hardware.
#include <atomic>
#include <cstdint>

#include "common/types.h"
#include "env/prod_clock.h"
#include "exchanged/config.h"

namespace lle::exch {

class NodeClock {
 public:
  NodeClock(ClockMode mode, Nanos start_unix_ns) noexcept : mode_(mode) {
    const env::ProdClock c;
    offset_ = mode == ClockMode::Offset ? start_unix_ns - c.now_real() : 0;
    manual_.store(start_unix_ns, std::memory_order_relaxed);
  }
  NodeClock(const NodeClock&) = delete;
  NodeClock& operator=(const NodeClock&) = delete;

  [[nodiscard]] Nanos now_mono() const noexcept { return env::ProdClock{}.now_mono(); }
  [[nodiscard]] Nanos now_real() const noexcept {
    if (const Nanos f = frozen_.load(std::memory_order_acquire); f != 0) [[unlikely]] return f;
    switch (mode_) {
      case ClockMode::Real: return env::ProdClock{}.now_real();
      case ClockMode::Offset: return env::ProdClock{}.now_real() + offset_;
      case ClockMode::Manual: return manual_.load(std::memory_order_acquire);
    }
    return 0;
  }
  [[nodiscard]] std::uint64_t tsc() const noexcept { return env::read_tsc(); }

  [[nodiscard]] ClockMode mode() const noexcept { return mode_; }
  // Manual mode: moves forward only. Written by the seq stage alone.
  void set_manual(Nanos t) noexcept {
    if (t > manual_.load(std::memory_order_relaxed)) manual_.store(t, std::memory_order_release);
  }
  [[nodiscard]] Nanos manual() const noexcept { return manual_.load(std::memory_order_acquire); }

  // The day-start records are stamped at a fixed time (local midnight): both data nodes
  // of a pair write them independently and must hold byte-identical journals (10 §3),
  // and a restarted day reproduces them. 0 releases the clock.
  void freeze(Nanos t) noexcept { frozen_.store(t, std::memory_order_release); }

 private:
  ClockMode mode_;
  Nanos offset_ = 0;
  std::atomic<Nanos> manual_{0};
  std::atomic<Nanos> frozen_{0};
};

}  // namespace lle::exch

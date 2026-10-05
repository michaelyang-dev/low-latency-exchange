#pragma once
// Per-node simulated clock (09 §3), satisfying env::ClockLike.
//
//  - now_mono(): virtual time. Never jumps backwards, unaffected by faults
//    (the failure model assumes sane monotonic clocks, 01 §9).
//  - now_real(): epoch + virtual + per-node offset + linear drift (up to
//    +-500 ppm) + accumulated steps (up to +-1 s each). Offset, drift and steps
//    are non-zero only when the clock fault class is enabled.
//  - tsc(): a 3 GHz cycle counter derived from virtual time.
#include <cstdint>

#include "common/int128.h"
#include "common/types.h"
#include "env/concepts.h"
#include "sim/world.h"

namespace lle::sim {

struct ClockParams {
  Nanos offset_ns = 0;     // initial realtime offset
  std::int64_t drift_ppb = 0;  // realtime rate error, parts per billion
  std::uint64_t tsc_base = 0;
};

// 2026-09-30T13:30:00Z: realtime epoch for every simulated node.
inline constexpr Nanos kSimEpochRealNs = 1'790'775'000'000'000'000;
inline constexpr std::uint64_t kTscPerNs = 3;

class Clock {
 public:
  Clock(const World& w, const ClockParams& p) noexcept : w_(&w), p_(p) {}

  [[nodiscard]] Nanos now_mono() const noexcept { return w_->now(); }
  [[nodiscard]] Nanos now_real() const noexcept { return real_at(now_mono()); }
  [[nodiscard]] std::uint64_t tsc() const noexcept {
    return p_.tsc_base + static_cast<std::uint64_t>(now_mono()) * kTscPerNs;
  }

  // Realtime this clock would report at virtual time t (for tests/oracles).
  [[nodiscard]] Nanos real_at(Nanos t) const noexcept {
    const auto drift = static_cast<Nanos>((static_cast<i128>(t) * p_.drift_ppb) / 1'000'000'000);
    return kSimEpochRealNs + t + p_.offset_ns + drift + steps_ns_;
  }

  // Clock fault: realtime jumps by delta (may be negative).
  void step(Nanos delta) noexcept {
    steps_ns_ += delta;
    ++steps_;
  }

  [[nodiscard]] const ClockParams& params() const noexcept { return p_; }
  [[nodiscard]] Nanos steps_total_ns() const noexcept { return steps_ns_; }
  [[nodiscard]] std::uint64_t step_count() const noexcept { return steps_; }

 private:
  const World* w_;
  ClockParams p_;
  Nanos steps_ns_ = 0;
  std::uint64_t steps_ = 0;
};

static_assert(env::ClockLike<Clock>);

}  // namespace lle::sim

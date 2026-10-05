#pragma once
// Stage latency probes (11-logging-observability §3 "Latency probes"): per-stage
// counter stamps (rx, sequenced, engine-applied, released, tx) are sampled 1 in N
// and the deltas recorded, in nanoseconds, into a stage's HDR histogram in the
// metrics segment. Single writer (the stage's thread), no allocation, integer
// arithmetic only: ticks are converted with a 32.32 fixed-point multiplier.
//
//   StageProbe probe(seg.histogram("engine_apply_ns"), 64, tsc_hz);
//   if (probe.sample()) { const auto t0 = read_tsc(); ...; probe.record_ticks(read_tsc() - t0); }
//   // or, with stamps carried in the message: probe.record_span(msg.rx_tsc, now_tsc);
#include <cstdint>

#include "common/int128.h"
#include "metrics/segment.h"

namespace lle::metrics {

class StageProbe {
 public:
  StageProbe() = default;
  // `sample_every` is rounded up to a power of two (1 = every event).
  StageProbe(Histogram h, std::uint32_t sample_every, std::uint64_t tsc_hz) noexcept
      : h_(h), mask_(pow2_at_least(sample_every) - 1), ns_per_tick_q32_(q32(tsc_hz)) {}

  // True for one event in N (deterministic: every N-th call).
  [[nodiscard]] bool sample() noexcept { return (n_++ & mask_) == 0; }

  void record_ticks(std::uint64_t ticks) noexcept { h_.record(to_ns(ticks)); }

  // Records end - start if the event is sampled; a backwards span records 0.
  void record_span(std::uint64_t start_tsc, std::uint64_t end_tsc) noexcept {
    if (sample()) record_ticks(end_tsc >= start_tsc ? end_tsc - start_tsc : 0);
  }

  [[nodiscard]] std::int64_t to_ns(std::uint64_t ticks) const noexcept {
    const u128 ns = (static_cast<u128>(ticks) * ns_per_tick_q32_ + (u128{1} << 31)) >> 32;  // rounded
    return ns > static_cast<u128>(INT64_MAX) ? INT64_MAX : static_cast<std::int64_t>(ns);
  }
  [[nodiscard]] std::uint64_t events() const noexcept { return n_; }

 private:
  static constexpr std::uint64_t pow2_at_least(std::uint32_t v) noexcept {
    std::uint64_t p = 1;
    while (p < v) p <<= 1;
    return p;
  }
  // ns per tick in 32.32 fixed point, rounded: (1e9 * 2^32 + hz / 2) / hz.
  static constexpr std::uint64_t q32(std::uint64_t hz) noexcept {
    return hz == 0 ? 0 : static_cast<std::uint64_t>(((static_cast<u128>(1'000'000'000) << 32) + hz / 2) / hz);
  }

  Histogram h_;
  std::uint64_t mask_ = 0;
  std::uint64_t ns_per_tick_q32_ = 0;
  std::uint64_t n_ = 0;
};

}  // namespace lle::metrics

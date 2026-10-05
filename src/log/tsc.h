#pragma once
// Cycle-counter helpers for nlog: frequency, calibration samples that map the
// counter to CLOCK_REALTIME, and the granularity probe used by the T31 coarse-TSC
// rule (11-logging-observability §2). Cold-path only.
#include <cstddef>
#include <cstdint>

namespace lle::nlog {

// Counter frequency in Hz. arm64: CNTFRQ_EL0 (exact). x86-64: measured once
// against CLOCK_MONOTONIC_RAW over ~20 ms and cached. Other: 1e9 (the fallback
// counter is clock_gettime nanoseconds).
[[nodiscard]] std::uint64_t tsc_hz() noexcept;

struct CalibrationSample {
  std::uint64_t tsc = 0;          // counter value at the midpoint of the read window
  std::int64_t realtime_ns = 0;   // CLOCK_REALTIME, ns since the UNIX epoch
  std::uint32_t window_ticks = 0;  // counter ticks spanned by the clock read
};

// Best (narrowest window) of a few counter/CLOCK_REALTIME pairings.
[[nodiscard]] CalibrationSample take_calibration_sample() noexcept;

struct TscGranularity {
  std::uint64_t hz = 0;              // counter frequency
  double tick_ns = 0.0;              // 1e9 / hz
  std::uint64_t min_step_ticks = 0;  // smallest non-zero difference between consecutive reads
  double min_step_ns = 0.0;          // min_step_ticks * tick_ns
  double read_cost_ns = 0.0;         // mean cost of one back-to-back read (wall clock)
  double zero_delta_fraction = 0.0;  // fraction of consecutive reads that returned the same value
  std::size_t samples = 0;
};

// Reads the counter back to back `samples` times. A min_step_ns above 1 ns means a
// single-call median cannot resolve a ~9 ns event (the T31 coarse-TSC rule then
// makes the mean of per-call deltas the headline).
[[nodiscard]] TscGranularity tsc_granularity_probe(std::size_t samples = 1'000'000) noexcept;

}  // namespace lle::nlog

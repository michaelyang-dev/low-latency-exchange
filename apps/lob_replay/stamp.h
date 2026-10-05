#pragma once
// Cycle-counter stamps for the sampled, block and all modes (04-order-book §5,
// 12 §3 "Definitions"). x86-64: LFENCE;RDTSC;LFENCE before the measured
// region and RDTSCP;LFENCE after it, so neither stamp drifts into the region.
// arm64: ISB around CNTVCT_EL0 reads. That counter ticks at 24 MHz on Apple
// parts (41.7 ns), which the coarse-TSC rule covers. Mac numbers are never
// published.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace lle::replay {

[[gnu::always_inline]] inline std::uint64_t stamp_begin() noexcept {
#if defined(__x86_64__)
  _mm_lfence();
  const std::uint64_t t = __rdtsc();
  _mm_lfence();
  return t;
#elif defined(__aarch64__)
  std::uint64_t t;
  asm volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(t)::"memory");
  return t;
#else
  return static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

[[gnu::always_inline]] inline std::uint64_t stamp_end() noexcept {
#if defined(__x86_64__)
  unsigned aux;
  const std::uint64_t t = __rdtscp(&aux);
  _mm_lfence();
  return t;
#elif defined(__aarch64__)
  std::uint64_t t;
  asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(t)::"memory");
  return t;
#else
  return static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

// Counter frequency. arm64 reads CNTFRQ_EL0. Elsewhere it is measured against
// steady_clock over `ms` milliseconds, which is enough for a 1e-4 relative error.
inline double counter_hz(int ms = 200) {
#if defined(__aarch64__)
  (void)ms;
  std::uint64_t f;
  asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
  return static_cast<double>(f);
#else
  using C = std::chrono::steady_clock;
  const auto t0 = C::now();
  const std::uint64_t c0 = stamp_begin();
  while (C::now() - t0 < std::chrono::milliseconds(ms)) {
  }
  const std::uint64_t c1 = stamp_end();
  const auto t1 = C::now();
  const double ns = static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
  return static_cast<double>(c1 - c0) * 1e9 / ns;
#endif
}

struct Granularity {
  std::uint64_t min_step_ticks = 0;  // smallest non-zero difference between consecutive reads
  double zero_delta_fraction = 0;    // fraction of consecutive reads that were equal
};

inline Granularity probe_granularity(std::size_t samples = 1'000'000) {
  Granularity g;
  std::uint64_t prev = stamp_begin(), zeros = 0, best = ~std::uint64_t{0};
  for (std::size_t i = 0; i < samples; ++i) {
    const std::uint64_t t = stamp_begin();
    const std::uint64_t d = t - prev;
    if (d == 0) ++zeros;
    else best = std::min(best, d);
    prev = t;
  }
  g.min_step_ticks = best == ~std::uint64_t{0} ? 0 : best;
  g.zero_delta_fraction = static_cast<double>(zeros) / static_cast<double>(samples);
  return g;
}

// Exact order statistics of a sample (nearest-rank).
class Quantiles {
 public:
  explicit Quantiles(std::vector<std::uint32_t> v) : v_(std::move(v)) { std::sort(v_.begin(), v_.end()); }
  [[nodiscard]] bool empty() const noexcept { return v_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return v_.size(); }
  [[nodiscard]] double at(double q) const noexcept {
    if (v_.empty()) return 0;
    const auto idx = static_cast<std::size_t>(q * static_cast<double>(v_.size() - 1) + 0.5);
    return v_[std::min(idx, v_.size() - 1)];
  }
  [[nodiscard]] double max() const noexcept { return v_.empty() ? 0 : v_.back(); }
  [[nodiscard]] double mean() const noexcept {
    if (v_.empty()) return 0;
    long double s = 0;
    for (std::uint32_t x : v_) s += x;
    return static_cast<double>(s / static_cast<long double>(v_.size()));
  }

 private:
  std::vector<std::uint32_t> v_;
};

}  // namespace lle::replay

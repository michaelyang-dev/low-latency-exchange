#include "log/tsc.h"

#include <ctime>

#include "common/int128.h"
#include "env/prod_clock.h"

namespace lle::nlog {
namespace {

std::int64_t clock_ns(clockid_t id) noexcept {
  timespec ts{};
  clock_gettime(id, &ts);
  return static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}

std::uint64_t measure_hz() noexcept {
#if defined(__aarch64__)
  std::uint64_t f = 0;
  asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
  return f;
#elif defined(__x86_64__)
  // Busy-wait ~20 ms against the raw monotonic clock; enough for ~1e-4 relative
  // accuracy, refined later by the decoder's interpolation between calibrations.
  const std::int64_t n0 = clock_ns(CLOCK_MONOTONIC_RAW);
  const std::uint64_t t0 = env::read_tsc();
  std::int64_t n1 = n0;
  while (n1 - n0 < 20'000'000) n1 = clock_ns(CLOCK_MONOTONIC_RAW);
  const std::uint64_t t1 = env::read_tsc();
  const auto dt = static_cast<lle::u128>(t1 - t0) * 1'000'000'000u;
  return static_cast<std::uint64_t>(dt / static_cast<std::uint64_t>(n1 - n0));
#else
  return 1'000'000'000;
#endif
}

}  // namespace

std::uint64_t tsc_hz() noexcept {
  static const std::uint64_t hz = measure_hz();
  return hz;
}

CalibrationSample take_calibration_sample() noexcept {
  CalibrationSample best{};
  std::uint64_t best_window = ~std::uint64_t{0};
  for (int i = 0; i < 8; ++i) {
    const std::uint64_t t0 = env::read_tsc();
    const std::int64_t real = clock_ns(CLOCK_REALTIME);
    const std::uint64_t t1 = env::read_tsc();
    const std::uint64_t w = t1 - t0;
    if (w < best_window) {
      best_window = w;
      best.tsc = t0 + w / 2;
      best.realtime_ns = real;
      best.window_ticks = w > 0xFFFF'FFFFu ? 0xFFFF'FFFFu : static_cast<std::uint32_t>(w);
    }
  }
  return best;
}

TscGranularity tsc_granularity_probe(std::size_t samples) noexcept {
  TscGranularity g;
  g.hz = tsc_hz();
  g.tick_ns = g.hz != 0 ? 1e9 / static_cast<double>(g.hz) : 0.0;
  g.samples = samples;
  if (samples < 2) return g;
  std::uint64_t min_step = ~std::uint64_t{0};
  std::size_t zeros = 0;
  const std::int64_t w0 = clock_ns(CLOCK_MONOTONIC);
  std::uint64_t prev = env::read_tsc();
  for (std::size_t i = 1; i < samples; ++i) {
    const std::uint64_t now = env::read_tsc();
    const std::uint64_t d = now - prev;
    if (d == 0) {
      ++zeros;
    } else if (d < min_step) {
      min_step = d;
    }
    prev = now;
  }
  const std::int64_t w1 = clock_ns(CLOCK_MONOTONIC);
  g.min_step_ticks = min_step == ~std::uint64_t{0} ? 0 : min_step;
  g.min_step_ns = static_cast<double>(g.min_step_ticks) * g.tick_ns;
  g.read_cost_ns = static_cast<double>(w1 - w0) / static_cast<double>(samples);
  g.zero_delta_fraction = static_cast<double>(zeros) / static_cast<double>(samples - 1);
  return g;
}

}  // namespace lle::nlog

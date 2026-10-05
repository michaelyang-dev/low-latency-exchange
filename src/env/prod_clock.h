#pragma once
// Production clock: monotonic/realtime from the OS, cycle counter from the CPU.
// Not usable from deterministic code (the purity audit rejects these symbols
// in sim builds).
#include <cstdint>
#include <ctime>

#include "common/types.h"

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace lle::env {

[[nodiscard]] inline std::uint64_t read_tsc() noexcept {
#if defined(__x86_64__)
  return __rdtsc();
#elif defined(__aarch64__)
  std::uint64_t v;
  asm volatile("mrs %0, cntvct_el0" : "=r"(v));
  return v;
#else
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<std::uint64_t>(ts.tv_sec) * 1'000'000'000ull + static_cast<std::uint64_t>(ts.tv_nsec);
#endif
}

struct ProdClock {
  [[nodiscard]] Nanos now_mono() const noexcept { return read(CLOCK_MONOTONIC_RAW); }
  [[nodiscard]] Nanos now_real() const noexcept { return read(CLOCK_REALTIME); }
  [[nodiscard]] std::uint64_t tsc() const noexcept { return read_tsc(); }

 private:
  static Nanos read(clockid_t id) noexcept {
    timespec ts{};
    clock_gettime(id, &ts);
    return static_cast<Nanos>(ts.tv_sec) * kNsPerSec + ts.tv_nsec;
  }
};

}  // namespace lle::env

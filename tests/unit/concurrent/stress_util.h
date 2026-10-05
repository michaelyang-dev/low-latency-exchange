#pragma once
// Helpers for the multi-threaded queue stress tests (08-concurrency-runtime §8).
#include <cstdint>
#include <cstdlib>
#include <thread>

#include "common/prng.h"
#include "concurrent/wait.h"

namespace lle::conc::test {

#if defined(__SANITIZE_THREAD__)
inline constexpr bool kTsan = true;
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
inline constexpr bool kTsan = true;
#else
inline constexpr bool kTsan = false;
#endif
#else
inline constexpr bool kTsan = false;
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_MEMORY__)
inline constexpr bool kOtherSanitizer = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
inline constexpr bool kOtherSanitizer = true;
#else
inline constexpr bool kOtherSanitizer = false;
#endif
#else
inline constexpr bool kOtherSanitizer = false;
#endif

#if defined(LLE_STRESS_LONG)
inline constexpr bool kLongRun = true;  // concurrent_stress_long_test (ctest label "stress")
#else
inline constexpr bool kLongRun = false;  // concurrent_stress_test (ctest label "unit")
#endif

// Item count for a stress run. The long binary always runs `full` (no scaling of any
// kind: it is the evidence run of docs/verification/queues-stress.md). The default
// binary runs `quick`, divided by 4 under sanitizers, so Debug/ASan/TSan unit runs stay
// far below the ctest timeout even on a loaded machine; LLE_STRESS_SCALE (a positive
// divisor) shrinks it further for local runs.
inline std::uint64_t stress_items(std::uint64_t full, std::uint64_t quick) {
  if (kLongRun) return full;
  std::uint64_t n = quick;
  if (kTsan || kOtherSanitizer) n /= 4;
  if (const char* s = std::getenv("LLE_STRESS_SCALE")) {
    const long long d = std::atoll(s);
    if (d > 1) n /= static_cast<std::uint64_t>(d);
  }
  return n == 0 ? 1 : n;
}

// Random producer/consumer pauses: mostly none, sometimes a short spin, rarely a
// yield (which on a loaded machine can deschedule the thread mid-stream). Seeded, so
// the decision sequence is reproducible; the interleaving of course is not.
//
// LLE_STRESS_SEED_OFFSET varies the pause sequences between repeated runs (shards of the
// T28 accumulation, tools/stress/run_shards.py) without editing the tests.
inline std::uint64_t seed_offset() {
  if (const char* s = std::getenv("LLE_STRESS_SEED_OFFSET")) return std::strtoull(s, nullptr, 10);
  return 0;
}

class Pauser {
 public:
  explicit Pauser(std::uint64_t seed) : rng_(seed + 0x9E37'79B9'7F4A'7C15ull * seed_offset()) {}
  void maybe_pause() {
    const std::uint64_t r = rng_.below(4096);
    if (r < 4064) return;
    if (r < 4094) {
      const std::uint64_t spins = rng_.below(256);
      for (std::uint64_t i = 0; i < spins; ++i) cpu_relax();
      return;
    }
    std::this_thread::yield();
  }

 private:
  Prng rng_;
};

// Waiting on a full/empty queue in tests: yield-based so oversubscribed CI and TSan
// make progress.
inline void wait_a_bit(Backoff& b) { b.wait(); }

}  // namespace lle::conc::test

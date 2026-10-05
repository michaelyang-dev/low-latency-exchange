#pragma once
// Integer-only distributions for the simulator. std:: distributions are
// implementation-defined and floating point is banned from decisions
// (01-architecture §5), so these are built from lle::Prng with fixed-point math.
//
// Every helper consumes the same number of raw draws regardless of its
// parameters (a zero probability still draws), so turning a fault off does not
// shift the stream for the draws that follow.
#include <bit>
#include <cstdint>

#include "common/int128.h"
#include "common/prng.h"
#include "common/types.h"

namespace lle::sim {

inline constexpr std::uint64_t kPpm = 1'000'000;
inline constexpr Nanos kUs = 1'000;
inline constexpr Nanos kMs = 1'000'000;
inline constexpr Nanos kSec = 1'000'000'000;

// -ln(x / 2^64) in Q16 fixed point for x in [1, 2^64). log2 is computed by
// repeated squaring of the normalized mantissa (16 fractional bits).
[[nodiscard]] constexpr std::uint64_t neg_ln_q16(std::uint64_t x) noexcept {
  if (x == 0) x = 1;
  const int e = 63 - std::countl_zero(x);
  std::uint64_t m = e >= 31 ? (x >> (e - 31)) : (x << (31 - e));  // Q1.31 in [2^31, 2^32)
  std::uint64_t frac = 0;
  for (int i = 15; i >= 0; --i) {
    m = (m * m) >> 31;
    if (m >= (1ull << 32)) {
      m >>= 1;
      frac |= 1ull << i;
    }
  }
  const std::uint64_t log2_q16 = (static_cast<std::uint64_t>(e) << 16) + frac;
  const std::uint64_t neg_log2_q16 = (64ull << 16) - log2_q16;
  return (neg_log2_q16 * 45426ull) >> 16;  // * ln(2) in Q16
}

// True with probability ppm / 10^6. Always one draw.
[[nodiscard]] constexpr bool chance_ppm(Prng& r, std::uint64_t ppm) noexcept { return r.below(kPpm) < ppm; }

// Exponential sample with the given mean. Always one draw; 0 when mean <= 0.
[[nodiscard]] constexpr Nanos exp_ns(Prng& r, Nanos mean) noexcept {
  const std::uint64_t x = r.next_u64();
  if (mean <= 0) return 0;
  const auto prod = static_cast<u128>(static_cast<std::uint64_t>(mean)) * neg_ln_q16(x);
  return static_cast<Nanos>(prod >> 16);
}

// Uniform in [lo, hi] (inclusive). Always one draw; lo when hi <= lo.
[[nodiscard]] constexpr std::int64_t uniform(Prng& r, std::int64_t lo, std::int64_t hi) noexcept {
  if (hi <= lo) {
    (void)r.next_u64();
    return lo;
  }
  return r.range(lo, hi);
}

// Approximately log-uniform in [lo, hi]: a uniformly chosen octave, then
// uniform inside it. Two draws.
[[nodiscard]] constexpr std::int64_t log_uniform(Prng& r, std::int64_t lo, std::int64_t hi) noexcept {
  if (lo < 1) lo = 1;
  if (hi <= lo) {
    (void)r.next_u64();
    (void)r.next_u64();
    return lo;
  }
  int octaves = 0;
  while (octaves < 62 && (lo << (octaves + 1)) <= hi) ++octaves;
  const auto b = static_cast<int>(r.below(static_cast<std::uint64_t>(octaves) + 1));
  const std::int64_t base = lo << b;
  const std::int64_t top = (base << 1) - 1 < hi ? (base << 1) - 1 : hi;
  return uniform(r, base, top);
}

// Scales v by pct/100 using 128-bit intermediate math.
[[nodiscard]] constexpr std::int64_t scale_pct(std::int64_t v, std::int64_t pct) noexcept {
  return static_cast<std::int64_t>((static_cast<i128>(v) * pct) / 100);
}

}  // namespace lle::sim

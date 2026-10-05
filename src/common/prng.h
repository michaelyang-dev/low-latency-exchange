#pragma once
// Deterministic PRNGs (01-architecture §5): never use std distributions,
// whose algorithms are implementation-defined.
#include <cstdint>

#include "common/int128.h"

namespace lle {

// SplitMix64: seeding and stream derivation.
class SplitMix64 {
 public:
  constexpr explicit SplitMix64(std::uint64_t seed) noexcept : s_(seed) {}
  constexpr std::uint64_t next() noexcept {
    std::uint64_t z = (s_ += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }

 private:
  std::uint64_t s_;
};

// xoshiro256** 1.0 (Blackman & Vigna).
class Prng {
 public:
  constexpr explicit Prng(std::uint64_t seed = 0x5EED) noexcept { reseed(seed); }

  constexpr void reseed(std::uint64_t seed) noexcept {
    SplitMix64 sm(seed);
    for (auto& w : s_) w = sm.next();
  }

  constexpr std::uint64_t next_u64() noexcept {
    const std::uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const std::uint64_t t = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);
    return result;
  }
  constexpr std::uint64_t operator()() noexcept { return next_u64(); }

  // Uniform in [0, n) without modulo bias (Lemire's method). n must be > 0.
  constexpr std::uint64_t below(std::uint64_t n) noexcept {
    std::uint64_t x = next_u64();
    u128 m = static_cast<u128>(x) * n;
    auto l = static_cast<std::uint64_t>(m);
    if (l < n) {
      const std::uint64_t t = (0 - n) % n;
      while (l < t) {
        x = next_u64();
        m = static_cast<u128>(x) * n;
        l = static_cast<std::uint64_t>(m);
      }
    }
    return static_cast<std::uint64_t>(m >> 64);
  }

  // Uniform in [lo, hi] (inclusive).
  constexpr std::int64_t range(std::int64_t lo, std::int64_t hi) noexcept {
    return lo + static_cast<std::int64_t>(below(static_cast<std::uint64_t>(hi - lo) + 1));
  }

  // True with probability num/den (integer ratio; no floating point).
  constexpr bool chance(std::uint64_t num, std::uint64_t den) noexcept { return below(den) < num; }

  // Derive an independent stream (e.g. per subsystem in the simulator).
  [[nodiscard]] constexpr Prng fork(std::uint64_t stream_id) noexcept {
    SplitMix64 sm(next_u64() ^ (stream_id * 0xD1B54A32D192ED03ull));
    return Prng(sm.next());
  }

 private:
  static constexpr std::uint64_t rotl(std::uint64_t x, int k) noexcept { return (x << k) | (x >> (64 - k)); }
  std::uint64_t s_[4]{};
};

}  // namespace lle

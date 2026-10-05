#pragma once
// Seed derivation for the simulator (09 §4).
//
// One 64-bit master seed feeds independent SplitMix-derived streams, one per
// subsystem. A stream's seed is a pure function of (master, stream, sub), never
// of how many values another stream consumed, so disabling one fault class or
// adding traffic on one link leaves every other stream bit-identical. That is
// what makes fault-class ablation a valid shrinking step.
#include <cstdint>

#include "common/hash.h"
#include "common/prng.h"

namespace lle::sim {

enum class Stream : std::uint64_t {
  Workload = 1,
  Network = 2,
  Disk = 3,
  Process = 4,
  Clock = 5,
  Scheduler = 6,
  Buggify = 7,
  Swarm = 8,
};

[[nodiscard]] constexpr std::uint64_t derive_seed(std::uint64_t master, Stream s, std::uint64_t sub = 0) noexcept {
  SplitMix64 outer(master ^ (static_cast<std::uint64_t>(s) * 0x9E3779B97F4A7C15ull));
  SplitMix64 inner(outer.next() ^ mix64(sub + 0x632BE59BD9B4E019ull));
  return inner.next();
}

// sim::Rng satisfies env::RngLike (next_u64). It is xoshiro256** (lle::Prng)
// seeded from a derived stream, so component code sees the same type in tests.
using Rng = Prng;

[[nodiscard]] inline Rng make_rng(std::uint64_t master, Stream s, std::uint64_t sub = 0) noexcept {
  return Rng(derive_seed(master, s, sub));
}

}  // namespace lle::sim

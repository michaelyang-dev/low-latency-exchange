#pragma once
// Seeded open-loop arrival times (plan 12 §5: schedules are precomputed and never
// depend on responses). Exponential inter-arrival gaps come from a 4,096-entry quantile
// table in 20-bit fixed point, computed once with std::log and rounded, so a schedule
// depends only on its seed (the rounding absorbs last-ulp differences between libms).
// Used by loadgen's message schedule and ttt_harness's trigger schedule.
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "common/int128.h"
#include "common/prng.h"
#include "common/types.h"

namespace lle::client {

// E[i] = -ln((i + 0.5) / 4096) * 2^20.
struct ExpTable {
  std::array<std::uint64_t, 4096> e{};
  ExpTable() {
    for (std::size_t i = 0; i < e.size(); ++i) {
      const double u = (static_cast<double>(i) + 0.5) / static_cast<double>(e.size());
      e[i] = static_cast<std::uint64_t>(std::llround(-std::log(u) * static_cast<double>(1u << 20)));
    }
  }
  static const ExpTable& get() {
    static const ExpTable t;
    return t;
  }
};

// Arrival times in ns from 0 at `rate` per second: Poisson (exponential gaps) or a
// constant rate. next() is non-decreasing.
class Arrivals {
 public:
  Arrivals(std::uint64_t seed, std::uint64_t rate, bool poisson = true)
      : rng_(seed), mean_fp_((static_cast<u128>(kNsPerSec) << 20) / (rate == 0 ? 1 : rate)), poisson_(poisson) {}

  Nanos next() noexcept {
    const ExpTable& t = ExpTable::get();
    t_fp_ += poisson_ ? mean_fp_ * t.e[rng_.below(t.e.size())] >> 20 : mean_fp_;
    return static_cast<Nanos>(t_fp_ >> 20);
  }

 private:
  Prng rng_;
  u128 mean_fp_;
  u128 t_fp_ = 0;
  bool poisson_;
};

}  // namespace lle::client

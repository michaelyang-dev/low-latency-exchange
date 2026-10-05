#pragma once
// Fixed-size base-2 histogram for arbiter metrics (A/B skew, re-request RTT).
// Integer-only and allocation-free; quantiles are reported as bucket upper
// bounds, which is what sizing a timer from "2x p99.9" needs.
#include <array>
#include <bit>
#include <cstdint>

#include "common/int128.h"

namespace lle::mold {

class Log2Histogram {
 public:
  static constexpr std::size_t kBuckets = 65;  // bucket 0 holds 0; bucket i holds [2^(i-1), 2^i)

  constexpr void add(std::uint64_t v) noexcept {
    ++b_[bucket(v)];
    ++n_;
    if (v > max_) max_ = v;
    if (n_ == 1 || v < min_) min_ = v;
  }

  [[nodiscard]] constexpr std::uint64_t count() const noexcept { return n_; }
  [[nodiscard]] constexpr std::uint64_t max() const noexcept { return max_; }
  [[nodiscard]] constexpr std::uint64_t min() const noexcept { return n_ != 0 ? min_ : 0; }
  [[nodiscard]] constexpr std::uint64_t bucket_count(std::size_t i) const noexcept { return b_[i]; }

  // Upper bound of the smallest bucket at which the cumulative count reaches
  // ppm parts per million of all samples (never above the observed maximum).
  [[nodiscard]] constexpr std::uint64_t quantile_upper(std::uint64_t ppm) const noexcept {
    if (n_ == 0) return 0;
    const u128 want128 = (static_cast<u128>(n_) * ppm + 999'999) / 1'000'000;
    const std::uint64_t want = want128 == 0 ? 1 : static_cast<std::uint64_t>(want128);
    std::uint64_t cum = 0;
    for (std::size_t i = 0; i < kBuckets; ++i) {
      cum += b_[i];
      if (cum >= want) {
        const std::uint64_t upper = i == 0 ? 0 : (i >= 64 ? ~std::uint64_t{0} : (std::uint64_t{1} << i) - 1);
        return upper < max_ ? upper : max_;
      }
    }
    return max_;
  }

  constexpr void reset() noexcept { *this = Log2Histogram{}; }

  [[nodiscard]] static constexpr std::size_t bucket(std::uint64_t v) noexcept {
    return v == 0 ? 0 : static_cast<std::size_t>(64 - std::countl_zero(v));
  }

 private:
  std::array<std::uint64_t, kBuckets> b_{};
  std::uint64_t n_ = 0, max_ = 0, min_ = 0;
};

}  // namespace lle::mold

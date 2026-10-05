#pragma once
// Clock-domain rule (07 §2.5, T17): every reported interval subtracts two hardware
// timestamps taken by the SAME PHC. Each mlx5 PCI function has its own PHC unless real-
// time clock mode is on, so stamps from two ports are not comparable by default. Stamps
// carry the PHC index of the port that produced them (hwts::TsInfo::phc_index); an
// interval across PHCs, or involving a software or missing stamp, is refused and
// counted instead of computed. Integer-only; allocation-free.
#include <cstdint>
#include <expected>

#include "common/types.h"

namespace lle::net::hwts {

struct PhcStamp {
  int phc = -1;    // PHC index of the stamping port; -1 = not a hardware stamp
  Nanos ns = 0;    // raw PHC time; 0 = missing
};

enum class IntervalError : std::uint8_t { Missing, Software, CrossPhc };

[[nodiscard]] constexpr std::expected<Nanos, IntervalError> phc_interval(PhcStamp later, PhcStamp earlier) noexcept {
  if (later.ns == 0 || earlier.ns == 0) return std::unexpected(IntervalError::Missing);
  if (later.phc < 0 || earlier.phc < 0) return std::unexpected(IntervalError::Software);
  if (later.phc != earlier.phc) return std::unexpected(IntervalError::CrossPhc);
  return later.ns - earlier.ns;
}

// Per-run accounting of attempted intervals (published with every result).
struct IntervalAccounting {
  std::uint64_t ok = 0;
  std::uint64_t missing = 0;
  std::uint64_t software = 0;
  std::uint64_t cross_phc = 0;

  // Records the outcome; returns the interval when it is valid.
  constexpr std::expected<Nanos, IntervalError> record(PhcStamp later, PhcStamp earlier) noexcept {
    const auto r = phc_interval(later, earlier);
    if (r) {
      ++ok;
    } else if (r.error() == IntervalError::Missing) {
      ++missing;
    } else if (r.error() == IntervalError::Software) {
      ++software;
    } else {
      ++cross_phc;
    }
    return r;
  }
  [[nodiscard]] constexpr std::uint64_t total() const noexcept { return ok + missing + software + cross_phc; }
  // 07 §2.5: ≥ 99.9% hardware pairs, no software stamp, and (clock-domain rule) no
  // cross-PHC subtraction.
  [[nodiscard]] constexpr bool valid() const noexcept {
    return total() > 0 && software == 0 && cross_phc == 0 && ok * 1000 >= total() * 999;
  }
};

}  // namespace lle::net::hwts

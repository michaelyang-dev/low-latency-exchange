#pragma once
// LULD price bands (the Limit Up-Limit Down Plan; R2 D2.4/D3.1), computed the
// way the engine's band feed needs them: the engine never computes bands, it
// receives Admin LuldBands records (docs/design/market-model.md). The
// luld_feed simulator drives this from a trade stream. Deterministic integer
// arithmetic; prices are PxE4; times are ns since local midnight.
//
// Model (documented choices where the Plan leaves room):
//  - Bands apply 09:30:00-16:00:00.
//  - Reference price: the first trade at or after 09:30 (the opening print);
//    then the arithmetic mean of the trades of the preceding 5 minutes
//    (rounded half up), adopted only when it moves 1% or more from the
//    reference in effect. No trades in the window: the reference stays.
//  - Percentage parameters: reference above $3.00: Tier 1 5%, Tier 2 10%;
//    $0.75-$3.00: 20%; below $0.75: the lesser of $0.15 or 75%. All doubled
//    09:30-09:45 and 15:35-16:00.
//  - Bands are rounded to the nearest $0.01 (to the nearest $0.0001 for a
//    reference below $1.00); the lower band is at least $0.0001.
#include <cstdint>
#include <deque>
#include <utility>
#include <optional>

#include "common/types.h"

namespace lle::admin {

struct LuldBands {
  PxE4 lower = 0;
  PxE4 upper = 0;
  PxE4 reference = 0;
  friend bool operator==(const LuldBands&, const LuldBands&) = default;
};

// Bands around `reference` for a tier ('1' or '2') at time `t`.
[[nodiscard]] LuldBands luld_bands(PxE4 reference, char tier, Nanos t) noexcept;

class LuldSymbol {
 public:
  explicit LuldSymbol(char tier = '2') noexcept : tier_(tier) {}

  // A trade; returns new bands when they change.
  std::optional<LuldBands> on_trade(Nanos t, PxE4 px);
  // The clock (doubling windows begin and end); returns new bands when they change.
  std::optional<LuldBands> on_time(Nanos t);
  [[nodiscard]] const LuldBands& bands() const noexcept { return bands_; }

 private:
  std::optional<LuldBands> publish(Nanos t);

  char tier_;
  PxE4 ref_ = 0;
  std::deque<std::pair<Nanos, PxE4>> window_;  // trades of the last 5 minutes
  std::int64_t sum_ = 0;
  LuldBands bands_{};
};

}  // namespace lle::admin

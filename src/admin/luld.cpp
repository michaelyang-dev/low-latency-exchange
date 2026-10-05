#include "admin/luld.h"

#include <algorithm>

#include "common/time.h"

namespace lle::admin {

namespace {
constexpr Nanos kOpen = hms_ns(9, 30, 0);
constexpr Nanos kClose = hms_ns(16, 0, 0);
constexpr Nanos kWindow = 5 * 60 * kNsPerSec;

bool doubled(Nanos t) noexcept {
  return (t >= kOpen && t < hms_ns(9, 45, 0)) || (t >= hms_ns(15, 35, 0) && t < kClose);
}

// To the nearest multiple of `unit`, half up.
PxE4 round_to(PxE4 v, PxE4 unit) noexcept { return (v + unit / 2) / unit * unit; }
}  // namespace

LuldBands luld_bands(PxE4 ref, char tier, Nanos t) noexcept {
  LuldBands b;
  b.reference = ref;
  if (ref <= 0) return b;
  const int mult = doubled(t) ? 2 : 1;
  PxE4 delta = 0;
  if (ref > 30'000) {
    delta = ref * (tier == '1' ? 5 : 10) * mult / 100;
  } else if (ref >= 7'500) {
    delta = ref * 20 * mult / 100;
  } else {
    delta = std::min<PxE4>(1'500 * mult, ref * 75 * mult / 100);
  }
  const PxE4 unit = ref >= 10'000 ? 100 : 1;
  b.lower = std::max<PxE4>(1, round_to(ref - delta, unit));
  b.upper = round_to(ref + delta, unit);
  return b;
}

std::optional<LuldBands> LuldSymbol::publish(Nanos t) {
  if (t < kOpen || t >= kClose || ref_ <= 0) return std::nullopt;
  const LuldBands b = luld_bands(ref_, tier_, t);
  if (b == bands_) return std::nullopt;
  bands_ = b;
  return b;
}

std::optional<LuldBands> LuldSymbol::on_trade(Nanos t, PxE4 px) {
  if (t < kOpen || t >= kClose || px <= 0) return std::nullopt;
  window_.emplace_back(t, px);
  sum_ += px;
  while (!window_.empty() && window_.front().first < t - kWindow) {
    sum_ -= window_.front().second;
    window_.pop_front();
  }
  if (ref_ == 0) {
    ref_ = px;  // the opening print
    return publish(t);
  }
  const auto n = static_cast<std::int64_t>(window_.size());
  const PxE4 mean = (sum_ + n / 2) / n;
  const PxE4 move = mean > ref_ ? mean - ref_ : ref_ - mean;
  if (move * 100 >= ref_) ref_ = mean;
  return publish(t);
}

std::optional<LuldBands> LuldSymbol::on_time(Nanos t) {
  if (t >= kClose) {
    bands_ = {};
    return std::nullopt;
  }
  return publish(t);
}

}  // namespace lle::admin

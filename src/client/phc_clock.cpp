#include "client/phc_clock.h"

#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include "common/int128.h"

namespace lle::client {

namespace {
Nanos read_clock(clockid_t id) noexcept {
  timespec ts{};
  clock_gettime(id, &ts);
  return static_cast<Nanos>(ts.tv_sec) * kNsPerSec + ts.tv_nsec;
}
}  // namespace

std::optional<PhcClock> PhcClock::open(int phc_index) {
#if defined(__linux__)
  if (phc_index < 0) return std::nullopt;
  const std::string dev = "/dev/ptp" + std::to_string(phc_index);
  const int fd = ::open(dev.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return std::nullopt;
  return PhcClock(fd);
#else
  (void)phc_index;
  return std::nullopt;
#endif
}

PhcClock& PhcClock::operator=(PhcClock&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

PhcClock::~PhcClock() {
  if (fd_ >= 0) ::close(fd_);
}

Nanos PhcClock::now() const noexcept {
#if defined(__linux__)
  // FD_TO_CLOCKID (include/linux/posix-timers.h, Documentation/ptp/testptp.c).
  const auto id = static_cast<clockid_t>((~static_cast<unsigned>(fd_) << 3) | 3u);
  return read_clock(id);
#else
  return 0;
#endif
}

PhcSample PhcClock::sample(int tries) const noexcept {
  PhcSample best{};
  best.width = -1;
  for (int i = 0; i < tries; ++i) {
    const Nanos a = read_clock(CLOCK_MONOTONIC_RAW);
    const Nanos p = now();
    const Nanos b = read_clock(CLOCK_MONOTONIC_RAW);
    if (best.width < 0 || b - a < best.width) best = PhcSample{a + (b - a) / 2, p, b - a};
  }
  return best;
}

Nanos PhcMap::to_phc(Nanos mono) const noexcept {
  if (s_.empty()) return 0;
  if (s_.size() == 1) return s_[0].phc + (mono - s_[0].mono);
  // The bracketing pair (or the outermost pair for extrapolation).
  auto it = std::upper_bound(s_.begin(), s_.end(), mono, [](Nanos m, const PhcSample& x) { return m < x.mono; });
  std::size_t hi = static_cast<std::size_t>(it - s_.begin());
  if (hi == 0) hi = 1;
  if (hi >= s_.size()) hi = s_.size() - 1;
  const PhcSample& a = s_[hi - 1];
  const PhcSample& b = s_[hi];
  const i128 dm = static_cast<i128>(b.mono - a.mono);
  const i128 dp = static_cast<i128>(b.phc - a.phc);
  return a.phc + static_cast<Nanos>(static_cast<i128>(mono - a.mono) * dp / dm);
}

Nanos PhcMap::uncertainty() const noexcept {
  Nanos w = 0;
  for (const PhcSample& s : s_) w = std::max(w, s.width);
  return w / 2;
}

std::int64_t PhcMap::drift_ppb() const noexcept {
  if (s_.size() < 2) return 0;
  const PhcSample& a = s_.front();
  const PhcSample& b = s_.back();
  const i128 dm = static_cast<i128>(b.mono - a.mono);
  if (dm == 0) return 0;
  return static_cast<std::int64_t>((static_cast<i128>(b.phc - a.phc) - dm) * 1'000'000'000 / dm);
}

}  // namespace lle::client

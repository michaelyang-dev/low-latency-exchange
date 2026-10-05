#pragma once
// Reading a NIC's PTP hardware clock and mapping the instruments' monotonic schedule
// into its time domain (07 §3: "the schedule is precomputed in the PHC time domain";
// generator lateness = tx_hw - scheduled, both on the port's PHC).
//
// A sample brackets one PHC read between two CLOCK_MONOTONIC_RAW reads (the clock of
// env::ProdClock::now_mono); the narrowest of a few tries is kept and its midpoint
// pairs the two clocks with an uncertainty of half its width. PhcMap interpolates
// linearly between samples taken before, during (idle moments only) and after a run,
// so PHC drift against the system clock is followed, and reports its worst
// half-width as the mapping uncertainty published with every lateness figure.
// Linux only (dynamic POSIX clock /dev/ptpN); elsewhere open() returns nullopt.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/types.h"

namespace lle::client {

struct PhcSample {
  Nanos mono = 0;   // midpoint of the bracketing CLOCK_MONOTONIC_RAW reads
  Nanos phc = 0;
  Nanos width = 0;  // bracket width
};

class PhcClock {
 public:
  static std::optional<PhcClock> open(int phc_index);
  PhcClock(PhcClock&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  PhcClock& operator=(PhcClock&& o) noexcept;
  PhcClock(const PhcClock&) = delete;
  PhcClock& operator=(const PhcClock&) = delete;
  ~PhcClock();

  [[nodiscard]] Nanos now() const noexcept;
  [[nodiscard]] PhcSample sample(int tries = 5) const noexcept;

 private:
  explicit PhcClock(int fd) : fd_(fd) {}
  int fd_ = -1;
};

class PhcMap {
 public:
  void reserve(std::size_t n) { s_.reserve(n); }
  // Samples must be added in increasing `mono` order (reserved: no allocation).
  void add(const PhcSample& s) noexcept {
    if (s_.size() < s_.capacity() && (s_.empty() || s.mono > s_.back().mono)) s_.push_back(s);
  }
  [[nodiscard]] bool valid() const noexcept { return s_.size() >= 2; }
  [[nodiscard]] std::size_t size() const noexcept { return s_.size(); }
  // The PHC time at monotonic time `mono` (extrapolated beyond the first/last sample).
  [[nodiscard]] Nanos to_phc(Nanos mono) const noexcept;
  // Half of the widest bracket: the mapping's uncertainty (ns).
  [[nodiscard]] Nanos uncertainty() const noexcept;
  // PHC rate against the monotonic clock over the samples, in parts per billion.
  [[nodiscard]] std::int64_t drift_ppb() const noexcept;
  [[nodiscard]] const std::vector<PhcSample>& samples() const noexcept { return s_; }

 private:
  std::vector<PhcSample> s_;
};

}  // namespace lle::client

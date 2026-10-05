#pragma once
// HdrHistogram wrapper for the lab instruments (plan 12 §5, §7): 3 significant digits,
// values in ns from 1 ns to 1 hour. Values below 1 are counted apart (`below_range`),
// never folded into the distribution; values above the range are clamped and counted.
// record() is allocation-free; construction allocates (startup only).
//
// write_hdr_log() writes the HdrHistogram interval-log format (".hdr", readable by the
// HdrHistogram tools and HistogramLogAnalyzer): one entry per interval histogram, then
// the whole-run histogram tagged "all".
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

#include "common/types.h"

struct hdr_histogram;

namespace lle::client {

class JsonObject;

class Histogram {
 public:
  static constexpr std::int64_t kHighest = 3600LL * 1'000'000'000LL;

  Histogram();
  ~Histogram();
  Histogram(const Histogram&) = delete;
  Histogram& operator=(const Histogram&) = delete;
  Histogram(Histogram&& o) noexcept;
  Histogram& operator=(Histogram&& o) noexcept;

  void record(std::int64_t v) noexcept;
  void reset() noexcept;
  void add(const Histogram& o) noexcept;

  [[nodiscard]] std::int64_t count() const noexcept;
  [[nodiscard]] std::int64_t percentile(double p) const noexcept;
  [[nodiscard]] std::int64_t min() const noexcept;
  [[nodiscard]] std::int64_t max() const noexcept;
  [[nodiscard]] double mean() const noexcept;
  [[nodiscard]] std::uint64_t below_range() const noexcept { return below_; }
  [[nodiscard]] std::uint64_t clamped() const noexcept { return clamped_; }
  [[nodiscard]] hdr_histogram* raw() const noexcept { return h_; }

  // <prefix>count, <prefix>p50_ns, p90, p99, p999, p9999, min, max, mean (ns).
  void json(JsonObject& j, std::string_view prefix) const;
  // hdr_percentiles_print (CLASSIC), ns.
  void print_percentiles(std::FILE* f) const;

 private:
  hdr_histogram* h_ = nullptr;
  std::uint64_t below_ = 0, clamped_ = 0;
};

struct IntervalHistogram {
  Nanos start = 0;  // ns since the run's start
  Nanos end = 0;
  const Histogram* h = nullptr;
};

// The ".hdr" interval log; `start_ms` is the run's start (epoch milliseconds).
bool write_hdr_log(const std::string& path, std::span<const IntervalHistogram> intervals, const Histogram& whole,
                   Nanos whole_len, std::int64_t start_ms, std::string_view comment);

}  // namespace lle::client

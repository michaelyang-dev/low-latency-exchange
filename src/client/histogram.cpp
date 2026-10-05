#include "client/histogram.h"

#include <hdr/hdr_histogram.h>
#include <hdr/hdr_histogram_log.h>

#include <string>

#include "client/report.h"

namespace lle::client {

Histogram::Histogram() { (void)hdr_init(1, kHighest, 3, &h_); }
Histogram::~Histogram() {
  if (h_ != nullptr) hdr_close(h_);
}
Histogram::Histogram(Histogram&& o) noexcept : h_(o.h_), below_(o.below_), clamped_(o.clamped_) { o.h_ = nullptr; }
Histogram& Histogram::operator=(Histogram&& o) noexcept {
  if (this != &o) {
    if (h_ != nullptr) hdr_close(h_);
    h_ = o.h_;
    below_ = o.below_;
    clamped_ = o.clamped_;
    o.h_ = nullptr;
  }
  return *this;
}

void Histogram::record(std::int64_t v) noexcept {
  if (v < 1) {
    ++below_;
    return;
  }
  if (v > kHighest) {
    ++clamped_;
    v = kHighest;
  }
  (void)hdr_record_value(h_, v);
}

void Histogram::reset() noexcept {
  hdr_reset(h_);
  below_ = clamped_ = 0;
}

void Histogram::add(const Histogram& o) noexcept {
  (void)hdr_add(h_, o.h_);
  below_ += o.below_;
  clamped_ += o.clamped_;
}

std::int64_t Histogram::count() const noexcept { return h_->total_count; }
std::int64_t Histogram::percentile(double p) const noexcept { return count() == 0 ? 0 : hdr_value_at_percentile(h_, p); }
std::int64_t Histogram::min() const noexcept { return count() == 0 ? 0 : hdr_min(h_); }
std::int64_t Histogram::max() const noexcept { return count() == 0 ? 0 : hdr_max(h_); }
double Histogram::mean() const noexcept { return count() == 0 ? 0.0 : hdr_mean(h_); }

void Histogram::json(JsonObject& j, std::string_view prefix) const {
  const std::string p(prefix);
  j.num(p + "count", static_cast<std::uint64_t>(count()));
  j.inum(p + "p50_ns", percentile(50.0)).inum(p + "p90_ns", percentile(90.0)).inum(p + "p99_ns", percentile(99.0));
  j.inum(p + "p999_ns", percentile(99.9)).inum(p + "p9999_ns", percentile(99.99));
  j.inum(p + "min_ns", min()).inum(p + "max_ns", max()).inum(p + "mean_ns", static_cast<std::int64_t>(mean()));
  if (below_ != 0) j.num(p + "below_range", below_);
  if (clamped_ != 0) j.num(p + "clamped", clamped_);
}

void Histogram::print_percentiles(std::FILE* f) const { hdr_percentiles_print(h_, f, 5, 1.0, CLASSIC); }

namespace {
hdr_timespec ts_of(std::int64_t ms) {
  hdr_timespec t{};
  t.tv_sec = ms / 1000;
  t.tv_nsec = (ms % 1000) * 1'000'000;
  return t;
}
hdr_timespec ts_of_ns(std::int64_t ns) {
  hdr_timespec t{};
  t.tv_sec = ns / 1'000'000'000;
  t.tv_nsec = ns % 1'000'000'000;
  return t;
}
}  // namespace

bool write_hdr_log(const std::string& path, std::span<const IntervalHistogram> intervals, const Histogram& whole,
                   Nanos whole_len, std::int64_t start_ms, std::string_view comment) {
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) return false;
  hdr_log_writer w;
  bool ok = hdr_log_writer_init(&w) == 0;
  hdr_timespec start = ts_of(start_ms);
  const std::string c(comment);
  ok = ok && hdr_log_write_header(&w, f, c.c_str(), &start) == 0;
  for (const IntervalHistogram& iv : intervals) {
    if (!ok || iv.h == nullptr) continue;
    hdr_log_entry e{};
    e.start_timestamp = ts_of_ns(iv.start);
    e.interval = ts_of_ns(iv.end - iv.start);
    ok = hdr_log_write_entry(&w, f, &e, iv.h->raw()) == 0;
  }
  if (ok) {
    hdr_log_entry e{};
    e.start_timestamp = ts_of_ns(0);
    e.interval = ts_of_ns(whole_len);
    char tag[] = "all";
    e.tag = tag;
    e.tag_len = 3;
    ok = hdr_log_write_entry(&w, f, &e, whole.raw()) == 0;
  }
  ok = std::fclose(f) == 0 && ok;
  return ok;
}

}  // namespace lle::client

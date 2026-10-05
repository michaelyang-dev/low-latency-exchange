#include "client/backlog.h"

#include <algorithm>
#include <charconv>
#include <fstream>

#include "client/report.h"
#include "metrics/segment.h"

namespace lle::client {

struct MetricsSampler::Impl {
  explicit Impl(metrics::Reader r) : reader(std::move(r)) {}
  metrics::Reader reader;
};

MetricsSampler::MetricsSampler() = default;
MetricsSampler::MetricsSampler(MetricsSampler&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
MetricsSampler& MetricsSampler::operator=(MetricsSampler&& o) noexcept {
  if (this != &o) {
    delete impl_;
    impl_ = o.impl_;
    o.impl_ = nullptr;
  }
  return *this;
}
MetricsSampler::~MetricsSampler() { delete impl_; }

std::optional<MetricsSampler> MetricsSampler::open(const std::string& node, std::string* err) {
  auto r = metrics::Reader::open_shm(node);
  if (!r) {
    if (err) *err = r.error();
    return std::nullopt;
  }
  MetricsSampler s;
  s.impl_ = new Impl(std::move(*r));
  return s;
}

MetricsSample MetricsSampler::sample(std::int64_t t_ns) const {
  MetricsSample s;
  s.t_ns = t_ns;
  const metrics::Reader& r = impl_->reader;
  for (std::size_t i = 0; i < r.counter_count(); ++i) {
    const metrics::CounterValue c = r.counter(i);
    s.v[std::string(c.name)] = c.value;
  }
  s.v["writer_pid"] = r.writer_pid();
  s.v["heartbeat"] = r.heartbeat();
  return s;
}

std::string sample_json_line(const MetricsSample& s) {
  std::string out = "{\"t_ns\": " + std::to_string(s.t_ns);
  for (const auto& [k, v] : s.v) out += ", \"" + k + "\": " + std::to_string(v);
  out += "}";
  return out;
}

std::optional<MetricsSample> parse_sample_line(const std::string& line) {
  const auto m = parse_flat_json(line);
  if (!m || !m->contains("t_ns")) return std::nullopt;
  MetricsSample s;
  for (const auto& [k, v] : *m) {
    if (k == "t_ns") {
      std::int64_t t = 0;
      if (std::from_chars(v.data(), v.data() + v.size(), t).ec != std::errc{}) return std::nullopt;
      s.t_ns = t;
      continue;
    }
    std::uint64_t x = 0;
    if (std::from_chars(v.data(), v.data() + v.size(), x).ec != std::errc{}) continue;
    s.v[k] = x;
  }
  return s;
}

bool read_samples(const std::string& path, std::vector<MetricsSample>& out, std::string* err) {
  std::ifstream f(path);
  if (!f) {
    if (err) *err = "cannot open " + path;
    return false;
  }
  std::string line;
  std::size_t n = 0;
  while (std::getline(f, line)) {
    ++n;
    if (line.empty()) continue;
    auto s = parse_sample_line(line);
    if (!s) {
      if (err) *err = path + ":" + std::to_string(n) + ": not a sample";
      return false;
    }
    out.push_back(std::move(*s));
  }
  std::sort(out.begin(), out.end(), [](const MetricsSample& a, const MetricsSample& b) { return a.t_ns < b.t_ns; });
  return true;
}

BacklogVerdict check_backlog(const std::vector<MetricsSample>& samples, std::int64_t from_ns, std::int64_t to_ns) {
  BacklogVerdict v;
  auto why = [&](const std::string& r) {
    if (!v.reason.empty()) v.reason += "; ";
    v.reason += r;
  };
  if (samples.size() < 2) {
    why("no metrics samples");
    return v;
  }
  // Restarts (the segment is recreated by a new process).
  for (std::size_t i = 1; i < samples.size(); ++i) {
    const auto& a = samples[i - 1];
    const auto& b = samples[i];
    if (b.t_ns < from_ns - kNsPerSec || a.t_ns > to_ns) continue;
    if (a.get("node_start_ns") != b.get("node_start_ns") || a.get("writer_pid") != b.get("writer_pid")) v.restarted = true;
  }
  if (v.restarted) why("the exchange node restarted during the span");
  if (!samples.front().has("ring_l2_window")) {
    why("metrics: absent (no ring fields in the segment)");
    return v;
  }
  bool all_ok = !v.restarted;
  bool evaluated = true;
  for (const char* rname : kRings) {
    RingVerdict rv;
    rv.name = rname;
    const std::string pre = std::string("ring_") + rname + "_";
    for (const auto& s : samples) rv.cap = std::max(rv.cap, s.get(pre + "cap"));
    rv.present = rv.cap != 0;
    if (!rv.present) {
      rv.ok = true;
      v.rings.push_back(rv);
      continue;
    }
    std::vector<std::uint64_t> peaks;  // completed windows inside the span, in time order
    for (std::size_t i = 1; i < samples.size(); ++i) {
      const auto& a = samples[i - 1];
      const auto& b = samples[i];
      const std::uint64_t wa = a.get(pre + "window"), wb = b.get(pre + "window");
      if (wb <= wa) continue;
      const bool inside = b.t_ns >= from_ns + kNsPerSec && b.t_ns <= to_ns;
      if (!inside) continue;
      if (wb - wa > 1) {
        ++rv.skipped;
        continue;
      }
      peaks.push_back(b.get(pre + "peak"));
    }
    rv.windows = peaks.size();
    if (rv.windows < 20) {
      evaluated = false;
      why(std::string("ring ") + rname + ": " + std::to_string(rv.windows) + " windows in the span (need 20)");
    } else {
      for (std::size_t i = 0; i < 10; ++i) rv.first10 = std::max(rv.first10, peaks[i]);
      for (std::size_t i = peaks.size() - 10; i < peaks.size(); ++i) rv.last10 = std::max(rv.last10, peaks[i]);
      for (const std::uint64_t p : peaks) rv.max_peak = std::max(rv.max_peak, p);
    }
    rv.ok = rv.windows >= 20 && rv.skipped == 0 && rv.last10 <= rv.first10 + rv.cap / 100 && rv.max_peak <= rv.cap / 2;
    if (rv.skipped != 0) why(std::string("ring ") + rname + ": skipped windows (sampling too slow)");
    if (rv.windows >= 20 && rv.last10 > rv.first10 + rv.cap / 100) why(std::string("ring ") + rname + ": backlog grew");
    if (rv.windows >= 20 && rv.max_peak > rv.cap / 2) why(std::string("ring ") + rname + ": above 50% of capacity");
    all_ok = all_ok && rv.ok;
    v.rings.push_back(rv);
  }
  v.evaluated = evaluated && !v.restarted;
  v.ok = v.evaluated && all_ok;

  // T32 work time per inbound message over the span.
  const MetricsSample* first = nullptr;
  const MetricsSample* last = nullptr;
  for (const auto& s : samples) {
    if (s.t_ns < from_ns || s.t_ns > to_ns) continue;
    if (first == nullptr) first = &s;
    last = &s;
  }
  if (first != nullptr && last != first && first->get("tsc_hz") != 0) {
    std::uint64_t tsc = 0;
    for (const char* st : kStages) {
      const std::string k = std::string(st) + "_work_tsc";
      tsc += last->get(k) - first->get(k);
    }
    v.inbound = (last->get("gw0_msgs_in") + last->get("gw1_msgs_in")) - (first->get("gw0_msgs_in") + first->get("gw1_msgs_in"));
    if (v.inbound != 0)
      v.work_ns_per_msg = static_cast<double>(tsc) * 1e9 / static_cast<double>(first->get("tsc_hz")) /
                          static_cast<double>(v.inbound);
  }
  return v;
}

}  // namespace lle::client

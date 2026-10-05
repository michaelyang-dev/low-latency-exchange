#pragma once
// T20 validity condition 3, bounded backlog (METHODOLOGY §15; 07 §4 "T20"), and the
// T32 per-message work time (METHODOLOGY §16), both read from exchanged's metrics
// segment (/lle-stats-<node>; apps/exchanged/metrics.h, ring_gauge.h).
//
// Ring fields per ring R in {l2, egress, ouch, events, tee}: ring_R_cap (0 = ring absent),
// ring_R_used, ring_R_hwm, ring_R_peak (largest sample of the last completed 1 s
// window of the node's monotonic clock) and ring_R_window (completed windows). A
// sampler reads them a few times per second; every time a ring's window counter
// advances by one, the peak of that completed window is recorded with the sample's
// wall-clock time. An advance by more than one is a skipped window: the backlog check
// then cannot be evaluated and the run is invalid (never assumed bounded). A restart
// of the node (node_start_ns or the writer PID changes, or the heartbeat stops) also
// invalidates the samples.
//
// Over the measured window (60 s): with first10 = the largest per-second peak of the
// first 10 s and last10 = that of the last 10 s, every present ring needs
//   last10 <= first10 + cap / 100   and   every per-second peak <= cap / 2.
//
// Samples travel as JSON lines (`loadgen sample-metrics` runs on the exchange host;
// the run's verdict is computed where the files meet), one object per sample with the
// wall-clock time `t_ns` (CLOCK_REALTIME, ns) and the counters by name.
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common/types.h"

namespace lle::client {

inline constexpr std::array<const char*, 5> kRings = {"l2", "egress", "ouch", "events", "tee"};
// Stages whose work time sums to the T32 per-message cost.
inline constexpr std::array<const char*, 8> kStages = {"gw0", "gw1", "seq", "engine", "io", "md", "repl", "glimpse"};

struct MetricsSample {
  std::int64_t t_ns = 0;  // CLOCK_REALTIME of the sample
  std::map<std::string, std::uint64_t> v;
  [[nodiscard]] std::uint64_t get(const std::string& k) const {
    const auto it = v.find(k);
    return it == v.end() ? 0 : it->second;
  }
  [[nodiscard]] bool has(const std::string& k) const { return v.contains(k); }
};

// Reads the node's segment. Linux and macOS (POSIX shm).
class MetricsSampler {
 public:
  [[nodiscard]] static std::optional<MetricsSampler> open(const std::string& node, std::string* err);
  MetricsSampler(MetricsSampler&&) noexcept;
  MetricsSampler& operator=(MetricsSampler&&) noexcept;
  ~MetricsSampler();
  // Every counter of the segment plus writer_pid and heartbeat.
  [[nodiscard]] MetricsSample sample(std::int64_t t_ns) const;

 private:
  MetricsSampler();
  struct Impl;
  Impl* impl_ = nullptr;
};

std::string sample_json_line(const MetricsSample& s);
[[nodiscard]] std::optional<MetricsSample> parse_sample_line(const std::string& line);
bool read_samples(const std::string& path, std::vector<MetricsSample>& out, std::string* err);

struct RingVerdict {
  std::string name;
  bool present = false;
  std::uint64_t cap = 0;
  std::uint64_t windows = 0;      // completed windows inside the measured span
  std::uint64_t skipped = 0;      // window counter advances > 1
  std::uint64_t first10 = 0, last10 = 0, max_peak = 0;
  bool ok = false;
};

struct BacklogVerdict {
  bool evaluated = false;         // enough samples and windows to decide
  bool ok = false;
  std::string reason;             // why not ok / not evaluated
  std::vector<RingVerdict> rings;
  bool restarted = false;
  // T32: summed stage work time per inbound message over the span (0: not available).
  double work_ns_per_msg = 0.0;
  std::uint64_t inbound = 0;      // gw0_msgs_in + gw1_msgs_in over the span
};

// Measured span [from_ns, to_ns] in CLOCK_REALTIME ns.
[[nodiscard]] BacklogVerdict check_backlog(const std::vector<MetricsSample>& samples, std::int64_t from_ns,
                                           std::int64_t to_ns);

}  // namespace lle::client

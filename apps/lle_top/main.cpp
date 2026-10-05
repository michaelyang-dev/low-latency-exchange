// lle_top: text view of a node's metrics segment /lle-stats-<node>
// (11-logging-observability §3). Minimal M8 version: re-reads the segment and
// redraws counters, rates and histogram percentiles; the interactive TUI
// (per-stage panes, ring occupancy, replication lag) comes with exchange assembly.
//
// STAGE WORK (METHODOLOGY §16, T32): for every stage that publishes <stage>_work_tsc
// and <stage>_work_items, its work time (cycle counter over the polls that processed at
// least one item) in ns per item, converted with the tsc_hz gauge: since the start, and
// over the last interval once there is one.
//
//   lle_top NODE [--interval-ms N] [--once] [--count N]
//
// Exit status: 0 ok, 1 usage, 2 the segment cannot be opened.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "metrics/segment.h"

namespace {

struct WorkRow {
  std::string stage;
  std::size_t tsc = 0;    // counter index of <stage>_work_tsc
  std::size_t items = 0;  // of <stage>_work_items
};

// The stages publishing work time, in segment order.
std::vector<WorkRow> work_rows(const lle::metrics::Reader& r, std::size_t* hz_index) {
  constexpr std::string_view kTsc = "_work_tsc";
  constexpr std::string_view kItems = "_work_items";
  std::vector<WorkRow> rows;
  *hz_index = r.counter_count();
  for (std::size_t i = 0; i < r.counter_count(); ++i) {
    const std::string_view n = r.counter(i).name;
    if (n == "tsc_hz") *hz_index = i;
    if (n.size() <= kTsc.size() || n.substr(n.size() - kTsc.size()) != kTsc) continue;
    const std::string stage(n.substr(0, n.size() - kTsc.size()));
    for (std::size_t k = 0; k < r.counter_count(); ++k) {
      if (r.counter(k).name == stage + std::string(kItems)) rows.push_back(WorkRow{stage, i, k});
    }
  }
  return rows;
}

// ns per item, or ticks per item when the frequency is unknown.
double per_item(std::uint64_t ticks, std::uint64_t items, std::uint64_t hz) {
  if (items == 0) return 0.0;
  const double t = static_cast<double>(ticks) / static_cast<double>(items);
  return hz == 0 ? t : t * 1e9 / static_cast<double>(hz);
}

std::string work_section(const lle::metrics::Reader& r, const std::vector<WorkRow>& rows, std::size_t hz_index,
                         const std::vector<std::uint64_t>& prev, bool have_prev) {
  if (rows.empty()) return {};
  const std::uint64_t hz = hz_index < r.counter_count() ? r.counter(hz_index).value : 0;
  const char* unit = hz == 0 ? "ticks/item" : "ns/item";
  std::string out;
  char line[160];
  std::snprintf(line, sizeof line, "STAGE WORK (non-empty polls; tsc_hz %llu)\n", static_cast<unsigned long long>(hz));
  out += line;
  std::snprintf(line, sizeof line, "%-10s %16s %14s %14s %16s\n", "stage", "items", "work_ms", unit,
                have_prev ? "interval" : "");
  out += line;
  for (const WorkRow& w : rows) {
    const std::uint64_t ticks = r.counter(w.tsc).value;
    const std::uint64_t items = r.counter(w.items).value;
    const double ms = hz == 0 ? 0.0 : static_cast<double>(ticks) * 1e3 / static_cast<double>(hz);
    if (have_prev) {
      const std::uint64_t dt = ticks - prev[w.tsc];
      const std::uint64_t di = items - prev[w.items];
      std::snprintf(line, sizeof line, "%-10s %16llu %14.3f %14.1f %16.1f\n", w.stage.c_str(),
                    static_cast<unsigned long long>(items), ms, per_item(ticks, items, hz), per_item(dt, di, hz));
    } else {
      std::snprintf(line, sizeof line, "%-10s %16llu %14.3f %14.1f\n", w.stage.c_str(),
                    static_cast<unsigned long long>(items), ms, per_item(ticks, items, hz));
    }
    out += line;
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  std::string node;
  long interval_ms = 1000;
  long count = -1;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if (a == "--once") {
      count = 1;
    } else if (a == "--interval-ms" && i + 1 < argc) {
      interval_ms = std::strtol(argv[++i], nullptr, 10);
    } else if (a == "--count" && i + 1 < argc) {
      count = std::strtol(argv[++i], nullptr, 10);
    } else if (!a.empty() && a.front() != '-' && node.empty()) {
      node = a;
    } else {
      std::fprintf(stderr, "usage: lle_top NODE [--interval-ms N] [--once] [--count N]\n");
      return 1;
    }
  }
  if (node.empty() || interval_ms <= 0) {
    std::fprintf(stderr, "usage: lle_top NODE [--interval-ms N] [--once] [--count N]\n");
    return 1;
  }
  auto r = lle::metrics::Reader::open_shm(node);
  if (!r) {
    std::fprintf(stderr, "lle_top: %s\n", r.error().c_str());
    return 2;
  }
  std::vector<std::uint64_t> prev(r->counter_count(), 0);
  std::size_t hz_index = 0;
  const std::vector<WorkRow> rows = work_rows(*r, &hz_index);
  auto last = std::chrono::steady_clock::now();
  for (long n = 0; count < 0 || n < count; ++n) {
    if (n != 0) std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    const auto now = std::chrono::steady_clock::now();
    const double secs = std::chrono::duration<double>(now - last).count();
    last = now;
    std::string out = count == 1 ? std::string{} : std::string{"\x1b[H\x1b[2J"};
    out += lle::metrics::dump_text(*r);
    out += work_section(*r, rows, hz_index, prev, n != 0);
    if (n != 0 && secs > 0) {
      out += "RATES (per second)\n";
      for (std::size_t i = 0; i < r->counter_count(); ++i) {
        const auto c = r->counter(i);
        if (c.kind != lle::metrics::CounterKind::kCounter) continue;
        const double rate = static_cast<double>(c.value - prev[i]) / secs;
        char line[96];
        std::snprintf(line, sizeof line, "%-40s %20.1f\n", std::string(c.name).c_str(), rate);
        out += line;
      }
    }
    for (std::size_t i = 0; i < r->counter_count(); ++i) prev[i] = r->counter(i).value;
    std::fwrite(out.data(), 1, out.size(), stdout);
    std::fflush(stdout);
  }
  return 0;
}

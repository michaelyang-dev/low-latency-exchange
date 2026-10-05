// T31 logger benchmark protocol (11-logging-observability §2, R6 R5): variants
// M1a, M1b, M2, M4 and EV (plus DRAIN, the backend's capacity) for the fixed shape
//   NLOG_INFO("order {} accepted px {} qty {} side {}", u64, i64, u32, u8)
//
// Per-call stamps are fenced: LFENCE;RDTSC;LFENCE ... RDTSCP;LFENCE on x86-64,
// ISB;CNTVCT;ISB ... ISB;CNTVCT on arm64. The stamp floor (an empty bracket) is
// measured and subtracted ("net"). Raw and net p50/p90/p99/p99.9/max are printed.
//
// Coarse counters: when tsc_granularity_probe reports steps > 1 ns (e.g. the
// 24 MHz / 41.67 ns CNTVCT on Apple silicon) a single-call median cannot resolve
// a ~9 ns call; per the pre-registered rule the mean of the per-call sampled deltas
// is the estimate, and a batch-timed mean (K calls per bracket, minus the same
// batch without the call) is printed alongside.
//
// Numbers from a laptop (no core isolation, no pinning on macOS) are INDICATIVE
// ONLY and must never be quoted as the T31 headline.
//
//   nlog_bench [--variant all|m1a|m1b|m2|m4|ev|drain] [--calls N] [--m2-calls N]
//              [--m4-calls N] [--drain-sleep-us N] [--cpu N] [--drain-cpu N] [--out PATH] [--json PATH]
//
// --json writes one flat run file (numeric metrics plus "valid", false when the
// M1a run dropped records) for tools/results/summarize.py.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <numeric>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "log/backend.h"
#include "log/nlog.h"
#include "log/tsc.h"
#include "runtime/pinning.h"

#if defined(__x86_64__)
#include <x86intrin.h>
#endif
#if defined(__APPLE__)
#include <pthread/qos.h>
#endif

namespace {

using namespace lle::nlog;

#if defined(__x86_64__)
[[gnu::always_inline]] inline std::uint64_t stamp_begin() noexcept {
  _mm_lfence();
  const std::uint64_t t = __rdtsc();
  _mm_lfence();
  return t;
}
[[gnu::always_inline]] inline std::uint64_t stamp_end() noexcept {
  unsigned aux = 0;
  const std::uint64_t t = __rdtscp(&aux);
  _mm_lfence();
  return t;
}
#elif defined(__aarch64__)
[[gnu::always_inline]] inline std::uint64_t stamp_begin() noexcept {
  std::uint64_t v;
  asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(v) : : "memory");
  return v;
}
[[gnu::always_inline]] inline std::uint64_t stamp_end() noexcept {
  std::uint64_t v;
  asm volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(v) : : "memory");
  return v;
}
#else
#error "nlog_bench needs x86-64 or arm64"
#endif

// The fixed T31 shape.
[[gnu::always_inline]] inline void log_shape(std::uint64_t ref, std::int64_t px, std::uint32_t qty, std::uint8_t side) {
  NLOG_INFO("order {} accepted px {} qty {} side {}", ref, px, qty, side);
}
[[gnu::always_inline]] inline void log_shape_ev(std::uint64_t ev, std::uint64_t ref, std::int64_t px, std::uint32_t qty,
                                                std::uint8_t side) {
  NLOG_EV(ev, "order {} accepted px {} qty {} side {}", ref, px, qty, side);
}

// ~200 ns of dependent integer work between calls (keeps the core busy the way
// order handling would, without touching memory).
struct Work {
  std::uint64_t iters = 1;
  std::uint64_t x = 0x9E3779B97F4A7C15ull;
  [[gnu::always_inline]] void run() noexcept {
    std::uint64_t v = x;
    for (std::uint64_t i = 0; i < iters; ++i) {
      v ^= v << 13;
      v ^= v >> 7;
      v ^= v << 17;
      asm volatile("" : "+r"(v));
    }
    x = v;
  }
};

double now_ns() {
  return static_cast<double>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

Work calibrate_work(double target_ns) {
  Work w;
  w.iters = 1'000'000;
  const double t0 = now_ns();
  w.run();
  const double per_iter = (now_ns() - t0) / 1e6;
  w.iters = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(target_ns / per_iter));
  return w;
}

struct Stats {
  double p50, p90, p99, p999, max, mean;
};

Stats stats_of(std::vector<std::uint32_t>& v) {
  std::sort(v.begin(), v.end());
  auto at = [&](double p) { return static_cast<double>(v[static_cast<std::size_t>(p * static_cast<double>(v.size() - 1))]); };
  const double sum = std::accumulate(v.begin(), v.end(), 0.0);
  return Stats{at(0.5), at(0.9), at(0.99), at(0.999), static_cast<double>(v.back()), sum / static_cast<double>(v.size())};
}

struct Ctx {
  int drain_cpu = -1;  // --drain-cpu: the backend (drain) thread's core, Linux only
  double tick_ns = 1.0;
  Stats floor{};
  std::string out_path;
  std::uint32_t drain_sleep_us = 0;
};

Stats measure_floor(std::size_t n) {
  std::vector<std::uint32_t> d(n);
  for (std::size_t i = 0; i < n; ++i) {
    const std::uint64_t t0 = stamp_begin();
    const std::uint64_t t1 = stamp_end();
    d[i] = static_cast<std::uint32_t>(t1 - t0);
  }
  return stats_of(d);
}

// Flat metrics for --json (tools/results/summarize.py reads run-*.json files).
std::vector<std::pair<std::string, double>> g_metrics;
void metric(const char* variant, const char* key, double v) {
  std::string k = variant;
  for (char& ch : k) ch = static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
  g_metrics.emplace_back(k + "_" + key, v);
}

void print_row(const Ctx& c, const char* name, const Stats& raw, std::uint64_t drops, std::size_t n) {
  const double t = c.tick_ns;
  std::printf("%-5s raw  ticks p50 %6.0f p90 %6.0f p99 %6.0f p99.9 %6.0f max %8.0f | ns p50 %7.2f p90 %7.2f p99 %7.2f "
              "p99.9 %7.2f max %9.1f mean %7.2f\n",
              name, raw.p50, raw.p90, raw.p99, raw.p999, raw.max, raw.p50 * t, raw.p90 * t, raw.p99 * t, raw.p999 * t,
              raw.max * t, raw.mean * t);
  std::printf("%-5s net  ns p50 %7.2f p90 %7.2f p99 %7.2f p99.9 %7.2f | mean of sampled deltas %7.2f ns "
              "(floor mean %.2f ns subtracted) | calls %zu drops %llu%s\n",
              name, (raw.p50 - c.floor.p50) * t, (raw.p90 - c.floor.p50) * t, (raw.p99 - c.floor.p50) * t,
              (raw.p999 - c.floor.p50) * t, (raw.mean - c.floor.mean) * t, c.floor.mean * t, n,
              static_cast<unsigned long long>(drops), drops != 0 ? "  ** INVALID: drops > 0 **" : "");
  metric(name, "raw_p50_ns", raw.p50 * t);
  metric(name, "raw_p99_ns", raw.p99 * t);
  metric(name, "raw_max_ns", raw.max * t);
  metric(name, "net_p50_ns", (raw.p50 - c.floor.p50) * t);
  metric(name, "net_p90_ns", (raw.p90 - c.floor.p50) * t);
  metric(name, "net_p99_ns", (raw.p99 - c.floor.p50) * t);
  metric(name, "net_p999_ns", (raw.p999 - c.floor.p50) * t);
  metric(name, "net_mean_ns", (raw.mean - c.floor.mean) * t);
  metric(name, "drops", static_cast<double>(drops));
}

auto shape_call() {
  return [](std::size_t i) {
    log_shape(0x1000'0000ull + i, 1'500'000 + static_cast<std::int64_t>(i & 0xFF), 100 + static_cast<std::uint32_t>(i & 7),
              static_cast<std::uint8_t>('B' + (i & 1)));
  };
}

// Batch-timed mean: K iterations of (work + call) per bracket minus K iterations of
// (work) alone, interleaved. Resolves sub-tick costs on a coarse counter.
struct BatchMean {
  double mean_ns;    // sum(with - without) / calls
  double median_ns;  // median over batches of (with - without) / k
};

template <class Call>
BatchMean batch_mean_ns(const Ctx& c, Work& w, Call&& call, std::size_t batches, std::size_t k) {
  std::vector<double> diff(batches);
  double total = 0;
  for (std::size_t b = 0; b < batches; ++b) {
    std::uint64_t t0 = stamp_begin();
    for (std::size_t i = 0; i < k; ++i) {
      w.run();
      call(b * k + i);
    }
    std::uint64_t t1 = stamp_end();
    const auto with = static_cast<double>(t1 - t0);
    t0 = stamp_begin();
    for (std::size_t i = 0; i < k; ++i) {
      w.run();
      asm volatile("" ::: "memory");
    }
    t1 = stamp_end();
    diff[b] = (with - static_cast<double>(t1 - t0)) * c.tick_ns / static_cast<double>(k);
    total += diff[b];
  }
  std::nth_element(diff.begin(), diff.begin() + static_cast<std::ptrdiff_t>(batches / 2), diff.end());
  return BatchMean{total / static_cast<double>(batches), diff[batches / 2]};
}

// Producer-only back-to-back batches: K calls per fenced bracket into a ring that
// never fills (pipelined throughput cost, not serialized latency).
BatchMean back_to_back_batches(const Ctx& c, std::size_t batches, std::size_t k) {
  std::vector<double> per(batches);
  double total = 0;
  auto call = shape_call();
  for (std::size_t b = 0; b < batches; ++b) {
    const std::uint64_t t0 = stamp_begin();
    for (std::size_t i = 0; i < k; ++i) call(b * k + i);
    const std::uint64_t t1 = stamp_end();
    per[b] = static_cast<double>(t1 - t0) * c.tick_ns / static_cast<double>(k);
    total += per[b];
  }
  std::nth_element(per.begin(), per.begin() + static_cast<std::ptrdiff_t>(batches / 2), per.end());
  return BatchMean{total / static_cast<double>(batches), per[batches / 2]};
}

// Lets a backend drain (to /dev/null) whatever a finished variant left in its ring.
void drain_leftovers() {
  Backend be;
  BackendOptions o;
  o.path = "/dev/null";
  o.idle_sleep_us = 0;
  if (be.start(o)) be.stop();
}

std::size_t pow2_at_least(std::size_t v) {
  std::size_t p = 4096;
  while (p < v) p <<= 1;
  return p;
}

// Per-call stamped loop with `w` between calls.
template <class Call>
std::vector<std::uint32_t> stamped(Work& w, std::size_t n, Call&& call) {
  std::vector<std::uint32_t> d(n);
  for (std::size_t i = 0; i < n; ++i) {
    w.run();
    const std::uint64_t t0 = stamp_begin();
    call(i);
    const std::uint64_t t1 = stamp_end();
    d[i] = static_cast<std::uint32_t>(t1 - t0);
  }
  return d;
}

void run_m1(const Ctx& c, Work& w, std::size_t calls, bool drain, bool ev) {
  const char* name = ev ? "EV" : (drain ? "M1a" : "M1b");
  // M1b: room for warm-up, the stamped run and the 2000 x 1000 back-to-back batches
  // (48 ring bytes per record) so the ring never fills.
  const std::size_t ring = drain ? (std::size_t{4} << 20) : pow2_at_least((calls + 100'000 + 2'000'000) * 48);
  ThreadScope scope({.ring_bytes = ring, .name = name});
  if (!scope.ok()) {
    std::printf("%s: register_thread failed (ring %zu bytes)\n", name, ring);
    return;
  }
  Backend be;
  if (drain) {
    BackendOptions o;
    o.path = c.out_path;
    o.node = "bench";
    o.idle_sleep_us = c.drain_sleep_us;  // 0: spin on a sibling core
    o.pin_cpu = c.drain_cpu;
    if (auto r = be.start(o); !r) {
      std::printf("%s: backend start failed: %s\n", name, r.error().c_str());
      return;
    }
  }
  const std::uint64_t drops0 = thread_drops();
  auto call = [ev](std::size_t i) {
    if (ev) {
      log_shape_ev(i * 3, 0x1000'0000ull + i, 1'500'000 + static_cast<std::int64_t>(i & 0xFF),
                   100 + static_cast<std::uint32_t>(i & 7), static_cast<std::uint8_t>('B' + (i & 1)));
    } else {
      shape_call()(i);
    }
  };
  for (std::size_t i = 0; i < std::min<std::size_t>(calls / 10, 100'000); ++i) {
    w.run();
    call(i);
  }
  auto d = stamped(w, calls, call);
  const std::uint64_t drops = thread_drops() - drops0;
  const Stats raw = stats_of(d);
  print_row(c, name, raw, drops, calls);
  if (!drain) {
    std::printf("%-5s (ring %zu MiB, pre-sized so it never fills; no consumer)\n", name, ring >> 20);
    const BatchMean bb = back_to_back_batches(c, 2000, 1000);
    metric(name, "b2b_batch_mean_ns", bb.mean_ns);
    metric(name, "b2b_batch_median_ns", bb.median_ns);
    std::printf("%-5s producer-only back-to-back: mean %.2f ns/call, median batch %.2f ns/call (2000 x 1000 calls "
                "per fenced bracket; pipelined throughput, not latency) drops %llu\n",
                name, bb.mean_ns, bb.median_ns, static_cast<unsigned long long>(thread_drops() - drops0 - drops));
  } else {
    const BatchMean bm = batch_mean_ns(c, w, call, 2000, 1000);
    metric(name, "batch_mean_ns", bm.mean_ns);
    metric(name, "batch_median_ns", bm.median_ns);
    std::printf("%-5s batch-timed: mean %.2f ns/call, median batch %.2f ns/call (2000 x 1000 x (work + call) minus "
                "work-only batches) drops %llu\n",
                name, bm.mean_ns, bm.median_ns, static_cast<unsigned long long>(thread_drops() - drops0 - drops));
    be.stop();
  }
}

void run_m2(const Ctx& c, std::size_t calls) {
  ThreadScope scope({.ring_bytes = std::size_t{4} << 20, .name = "M2"});
  Backend be;
  BackendOptions o;
  o.path = c.out_path;
  o.node = "bench";
  o.idle_sleep_us = 0;
  o.pin_cpu = c.drain_cpu;
  if (auto r = be.start(o); !r) {
    std::printf("M2: backend start failed: %s\n", r.error().c_str());
    return;
  }
  auto call = shape_call();
  for (std::size_t i = 0; i < 100'000; ++i) call(i);
  const std::uint64_t drops0 = thread_drops();
  const double t0 = now_ns();
  for (std::size_t i = 0; i < calls; ++i) call(i);
  const double t1 = now_ns();
  const std::uint64_t drops = thread_drops() - drops0;
  be.stop();
  metric("m2", "mean_ns", (t1 - t0) / static_cast<double>(calls));
  metric("m2", "drops", static_cast<double>(drops));
  std::printf("M2    back-to-back mean %.2f ns/call over %zu calls (wall clock), drain live | drops %llu%s\n",
              (t1 - t0) / static_cast<double>(calls), calls, static_cast<unsigned long long>(drops),
              drops != 0 ? "  ** INVALID per protocol (drops > 0): an unthrottled producer outruns the drain; "
                           "the mean then includes cheap drop-path calls **"
                         : "");
}

// Backend capacity: fill a ring with `n` records (no consumer), then time how long
// the backend takes to compact and write them all.
void run_drain(const Ctx& c, std::size_t n) {
  {
    ThreadScope scope({.ring_bytes = pow2_at_least(n * 48 + (1 << 20)), .name = "DRAIN"});
    auto call = shape_call();
    for (std::size_t i = 0; i < n; ++i) call(i);
  }  // the closed ring stays registered until a consumer drains it
  Backend be;
  BackendOptions o;
  o.path = c.out_path;
  o.node = "bench";
  o.idle_sleep_us = 0;
  const double t0 = now_ns();
  if (auto r = be.start(o); !r) return;
  while (be.stats().records < n) {
  }
  const double t1 = now_ns();
  be.stop();
  const BackendStats st = be.stats();
  metric("drain", "ns_per_record", (t1 - t0) / static_cast<double>(n));
  metric("drain", "bytes_per_record", static_cast<double>(st.bytes_written) / static_cast<double>(n));
  std::printf("DRAIN backend compacted+wrote %llu records in %.1f ms: %.1f ns/record = %.1f M records/s, %.2f bytes/record "
              "on disk (raw ring record 48 B)\n",
              static_cast<unsigned long long>(st.records), (t1 - t0) / 1e6, (t1 - t0) / static_cast<double>(n),
              static_cast<double>(n) / (t1 - t0) * 1e3, static_cast<double>(st.bytes_written) / static_cast<double>(n));
}

void run_m4(const Ctx& c, Work& w, std::size_t calls) {
  ThreadScope scope({.ring_bytes = std::size_t{4} << 20, .name = "M4"});
  Backend be;
  BackendOptions o;
  o.path = c.out_path;
  o.node = "bench";
  if (auto r = be.start(o); !r) return;
  // Evict L1/L2 (and most of the SLC) before each call: stream through 64 MiB.
  const std::size_t poison_bytes = std::size_t{64} << 20;
  std::vector<std::uint8_t> poison(poison_bytes, 1);
  volatile std::uint64_t sink = 0;
  const std::uint64_t drops0 = thread_drops();
  auto call = shape_call();
  std::vector<std::uint32_t> d(calls);
  for (std::size_t i = 0; i < calls; ++i) {
    std::uint64_t s = 0;
    for (std::size_t j = 0; j < poison_bytes; j += 64) s += poison[j];
    sink = sink + s;
    w.run();
    const std::uint64_t t0 = stamp_begin();
    call(i);
    const std::uint64_t t1 = stamp_end();
    d[i] = static_cast<std::uint32_t>(t1 - t0);
  }
  const std::uint64_t drops = thread_drops() - drops0;
  be.stop();
  const Stats raw = stats_of(d);
  print_row(c, "M4", raw, drops, calls);
}

}  // namespace

int main(int argc, char** argv) {
  std::string variant = "all";
  std::string json_path;
  std::uint32_t drain_sleep_us = 0;
  int cpu = -1, drain_cpu = -1;
  std::size_t calls = 10'000'000;
  std::size_t m2_calls = 100'000'000;
  std::size_t m4_calls = 5'000;
  const char* tmp = std::getenv("TMPDIR");
  std::string out = std::string(tmp != nullptr ? tmp : "/tmp") + "/nlog_bench.nlog";
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    auto next = [&] { return i + 1 < argc ? std::string_view{argv[++i]} : std::string_view{}; };
    if (a == "--variant") {
      variant = next();
    } else if (a == "--calls") {
      calls = std::strtoull(std::string(next()).c_str(), nullptr, 10);
    } else if (a == "--m2-calls") {
      m2_calls = std::strtoull(std::string(next()).c_str(), nullptr, 10);
    } else if (a == "--m4-calls") {
      m4_calls = std::strtoull(std::string(next()).c_str(), nullptr, 10);
    } else if (a == "--drain-sleep-us") {
      drain_sleep_us = static_cast<std::uint32_t>(std::strtoul(std::string(next()).c_str(), nullptr, 10));
    } else if (a == "--cpu") {
      cpu = std::atoi(std::string(next()).c_str());
    } else if (a == "--drain-cpu") {
      drain_cpu = std::atoi(std::string(next()).c_str());
    } else if (a == "--json") {
      json_path = next();
    } else if (a == "--out") {
      out = next();
    } else {
      std::fprintf(stderr, "usage: nlog_bench [--variant all|m1a|m1b|m2|m4|ev|drain] [--calls N] [--m2-calls N] "
                           "[--m4-calls N] [--drain-sleep-us N] [--cpu N] [--drain-cpu N] [--out PATH] [--json PATH]\n");
      return 1;
    }
  }
#if defined(__APPLE__)
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
  const TscGranularity g = tsc_granularity_probe();
  Ctx c;
  c.tick_ns = g.tick_ns;
  c.out_path = out;
  c.drain_sleep_us = drain_sleep_us;
  c.drain_cpu = drain_cpu;
  if (cpu >= 0) std::printf("pin producer to cpu %d: %s\n", cpu, lle::rt::to_string(lle::rt::pin_current_thread(cpu)));
  std::printf("INDICATIVE DEV-LAPTOP DATA - not a T31 headline (no isolated cores; macOS cannot pin threads)\n");
  std::printf("counter: %llu Hz, tick %.3f ns, min step %llu ticks (%.3f ns), read cost %.2f ns, zero-delta %.1f%%%s\n",
              static_cast<unsigned long long>(g.hz), g.tick_ns, static_cast<unsigned long long>(g.min_step_ticks),
              g.min_step_ns, g.read_cost_ns, 100.0 * g.zero_delta_fraction,
              g.min_step_ns > 1.0 ? "  -> coarse counter: per-call percentiles are quantized; use the means" : "");
  Work w = calibrate_work(200.0);
  const double t0 = now_ns();
  for (int i = 0; i < 1000; ++i) w.run();
  std::printf("spacing work: %llu iterations ~ %.0f ns\n", static_cast<unsigned long long>(w.iters),
              (now_ns() - t0) / 1000.0);
  c.floor = measure_floor(1'000'000);
  std::printf("floor (empty fenced bracket): ticks p50 %.0f p99 %.0f mean %.3f (= %.2f ns)\n", c.floor.p50,
              c.floor.p99, c.floor.mean, c.floor.mean * c.tick_ns);

  const bool all = variant == "all";
  if (all || variant == "m1a") run_m1(c, w, calls, true, false);
  if (all || variant == "m1b") {
    run_m1(c, w, calls, false, false);
    drain_leftovers();
  }
  if (all || variant == "ev") run_m1(c, w, calls, true, true);
  if (all || variant == "m2") run_m2(c, m2_calls);
  if (all || variant == "drain") run_drain(c, std::min<std::size_t>(calls, 10'000'000));
  if (all || variant == "m4") run_m4(c, w, m4_calls);
  std::remove(out.c_str());
  if (!json_path.empty()) {
    // Coarse-TSC rule (plan 11 §2): with counter steps > 1 ns the headline is the
    // mean of the per-call sampled deltas; the quantized median stays alongside.
    double m1a_drops = 0;
    for (const auto& [k, v] : g_metrics)
      if (k == "m1a_drops") m1a_drops = v;
    std::FILE* f = std::fopen(json_path.c_str(), "w");
    if (f == nullptr) return 1;
    std::fprintf(f, "{\"host_indicative_only\": true, \"coarse_tsc\": %s, \"tsc_min_step_ns\": %.4f, \"tsc_hz\": %llu, "
                 "\"floor_mean_ns\": %.4f, \"valid\": %s",
                 g.min_step_ns > 1.0 ? "true" : "false", g.min_step_ns, static_cast<unsigned long long>(g.hz),
                 c.floor.mean * c.tick_ns, m1a_drops == 0 ? "true" : "false");
    for (const auto& [k, v] : g_metrics) std::fprintf(f, ", \"%s\": %.4f", k.c_str(), v);
    std::fprintf(f, "}\n");
    std::fclose(f);
  }
  return 0;
}

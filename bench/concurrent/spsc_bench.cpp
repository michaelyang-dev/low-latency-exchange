// SpscRing microbenchmarks (08-concurrency-runtime §9): consumer-side throughput with a
// producer thread pushing flat out, the batch-drain effect, and ping-pong round trip.
#include <benchmark/benchmark.h>

#include <atomic>
#include <cstdint>
#include <memory>

#include "bench_util.h"
#include "concurrent/spsc_ring.h"

namespace lle::conc {
namespace {

using bench::Background;
using bench::stopped;

// One iteration = one item popped (the producer keeps the ring as full as it can).
template <std::size_t Cap>
void BM_SpscThroughputPop(benchmark::State& state) {
  auto q = std::make_unique<SpscRing<std::uint64_t, Cap>>();
  Background producer([&](std::atomic<bool>& stop) {
    std::uint64_t i = 0;
    while (!stopped(stop)) {
      if (q->try_push(i)) ++i;
    }
  });
  std::uint64_t v = 0, sum = 0;
  for (auto _ : state) {
    while (!q->try_pop(v)) {
    }
    sum += v;
  }
  benchmark::DoNotOptimize(sum);
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  producer.stop();
}
BENCHMARK(BM_SpscThroughputPop<1024>)->UseRealTime();              // 8 KiB ring
BENCHMARK(BM_SpscThroughputPop<64 * 1024>)->UseRealTime();         // 512 KiB ring

// One iteration = one drain() batch of up to 64 items; items/s is the comparable number.
template <std::size_t Cap>
void BM_SpscThroughputDrain(benchmark::State& state) {
  auto q = std::make_unique<SpscRing<std::uint64_t, Cap>>();
  Background producer([&](std::atomic<bool>& stop) {
    std::uint64_t i = 0;
    while (!stopped(stop)) {
      if (q->try_push(i)) ++i;
    }
  });
  std::uint64_t sum = 0, items = 0;
  for (auto _ : state) {
    std::size_t n = 0;
    while ((n = q->drain([&](const std::uint64_t& x) { sum += x; }, 64)) == 0) {
    }
    items += n;
  }
  benchmark::DoNotOptimize(sum);
  state.SetItemsProcessed(static_cast<std::int64_t>(items));
  producer.stop();
}
BENCHMARK(BM_SpscThroughputDrain<1024>)->UseRealTime();
BENCHMARK(BM_SpscThroughputDrain<64 * 1024>)->UseRealTime();

// One iteration = one round trip through two rings and an echo thread.
void BM_SpscPingPong(benchmark::State& state) {
  auto ping = std::make_unique<SpscRing<std::uint64_t, 1024>>();
  auto pong = std::make_unique<SpscRing<std::uint64_t, 1024>>();
  Background echo([&](std::atomic<bool>& stop) {
    std::uint64_t v = 0;
    while (!stopped(stop)) {
      if (ping->try_pop(v)) {
        while (!pong->try_push(v)) {
        }
      }
    }
  });
  std::uint64_t i = 0, v = 0;
  for (auto _ : state) {
    while (!ping->try_push(i)) {
    }
    while (!pong->try_pop(v)) {
    }
    ++i;
  }
  benchmark::DoNotOptimize(v);
  echo.stop();
}
BENCHMARK(BM_SpscPingPong)->UseRealTime();

}  // namespace
}  // namespace lle::conc

BENCHMARK_MAIN();

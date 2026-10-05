// SpscByteRing with logger-shaped records (08-concurrency-runtime §4, §9; 11-logging):
// 24-64-byte payloads into a 1 MiB ring with a drain thread, measured on the producer
// (the logging call site) and on the consumer (the backend).
#include <benchmark/benchmark.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "bench_util.h"
#include "concurrent/spsc_byte_ring.h"

namespace lle::conc {
namespace {

using bench::Background;
using bench::stopped;

constexpr std::size_t kCap = 1 << 20;
constexpr std::uint32_t kSizes[6] = {24, 32, 40, 48, 56, 64};

// One iteration = one record reserved, filled (16-byte site/tsc header + args) and
// committed by the producer; a background thread drains in batches of 64.
void BM_ByteRingProducer(benchmark::State& state) {
  std::vector<std::uint64_t> storage(kCap / 8);
  SpscByteRing ring;
  ring.init(reinterpret_cast<std::byte*>(storage.data()), kCap);
  Background drainer([&](std::atomic<bool>& stop) {
    std::uint64_t sum = 0;
    while (!stopped(stop)) {
      ring.drain([&](const std::byte* p, std::uint32_t len) { sum += len + static_cast<std::uint64_t>(p[0]); }, 64);
    }
    benchmark::DoNotOptimize(sum);
  });
  std::uint64_t i = 0;
  for (auto _ : state) {
    const std::uint32_t len = kSizes[i % 6];
    std::byte* p = nullptr;
    while ((p = ring.try_reserve(len)) == nullptr) {
    }
    std::memcpy(p, &i, 8);
    std::memcpy(p + 8, &i, 8);
    ring.commit();
    ++i;
  }
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  drainer.stop();
}
BENCHMARK(BM_ByteRingProducer)->UseRealTime();

// Same records; one iteration = one drain() batch (up to 64 records) by the consumer.
void BM_ByteRingConsumerDrain(benchmark::State& state) {
  std::vector<std::uint64_t> storage(kCap / 8);
  SpscByteRing ring;
  ring.init(reinterpret_cast<std::byte*>(storage.data()), kCap);
  Background producer([&](std::atomic<bool>& stop) {
    std::uint64_t i = 0;
    while (!stopped(stop)) {
      const std::uint32_t len = kSizes[i % 6];
      if (std::byte* p = ring.try_reserve(len)) {
        std::memcpy(p, &i, 8);
        ring.commit();
        ++i;
      }
    }
  });
  std::uint64_t sum = 0, items = 0;
  for (auto _ : state) {
    std::size_t n = 0;
    while ((n = ring.drain([&](const std::byte* p, std::uint32_t len) { sum += len + static_cast<std::uint64_t>(p[0]); },
                           64)) == 0) {
    }
    items += n;
  }
  benchmark::DoNotOptimize(sum);
  state.SetItemsProcessed(static_cast<std::int64_t>(items));
  producer.stop();
}
BENCHMARK(BM_ByteRingConsumerDrain)->UseRealTime();

}  // namespace
}  // namespace lle::conc

BENCHMARK_MAIN();

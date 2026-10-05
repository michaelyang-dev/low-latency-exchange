// BroadcastRing writer cost with 3 consumer cursors (08-concurrency-runtime §6, §9):
// journal-shaped 64-byte records into a 1 MiB ring, three threads draining in batches.
#include <benchmark/benchmark.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "bench_util.h"
#include "concurrent/broadcast_ring.h"

namespace lle::conc {
namespace {

using bench::Background;
using bench::stopped;

// One iteration = one record reserved, filled and committed by the writer.
void BM_BroadcastWriter3(benchmark::State& state) {
  constexpr std::size_t kCap = 1 << 20;
  const auto payload = static_cast<std::uint32_t>(state.range(0));
  std::vector<std::uint64_t> storage(kCap / 8);
  auto ring = std::make_unique<BroadcastRing<3>>();
  ring->init(reinterpret_cast<std::byte*>(storage.data()), kCap);
  std::vector<std::unique_ptr<Background>> readers;
  for (std::size_t c = 0; c < 3; ++c) {
    readers.push_back(std::make_unique<Background>([&, c](std::atomic<bool>& stop) {
      std::uint64_t sum = 0;
      while (!stopped(stop)) {
        ring->drain(
            c, [&](const std::byte* p, std::uint32_t) { sum += static_cast<std::uint64_t>(p[0]); }, 64);
      }
      benchmark::DoNotOptimize(sum);
    }));
  }
  std::uint64_t seq = 0;
  for (auto _ : state) {
    std::byte* p = nullptr;
    while ((p = ring->try_reserve(payload)) == nullptr) {
    }
    std::memcpy(p, &seq, sizeof(seq));
    ring->commit();
    ++seq;
  }
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * (payload + 8));
  for (auto& r : readers) r->stop();
}
BENCHMARK(BM_BroadcastWriter3)->Arg(56)->Arg(248)->UseRealTime();

}  // namespace
}  // namespace lle::conc

BENCHMARK_MAIN();

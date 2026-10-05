// MPSC microbenchmarks (08-concurrency-runtime §5, §9): consumer ns/msg with 1-4
// producer threads pushing flat out, and the cost of one producer's push while P-1
// other producers and a consumer run. SCQ vs the Vyukov baseline (blocking in
// practice), u64 items and 256-byte inbound-message-sized items.
#include <benchmark/benchmark.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

#include "bench_util.h"
#include "concurrent/mpsc_scq.h"
#include "concurrent/mpsc_vyukov.h"
#include "concurrent/spsc_ring.h"
#include "concurrent/wait.h"

namespace lle::conc {
namespace {

using bench::Background;
using bench::stopped;

struct alignas(64) Msg256 {  // InboundMsg-sized slot (08 §5)
  std::uint64_t seq;
  std::uint8_t body[248];
};

template <class T>
T make_item(std::uint64_t i) {
  if constexpr (sizeof(T) == sizeof(std::uint64_t)) {
    return i;
  } else {
    T m{};
    m.seq = i;
    return m;
  }
}

// One iteration = one item popped by the (benchmark) consumer thread. With kBackoff
// false, producers retry a full queue immediately (saturation: in SCQ every failed push
// runs the free-index ring's empty path, contending with the consumer); with kBackoff
// true they back off (PAUSE bursts, then yield) like a gateway applying flow control.
template <class Q, bool kBackoff = false>
void BM_MpscConsumer(benchmark::State& state) {
  using T = typename Q::value_type;
  auto q = std::make_unique<Q>();
  std::vector<std::unique_ptr<Background>> producers;
  for (std::int64_t p = 0; p < state.range(0); ++p) {
    producers.push_back(std::make_unique<Background>([&](std::atomic<bool>& stop) {
      std::uint64_t i = 0;
      Backoff wait(4);
      while (!stopped(stop)) {
        if (q->try_push(make_item<T>(i))) {
          ++i;
          wait.reset();
        } else if constexpr (kBackoff) {
          wait.wait();
        }
      }
    }));
  }
  T v{};
  for (auto _ : state) {
    while (!q->try_pop(v)) {
    }
    benchmark::DoNotOptimize(v);
  }
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  for (auto& p : producers) p->stop();
}

// One iteration = one successful push by the measured producer, with range(0)-1 other
// producers and one consumer running.
template <class Q>
void BM_MpscProducer(benchmark::State& state) {
  using T = typename Q::value_type;
  auto q = std::make_unique<Q>();
  Background consumer([&](std::atomic<bool>& stop) {
    T v{};
    while (!stopped(stop)) {
      if (q->try_pop(v)) benchmark::DoNotOptimize(v);
    }
  });
  std::vector<std::unique_ptr<Background>> others;
  for (std::int64_t p = 1; p < state.range(0); ++p) {
    others.push_back(std::make_unique<Background>([&](std::atomic<bool>& stop) {
      std::uint64_t i = 0;
      while (!stopped(stop)) {
        if (q->try_push(make_item<T>(i))) ++i;
      }
    }));
  }
  std::uint64_t i = 0;
  for (auto _ : state) {
    while (!q->try_push(make_item<T>(i))) {
    }
    ++i;
  }
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  for (auto& o : others) o->stop();
  consumer.stop();
}

// Unsaturated latency: one iteration = push into the MPSC queue, a consumer thread pops
// and echoes through an SpscRing, the benchmark thread pops the echo (one round trip).
// The queue holds at most one item, so this measures the uncontended push/pop paths
// plus two cross-core transfers, not the full-queue regime.
template <class Q>
void BM_MpscPingPong(benchmark::State& state) {
  using T = typename Q::value_type;
  auto q = std::make_unique<Q>();
  auto back = std::make_unique<SpscRing<std::uint64_t, 64>>();
  Background echo([&](std::atomic<bool>& stop) {
    T v{};
    while (!stopped(stop)) {
      if (q->try_pop(v)) {
        while (!back->try_push(1)) {
        }
      }
    }
  });
  std::uint64_t i = 0, r = 0;
  for (auto _ : state) {
    while (!q->try_push(make_item<T>(i))) {
    }
    while (!back->try_pop(r)) {
    }
    ++i;
  }
  benchmark::DoNotOptimize(r);
  echo.stop();
}

using Scq64 = MpscScqRing<std::uint64_t, 1024>;
using Vyu64 = VyukovMpscRing<std::uint64_t, 1024>;
using Scq256 = MpscScqRing<Msg256, 1024>;
using Vyu256 = VyukovMpscRing<Msg256, 1024>;

// ---- Production-shaped SCQ measurements (docs/results/concurrency.md decision rule) ----
// The OUCH queue of apps/exchanged/shared.h: 4096 slots of an InboundMsg-sized payload.
using ScqSeq = MpscScqRing<Msg256, 4096>;

// Consumer ns per successful pop: P gateway threads push flat out and back off when the
// queue is full (flow control); the benchmark thread is the sequencer's OUCH loop.
template <class Q>
void BM_ScqSeqConsumer(benchmark::State& state) {
  BM_MpscConsumer<Q, true>(state);
}
// Cost of polling an empty queue (the sequencer polls the session and admin queues on
// every pass): no producers.
template <class Q>
void BM_ScqEmptyPoll(benchmark::State& state) {
  auto q = std::make_unique<Q>();
  typename Q::value_type v{};
  for (auto _ : state) {
    benchmark::DoNotOptimize(q->try_pop(v));
  }
}
// Single-thread push + pop (no contention): the queue's own instruction cost.
template <class Q>
void BM_ScqUncontended(benchmark::State& state) {
  auto q = std::make_unique<Q>();
  typename Q::value_type v{};
  std::uint64_t i = 0;
  for (auto _ : state) {
    benchmark::DoNotOptimize(q->try_push(make_item<typename Q::value_type>(i++)));
    benchmark::DoNotOptimize(q->try_pop(v));
  }
}
// The single-consumer specialization of the same queue (ADR-031), for the A/B
// comparison of the decision rule.
using ScqSeqSC = MpscScqRing<Msg256, 4096, true>;
BENCHMARK(BM_ScqSeqConsumer<ScqSeq>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_ScqSeqConsumer<ScqSeqSC>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_ScqEmptyPoll<ScqSeq>);
BENCHMARK(BM_ScqEmptyPoll<ScqSeqSC>);
BENCHMARK(BM_ScqUncontended<ScqSeq>);
BENCHMARK(BM_ScqUncontended<ScqSeqSC>);

BENCHMARK(BM_MpscConsumer<Scq64>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscConsumer<Scq64, true>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscConsumer<Vyu64, true>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscConsumer<Vyu64>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscConsumer<Scq256>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscConsumer<Vyu256>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscPingPong<Scq64>)->UseRealTime();
BENCHMARK(BM_MpscPingPong<Vyu64>)->UseRealTime();
BENCHMARK(BM_MpscProducer<Scq64>)->DenseRange(1, 4)->UseRealTime();
BENCHMARK(BM_MpscProducer<Vyu64>)->DenseRange(1, 4)->UseRealTime();

}  // namespace
}  // namespace lle::conc

BENCHMARK_MAIN();

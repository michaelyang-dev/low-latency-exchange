// exsim_speed: simulated events per core-second (09 §13, target >= 10^6).
//
//   BM_EventLoop     raw heap + dispatch + trace hash: 64 self-rescheduling
//                    timers with seeded delays (upper bound of the loop).
//   BM_World/<w>/<m> a whole demo world per iteration (setup included), in
//                    no-faults (m=0) and swarm (m=1) modes; counter
//                    events_per_s is simulated events per wall second.
#include <benchmark/benchmark.h>

#include <cstdint>

#include "sim/worlds/worlds.h"
#include "sim/dist.h"
#include "sim/world.h"

namespace {

using namespace lle;
using namespace lle::sim;

struct Timers {
  World* w = nullptr;
  HandlerId h = 0;
  Prng rng{42};
  static Dispatch on(void* ctx, const Event& ev) {
    auto* t = static_cast<Timers*>(ctx);
    t->w->schedule(t->w->now() + 1 + static_cast<Nanos>(t->rng.below(10'000)), t->h, 0, ev.node, ev.a, 0, ev.a);
    return {true, ev.a};
  }
};

void BM_EventLoop(benchmark::State& state) {
  World w(1, base_fault_config());
  Timers t;
  t.w = &w;
  t.h = w.register_handler(&t, &Timers::on, "timer");
  for (std::uint64_t i = 0; i < 64; ++i) w.schedule(static_cast<Nanos>(i), t.h, 0, kNoNode, i);
  for (auto _ : state) {
    for (int i = 0; i < 4096; ++i) w.step();
  }
  state.counters["events_per_s"] =
      benchmark::Counter(static_cast<double>(state.iterations()) * 4096.0, benchmark::Counter::kIsRate);
  benchmark::DoNotOptimize(w.trace_hash());
}
BENCHMARK(BM_EventLoop);

void BM_World(benchmark::State& state) {
  const auto kind = static_cast<worlds::WorldKind>(state.range(0));
  if (!worlds::world_built(kind)) {
    state.SkipWithError("world not part of this build");
    return;
  }
  const Mode mode = state.range(1) != 0 ? Mode::Swarm : Mode::NoFaults;
  std::uint64_t seed = 1;
  std::uint64_t events = 0;
  for (auto _ : state) {
    worlds::Options o;
    o.seed = seed;
    o.faults = draw_fault_config(seed, mode, 0);
    o.plan = worlds::default_plan();
    const worlds::Report r = worlds::run_world(kind, o);
    events += r.run.events;
    seed = seed % 16 + 1;  // cycle over 16 seeds so swarm diversity is averaged
  }
  state.counters["events_per_s"] = benchmark::Counter(static_cast<double>(events), benchmark::Counter::kIsRate);
  state.counters["events_per_run"] =
      benchmark::Counter(static_cast<double>(events), benchmark::Counter::kAvgIterations);
  state.SetLabel(std::string(worlds::world_name(kind)) + (mode == Mode::Swarm ? "/swarm" : "/no-faults"));
}
BENCHMARK(BM_World)->ArgsProduct({{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, {0, 1}})->Unit(benchmark::kMillisecond);

}  // namespace

BENCHMARK_MAIN();

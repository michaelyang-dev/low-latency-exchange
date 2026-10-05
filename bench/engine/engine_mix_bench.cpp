// engine_mix_bench: Engine::apply() cost on the T20 message mix
// (05-matching-engine §8; 12-benchmarking-evidence). Indicative only on the
// dev Mac: never a headline number.
//
// Mix per OUCH inbound message: 45% Enter non-marketable over ~2,000 symbols,
// 40% Cancel, 10% Replace (non-marketable, new UserRefNum), 5% marketable IOC.
// The record stream is generated before timing; each timed iteration applies
// one record (decode, validation, matching, OUCH/ITCH encoding into a
// counting sink). When the stream is exhausted the engine is rebuilt outside
// the timed region and the stream replays from the start.
//
// BM_EngineMix/1 loads the pre-registered T20 risk profile
// (engine/risk/profiles.h) on every account; /0 runs with no risk limits
// (Limit Order Protection, on by default, still applies).
#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "common/prng.h"
#include "engine/engine.h"
#include "engine/risk/profiles.h"
#include "engine/scenario.h"

namespace {

using namespace lle;
using namespace lle::engine;

constexpr std::size_t kSymbols = 2'000;
constexpr std::size_t kSessions = 64;
constexpr PxE4 kMid = 500'000;  // $50.00
constexpr PxE4 kTick = 100;

struct Workload {
  Scenario sc;
  std::size_t setup = 0;  // records before order flow
  std::uint64_t enters = 0, cancels = 0, replaces = 0, iocs = 0;
};

std::unique_ptr<Workload> build(std::size_t n_msgs, std::uint64_t seed, bool risk) {
  auto w = std::make_unique<Workload>();
  Scenario& sc = w->sc;
  sc.day_start();
  std::vector<SymbolEntry> syms(kSymbols);
  std::vector<std::string> names(kSymbols);
  for (std::size_t i = 0; i < kSymbols; ++i) {
    names[i] = "S" + std::to_string(i);
    syms[i].symbol = Symbol8(names[i]);
    syms[i].adv = 10'000'000;
  }
  std::vector<AccountEntry> accts(kSessions);
  std::vector<SessionEntry> sess(kSessions);
  for (std::size_t i = 0; i < kSessions; ++i) {
    accts[i].account_id = static_cast<std::uint32_t>(1000 + i);
    accts[i].firms[0] = Mpid4("F" + std::to_string(i));
    sess[i] = SessionEntry{static_cast<std::uint32_t>(i + 1), accts[i].account_id,
                           SessionEntry::kCancelOnDisconnect | SessionEntry::kMarketOrders, 'N'};
  }
  sc.symbols(syms);
  sc.accounts(accts);
  sc.sessions(sess);
  if (risk) {
    std::vector<std::uint32_t> ids;
    for (const AccountEntry& a : accts) ids.push_back(a.account_id);
    sc.risk(risk_profiles::entries(risk_profiles::kT20, ids));
  }
  w->setup = sc.size();

  struct Live {
    std::uint32_t session;
    UserRefNum urn;
    std::uint16_t sym;
    bool buy;
  };
  std::vector<Live> live;
  live.reserve(n_msgs);
  std::vector<UserRefNum> next(kSessions + 1, 1);
  Prng rng(seed);
  auto price = [&](bool buy) {
    const auto k = static_cast<PxE4>(1 + rng.below(10));
    return static_cast<std::uint64_t>(buy ? kMid - k * kTick : kMid + k * kTick);
  };
  for (std::size_t i = 0; i < n_msgs; ++i) {
    const std::uint64_t r = rng.below(100);
    if (r < 45 || live.empty()) {  // non-marketable enter
      const auto s = static_cast<std::uint32_t>(1 + rng.below(kSessions));
      const auto sym = static_cast<std::uint16_t>(rng.below(kSymbols));
      const bool buy = rng.chance(1, 2);
      const UserRefNum u = next[s]++;
      sc.ouch(s, accts[s - 1].account_id,
              enter_msg({.urn = u,
                         .side = buy ? ouch50::Side::Buy : ouch50::Side::Sell,
                         .qty = static_cast<Qty>(100 * (1 + rng.below(5))),
                         .symbol = names[sym],
                         .price = price(buy)}));
      live.push_back(Live{s, u, sym, buy});
      ++w->enters;
    } else if (r < 85) {  // cancel a (probably) live order
      const std::size_t k = rng.below(live.size());
      const Live o = live[k];
      live[k] = live.back();
      live.pop_back();
      sc.ouch(o.session, accts[o.session - 1].account_id, cancel_msg(o.urn, 0));
      ++w->cancels;
    } else if (r < 95) {  // replace: new price, new UserRefNum, back of the queue
      Live& o = live[rng.below(live.size())];
      const UserRefNum u = next[o.session]++;
      sc.ouch(o.session, accts[o.session - 1].account_id,
              replace_msg({.orig = o.urn, .urn = u, .qty = static_cast<Qty>(100 * (1 + rng.below(5))),
                           .price = price(o.buy)}));
      o.urn = u;
      ++w->replaces;
    } else {  // marketable IOC through the touch
      const auto s = static_cast<std::uint32_t>(1 + rng.below(kSessions));
      const auto sym = static_cast<std::uint16_t>(rng.below(kSymbols));
      const bool buy = rng.chance(1, 2);
      sc.ouch(s, accts[s - 1].account_id,
              enter_msg({.urn = next[s]++,
                         .side = buy ? ouch50::Side::Buy : ouch50::Side::Sell,
                         .qty = 100,
                         .symbol = names[sym],
                         .price = static_cast<std::uint64_t>(buy ? kMid + 10 * kTick : kMid - 10 * kTick),
                         .tif = ouch50::TimeInForce::Ioc}));
      ++w->iocs;
    }
  }
  return w;
}

// CountingSink plus the number of OUCH rejects ('J').
struct MixSink {
  std::uint64_t itch_msgs = 0, ouch_msgs = 0, rejects = 0;
  void itch(std::uint64_t, std::span<const std::byte>) noexcept { ++itch_msgs; }
  void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte> b) noexcept {
    ++ouch_msgs;
    rejects += b[0] == std::byte{'J'} ? 1u : 0u;
  }
  void audit(std::uint64_t, const AuditEvent&) noexcept {}
};
static_assert(OutputSink<MixSink>);

EngineConfig bench_config() {
  EngineConfig c;
  c.book.reserve_orders = std::size_t{1} << 18;
  c.book.reserve_levels = std::size_t{1} << 16;
  c.book.levels_per_side = 24;
  c.urn_capacity = std::size_t{1} << 18;
  return c;
}

void BM_EngineMix(benchmark::State& state) {
  static const std::unique_ptr<Workload> plain = build(std::size_t{1} << 21, 42, false);
  static const std::unique_ptr<Workload> risk = build(std::size_t{1} << 21, 42, true);
  const std::unique_ptr<Workload>& w = state.range(0) != 0 ? risk : plain;
  const Scenario& sc = w->sc;
  auto fresh = [&] {
    auto e = std::make_unique<Engine>(bench_config());
    CountingSink s;
    for (std::size_t i = 0; i < w->setup; ++i) e->apply(sc[i], s);
    return e;
  };
  std::unique_ptr<Engine> eng = fresh();
  MixSink sink;
  std::size_t i = w->setup;
  std::uint64_t peak = 0;
  for (auto _ : state) {
    eng->apply(sc[i], sink);
    if (++i == sc.size()) {
      state.PauseTiming();
      peak = std::max<std::uint64_t>(peak, eng->live_orders());
      eng = fresh();
      i = w->setup;
      state.ResumeTiming();
    }
  }
  peak = std::max<std::uint64_t>(peak, eng->live_orders());
  state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
  state.counters["ns/msg"] =
      benchmark::Counter(static_cast<double>(state.iterations()), benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
  state.counters["out_msgs/in"] =
      static_cast<double>(sink.itch_msgs + sink.ouch_msgs) / static_cast<double>(state.iterations());
  state.counters["live_orders"] = static_cast<double>(peak);
  state.counters["rejects/in"] = static_cast<double>(sink.rejects) / static_cast<double>(state.iterations());
  state.counters["symbols"] = static_cast<double>(kSymbols);
}
BENCHMARK(BM_EngineMix)->Arg(0)->Arg(1)->Iterations(std::int64_t{1} << 22)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_EngineMix)->Arg(0)->Arg(1)->MinTime(2.0)->Unit(benchmark::kNanosecond);

}  // namespace

BENCHMARK_MAIN();

// risk_gate_bench: RiskGate::check() cost with the pre-registered T20 risk
// profile (05-matching-engine §7 "Latency"): 64 accounts and sessions, 2,000
// symbols, non-marketable 100-500 share orders around a $50 mid, records
// 250 ns apart. This is the gate alone (inside the engine's T20 number, outside
// the T11 book number). Indicative only on the dev Mac.
#include <benchmark/benchmark.h>

#include <cstdint>
#include <vector>

#include "common/prng.h"
#include "engine/risk/profiles.h"
#include "engine/risk/risk_gate.h"

namespace {

using namespace lle;
using namespace lle::engine;

constexpr std::uint32_t kAccounts = 64;
constexpr std::uint32_t kSymbols = 2'000;
constexpr PxE4 kMid = 500'000;
constexpr PxE4 kTick = 100;

void BM_RiskGateCheck(benchmark::State& state) {
  RiskGate g;
  std::vector<std::uint32_t> session_account(kAccounts);
  std::vector<std::uint32_t> ids(kAccounts);
  for (std::uint32_t i = 0; i < kAccounts; ++i) {
    session_account[i] = i;
    ids[i] = i;
  }
  g.configure(kAccounts, session_account, kSymbols);
  for (const RiskEntry& e : risk_profiles::entries(risk_profiles::kT20, ids))
    if (!g.set(e.account_id, e.kind, e.value, 0)) state.SkipWithError("profile rejected");
  (void)g.take_rebuild();
  // Pre-generated requests (the generator is not timed).
  struct Req {
    RiskRequest r;
    RiskQuote q;
  };
  std::vector<Req> reqs(1u << 16);
  Prng rng(7);
  for (Req& x : reqs) {
    x.r.account = static_cast<std::uint32_t>(rng.below(kAccounts));
    x.r.session = x.r.account;
    x.r.locate = static_cast<Locate>(1 + rng.below(kSymbols));
    const bool buy = rng.chance(1, 2);
    x.r.marking = buy ? Marking::Buy : Marking::Sell;
    x.r.qty = static_cast<Qty>(100 * (1 + rng.below(5)));
    x.r.open = x.r.qty;
    const auto k = static_cast<PxE4>(1 + rng.below(10));
    x.r.px = buy ? kMid - k * kTick : kMid + k * kTick;
    x.r.content = dup_content(x.r.locate, x.r.marking, x.r.qty, static_cast<std::uint64_t>(x.r.px), Tif::Day,
                              Display::Visible, CrossType::Continuous);
    x.q.bid = kMid - kTick;
    x.q.ask = kMid + kTick;
    x.q.last = kMid;
    x.q.prior = kMid;
    x.q.adv = 10'000'000;
  }
  std::size_t i = 0;
  std::int64_t now = 34'200'000'000'000;
  std::uint64_t rejects = 0;
  PxE4 rp = 0;
  for (auto _ : state) {
    const Req& x = reqs[i];
    std::uint16_t c = g.check(x.r, x.q, now, &rp);
    benchmark::DoNotOptimize(c);
    rejects += c != 0 ? 1u : 0u;
    now += 250;
    if (++i == reqs.size()) i = 0;
  }
  state.counters["ns/check"] =
      benchmark::Counter(static_cast<double>(state.iterations()), benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
  state.counters["rejects/check"] = static_cast<double>(rejects) / static_cast<double>(state.iterations());
}
BENCHMARK(BM_RiskGateCheck)->MinTime(1.0)->Unit(benchmark::kNanosecond);

}  // namespace

BENCHMARK_MAIN();

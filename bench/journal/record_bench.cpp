// Record build + CRC throughput and the sequencer's per-message cost (06 §2: budget
// <= 238 ns/msg, internal goal <= 150 ns: SCQ pop, stamp, CRC, copy into L2).
// Indicative on the dev Mac; budgets are measured on host A.
#include <benchmark/benchmark.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "concurrent/mpsc_scq.h"
#include "journal/l2_ring.h"
#include "journal/record.h"
#include "sequencer/sequencer.h"

namespace {

using namespace lle;
using namespace lle::journal;

constexpr std::uint64_t kNonceA = 0x1234567890ABCDEFull;
constexpr std::uint64_t kNonceB = 0x0FEDCBA987654321ull;

// One OUCH Enter Order (47 bytes) -> a ~104-byte OuchInbound record.
void BM_BuildAndSeal(benchmark::State& st) {
  const Sealer sealer(kNonceA);
  std::vector<std::byte> msg(static_cast<std::size_t>(st.range(0)), std::byte{0x41});
  const OuchInbound o{1, 2, 3, msg};
  const std::uint32_t len = record_size(o);
  std::vector<std::byte> ring(std::size_t{1} << 20);
  std::size_t off = 0;
  ChainState c{};
  for (auto _ : st) {
    if (off + len > ring.size()) off = 0;
    ++c.last_index;
    const Stamp stamp{c.last_index, static_cast<Nanos>(c.last_index), 1, c.last_crc, 0};
    c.last_crc = build_record(ring.data() + off, stamp, o, sealer);
    off += len;
    benchmark::DoNotOptimize(c.last_crc);
  }
  st.SetItemsProcessed(st.iterations());
  st.SetBytesProcessed(st.iterations() * len);
  st.counters["record_bytes"] = len;
}
BENCHMARK(BM_BuildAndSeal)->Arg(47)->Arg(140)->Arg(1000);

// L2 -> L3: the io stage re-seals each record for the segment nonce (one XOR).
void BM_Reseal(benchmark::State& st) {
  const Sealer a(kNonceA), b(kNonceB);
  std::vector<std::byte> rec(104);
  std::vector<std::byte> msg(47);
  (void)build_record(rec.data(), Stamp{1, 1, 1, 0, 0}, OuchInbound{1, 2, 3, msg}, a);
  for (auto _ : st) {
    benchmark::DoNotOptimize(b.reseal(rec.data(), a));
    benchmark::DoNotOptimize(a.reseal(rec.data(), b));
  }
  st.SetItemsProcessed(2 * st.iterations());
}
BENCHMARK(BM_Reseal);

// Recovery / paired-assertion cost: verify a seal (one CRC pass).
void BM_Verify(benchmark::State& st) {
  const Sealer a(kNonceA);
  std::vector<std::byte> msg(static_cast<std::size_t>(st.range(0)));
  const OuchInbound o{1, 2, 3, msg};
  std::vector<std::byte> rec(record_size(o));
  (void)build_record(rec.data(), Stamp{1, 1, 1, 0, 0}, o, a);
  for (auto _ : st) benchmark::DoNotOptimize(a.verify(rec.data()));
  st.SetBytesProcessed(st.iterations() * static_cast<std::int64_t>(rec.size()));
}
BENCHMARK(BM_Verify)->Arg(47)->Arg(4000);

struct BenchClock {
  Nanos t = 1'790'000'000'000'000'000;
  Nanos now_mono() noexcept { return 0; }
  Nanos now_real() noexcept { return t += 50; }
  std::uint64_t tsc() noexcept { return 0; }
};
struct BenchEnv {
  using Clock = BenchClock;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 1024>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 16>;
  using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 16>;
  using Ring = L2Ring<1>;
};

// Single-threaded sequencer cost per message: SCQ pop + timer check + stamp + CRC +
// copy into the L2 ring + commit (the consumer drain is excluded from the timing).
void BM_SequencerPerMessage(benchmark::State& st) {
  constexpr std::size_t kRing = std::size_t{64} << 20;
  std::unique_ptr<std::uint64_t[]> storage(new std::uint64_t[kRing / 8]());
  BenchEnv::Ring ring;
  ring.init(reinterpret_cast<std::byte*>(storage.get()), kRing, kNonceA);
  BenchClock clock;
  auto ouch = std::make_unique<BenchEnv::OuchQueue>();
  auto sessions = std::make_unique<BenchEnv::SessionQueue>();
  auto admin = std::make_unique<BenchEnv::AdminQueue>();
  seq::SequencerConfig cfg;
  cfg.ouch_batch = 64;
  seq::Sequencer<BenchEnv> s(clock, *ouch, *sessions, *admin, ring, {}, cfg);
  s.resume(ChainState{}, 0, 1);
  seq::InboundMsg m;
  m.session_id = 1;
  m.account = 2;
  m.len = 47;
  std::uint64_t n = 0;
  for (auto _ : st) {
    st.PauseTiming();
    for (int i = 0; i < 64; ++i) (void)ouch->try_push(m);
    st.ResumeTiming();
    (void)s.poll();
    st.PauseTiming();
    n += ring.drain(0, [](const RecordView&) {}, 1000);
    st.ResumeTiming();
  }
  st.SetItemsProcessed(static_cast<std::int64_t>(n));
  st.counters["ns_per_msg"] =
      benchmark::Counter(static_cast<double>(n), benchmark::Counter::kIsRate | benchmark::Counter::kInvert);
}
BENCHMARK(BM_SequencerPerMessage);

}  // namespace

BENCHMARK_MAIN();

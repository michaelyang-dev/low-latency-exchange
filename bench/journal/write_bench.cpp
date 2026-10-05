// L3 journal device benchmarks on PosixJournalDevice (06 §6, §12):
//   BM_SustainedWrite   records/s and MB/s through JournalWriter (64 KiB group-commit
//                       batches, every write durable before it counts)
//   BM_CommitLatency    one 4 KiB overwrite of pre-zeroed space + durability, p50/p99
// Each runs with fsync (arg 0) and, on macOS, F_FULLFSYNC (arg 1). macOS numbers are
// indicative only (R6 R11): plain fsync there does not flush the drive cache, and
// F_FULLFSYNC is the true durability cost. The lab numbers come from
// IoUringJournalDevice with RWF_DSYNC on the PLP NVMe.
// LLE_BENCH_DIR selects the directory (default: the system temp directory).
#include <benchmark/benchmark.h>

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/posix_segment_dir.h"
#include "journal/record.h"
#include "journal/segment_preparer.h"

namespace {

using namespace lle;
using namespace lle::journal;
namespace fs = std::filesystem;

fs::path bench_dir(const char* tag) {
  const char* env = std::getenv("LLE_BENCH_DIR");
  fs::path p = fs::path(env != nullptr ? env : fs::temp_directory_path().string()) /
               (std::string("lle_journal_bench_") + tag + "_" + std::to_string(::getpid()));
  fs::remove_all(p);
  fs::create_directories(p);
  return p;
}

void BM_SustainedWrite(benchmark::State& st) {
  const bool full = st.range(0) != 0;
  const fs::path dir = bench_dir("sustained");
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + (std::uint64_t{256} << 20);
  auto d = PosixSegmentDir::open(dir.string(), false, PosixDeviceOptions{.full_fsync = full});
  Prng rng(1);
  SegmentPreparer prep(*d, rng, 20260930, kSeg);
  JournalWriterOptions o;
  o.day = 20260930;
  o.verify_records = true;
  JournalWriter<PosixJournalDevice> w(o);
  w.start(ChainState{});
  auto p = prep.create();
  if (!p || !w.add_prepared(d->device(p->handle), p->handle, p->header)) {
    st.SkipWithError("segment preparation failed");
    return;
  }
  // ~104-byte OuchInbound records, as the sequencer seals them for L2.
  const Sealer l2(0x5EED);
  RecordBuilder b(l2);
  std::vector<std::byte> msg(47, std::byte{0x4F});
  std::vector<std::byte> rec(128);
  std::uint64_t bytes = 0;
  std::uint64_t records = 0;
  for (auto _ : st) {
    for (int i = 0; i < 1000; ++i) {
      const auto r = b.append(rec, static_cast<Nanos>(records + 1), OuchInbound{1, 2, 3, msg});
      for (;;) {
        const auto s = w.append(r, l2);
        if (s == JournalWriter<PosixJournalDevice>::Status::Ok) break;
        if (s != JournalWriter<PosixJournalDevice>::Status::Busy) {
          st.SkipWithError("append failed (segment full or I/O error)");
          return;
        }
        (void)w.flush();
        (void)w.poll();
      }
      bytes += r.size();
      ++records;
    }
    (void)w.flush();
    (void)w.poll();
  }
  while (w.batch_used() != 0 || w.in_flight() != 0) {
    (void)w.flush();
    (void)w.poll();
  }
  st.SetItemsProcessed(static_cast<std::int64_t>(records));
  st.SetBytesProcessed(static_cast<std::int64_t>(bytes));
  st.counters["writes"] = static_cast<double>(w.stats().writes);
  st.counters["avg_write_KiB"] = static_cast<double>(w.stats().write_bytes) / static_cast<double>(w.stats().writes) / 1024.0;
  fs::remove_all(dir);
}
// Fixed iteration counts keep the data (1000 x 104-byte records per iteration) inside
// one 256 MiB segment.
BENCHMARK(BM_SustainedWrite)->Arg(0)->Iterations(2000)->Unit(benchmark::kMillisecond)->UseRealTime();
#if defined(__APPLE__)
BENCHMARK(BM_SustainedWrite)->Arg(1)->Iterations(300)->Unit(benchmark::kMillisecond)->UseRealTime();
#endif

void BM_CommitLatency(benchmark::State& st) {
  const bool full = st.range(0) != 0;
  const fs::path dir = bench_dir("commit");
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + (std::uint64_t{64} << 20);
  auto d = PosixSegmentDir::open(dir.string(), false, PosixDeviceOptions{.full_fsync = full});
  Prng rng(2);
  SegmentPreparer prep(*d, rng, 20260930, kSeg);
  auto p = prep.create();
  if (!p) {
    st.SkipWithError("segment preparation failed");
    return;
  }
  auto& dev = d->device(p->handle);
  std::vector<std::byte> block(kBlockBytes, std::byte{0x42});
  std::vector<double> us;
  std::uint64_t off = kSegmentHeaderBytes;
  for (auto _ : st) {
    const auto t0 = std::chrono::steady_clock::now();
    const std::int32_t r = write_sync(dev, off, block, true);
    const auto t1 = std::chrono::steady_clock::now();
    if (r != static_cast<std::int32_t>(kBlockBytes)) {
      st.SkipWithError("write failed");
      return;
    }
    us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
    st.SetIterationTime(std::chrono::duration<double>(t1 - t0).count());
    off += kBlockBytes;
    if (off + kBlockBytes > kSeg) off = kSegmentHeaderBytes;
  }
  std::sort(us.begin(), us.end());
  const auto pct = [&](double q) { return us.empty() ? 0.0 : us[static_cast<std::size_t>(q * static_cast<double>(us.size() - 1))]; };
  st.counters["p50_us"] = pct(0.50);
  st.counters["p99_us"] = pct(0.99);
  st.counters["max_us"] = us.empty() ? 0.0 : us.back();
  fs::remove_all(dir);
}
BENCHMARK(BM_CommitLatency)->Arg(0)->Iterations(5000)->UseManualTime()->Unit(benchmark::kMicrosecond);
#if defined(__APPLE__)
BENCHMARK(BM_CommitLatency)->Arg(1)->Iterations(500)->UseManualTime()->Unit(benchmark::kMicrosecond);
#endif

}  // namespace

BENCHMARK_MAIN();

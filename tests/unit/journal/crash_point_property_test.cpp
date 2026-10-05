// crash_point_property_test (06 §12): seeded crashes at random I/O steps of the L3
// writer, with out-of-order completion, out-of-order and torn persistence of
// in-flight writes (512 B or 4 KiB sectors, optionally garbage), random queue depths
// and segment sizes. For every case:
//   - recovery succeeds (a crash is never mistaken for corruption);
//   - no record that was durable at the crash is lost (last_index >= durable_index);
//   - the recovered journal is exactly a prefix of what was appended (content-wise);
//   - the writer resumes from the recovery result, a second crash (or a clean drain)
//     recovers the same way, and the final journal reads back exactly.
// Cases: LLE_CRASH_CASES (default 10,000); first seed: LLE_CRASH_SEED (default 1).
#include <gtest/gtest.h>

#include <cstdlib>
#include <string>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal_test_util.h"

namespace lle::journal {
namespace {

using testing::kDay;
using testing::MemWriter;
using testing::RecordStream;

std::uint64_t env_u64(const char* name, std::uint64_t dflt) {
  const char* v = std::getenv(name);
  return v != nullptr ? std::strtoull(v, nullptr, 10) : dflt;
}

struct Case {
  std::uint64_t seed;
  Prng rng;
  std::uint32_t qd = 4;
  std::uint64_t seg_bytes = 0;
  MemCrashOptions crash;
  MemSegmentDir dir;
  Prng nonces;
  Prng order;
  bool random_order = false;

  explicit Case(std::uint64_t s) : seed(s), rng(s), nonces(s ^ 0xA5A5), order(s ^ 0x5A5A) {
    static constexpr std::uint32_t kQd[] = {1, 2, 4, 4};
    qd = kQd[rng.below(4)];
    seg_bytes = kSegmentHeaderBytes + (rng.chance(1, 5) ? 512 * 1024 : 128 * 1024);
    crash.sector_bytes = rng.chance(1, 2) ? 512 : 4096;
    crash.w_drop = static_cast<std::uint32_t>(rng.below(3));
    crash.w_full = static_cast<std::uint32_t>(rng.below(3));
    crash.w_torn = 1 + static_cast<std::uint32_t>(rng.below(3));
    crash.garbage_den = rng.chance(1, 4) ? 8 : 0;
    random_order = rng.chance(3, 4);
  }

  JournalWriterOptions writer_opts() const {
    JournalWriterOptions o;
    o.day = kDay;
    o.queue_depth = qd;
    o.buffers = qd + 1;
    o.verify_records = rng_verify;
    return o;
  }
  RecoveryOptions recovery_opts() const { return RecoveryOptions{0, std::uint64_t{qd} * kBatchBytes, true}; }

  void add_segments(MemWriter& w, std::size_t n) {
    SegmentPreparer prep(dir, nonces, kDay, seg_bytes);
    for (std::size_t i = 0; i < n; ++i) {
      auto p = prep.create();
      ASSERT_TRUE(p.has_value());
      if (random_order) dir.device(p->handle).set_completion_rng(&order);
      ASSERT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
    }
  }

  // Runs random appends/flushes/polls for `steps` steps; returns false if the writer
  // ran out of prepared segments (the case then just crashes there).
  void run(MemWriter& w, RecordStream& s, std::uint64_t steps) {
    std::vector<std::byte> pending;
    for (std::uint64_t step = 0; step < steps; ++step) {
      const std::uint64_t a = rng.below(10);
      if (a < 6) {
        const std::uint64_t n = 1 + rng.below(20);
        for (std::uint64_t i = 0; i < n; ++i) {
          if (pending.empty()) {
            const auto r = s.next();
            pending.assign(r.begin(), r.end());
          }
          const auto st = w.append(pending, s.sealer());
          if (st != MemWriter::Status::Ok) {
            ASSERT_TRUE(st == MemWriter::Status::Busy || st == MemWriter::Status::NeedSegment)
                << "seed " << seed << " status " << static_cast<int>(st);
            break;
          }
          pending.clear();
        }
      } else if (a < 8) {
        (void)w.flush();
      } else {
        (void)w.poll();
      }
      ASSERT_FALSE(w.failed());
    }
  }

  bool rng_verify = true;
};

void check_prefix(MemSegmentDir& dir, const RecordStream& s, const RecoveryResult& r, std::uint64_t seed) {
  std::uint64_t next = 1;
  const auto sum = read_journal(dir, ReadOptions{}, [&](const RecordView& rec, const RecordLocation&) {
    EXPECT_EQ(rec.index(), next) << "seed " << seed;
    EXPECT_LE(next, s.size()) << "seed " << seed;
    if (next <= s.size()) EXPECT_TRUE(same_content(rec, RecordView(s.at(next)))) << "seed " << seed << " index " << next;
    ++next;
    return next <= s.size() + 1;
  });
  EXPECT_EQ(sum.chain, r.chain) << "seed " << seed;
  EXPECT_EQ(next - 1, r.chain.last_index) << "seed " << seed;
}

// Recovery, plus recycling of dirty spares so the writer can reuse them.
RecoveryResult recover_and_clean(Case& c) {
  RecoveryResult r = recover(c.dir, c.recovery_opts());
  if (!r.dirty_spares.empty() && r.usable()) {
    SegmentPreparer prep(c.dir, c.nonces, kDay, c.seg_bytes);
    for (std::size_t h : r.dirty_spares) EXPECT_TRUE(prep.recycle(h).has_value());
    r = recover(c.dir, c.recovery_opts());
    EXPECT_TRUE(r.dirty_spares.empty());
  }
  return r;
}

std::string describe(const RecoveryResult& r) {
  std::string out = std::string(to_string(r.status)) + " last=" + std::to_string(r.chain.last_index) +
                    " tail=" + std::to_string(r.tail_offset) + " resume=" + std::to_string(r.resume_offset) +
                    " torn=" + std::to_string(r.torn_tail) + " segs:";
  for (const auto& sg : r.segments) {
    out += " [h" + std::to_string(sg.handle) + " first=" + std::to_string(sg.header.first_index) +
           " end=" + std::to_string(sg.data_end) + " n=" + std::to_string(sg.records) + "]";
  }
  out += " spares:";
  for (const auto& sp : r.spares) out += " h" + std::to_string(sp.handle);
  out += " dirty:";
  for (auto h : r.dirty_spares) out += " h" + std::to_string(h);
  return out;
}

void run_case(std::uint64_t seed) {
  Case c(seed);
  RecordStream s(seed * 7919, testing::StreamMix{140, static_cast<std::uint32_t>(c.rng.chance(1, 3) ? 37 : 0), 12000});

  // Phase 1: write, crash at a random I/O step.
  MemWriter w(c.writer_opts());
  w.start(ChainState{});
  c.add_segments(w, 3);
  c.run(w, s, c.rng.below(300));
  const std::uint64_t durable = w.durable_index();
  c.dir.crash(c.rng, c.crash);

  RecoveryResult r = recover_and_clean(c);
  ASSERT_TRUE(r.usable()) << "seed " << seed << ": " << r.detail;
  ASSERT_GE(r.chain.last_index, durable) << "seed " << seed << ": committed record lost";
  ASSERT_LE(r.chain.last_index, s.size()) << "seed " << seed;
  check_prefix(c.dir, s, r, seed);
  if (r.chain.last_index != 0) ASSERT_EQ(r.chain.last_crc, RecordView(s.at(r.chain.last_index)).content());

  // Phase 2: resume, write more, then crash again or drain cleanly.
  MemWriter w2(c.writer_opts());
  ASSERT_TRUE(resume_writer(w2, c.dir, r)) << "seed " << seed;
  for (const auto& sp : r.spares) {
    if (c.random_order) c.dir.device(sp.handle).set_completion_rng(&c.order);
  }
  if (w2.prepared_count() < 2) c.add_segments(w2, 2);
  s.rewind(r.chain);
  c.run(w2, s, 1 + c.rng.below(200));
  const bool clean = c.rng.chance(1, 3);
  if (clean) {
    for (int spins = 0; w2.batch_used() != 0 || w2.in_flight() != 0; ++spins) {
      ASSERT_LT(spins, 100000);
      if (!w2.flush() && w2.in_flight() == 0 && w2.batch_used() != 0) break;  // NeedSegment edge
      (void)w2.poll();
    }
  }
  const std::uint64_t durable2 = w2.durable_index();
  c.dir.crash(c.rng, c.crash);
  const RecoveryResult r2 = recover_and_clean(c);
  ASSERT_TRUE(r2.usable()) << "seed " << seed << ": " << r2.detail << "\n phase1: " << describe(r)
                           << "\n phase2 writer segments=" << w2.stats().segments << " durable=" << durable2;
  ASSERT_GE(r2.chain.last_index, durable2) << "seed " << seed << ": committed record lost after resume";
  ASSERT_GE(r2.chain.last_index, r.chain.last_index) << "seed " << seed;
  check_prefix(c.dir, s, r2, seed);
  if (clean && w2.batch_used() == 0) ASSERT_EQ(r2.chain.last_index, w2.appended_index()) << "seed " << seed;
}

// Ten shards so CTest can run them in parallel; together they cover LLE_CRASH_CASES.
constexpr int kShards = 10;
class CrashPointProperty : public ::testing::TestWithParam<int> {};

TEST_P(CrashPointProperty, RecoversEveryCrash) {
  const std::uint64_t cases = env_u64("LLE_CRASH_CASES", 10'000);
  const std::uint64_t first = env_u64("LLE_CRASH_SEED", 1);
  const auto shard = static_cast<std::uint64_t>(GetParam());
  for (std::uint64_t k = shard; k < cases; k += kShards) {
    const std::uint64_t seed = first + k;
    run_case(seed);
    if (::testing::Test::HasFatalFailure() || ::testing::Test::HasNonfatalFailure()) {
      FAIL() << "first failing seed " << seed << " (rerun with LLE_CRASH_SEED=" << seed << " LLE_CRASH_CASES=1)";
    }
  }
}

INSTANTIATE_TEST_SUITE_P(Journal, CrashPointProperty, ::testing::Range(0, kShards));

}  // namespace
}  // namespace lle::journal

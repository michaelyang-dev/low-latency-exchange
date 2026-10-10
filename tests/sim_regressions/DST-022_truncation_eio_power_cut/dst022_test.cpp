// DST-022 regression test (scripted, seed-independent): after a rejoin truncation whose
// zeroing write failed, and the truncation that the rejoin then retries, a power cut must
// leave a journal that recovery accepts and that still ends at t. Found by `exsim`
// (exchange_ha_split, O-RECOVER); see sim/ledger/bugs.yaml.
//
// A dsync write that fails leaves its bytes in the page cache but not on the disk, and the
// kernel marks the pages clean (fsyncgate). When one of the truncation's zeroing writes
// fails, reads return zeros where the disk still holds the old records. The node exits and
// restarts, and recovery takes the end of the journal from what reads return. At the found
// tree it relied on those zeros after the tail without writing them, so the disk kept the
// old records. The retried truncation zeroed only up to that tail, which left the old
// records as an island past recovery's in-flight window. After a power cut, recovery
// refused the journal at every start ("valid record beyond in-flight window").
//
// The test fails each write of the truncation in turn (MemJournalDevice: the write
// completes with -EIO, its bytes are readable and never become durable), restarts
// (recovery with repair), truncates again, cuts the power (the durable images only), and
// requires recovery to accept the journal ending exactly at t with records 1..t intact.
#include <gtest/gtest.h>

#include <cerrno>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common/prng.h"
#include "journal/journal_writer.h"
#include "journal/reader.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "repl/journal_truncate.h"

namespace lle::repl {
namespace {

using namespace lle::journal;
using Bytes = std::vector<std::byte>;
using Writer = JournalWriter<MemJournalDevice>;
constexpr std::uint32_t kDay = 20261009;
// Segments well above the in-flight window, as in production (1 GiB) and the simulator.
constexpr std::uint64_t kSegBytes = kSegmentHeaderBytes + 1024 * 1024;

std::vector<Bytes> make_records(std::size_t n) {
  static const Sealer canonical;
  Prng rng(22);
  RecordBuilder b(canonical, ChainState{});
  b.set_epoch(1);
  std::vector<Bytes> out;
  Bytes buf(kMaxRecordBytes);
  const Bytes blob(4000, std::byte{0x5a});
  for (std::size_t i = 0; i < n; ++i) {
    const auto len = static_cast<std::size_t>(rng.below(3000));
    const auto r =
        b.append(std::span<std::byte>(buf), 1'790'000'000'000'000'000 + static_cast<Nanos>(i + 1) * 1000,
                 OuchInbound{static_cast<std::uint32_t>(i), 1, 1, std::span<const std::byte>(blob).first(len)});
    out.emplace_back(r.begin(), r.end());
  }
  return out;
}

void write_all(Writer& w, const std::vector<Bytes>& recs) {
  static const Sealer canonical;
  for (const Bytes& rec : recs) {
    for (int spins = 0;; ++spins) {
      const auto st = w.append(rec, canonical);
      if (st == Writer::Status::Ok) break;
      ASSERT_EQ(st, Writer::Status::Busy);
      ASSERT_LT(spins, 100000);
      (void)w.flush();
      (void)w.poll();
    }
  }
  for (int spins = 0; w.durable_index() < recs.size(); ++spins) {
    ASSERT_LT(spins, 100000);
    (void)w.flush();
    (void)w.poll();
  }
}

std::vector<Bytes> read_back(MemSegmentDir& dir) {
  std::vector<Bytes> out;
  ReadOptions o;
  o.day = kDay;
  (void)read_journal(dir, o, [&](const RecordView& v, const RecordLocation& loc) {
    Bytes b(v.bytes().begin(), v.bytes().end());
    store_le32(b.data() + hdr::kCrc, loc.sealer->content_of(v.data()));  // canonical form
    out.push_back(std::move(b));
    return true;
  });
  return out;
}

TEST(DST022, AFailedTruncationWriteDoesNotComeBackAfterAPowerCut) {
  MemSegmentDir base;
  Prng nonces(31);
  SegmentPreparer<MemSegmentDir, Prng> base_prep(base, nonces, kDay, kSegBytes);
  JournalWriterOptions wo;
  wo.day = kDay;
  Writer w(wo);
  for (int i = 0; i < 3; ++i) {
    auto p = base_prep.create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(base.device(p->handle), p->handle, p->header));
  }
  // About 1.6 segments of records; t early in the first, so that what follows t in its
  // segment is several times recovery's in-flight window.
  const std::vector<Bytes> recs = make_records(1000);
  write_all(w, recs);
  const RecoveryResult full = recover(base, RecoveryOptions{kDay, kInflightWindow, false});
  ASSERT_EQ(full.status, RecoveryStatus::Ok);
  ASSERT_EQ(full.chain.last_index, recs.size());
  ASSERT_GE(full.segments.size(), 2u);
  constexpr std::uint64_t t = 10;
  const RecoveredSegment& holder = full.segments.front();
  ASSERT_GT(holder.data_end, kSegmentHeaderBytes + 3 * kInflightWindow) << "the tail after t must exceed the window";

  int failures_seen = 0;
  for (std::uint64_t n = 0;; ++n) {
    SCOPED_TRACE("write " + std::to_string(n) + " of the truncation fails");
    ASSERT_LT(n, 100u);
    MemSegmentDir dir = base.clone(true);
    Prng prep_nonces(700 + n);
    SegmentPreparer<MemSegmentDir, Prng> prep(dir, prep_nonces, kDay, kSegBytes);
    dir.device(holder.handle).inject_write_result(n, -EIO);
    const TruncateResult tr = truncate_journal(dir, prep, kDay, t);
    if (tr.ok) break;  // fewer than n + 1 writes: every failure point was tried
    ++failures_seen;
    // The node exits and restarts: recovery reads the page cache.
    const RecoveryResult r = recover(dir, RecoveryOptions{kDay, kInflightWindow, true});
    ASSERT_TRUE(r.usable()) << "truncation stopped (" << tr.detail << "), then recovery refused: " << r.detail;
    ASSERT_GE(r.chain.last_index, t);
    // The rejoin truncates again, and succeeds.
    const TruncateResult again = truncate_journal(dir, prep, kDay, t);
    ASSERT_TRUE(again.ok) << again.detail;
    const RecoveryResult r2 = recover(dir, RecoveryOptions{kDay, kInflightWindow, true});
    ASSERT_TRUE(r2.usable()) << r2.detail;
    ASSERT_EQ(r2.chain.last_index, t);
    // Power cut: only what reached the disk is left.
    MemSegmentDir cut = dir.clone(true);
    const RecoveryResult r3 = recover(cut, RecoveryOptions{kDay, kInflightWindow, true});
    ASSERT_TRUE(r3.usable()) << "after the power cut, recovery refused: " << r3.detail;
    EXPECT_EQ(r3.chain.last_index, t);
    const std::vector<Bytes> got = read_back(cut);
    ASSERT_EQ(got.size(), t);
    for (std::uint64_t i = 0; i < t; ++i) ASSERT_EQ(got[i], recs[i]) << "record " << i + 1;
  }
  EXPECT_GE(failures_seen, 3) << "the zeroing must take several writes";
}

}  // namespace
}  // namespace lle::repl

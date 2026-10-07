// DST-018 (sim/ledger/bugs.yaml): snapshotd's follow cursor took a rejoin's records as
// the continuation of the history it had walked. The cursor had moved into the writer's
// next segment (its header is written at the switch, before the first record) and had
// walked no record of it yet. A rejoin truncation then recycled that segment, and the
// writer wrote the partner's records at the same indices, from a new segment starting
// below the cursor's position. The cursor saw the recycled segment and positioned again,
// but without the content crc of the record it had delivered last: it kept that
// expectation only when it had walked a record of the current segment. It walked the
// new records up to its position, took them for its history and delivered the next one,
// so snapshotd applied the new history on top of the old one (O-SNAPSHOT: a snapshot
// whose state no replay of the final journal reaches).
//
// The fix: once its position is verified the cursor's chain state is the record it
// delivered last, whatever segment it is in, and a suspected divergence positions again
// expecting that record.
//
// Production pieces: the journal writer, truncate_journal (exchanged's rejoin
// truncation), recover() + resume_writer(), and the FollowCursor snapshotd follows the
// journal with.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#include "common/prng.h"
#include "journal/follow_cursor.h"
#include "journal/journal_writer.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "repl/journal_truncate.h"

namespace lle::journal {
namespace {

using Bytes = std::vector<std::byte>;
using Writer = JournalWriter<MemJournalDevice>;
constexpr std::uint32_t kDay = 20261001;
constexpr std::uint64_t kSegBytes = kSegmentHeaderBytes + kBatchBytes;  // the smallest: some 40 records

JournalWriterOptions opts() {
  JournalWriterOptions o;
  o.day = kDay;
  return o;
}

std::vector<Bytes> make_records(std::uint64_t seed, std::size_t n, ChainState start, std::uint32_t epoch) {
  static const Sealer canonical;
  Prng rng(seed);
  RecordBuilder b(canonical, start);
  b.set_epoch(epoch);
  std::vector<Bytes> out;
  Bytes buf(kMaxRecordBytes);
  const Bytes blob(2000, std::byte{0x5a});
  for (std::size_t i = 0; i < n; ++i) {
    const auto len = static_cast<std::size_t>(200 + rng.below(1600));
    const auto r = b.append(std::span<std::byte>(buf), 1'790'000'000'000'000'000 + static_cast<Nanos>(i + 1) * 1000,
                            OuchInbound{static_cast<std::uint32_t>(seed), 1, 1, std::span<const std::byte>(blob).first(len)});
    out.emplace_back(r.begin(), r.end());
  }
  return out;
}

// A listing of the directory, as a fresh open of a POSIX directory is to snapshotd.
struct DirView {
  using Device = MemJournalDevice;
  MemSegmentDir* d = nullptr;
  [[nodiscard]] std::size_t count() const noexcept { return d->count(); }
  Device& device(std::size_t i) noexcept { return d->device(i); }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return d->name(i); }
  std::optional<std::size_t> create(std::string_view n, std::uint64_t size) { return d->create(n, size); }
  bool rename(std::size_t i, std::string_view n) { return d->rename(i, n); }
  bool sync_dir() noexcept { return true; }
};
struct Opener {
  MemSegmentDir* dir;
  std::optional<DirView> operator()() const { return DirView{dir}; }
};

struct Journal {
  MemSegmentDir dir;
  Prng nonces{7};
  SegmentPreparer<MemSegmentDir, Prng> prep{dir, nonces, kDay, kSegBytes};
  void top_up(Writer& w) {
    while (w.prepared_count() < 2) {
      auto p = prep.create();
      ASSERT_TRUE(p.has_value());
      ASSERT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
    }
  }
  // Appends one record; true if it went into a segment the writer just switched to.
  bool append(Writer& w, const Bytes& rec) {
    static const Sealer canonical;
    top_up(w);
    const std::uint64_t before = w.stats().segments;
    for (int spins = 0;; ++spins) {
      const auto st = w.append(rec, canonical);
      if (st == Writer::Status::Ok) break;
      EXPECT_EQ(st, Writer::Status::Busy);
      if (spins > 100000) return false;
      (void)w.flush();
      (void)w.poll();
    }
    return w.stats().segments != before;
  }
  void drain(Writer& w) {
    for (int spins = 0; (w.batch_used() != 0 || w.in_flight() != 0) && spins < 100000; ++spins) {
      (void)w.flush();
      (void)w.poll();
    }
  }
};

TEST(DST018FollowCursor, ASuspicionAfterASegmentSwitchKeepsTheRecordDeliveredLast) {
  Journal j;
  const std::vector<Bytes> old = make_records(1, 300, ChainState{}, 1);
  // The old history up to a segment switch past record 120: the switch's record stays in
  // the writer's batch, its segment's header is on the device.
  Writer w(opts());
  std::uint64_t n = 0;  // the record that went into the new segment
  for (std::size_t i = 0; i < old.size(); ++i) {
    if (j.append(w, old[i]) && i + 1 > 120) {
      n = i + 1;
      break;
    }
    if (i + 1 < old.size()) j.drain(w);
  }
  ASSERT_NE(n, 0u) << "no segment switch past record 120";
  for (int spins = 0; w.in_flight() != 0 && spins < 100000; ++spins) (void)w.poll();  // the header, not the record

  // snapshotd's cursor walks the old history to its end and moves into the new segment.
  FollowCursor<Opener> c(Opener{&j.dir});
  c.seek(1);
  std::uint64_t delivered = 0;
  for (int i = 0; i < 2000; ++i) {
    const FollowStatus st = c.poll([&](const RecordView& r) {
      EXPECT_EQ(r.index(), delivered + 1);
      ++delivered;
      return true;
    });
    ASSERT_NE(st, FollowStatus::Diverged) << c.detail();
  }
  ASSERT_EQ(delivered, n - 1);
  ASSERT_EQ(c.next_index(), n);
  ASSERT_GE(c.stats().segments, 2u);

  // exchanged dies with record n unwritten and rejoins: truncation to t, two segments
  // back; the partner's records (epoch 2) from t + 1, past n, with a segment switch
  // between t and n.
  const std::uint64_t t = n - 80;
  const repl::TruncateResult tr = repl::truncate_journal(j.dir, j.prep, kDay, t);
  ASSERT_TRUE(tr.ok) << tr.detail;
  ASSERT_GE(tr.recycled, 1u);
  const RecoveryResult r = recover(j.dir, RecoveryOptions{kDay, kInflightWindow, true});
  ASSERT_TRUE(r.usable()) << r.detail;
  ASSERT_EQ(r.chain.last_index, t);
  Writer w2(opts());
  ASSERT_TRUE(resume_writer(w2, j.dir, r));
  const std::vector<Bytes> next = make_records(2, 120, r.chain, 2);
  for (const Bytes& rec : next) (void)j.append(w2, rec);
  j.drain(w2);
  const RecoveryResult after = recover(j.dir, RecoveryOptions{kDay, kInflightWindow, false});
  ASSERT_EQ(after.chain.last_index, t + 120);
  bool starts_between = false;
  for (const auto& s : after.segments)
    starts_between = starts_between || (s.header.first_index > t + 1 && s.header.first_index < n);
  ASSERT_TRUE(starts_between) << "the new history must start a segment between t + 1 and n";

  // The cursor must report the divergence and deliver nothing of the new history.
  FollowStatus st = FollowStatus::Idle;
  std::uint64_t foreign = 0;
  for (int i = 0; i < 2000 && st != FollowStatus::Diverged; ++i) {
    st = c.poll([&](const RecordView&) {
      ++foreign;
      return true;
    });
  }
  EXPECT_EQ(st, FollowStatus::Diverged) << c.detail();
  EXPECT_EQ(foreign, 0u) << "records of the new history delivered after the old record " << n - 1;

  // Positioned again where the journal holds what it walked (record t), it follows the
  // new history.
  c.seek(t + 1, RecordView(old[t - 1]).content());
  std::uint64_t got = 0;
  for (int i = 0; i < 2000 && got < 120; ++i) {
    const FollowStatus s2 = c.poll([&](const RecordView& v) {
      EXPECT_EQ(v.index(), t + 1 + got);
      EXPECT_EQ(v.epoch(), 2u);
      ++got;
      return true;
    });
    ASSERT_NE(s2, FollowStatus::Diverged) << c.detail();
  }
  EXPECT_EQ(got, 120u);
}

}  // namespace
}  // namespace lle::journal

// FollowCursor (journal/follow_cursor.h): following a journal while the writer appends,
// across segment switches and restarts, without re-reading what was read; divergence
// (truncation, recycled segment, wrong position) reported after a confirming listing.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <vector>

#include "common/prng.h"
#include "journal/follow_cursor.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "journal_test_util.h"

namespace lle::journal {
namespace {

using testing::append_one;
using testing::drain;
using testing::kDay;
using testing::MemWriter;
using testing::RecordStream;
using testing::writer_options;

// A listing of a MemSegmentDir the writer keeps writing (what a fresh open of a POSIX
// directory is to a real follower).
struct MemDirView {
  using Device = MemJournalDevice;
  MemSegmentDir* d = nullptr;
  [[nodiscard]] std::size_t count() const noexcept { return d->count(); }
  Device& device(std::size_t i) noexcept { return d->device(i); }
  [[nodiscard]] std::string_view name(std::size_t i) const noexcept { return d->name(i); }
  std::optional<std::size_t> create(std::string_view n, std::uint64_t size) { return d->create(n, size); }
  bool rename(std::size_t i, std::string_view n) { return d->rename(i, n); }
  bool sync_dir() noexcept { return true; }
};
static_assert(SegmentDirLike<MemDirView>);

struct Opener {
  MemSegmentDir* dir;
  const bool* fail;
  std::optional<MemDirView> operator()() const {
    if (*fail) return std::nullopt;
    return MemDirView{dir};
  }
};
using Cursor = FollowCursor<Opener>;

struct Fixture {
  // `segments` prepared up front (at most the writer's queue); more as it uses them.
  explicit Fixture(std::size_t segments, std::uint64_t seg_bytes, std::uint64_t seed = 3,
                   RecordStream::Mix mix = RecordStream::Mix{})
      : w(writer_options()), s(seed, mix), nonce_rng(seed + 100), prep(dir, nonce_rng, kDay, seg_bytes) {
    w.start(ChainState{});
    for (std::size_t i = 0; i < segments; ++i) add_segment();
  }
  void add_segment() {
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    prepared.push_back(*p);
    ASSERT_TRUE(w.add_prepared(dir.device(p->handle), p->handle, p->header));
  }
  void top_up() {
    while (w.prepared_count() < 2) add_segment();
  }
  Opener opener() { return Opener{&dir, &fail}; }
  // Appends n records and makes them durable (and readable).
  void append(std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
      top_up();
      append_one(w, s.next(), s.sealer());
    }
    drain(w);
  }
  // Where record `index` lives (handle, offset, length).
  struct Where {
    std::size_t handle = 0;
    std::uint64_t offset = 0;
    std::uint32_t len = 0;
  };
  Where where(std::uint64_t index) {
    Where out;
    (void)read_journal(dir, ReadOptions{}, [&](const RecordView& r, const RecordLocation& l) {
      if (r.index() != index) return true;
      out = Where{l.handle, l.offset, r.len()};
      return false;
    });
    return out;
  }
  MemSegmentDir dir;
  std::vector<PreparedSegment> prepared;
  MemWriter w;
  RecordStream s;
  Prng nonce_rng;
  SegmentPreparer<MemSegmentDir, Prng> prep;
  bool fail = false;
};

// Polls until `want` records were delivered in total or `max_polls` polls passed.
template <class F>
FollowStatus poll_until(Cursor& c, std::uint64_t& delivered, std::uint64_t want, F&& f, int max_polls = 400) {
  FollowStatus st = FollowStatus::Idle;
  for (int i = 0; i < max_polls && delivered < want; ++i) {
    st = c.poll([&](const RecordView& r) {
      ++delivered;
      return f(r);
    });
    if (st == FollowStatus::Diverged || st == FollowStatus::IoError) break;
  }
  return st;
}

TEST(FollowCursor, FollowsTheWriterAcrossSegmentsWithoutRereading) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 256 * 1024;
  Fixture f(4, kSeg, 5, RecordStream::Mix{140, 40, 6000});
  Cursor c(f.opener());
  c.seek(1);
  std::uint64_t delivered = 0;
  auto check = [&](const RecordView& r) {
    EXPECT_EQ(r.index(), delivered);
    EXPECT_TRUE(same_content(r, RecordView(f.s.at(r.index())))) << r.index();
    return true;
  };
  f.append(40);
  EXPECT_EQ(poll_until(c, delivered, 40, check), FollowStatus::Records);
  ASSERT_EQ(delivered, 40u);
  Prng rng(11);
  std::uint64_t in_segment_polls = 0;
  for (int round = 0; round < 400; ++round) {
    const std::uint64_t segments = c.stats().segments;
    const std::uint64_t listings = c.stats().listings;
    const std::uint64_t bytes = c.stats().bytes_read;
    std::uint64_t appended_bytes = 0;
    const std::size_t n = 1 + static_cast<std::size_t>(rng.below(6));
    for (std::size_t i = 0; i < n; ++i) appended_bytes += f.s.next().size();
    for (std::size_t i = f.s.size() - n + 1; i <= f.s.size(); ++i) {
      f.top_up();
      append_one(f.w, f.s.at(i), f.s.sealer());
    }
    drain(f.w);
    const std::uint64_t before = delivered;
    const FollowStatus st = c.poll([&](const RecordView& r) {
      ++delivered;
      return check(r);
    });
    ASSERT_NE(st, FollowStatus::Diverged) << c.detail();
    if (delivered == before + n && c.stats().segments == segments) {
      // Records within one segment: the poll read about their bytes, not the segment so
      // far, and did not list the directory.
      ++in_segment_polls;
      EXPECT_LE(c.stats().bytes_read - bytes, 2 * appended_bytes + 2 * kMaxRecordBytes + kHeaderBytes) << round;
      EXPECT_EQ(c.stats().listings, listings) << round;
    } else {
      // The writer switched segments: the cursor finds the next one after a short idle.
      EXPECT_EQ(poll_until(c, delivered, f.s.size(), check), FollowStatus::Records) << c.detail();
    }
    ASSERT_EQ(delivered, f.s.size()) << round;
  }
  EXPECT_GT(in_segment_polls, 300u);
  EXPECT_GE(c.stats().segments, 4u) << "the stream spans several segments";
  EXPECT_EQ(c.stats().positions, 1u) << "never re-positioned";
  // All the journal holds, read about once (plus read-ahead and tail probes).
  std::uint64_t journal_bytes = 0;
  for (std::size_t i = 1; i <= f.s.size(); ++i) journal_bytes += f.s.at(i).size();
  EXPECT_LT(c.stats().bytes_read, 3 * journal_bytes + 400 * (2 * kMaxRecordBytes)) << c.stats().bytes_read;
  // Idle polls at the tail: header-sized probes, a listing only now and then.
  const std::uint64_t bytes = c.stats().bytes_read;
  const std::uint64_t listings = c.stats().listings;
  for (int i = 0; i < 200; ++i) EXPECT_EQ(c.poll(check), FollowStatus::Idle);
  EXPECT_LE(c.stats().listings - listings, 8u) << "rescans back off";
  EXPECT_LE(c.stats().bytes_read - bytes, 200 * kHeaderBytes + 8 * (2 * kMaxRecordBytes));
}

TEST(FollowCursor, StartsAtAPositionAndChecksTheRecordBeforeIt) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 64 * 1024;
  Fixture f(8, kSeg, 9);
  f.append(600);
  ASSERT_GE(f.w.stats().segments, 2u);
  const std::uint64_t total = f.s.size();
  const std::uint32_t crc200 = RecordView(f.s.at(200)).content();
  {
    Cursor c(f.opener());
    c.seek(201, crc200);
    std::uint64_t got = 0, next = 201;
    const FollowStatus st = poll_until(c, got, total - 200, [&](const RecordView& r) {
      EXPECT_EQ(r.index(), next++);
      return true;
    });
    EXPECT_EQ(st, FollowStatus::Records);
    EXPECT_EQ(got, total - 200);
    EXPECT_EQ(c.next_index(), total + 1);
  }
  {
    // A wrong crc for record 200: reported once a fresh listing confirms it.
    Cursor c(f.opener());
    c.seek(201, crc200 ^ 1u);
    int delivered = 0;
    EXPECT_EQ(c.poll([&](const RecordView&) { return ++delivered, true; }), FollowStatus::Idle);
    EXPECT_EQ(c.poll([&](const RecordView&) { return ++delivered, true; }), FollowStatus::Diverged) << c.detail();
    EXPECT_EQ(delivered, 0);
    EXPECT_EQ(c.poll([&](const RecordView&) { return ++delivered, true; }), FollowStatus::Diverged);
    c.seek(201, crc200);  // seek clears it
    EXPECT_EQ(c.poll([&](const RecordView&) { return ++delivered, true; }), FollowStatus::Records);
    EXPECT_GT(delivered, 0);
  }
  {
    // A position at a segment start: the segment header carries the previous crc.
    const auto w = f.where(total);
    std::uint64_t first = 0;
    for (const auto& p : f.prepared) {
      if (p.handle != w.handle) continue;
      const auto h = decode_segment_header(f.dir.device(p.handle).image().first(kSegmentHeaderBytes));
      ASSERT_TRUE(h.has_value());
      first = h->first_index;
    }
    ASSERT_GT(first, 1u);
    Cursor c(f.opener());
    c.seek(first, RecordView(f.s.at(first - 1)).content());
    std::uint64_t got = 0;
    EXPECT_EQ(poll_until(c, got, total - first + 1, [&](const RecordView& r) { return r.index() >= first; }),
              FollowStatus::Records);
    EXPECT_EQ(got, total - first + 1);
    Cursor bad(f.opener());
    bad.seek(first, RecordView(f.s.at(first - 1)).content() ^ 4u);
    EXPECT_EQ(bad.poll([](const RecordView&) { return true; }), FollowStatus::Idle);
    EXPECT_EQ(bad.poll([](const RecordView&) { return true; }), FollowStatus::Diverged) << bad.detail();
  }
  {
    // Beyond the journal's end: record total+9 is not there (walked, then confirmed).
    Cursor c(f.opener());
    c.seek(total + 10);
    int delivered = 0;
    FollowStatus st = FollowStatus::Idle;
    for (int i = 0; i < 10 && st != FollowStatus::Diverged; ++i)
      st = c.poll([&](const RecordView&) { return ++delivered, true; });
    EXPECT_EQ(st, FollowStatus::Diverged) << c.detail();
    EXPECT_EQ(delivered, 0);
    EXPECT_NE(c.detail().find("ends before the position"), std::string::npos) << c.detail();
  }
}

TEST(FollowCursor, TruncationBelowTheCursorIsDivergence) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 512 * 1024;
  Fixture f(2, kSeg, 21);
  f.append(120);
  Cursor c(f.opener());
  c.seek(1);
  std::uint64_t got = 0;
  ASSERT_EQ(poll_until(c, got, 120, [](const RecordView&) { return true; }), FollowStatus::Records);
  // A rejoin truncation to 79 (10 §5): everything from record 80 on is zeroed.
  const auto w = f.where(80);
  auto img = f.dir.device(w.handle).tamper();
  std::fill(img.begin() + static_cast<std::ptrdiff_t>(w.offset), img.end(), std::byte{0});
  FollowStatus st = FollowStatus::Idle;
  int polls = 0;
  for (; polls < 200 && st != FollowStatus::Diverged; ++polls) st = c.poll([](const RecordView&) { return true; });
  EXPECT_EQ(st, FollowStatus::Diverged) << c.detail();
  EXPECT_FALSE(c.detail().empty());
  // Re-positioned at the new end, the cursor is fine.
  c.seek(80, RecordView(f.s.at(79)).content());
  for (int i = 0; i < 10; ++i) EXPECT_NE(c.poll([](const RecordView&) { return true; }), FollowStatus::Diverged) << c.detail();
}

TEST(FollowCursor, ARecycledSegmentIsDivergence) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 512 * 1024;
  Fixture f(2, kSeg, 23);
  f.append(50);
  Cursor c(f.opener());
  c.seek(1);
  std::uint64_t got = 0;
  ASSERT_EQ(poll_until(c, got, 50, [](const RecordView&) { return true; }), FollowStatus::Records);
  ASSERT_TRUE(f.prep.recycle(f.where(50).handle).has_value());
  FollowStatus st = FollowStatus::Idle;
  for (int i = 0; i < 200 && st != FollowStatus::Diverged; ++i) st = c.poll([](const RecordView&) { return true; });
  EXPECT_EQ(st, FollowStatus::Diverged) << c.detail();
}

TEST(FollowCursor, WaitsForTheDirectoryAndTheFirstSegment) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 128 * 1024;
  Fixture f(2, kSeg, 31);
  Cursor c(f.opener());
  c.seek(1);
  f.fail = true;
  EXPECT_EQ(c.poll([](const RecordView&) { return true; }), FollowStatus::NoJournal);
  f.fail = false;
  EXPECT_EQ(c.poll([](const RecordView&) { return true; }), FollowStatus::Idle);
  EXPECT_NE(c.detail().find("no journal segment"), std::string::npos) << c.detail();
  f.append(10);
  std::uint64_t got = 0;
  EXPECT_EQ(poll_until(c, got, 10, [](const RecordView&) { return true; }), FollowStatus::Records);
  EXPECT_EQ(got, 10u);
}

// A writer restart (06 §7): recovery positions the new writer after the valid prefix of
// the last segment; the cursor at its tail goes on there.
TEST(FollowCursor, ContinuesAfterAWriterRestart) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 256 * 1024;
  Fixture f(3, kSeg, 41);
  f.append(70);
  Cursor c(f.opener());
  c.seek(1);
  std::uint64_t got = 0;
  ASSERT_EQ(poll_until(c, got, 70, [](const RecordView&) { return true; }), FollowStatus::Records);
  for (int i = 0; i < 5; ++i) EXPECT_EQ(c.poll([](const RecordView&) { return true; }), FollowStatus::Idle);
  RecoveryOptions ro;
  ro.day = kDay;
  const RecoveryResult rr = recover(f.dir, ro);
  ASSERT_TRUE(rr.usable());
  ASSERT_EQ(rr.chain.last_index, 70u);
  MemWriter w2(writer_options());
  ASSERT_TRUE(resume_writer(w2, f.dir, rr));
  for (int i = 0; i < 40; ++i) append_one(w2, f.s.next(), f.s.sealer());
  drain(w2);
  std::uint64_t next = 71;
  ASSERT_EQ(poll_until(c, got, 110,
                       [&](const RecordView& r) {
                         EXPECT_EQ(r.index(), next++);
                         EXPECT_TRUE(same_content(r, RecordView(f.s.at(r.index()))));
                         return true;
                       }),
            FollowStatus::Records)
      << c.detail();
  EXPECT_EQ(got, 110u);
}

// The callback stops the walk; the record it stopped at is consumed.
TEST(FollowCursor, ACallbackStopsAfterItsRecord) {
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 128 * 1024;
  Fixture f(2, kSeg, 51);
  f.append(30);
  Cursor c(f.opener());
  c.seek(1);
  std::vector<std::uint64_t> seen;
  EXPECT_EQ(c.poll([&](const RecordView& r) {
    seen.push_back(r.index());
    return r.index() != 12;
  }),
            FollowStatus::Stopped);
  EXPECT_EQ(seen.back(), 12u);
  EXPECT_EQ(c.next_index(), 13u);
  EXPECT_EQ(c.poll([&](const RecordView& r) {
    seen.push_back(r.index());
    return true;
  }),
            FollowStatus::Records);
  ASSERT_EQ(seen.size(), 30u);
  for (std::size_t i = 0; i < seen.size(); ++i) EXPECT_EQ(seen[i], i + 1);
}

}  // namespace
}  // namespace lle::journal

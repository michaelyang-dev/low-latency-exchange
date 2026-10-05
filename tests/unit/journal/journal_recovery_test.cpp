// Recovery (06 §7, §12): torn tails, out-of-order in-flight writes, recycled segments,
// corruption beyond the in-flight window, and the resume path.
#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal_test_util.h"

namespace lle::journal {
namespace {

using testing::append_one;
using testing::drain;
using testing::kDay;
using testing::MemWriter;
using testing::prepare_segments;
using testing::RecordStream;
using testing::writer_options;

void restore_image(MemJournalDevice& d, const std::vector<std::byte>& img) {
  auto t = d.tamper();
  ASSERT_EQ(t.size(), img.size());
  std::copy(img.begin(), img.end(), t.begin());
  d.sync_tamper();
}

std::vector<std::byte> durable_copy(const MemJournalDevice& d) {
  const auto img = d.durable_image();
  return {img.begin(), img.end()};
}

struct Journal {
  Journal(std::size_t segments, std::uint64_t seg_bytes, std::uint64_t seed = 7) : w(writer_options()) {
    prepared = prepare_segments(dir, segments, seg_bytes, seed);
    w.start(ChainState{});
    for (const auto& p : prepared) EXPECT_TRUE(w.add_prepared(dir.device(p.handle), p.handle, p.header));
  }
  MemJournalDevice& dev(std::size_t i = 0) { return dir.device(prepared[i].handle); }
  MemSegmentDir dir;
  std::vector<PreparedSegment> prepared;
  MemWriter w;
};

// The end offset of every record of the last segment, from a clean read-back.
std::vector<std::pair<std::uint64_t, std::uint64_t>> record_ends(MemSegmentDir& dir) {
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ends;  // (index, end offset)
  (void)read_journal(dir, ReadOptions{}, [&](const RecordView& r, const RecordLocation& loc) {
    ends.emplace_back(r.index(), loc.offset + r.len());
    return true;
  });
  return ends;
}

std::uint64_t expected_last(const std::vector<std::pair<std::uint64_t, std::uint64_t>>& ends, std::uint64_t cut) {
  std::uint64_t last = 0;
  for (const auto& [index, end] : ends) {
    if (end <= cut) last = index;
  }
  return last;
}

// Journal.TornTailRecoversByCrc: truncate (zero the rest) or garble one byte at every
// byte offset of the last batch; recovery must keep exactly the records before the
// damage, report a torn tail, and leave a journal that recovers cleanly and accepts
// appends.
TEST(Journal, TornTailRecoversByCrc) {
  Journal j(1, kSegmentHeaderBytes + 320 * 1024);
  RecordStream s(11);
  for (int i = 0; i < 150; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  const std::uint64_t b0 = j.w.write_offset();
  const std::uint64_t before_last_batch = j.w.durable_index();
  for (int i = 0; i < 50; ++i) ASSERT_EQ(j.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  drain(j.w);
  const std::uint64_t b1 = j.w.write_offset();
  ASSERT_GT(b1 - b0, std::uint64_t{kBlockBytes});  // the last batch spans several blocks
  ASSERT_LE(b1 - b0, std::uint64_t{kBatchBytes});
  const std::uint64_t last = j.w.durable_index();
  auto& dev = j.dev();
  const std::vector<std::byte> img = durable_copy(dev);
  const auto ends = record_ends(j.dir);
  ASSERT_EQ(ends.back().first, last);

  for (int mode = 0; mode < 2; ++mode) {
    for (std::uint64_t o = b0; o < b1; ++o) {
      restore_image(dev, img);
      auto t = dev.tamper();
      std::uint64_t cut = o;
      if (mode == 0) {
        std::fill(t.begin() + static_cast<std::ptrdiff_t>(o), t.begin() + static_cast<std::ptrdiff_t>(b1), std::byte{0});
        // Zeroing only changes non-zero bytes (padding is already zero): the damage
        // starts at the first one.
        cut = b1;
        for (std::uint64_t k = o; k < b1; ++k) {
          if (img[k] != std::byte{0}) {
            cut = k;
            break;
          }
        }
      } else {
        t[o] ^= std::byte{0xFF};
        // The damaged record is lost: the cut is its start.
        std::uint64_t start = b0;
        for (const auto& [index, end] : ends) {
          if (end <= o) start = std::max(start, end);
        }
        cut = start;
      }
      dev.sync_tamper();
      const RecoveryResult r = recover(j.dir);
      ASSERT_EQ(r.status, RecoveryStatus::Ok) << "mode " << mode << " offset " << o << ": " << r.detail;
      const std::uint64_t want = std::max(expected_last(ends, cut), before_last_batch);
      ASSERT_EQ(r.chain.last_index, want) << "mode " << mode << " offset " << o;
      ASSERT_EQ(r.chain.last_crc, RecordView(s.at(want)).content());
      ASSERT_EQ(r.resume_offset % kBlockBytes, 0u);
      ASSERT_GE(r.resume_offset, r.tail_offset);
      if (r.torn_tail) {
        ASSERT_TRUE(r.repaired);
      }
      // The repaired journal recovers cleanly to the same point (sampled: it doubles
      // the cost of each case).
      if ((o - b0) % 13 != 0) continue;
      const RecoveryResult again = recover(j.dir);
      ASSERT_EQ(again.status, RecoveryStatus::Ok);
      ASSERT_EQ(again.chain, r.chain);
      ASSERT_FALSE(again.torn_tail) << "mode " << mode << " offset " << o;
      ASSERT_EQ(again.resume_offset, r.resume_offset);
    }
  }

  // After the last case, resume and append: everything reads back.
  RecoveryResult r = recover(j.dir);
  MemWriter w2(writer_options());
  ASSERT_TRUE(resume_writer(w2, j.dir, r));
  s.rewind(r.chain);
  for (int i = 0; i < 50; ++i) append_one(w2, s.next(), s.sealer());
  drain(w2);
  testing::expect_journal_matches(j.dir, s, s.size());
}

// Journal.OutOfOrderInflightWritesAreTornTail: write k+1 persisted, write k did not.
TEST(Journal, OutOfOrderInflightWritesAreTornTail) {
  Journal j(1, kSegmentHeaderBytes + 1024 * 1024);
  RecordStream s(12);
  for (int i = 0; i < 400; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  const std::uint64_t durable = j.w.durable_index();
  auto& dev = j.dev();
  dev.set_hold(true);
  const std::uint64_t bk = j.w.write_offset();
  for (int i = 0; i < 30; ++i) ASSERT_EQ(j.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(j.w.flush());  // write k
  const std::uint64_t bk1 = j.w.write_offset();
  const std::uint64_t first_k1 = s.size() + 1;
  for (int i = 0; i < 30; ++i) ASSERT_EQ(j.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(j.w.flush());  // write k+1
  const std::uint64_t bk2 = j.w.write_offset();
  ASSERT_EQ(dev.in_flight(), 2u);
  EXPECT_EQ(j.w.durable_index(), durable);
  const auto cur = dev.image();
  const std::vector<std::byte> k1(cur.begin() + static_cast<std::ptrdiff_t>(bk1), cur.begin() + static_cast<std::ptrdiff_t>(bk2));
  // Crash: both writes lost, then write k+1 lands anyway (out-of-order persistence).
  Prng rng(1);
  dev.crash(rng, MemCrashOptions{512, 1, 0, 0, 0});
  auto t = dev.tamper();
  std::copy(k1.begin(), k1.end(), t.begin() + static_cast<std::ptrdiff_t>(bk1));
  dev.sync_tamper();
  // Records of write k+1 are validly sealed but cannot chain: index first_k1 follows a hole.
  ASSERT_TRUE(Sealer(j.prepared[0].header.nonce).verify(dev.image().data() + bk1).has_value());

  const RecoveryResult r = recover(j.dir);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, durable);
  EXPECT_EQ(r.tail_offset, bk);
  EXPECT_TRUE(r.torn_tail);
  EXPECT_TRUE(r.repaired);
  EXPECT_GE(r.discarded_records, 30u);  // write k+1's records (and its pad) were dropped
  EXPECT_EQ(r.resume_offset, bk);
  // Repair zeroed the window: write k+1 is gone.
  const auto after = dev.durable_image();
  EXPECT_TRUE(std::all_of(after.begin() + static_cast<std::ptrdiff_t>(bk1), after.begin() + static_cast<std::ptrdiff_t>(bk2),
                          [](std::byte b) { return b == std::byte{0}; }));
  (void)first_k1;

  // Nothing durable was lost, and the journal continues.
  MemWriter w2(writer_options());
  ASSERT_TRUE(resume_writer(w2, j.dir, r));
  s.rewind(r.chain);
  for (int i = 0; i < 100; ++i) append_one(w2, s.next(), s.sealer());
  drain(w2);
  const RecoveryResult r2 = recover(j.dir);
  ASSERT_EQ(r2.status, RecoveryStatus::Ok);
  EXPECT_FALSE(r2.torn_tail);
  EXPECT_EQ(r2.chain.last_index, s.size());
  testing::expect_journal_matches(j.dir, s, s.size());
}

// Journal.RecycledSegmentStaleRecordsRejected: a segment of yesterday's journal is
// recycled for today. Even if its old records survived (incomplete zero-fill), today's
// journal starts at index 1 with prev_crc 0 again, so those records would chain
// perfectly; only the fresh nonce rejects them.
TEST(Journal, RecycledSegmentStaleRecordsRejected) {
  constexpr std::uint64_t kSegBytes = kSegmentHeaderBytes + 1024 * 1024;
  MemSegmentDir dir;
  RecordStream yesterday(13);
  std::uint64_t old_nonce = 0;
  {
    auto prepared = prepare_segments(dir, 1, kSegBytes, 100);
    old_nonce = prepared[0].header.nonce;
    MemWriter w(writer_options());
    w.start(ChainState{});
    ASSERT_TRUE(w.add_prepared(dir.device(prepared[0].handle), prepared[0].handle, prepared[0].header));
    for (int i = 0; i < 5000; ++i) append_one(w, yesterday.next(), yesterday.sealer());
    drain(w);
    ASSERT_GT(w.write_offset(), kSegmentHeaderBytes + 2 * kInflightWindow);  // stale data beyond any window
  }
  auto& dev = dir.device(0);
  const std::vector<std::byte> stale = durable_copy(dev);

  // Recycle (re-zero + re-nonce), then put the stale bytes back after the header to
  // model a zero-fill that never reached the media.
  Prng nonce_rng(200);
  SegmentPreparer prep(dir, nonce_rng, kDay, kSegBytes);
  const auto recycled = prep.recycle(0);
  ASSERT_TRUE(recycled.has_value());
  ASSERT_NE(nonce_seed(recycled->header.nonce), nonce_seed(old_nonce));
  {
    auto t = dev.tamper();
    std::copy(stale.begin() + kSegmentHeaderBytes, stale.end(), t.begin() + kSegmentHeaderBytes);
    dev.sync_tamper();
  }

  // Today: the writer assigns the segment (first_index 1, prev_last_crc 0) and crashes
  // before its first batch persists.
  {
    MemWriter w(writer_options());
    w.start(ChainState{});
    ASSERT_TRUE(w.add_prepared(dev, 0, recycled->header));
    RecordStream today(14);
    dev.set_hold(true);
    ASSERT_EQ(w.append(today.next(), today.sealer()), MemWriter::Status::Ok);
    ASSERT_TRUE(w.flush());
    dev.deliver_only(0);  // the header write completes
    (void)w.poll();
    Prng rng(3);
    dev.crash(rng, MemCrashOptions{512, 1, 0, 0, 0});
  }
  const auto h = decode_segment_header(dev.image());
  ASSERT_TRUE(h.has_value());
  ASSERT_EQ(h->first_index, 1u);
  ASSERT_EQ(h->prev_last_crc, 0u);

  // Control: with the old nonce the first stale record would be fully valid.
  {
    const Sealer old(old_nonce);
    std::uint32_t content = 0;
    EXPECT_EQ(check_record(dev.image().data() + kSegmentHeaderBytes, kMaxRecordBytes, old, ChainState{}, content),
              RecordCheck::Valid);
  }

  const RecoveryResult r = recover(dir);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;  // stale records are neither accepted nor "corruption"
  EXPECT_EQ(r.chain.last_index, 0u);
  EXPECT_EQ(r.records, 0u);
  EXPECT_TRUE(r.torn_tail);
  EXPECT_EQ(r.discarded_records, 0u);  // not one stale record validates under the new nonce

  // The same segment, recycled properly, carries today's journal.
  MemWriter w(writer_options());
  ASSERT_TRUE(resume_writer(w, dir, r));
  RecordStream today(15);
  for (int i = 0; i < 1000; ++i) append_one(w, today.next(), today.sealer());
  drain(w);
  const RecoveryResult r2 = recover(dir);
  ASSERT_EQ(r2.status, RecoveryStatus::Ok) << r2.detail;
  EXPECT_EQ(r2.chain.last_index, 1000u);
  testing::expect_journal_matches(dir, today, 1000);
}

// Journal.CorruptionBeyondWindowRefused: a damaged record followed by valid records
// more than QD x 64 KiB later is corruption, never a torn tail; nothing is modified.
TEST(Journal, CorruptionBeyondWindowRefused) {
  Journal j(1, kSegmentHeaderBytes + 2 * 1024 * 1024);
  RecordStream s(16);
  for (int i = 0; i < 12000; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  const std::uint64_t end = j.w.write_offset();
  ASSERT_GT(end, kSegmentHeaderBytes + 3 * kInflightWindow);
  auto& dev = j.dev();
  // Damage a record ~300 KiB from the start, i.e. far from the tail.
  const std::uint64_t victim = kSegmentHeaderBytes + 300 * 1024;
  for (bool repair : {false, true}) {
    auto t = dev.tamper();
    t[victim] ^= std::byte{0x01};
    dev.sync_tamper();
    const std::vector<std::byte> before = durable_copy(dev);
    const RecoveryResult r = recover(j.dir, RecoveryOptions{0, kInflightWindow, repair});
    EXPECT_EQ(r.status, RecoveryStatus::Corruption);
    EXPECT_EQ(r.corruption, CorruptionKind::ValidRecordBeyondWindow) << r.detail;
    EXPECT_GE(r.bad_offset, victim + kInflightWindow - kMaxRecordBytes);
    EXPECT_EQ(durable_copy(dev), before);  // refused: never truncated
    MemWriter w2(writer_options());
    EXPECT_FALSE(resume_writer(w2, j.dir, r));
    t = dev.tamper();
    t[victim] ^= std::byte{0x01};  // undo
    dev.sync_tamper();
  }
  // The same damage inside the in-flight window of the tail is a torn tail.
  const std::uint64_t near_tail = end - 100 * 1024;
  auto t = dev.tamper();
  t[near_tail] ^= std::byte{0x01};
  dev.sync_tamper();
  const RecoveryResult r = recover(j.dir);
  EXPECT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_TRUE(r.torn_tail);
  EXPECT_LT(r.chain.last_index, s.size());
}

// DST-002 (exsim journal world): recovery reads the page cache. After a failed
// fdatasync (whose pages the kernel marks clean) or a kill between pwrite and
// fdatasync, records there may never reach the disk, yet the resumed writer reports
// everything recovery found as durable. inject_write_result(-EIO) models that state:
// the batch is readable, not durable. Recovery must re-persist it.
TEST(Journal, RecoveryRepersistsWhatOnlyThePageCacheHolds) {
  constexpr std::uint64_t kSegBytes = kSegmentHeaderBytes + 1024 * 1024;
  const RecoveryOptions ro{kDay, writer_options().queue_depth * std::uint64_t{kBatchBytes}, true};
  MemSegmentDir dir;
  RecordStream s(21);
  std::uint64_t durable = 0;
  {
    auto prepared = prepare_segments(dir, 1, kSegBytes, 300);
    MemWriter w(writer_options());
    w.start(ChainState{});
    ASSERT_TRUE(w.add_prepared(dir.device(prepared[0].handle), prepared[0].handle, prepared[0].header));
    for (int i = 0; i < 50; ++i) append_one(w, s.next(), s.sealer());
    drain(w);
    durable = w.durable_index();
    dir.device(prepared[0].handle).inject_write_result(0, -EIO);  // the next batch's fdatasync fails
    for (int i = 0; i < 5; ++i) append_one(w, s.next(), s.sealer());
    (void)w.flush();
    for (int spins = 0; w.in_flight() != 0 && spins < 1000; ++spins) (void)w.poll();
    ASSERT_TRUE(w.failed());  // 06 §6: fatal; the process exits
  }
  // Restart: what recovery finds becomes the resumed writer's durable_index.
  const RecoveryResult r = recover(dir, ro);
  ASSERT_TRUE(r.usable());
  ASSERT_EQ(r.chain.last_index, durable + 5);
  // Power cut: every write that was not durable is lost.
  Prng rng(3);
  dir.crash(rng, MemCrashOptions{512, 1, 0, 0, 0});
  const RecoveryResult after = recover(dir, ro);
  ASSERT_TRUE(after.usable()) << after.detail;
  EXPECT_EQ(after.chain.last_index, r.chain.last_index) << "records a resumed writer reported durable were lost";
  testing::expect_journal_matches(dir, s, after.chain.last_index);
}

// DST-002, second face: a retired segment whose header invalidation (the first step
// of recycling) failed its fdatasync looks recycled in the page cache. Unless
// recovery re-persists what it saw, a power cut brings the stale segment back and
// recovery refuses to start (segment chain break).
TEST(Journal, FailedRecycleDoesNotResurrectAfterPowerLoss) {
  const RecoveryOptions ro{kDay, writer_options().queue_depth * std::uint64_t{kBatchBytes}, true};
  MemSegmentDir dir;
  RecordStream s(22);
  std::vector<std::size_t> order;  // assigned segments, oldest first
  {
    auto prepared = prepare_segments(dir, 4, kMinSegmentBytes, 400);
    MemWriter w(writer_options());
    w.start(ChainState{});
    for (const auto& p : prepared) ASSERT_TRUE(w.add_prepared(dir.device(p.handle), p.handle, p.header));
    while (w.stats().segments < 3) append_one(w, s.next(), s.sealer());
    drain(w);
    MemWriter::AssignedSegment a;
    while (w.take_assigned(a)) order.push_back(a.handle);
  }
  ASSERT_GE(order.size(), 3u);
  // Retention retires the two oldest segments: recycling the first fails at its
  // header invalidation (fsyncgate), recycling the second succeeds.
  Prng nonce_rng(401);
  SegmentPreparer prep(dir, nonce_rng, kDay, kMinSegmentBytes);
  dir.device(order[0]).inject_write_result(0, -EIO);
  ASSERT_FALSE(prep.recycle(order[0]).has_value());
  ASSERT_TRUE(prep.recycle(order[1]).has_value());
  // Restart: the stale segment looks invalidated, so the chain starts at the third.
  const RecoveryResult r = recover(dir, ro);
  ASSERT_TRUE(r.usable()) << r.detail;
  // Power cut.
  Prng rng(4);
  dir.crash(rng, MemCrashOptions{512, 1, 0, 0, 0});
  const RecoveryResult after = recover(dir, ro);
  ASSERT_TRUE(after.usable()) << after.detail;
  EXPECT_EQ(after.first_index, r.first_index);
  EXPECT_EQ(after.chain.last_index, r.chain.last_index);
}

TEST(Recovery, EmptyJournalStartsFresh) {
  MemSegmentDir dir;
  (void)prepare_segments(dir, 2, kSegmentHeaderBytes + 256 * 1024);
  const RecoveryResult r = recover(dir);
  EXPECT_EQ(r.status, RecoveryStatus::Empty);
  EXPECT_EQ(r.spares.size(), 2u);
  EXPECT_EQ(r.day, kDay);
  MemWriter w(writer_options());
  ASSERT_TRUE(resume_writer(w, dir, r));
  EXPECT_EQ(w.prepared_count(), 2u);
  RecordStream s(17);
  for (int i = 0; i < 10; ++i) append_one(w, s.next(), s.sealer());
  drain(w);
  testing::expect_journal_matches(dir, s, 10);
}

TEST(Recovery, CleanJournalAcrossSegments) {
  Journal j(8, kSegmentHeaderBytes + 128 * 1024);
  RecordStream s(18, RecordStream::Mix{140, 40, 25000});
  for (int i = 0; i < 700; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  ASSERT_GE(j.w.stats().segments, 3u);
  const RecoveryResult r = recover(j.dir);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, s.size());
  EXPECT_EQ(r.chain, j.w.chain());
  EXPECT_EQ(r.first_index, 1u);
  EXPECT_EQ(r.records, s.size());
  EXPECT_FALSE(r.torn_tail);
  EXPECT_EQ(r.segments.size(), j.w.stats().segments);
  EXPECT_EQ(r.resume_offset, j.w.write_offset());
  EXPECT_EQ(r.spares.size(), 8 - j.w.stats().segments);
  // Resume and keep going across further segments.
  MemWriter w2(writer_options());
  ASSERT_TRUE(resume_writer(w2, j.dir, r));
  for (int i = 0; i < 200; ++i) append_one(w2, s.next(), s.sealer());
  drain(w2);
  testing::expect_journal_matches(j.dir, s, s.size());
}

// The header of a newly assigned segment never became durable, but a batch after it
// did: the segment is still "prepared" on media and must not be reused as is.
TEST(Recovery, DirtySpareDetected) {
  Journal j(2, kSegmentHeaderBytes + 128 * 1024);
  RecordStream s(19);
  auto& d1 = j.dev(1);
  d1.set_hold(true);
  while (!j.w.has_segment() || j.w.segment_handle() != j.prepared[1].handle) {
    const auto rec = s.next();
    for (;;) {
      const auto st = j.w.append(rec, s.sealer());
      if (st == MemWriter::Status::Ok) break;
      ASSERT_EQ(st, MemWriter::Status::Busy);
      (void)j.w.flush();
      (void)j.w.poll();
    }
  }
  const std::uint64_t durable_before = j.w.durable_index();
  for (int i = 0; i < 20; ++i) ASSERT_EQ(j.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(j.w.flush());
  ASSERT_EQ(d1.in_flight(), 2u);  // header + batch
  d1.deliver_only(1);             // the batch lands, the header does not
  (void)j.w.poll();
  EXPECT_EQ(j.w.durable_index(), durable_before);
  Prng rng(5);
  d1.crash(rng, MemCrashOptions{512, 1, 0, 0, 0});

  const RecoveryResult r = recover(j.dir);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_GE(r.chain.last_index, durable_before);
  ASSERT_EQ(r.dirty_spares.size(), 1u);
  EXPECT_EQ(r.dirty_spares[0], j.prepared[1].handle);
  EXPECT_TRUE(r.spares.empty());
  // Recycling makes it clean again.
  Prng nonce_rng(77);
  SegmentPreparer prep(j.dir, nonce_rng, kDay, kSegmentHeaderBytes + 128 * 1024);
  ASSERT_TRUE(prep.recycle(r.dirty_spares[0]).has_value());
  const RecoveryResult r2 = recover(j.dir);
  EXPECT_TRUE(r2.dirty_spares.empty());
  EXPECT_EQ(r2.spares.size(), 1u);
}

struct TwoSegments {
  TwoSegments() : j(3, kSegmentHeaderBytes + 128 * 1024), s(20) {
    while (j.w.stats().segments < 2 || j.w.write_offset() < kSegmentHeaderBytes + 64 * 1024) {
      append_one(j.w, s.next(), s.sealer());
    }
    drain(j.w);
  }
  Journal j;
  RecordStream s;
};

TEST(Recovery, SegmentChainBreakRefused) {
  TwoSegments t;
  auto& d = t.j.dev(1);
  auto h = decode_segment_header(d.image());
  ASSERT_TRUE(h.has_value());
  h->prev_last_crc ^= 1;
  auto img = d.tamper();
  encode_segment_header(img.first<kSegmentHeaderBytes>(), *h);
  d.sync_tamper();
  const RecoveryResult r = recover(t.j.dir);
  EXPECT_EQ(r.status, RecoveryStatus::Corruption);
  EXPECT_EQ(r.corruption, CorruptionKind::SegmentChainBreak);
}

TEST(Recovery, DuplicateSegmentRefused) {
  TwoSegments t;
  auto h0 = decode_segment_header(t.j.dev(0).image());
  auto h1 = decode_segment_header(t.j.dev(1).image());
  ASSERT_TRUE(h0 && h1);
  h1->first_index = h0->first_index;
  auto img = t.j.dev(1).tamper();
  encode_segment_header(img.first<kSegmentHeaderBytes>(), *h1);
  t.j.dev(1).sync_tamper();
  const RecoveryResult r = recover(t.j.dir);
  EXPECT_EQ(r.status, RecoveryStatus::Corruption);
  EXPECT_EQ(r.corruption, CorruptionKind::DuplicateSegment);
}

TEST(Recovery, DataAfterSealedSegmentRefused) {
  TwoSegments t;
  // Damage a record early in the (sealed) first segment.
  auto img = t.j.dev(0).tamper();
  img[kSegmentHeaderBytes + 1000] ^= std::byte{0x40};
  t.j.dev(0).sync_tamper();
  const RecoveryResult r = recover(t.j.dir);
  EXPECT_EQ(r.status, RecoveryStatus::Corruption);
  EXPECT_EQ(r.corruption, CorruptionKind::DataAfterSealedSegment);
  EXPECT_EQ(r.bad_handle, t.j.prepared[0].handle);
}

TEST(Recovery, ReportOnlyNeverWrites) {
  Journal j(1, kSegmentHeaderBytes + 512 * 1024);
  RecordStream s(21);
  for (int i = 0; i < 500; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  auto& d = j.dev();
  auto t = d.tamper();
  const std::uint64_t off = j.w.write_offset() - 3000;
  t[off] ^= std::byte{0x22};
  d.sync_tamper();
  const auto before = durable_copy(d);
  const RecoveryResult r = recover(j.dir, RecoveryOptions{0, kInflightWindow, false});
  ASSERT_EQ(r.status, RecoveryStatus::Ok);
  EXPECT_TRUE(r.torn_tail);
  EXPECT_FALSE(r.repaired);
  EXPECT_EQ(durable_copy(d), before);
  MemWriter w2(writer_options());
  EXPECT_FALSE(resume_writer(w2, j.dir, r));
}

TEST(Recovery, IgnoresBadHeadersAndOtherDays) {
  Journal j(2, kSegmentHeaderBytes + 256 * 1024);
  RecordStream s(22);
  for (int i = 0; i < 50; ++i) append_one(j.w, s.next(), s.sealer());
  drain(j.w);
  // A garbage file and a prepared segment of another day.
  const auto g = j.dir.create("junk.seg", 8192);
  ASSERT_TRUE(g.has_value());
  Prng nonce_rng(9);
  SegmentPreparer other_day(j.dir, nonce_rng, kDay - 1, kSegmentHeaderBytes + 256 * 1024);
  const auto od = other_day.create();
  ASSERT_TRUE(od.has_value());
  const RecoveryResult r = recover(j.dir);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, 50u);
  EXPECT_EQ(r.ignored.size(), 2u);
  EXPECT_EQ(r.spares.size(), 1u);
  // An explicit day that matches nothing assigned: empty, other files ignored.
  const RecoveryResult r2 = recover(j.dir, RecoveryOptions{kDay - 1, kInflightWindow, false});
  EXPECT_EQ(r2.status, RecoveryStatus::Empty);
  EXPECT_EQ(r2.spares.size(), 1u);
}

}  // namespace
}  // namespace lle::journal

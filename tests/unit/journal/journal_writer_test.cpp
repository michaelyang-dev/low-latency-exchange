// JournalWriter (06 §6): group commit, 4 KiB padding, in-order durable_index, fatal
// error policy, segment switching.
#include <gtest/gtest.h>

#include <cerrno>
#include <vector>

#include "journal/journal_writer.h"
#include "journal/mem_journal_device.h"
#include "journal/reader.h"
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

constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 512 * 1024;

struct Fixture {
  explicit Fixture(std::size_t segments = 2, std::uint64_t seg_bytes = kSeg, JournalWriterOptions o = writer_options())
      : w(o) {
    prepared = prepare_segments(dir, segments, seg_bytes);
    w.start(ChainState{});
    for (const auto& p : prepared) EXPECT_TRUE(w.add_prepared(dir.device(p.handle), p.handle, p.header));
  }
  MemJournalDevice& dev(std::size_t i = 0) { return dir.device(prepared[i].handle); }
  MemSegmentDir dir;
  std::vector<PreparedSegment> prepared;
  MemWriter w;
};

TEST(JournalWriter, GroupCommitPadsTo4KiB) {
  Fixture f;
  RecordStream s(1);
  for (int i = 0; i < 10; ++i) ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  EXPECT_EQ(f.w.durable_index(), 0u);
  ASSERT_TRUE(f.w.flush());
  EXPECT_EQ(f.w.in_flight(), 2u);  // segment header + one batch
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), 10u);
  EXPECT_EQ(f.w.write_offset(), kSegmentHeaderBytes + kBlockBytes);

  // On media: assigned header, the 10 records re-sealed with the segment nonce, a Pad
  // up to the 4 KiB boundary.
  const auto img = f.dev().durable_image();
  const auto h = decode_segment_header(img.first(kSegmentHeaderBytes));
  ASSERT_TRUE(h.has_value());
  EXPECT_EQ(h->first_index, 1u);
  EXPECT_EQ(h->epoch, 1u);
  EXPECT_EQ(h->prev_last_crc, 0u);
  const Sealer seg(h->nonce);
  std::uint64_t off = kSegmentHeaderBytes;
  for (std::uint64_t i = 1; i <= 10; ++i) {
    const auto v = parse_record(img.subspan(off));
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->index(), i);
    EXPECT_TRUE(seg.verify(v->data()).has_value());
    EXPECT_FALSE(s.sealer().verify(v->data()).has_value());
    EXPECT_TRUE(same_content(*v, RecordView(s.at(i))));
    off += v->len();
  }
  const auto pad = parse_record(img.subspan(off));
  ASSERT_TRUE(pad.has_value());
  EXPECT_EQ(pad->type(), RecordType::Pad);
  EXPECT_EQ(pad->index(), 10u);
  EXPECT_EQ(pad->prev_crc(), f.w.chain().last_crc);
  EXPECT_EQ(off + pad->len(), kSegmentHeaderBytes + kBlockBytes);
  EXPECT_GT(f.w.stats().pad_bytes, 0u);
}

TEST(JournalWriter, NaturalBatchingUpTo64KiBAndQueueDepth) {
  Fixture f;
  RecordStream s(2);
  f.dev().set_hold(true);
  std::size_t accepted = 0;
  // With completions held, the writer fills batches and submits each when it is full,
  // until queue_depth writes are outstanding; then append reports Busy.
  for (int i = 0; i < 5000; ++i) {
    const auto rec = s.next();
    const auto st = f.w.append(rec, s.sealer());
    if (st == MemWriter::Status::Busy) break;
    ASSERT_EQ(st, MemWriter::Status::Ok);
    ++accepted;
  }
  EXPECT_EQ(f.w.in_flight(), kQueueDepth);
  EXPECT_EQ(f.w.durable_index(), 0u);
  EXPECT_FALSE(f.w.flush());  // queue full
  f.dev().set_hold(false);
  (void)f.w.poll();
  EXPECT_GT(f.w.durable_index(), 0u);
  // Every write is a whole number of blocks, at most one batch.
  EXPECT_EQ(f.w.stats().write_bytes % kBlockBytes, 0u);
  EXPECT_LE(f.w.stats().write_bytes - kSegmentHeaderBytes, (f.w.stats().writes - 1) * kBatchBytes);
  // Finish: the rejected record and the rest.
  append_one(f.w, s.at(accepted + 1), s.sealer());
  for (std::size_t i = accepted + 2; i <= s.size(); ++i) append_one(f.w, s.at(i), s.sealer());
  drain(f.w);
  testing::expect_journal_matches(f.dir, s, s.size());
}

TEST(JournalWriter, DurableIndexOnlyOverContiguousCompletedWrites) {
  Fixture f;
  RecordStream s(3);
  auto& d = f.dev();
  d.set_hold(true);
  // Three batches, each closed by flush(): header write + 3 data writes in flight.
  std::uint64_t last_of_batch[3] = {};
  for (int b = 0; b < 3; ++b) {
    for (int i = 0; i < 5; ++i) ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
    last_of_batch[b] = s.size();
    ASSERT_TRUE(f.w.flush());
  }
  ASSERT_EQ(d.in_flight(), 4u);
  d.deliver_only(3);  // the third batch completes first
  EXPECT_EQ(f.w.poll(), 1u);
  EXPECT_EQ(f.w.durable_index(), 0u);
  d.deliver_only(0);  // the segment header
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), 0u);
  d.deliver_only(1);  // second batch: still waiting for the first
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), 0u);
  d.deliver_only(0);  // first batch: the whole prefix is now complete
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), last_of_batch[2]);
  EXPECT_EQ(f.w.in_flight(), 0u);
}

TEST(JournalWriter, HeaderCompletionGatesDurability) {
  Fixture f;
  RecordStream s(4);
  auto& d = f.dev();
  d.set_hold(true);
  for (int i = 0; i < 3; ++i) ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(f.w.flush());
  d.deliver_only(1);  // the batch completes, the header has not
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), 0u);
  d.deliver_only(0);
  (void)f.w.poll();
  EXPECT_EQ(f.w.durable_index(), 3u);
}

TEST(JournalWriter, EioIsFatalAndNeverRetried) {
  Fixture f;
  RecordStream s(5);
  auto& d = f.dev();
  const auto syncs = d.syncs_submitted();  // the preparer's
  // Write 0 is the segment header, write 1 the first batch, write 2 the second.
  d.inject_write_result(2, -EIO);
  for (int i = 0; i < 4; ++i) ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(f.w.flush());
  for (int i = 0; i < 4; ++i) ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(f.w.flush());
  (void)f.w.poll();
  EXPECT_TRUE(f.w.failed());
  EXPECT_EQ(f.w.error().result, -EIO);
  EXPECT_EQ(f.w.durable_index(), 4u);  // the first batch stays durable
  const auto writes = d.writes_submitted();
  EXPECT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Failed);
  EXPECT_FALSE(f.w.flush());
  (void)f.w.poll();
  EXPECT_EQ(d.writes_submitted(), writes);  // nothing retried, nothing new submitted
  EXPECT_EQ(d.syncs_submitted(), syncs);
}

TEST(JournalWriter, ShortWriteIsFatal) {
  Fixture f;
  RecordStream s(6);
  f.dev().inject_write_result(1, 512);
  ASSERT_EQ(f.w.append(s.next(), s.sealer()), MemWriter::Status::Ok);
  ASSERT_TRUE(f.w.flush());
  (void)f.w.poll();
  EXPECT_TRUE(f.w.failed());
  EXPECT_EQ(f.w.error().result, 512);
  EXPECT_EQ(f.w.error().expected, kBlockBytes);
  EXPECT_EQ(f.w.durable_index(), 0u);
}

TEST(JournalWriter, RejectsRecordsThatDoNotContinueTheChain) {
  Fixture f;
  RecordStream s(7);
  const auto r1 = s.next();
  const auto r2 = s.next();
  EXPECT_EQ(f.w.append(r2, s.sealer()), MemWriter::Status::BadRecord);  // index gap
  ASSERT_EQ(f.w.append(r1, s.sealer()), MemWriter::Status::Ok);
  EXPECT_EQ(f.w.append(r1, s.sealer()), MemWriter::Status::BadRecord);  // duplicate
  std::vector<std::byte> bad(r2.begin(), r2.end());
  bad[bad.size() - 1] ^= std::byte{1};
  EXPECT_EQ(f.w.append(bad, s.sealer()), MemWriter::Status::BadRecord);  // seal mismatch
  bad.assign(r2.begin(), r2.end());
  store_le32(bad.data() + hdr::kPrevCrc, 12345);
  (void)s.sealer().seal(bad.data());
  EXPECT_EQ(f.w.append(bad, s.sealer()), MemWriter::Status::BadRecord);  // broken chain
  std::vector<std::byte> pad(64);
  build_pad(pad.data(), 64, f.w.chain(), s.sealer());
  EXPECT_EQ(f.w.append(pad, s.sealer()), MemWriter::Status::BadRecord);  // Pads are writer-internal
  EXPECT_EQ(f.w.append(r2, Sealer(99)), MemWriter::Status::BadRecord);    // wrong source sealer
  EXPECT_EQ(f.w.append(r2, s.sealer()), MemWriter::Status::Ok);
}

TEST(JournalWriter, SegmentSwitchDrainsThenChains) {
  constexpr std::uint64_t kSmall = kSegmentHeaderBytes + 128 * 1024;
  Fixture f(8, kSmall);
  RecordStream s(8, RecordStream::Mix{140, 50, 20000});
  auto& d0 = f.dev(0);
  const auto seg1_writes = f.dev(1).writes_submitted();  // the preparer's
  // Fill the first segment with completions held: when it is full the writer must
  // wait for its outstanding writes before touching the next segment.
  d0.set_hold(true);
  MemWriter::Status st = MemWriter::Status::Ok;
  while (st == MemWriter::Status::Ok) st = f.w.append(s.next(), s.sealer());
  ASSERT_EQ(st, MemWriter::Status::Busy);
  EXPECT_EQ(f.dev(1).writes_submitted(), seg1_writes);
  d0.set_hold(false);
  append_one(f.w, s.at(s.size()), s.sealer());
  for (int i = 0; i < 1200; ++i) append_one(f.w, s.next(), s.sealer());
  drain(f.w);
  EXPECT_GE(f.w.stats().segments, 3u);

  MemWriter::AssignedSegment a;
  std::vector<MemWriter::AssignedSegment> assigned;
  while (f.w.take_assigned(a)) assigned.push_back(a);
  ASSERT_EQ(assigned.size(), f.w.stats().segments);
  EXPECT_EQ(assigned[0].header.first_index, 1u);
  for (std::size_t k = 1; k < assigned.size(); ++k) {
    const SegmentHeader& h = assigned[k].header;
    const RecordView prev(s.at(h.first_index - 1));
    EXPECT_EQ(h.prev_last_crc, prev.content()) << k;
    const auto on_media = decode_segment_header(f.dir.device(assigned[k].handle).durable_image());
    ASSERT_TRUE(on_media.has_value());
    EXPECT_EQ(*on_media, h);
  }
  testing::expect_journal_matches(f.dir, s, s.size());
}

TEST(JournalWriter, NeedSegmentUntilOneIsPrepared) {
  MemSegmentDir dir;
  MemWriter w(writer_options());
  w.start(ChainState{});
  RecordStream s(9);
  const auto r = s.next();
  EXPECT_EQ(w.append(r, s.sealer()), MemWriter::Status::NeedSegment);
  auto p = prepare_segments(dir, 1, kSeg);
  SegmentHeader wrong_day = p[0].header;
  wrong_day.day = kDay + 1;
  EXPECT_FALSE(w.add_prepared(dir.device(p[0].handle), p[0].handle, wrong_day));
  ASSERT_TRUE(w.add_prepared(dir.device(p[0].handle), p[0].handle, p[0].header));
  EXPECT_EQ(w.append(r, s.sealer()), MemWriter::Status::Ok);
}

TEST(JournalWriter, RandomCompletionOrderKeepsInvariants) {
  for (std::uint64_t seed = 1; seed <= 20; ++seed) {
    Fixture f(4);
    RecordStream s(seed, RecordStream::Mix{140, 97, 30000});
    Prng order(seed * 31);
    for (const auto& p : f.prepared) f.dir.device(p.handle).set_completion_rng(&order);
    std::uint64_t prev_durable = 0;
    for (int i = 0; i < 2500; ++i) {
      append_one(f.w, s.next(), s.sealer());
      if (order.chance(1, 8)) (void)f.w.flush();
      if (order.chance(1, 3)) (void)f.w.poll();
      ASSERT_GE(f.w.durable_index(), prev_durable);  // monotonic
      ASSERT_LE(f.w.durable_index(), f.w.appended_index());
      prev_durable = f.w.durable_index();
    }
    drain(f.w);
    testing::expect_journal_matches(f.dir, s, s.size());
  }
}

}  // namespace
}  // namespace lle::journal

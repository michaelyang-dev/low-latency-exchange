// The journal on a real file system: PosixJournalDevice, PosixSegmentDir, preparation,
// the writer, recover(path), and the journal tools run as processes.
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "journal/journal_device.h"
#include "journal/journal_writer.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "posix_test_util.h"

namespace lle::journal {
namespace {

using testing::kDay;
using testing::PosixWriter;
using testing::RecordStream;
using testing::TempDir;
using testing::write_journal;
namespace fs = std::filesystem;

TEST(PosixJournalDevice, WritesReadsAndSyncs) {
  TempDir t;
  const std::string f = (t.path / "x.seg").string();
  auto d = PosixJournalDevice::open(f, PosixDeviceOptions{.create = true, .exclusive = true});
  ASSERT_TRUE(d.has_value());
  EXPECT_FALSE(PosixJournalDevice::open(f, PosixDeviceOptions{.create = true, .exclusive = true}).has_value());
  ASSERT_TRUE(d->resize(8192));
  EXPECT_EQ(d->size(), 8192u);
  std::vector<std::byte> b(4096, std::byte{0x5A});
  ASSERT_TRUE(d->submit_write(4096, b, true, 7));
  ASSERT_TRUE(d->submit_sync(8));
  EXPECT_EQ(d->in_flight(), 2u);
  std::vector<env::DiskCompletion> got;
  EXPECT_EQ(d->poll([&](const env::DiskCompletion& c) { got.push_back(c); }), 2u);
  ASSERT_EQ(got.size(), 2u);
  EXPECT_EQ(got[0].tag, 7u);
  EXPECT_EQ(got[0].result, 4096);
  EXPECT_EQ(got[1].tag, 8u);
  EXPECT_EQ(got[1].result, 0);
  std::vector<std::byte> r(4096);
  EXPECT_EQ(d->read(4096, r), 4096);
  EXPECT_EQ(r, b);
  EXPECT_EQ(d->read(8000, r), 192);  // short at EOF
  EXPECT_EQ(write_sync(*d, 0, std::span<const std::byte>(b).first(512)), 512);
#if defined(__APPLE__)
  // F_FULLFSYNC flushes the drive cache (durability tests only, 06 §6).
  auto full = PosixJournalDevice::open(f, PosixDeviceOptions{.full_fsync = true});
  ASSERT_TRUE(full.has_value());
  EXPECT_EQ(sync_device(*full), 0);
#endif
  // Errors are reported, not retried: a read-only device cannot write.
  auto ro = PosixJournalDevice::open(f, PosixDeviceOptions{.read_only = true});
  ASSERT_TRUE(ro.has_value());
  EXPECT_LT(write_sync(*ro, 0, std::span<const std::byte>(b).first(512)), 0);
}

TEST(PosixJournal, WriteRecoverTornTailAndResume) {
  TempDir t;
  RecordStream s = write_journal(t.path, 4000, 1);
  // Segments carry canonical names; nothing else is in the directory.
  std::size_t segs = 0;
  for (const auto& e : fs::directory_iterator(t.path)) {
    const std::string n = e.path().filename().string();
    EXPECT_TRUE(n.ends_with(".seg"));
    if (!n.starts_with("prep-")) ++segs;
  }
  EXPECT_GE(segs, 2u);
  RecoveryResult r = recover(t.path.string());
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, 4000u);
  EXPECT_FALSE(r.torn_tail);

  // Tear the tail: zero the last 8 KiB of data in the last segment's file (more than
  // the closing Pad, whose payload is zeros anyway).
  auto d = PosixSegmentDir::open(t.path.string());
  ASSERT_TRUE(d.has_value());
  const RecoveredSegment& tail = r.segments.back();
  {
    std::vector<std::byte> zeros(8192);
    ASSERT_EQ(write_sync(d->device(tail.handle), tail.data_end - 8192, zeros), 8192);
  }
  r = recover(*d);
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_TRUE(r.torn_tail);
  EXPECT_TRUE(r.repaired);
  EXPECT_LT(r.chain.last_index, 4000u);
  // Resume on the same files and finish the day.
  JournalWriterOptions o;
  o.day = kDay;
  PosixWriter w(o);
  ASSERT_TRUE(resume_writer(w, *d, r));
  s.rewind(r.chain);
  for (int i = 0; i < 300; ++i) {
    const auto rec = s.next();
    while (w.append(rec, s.sealer()) != PosixWriter::Status::Ok) {
      (void)w.flush();
      (void)w.poll();
    }
  }
  while (w.batch_used() != 0 || w.in_flight() != 0) {
    (void)w.flush();
    (void)w.poll();
  }
  const RecoveryResult r2 = recover(t.path.string());
  ASSERT_EQ(r2.status, RecoveryStatus::Ok) << r2.detail;
  EXPECT_EQ(r2.chain.last_index, s.size());
  EXPECT_FALSE(r2.torn_tail);
}

}  // namespace
}  // namespace lle::journal

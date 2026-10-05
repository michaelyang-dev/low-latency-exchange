// UringSegmentDir (06 §6): the node's journal directory, io_uring where the platform
// allows it and POSIX otherwise. The writer runs end to end across two segments on
// whatever device each segment got, and recovery reads the result back.
// LLE_IO_URING_DIR selects the directory on Linux (default /var/tmp: O_DIRECT needs a
// real file system; tmpfs gets io_uring on a buffered fd).
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "journal/journal_writer.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "journal/uring_segment_dir.h"
#include "journal_test_util.h"

namespace lle::journal {
namespace {

namespace fs = std::filesystem;
using testing::kDay;
using testing::RecordStream;
using Writer = JournalWriter<UringOrPosixDevice>;

fs::path test_dir(const char* tag) {
#if defined(__linux__)
  const char* env = std::getenv("LLE_IO_URING_DIR");
  const fs::path base = env != nullptr ? env : "/var/tmp";
#else
  const fs::path base = fs::temp_directory_path();
#endif
  const fs::path d = base / (std::string("lle_uring_dir_") + tag + "_" + std::to_string(::getpid()));
  fs::remove_all(d);
  return d;
}

// Writes `n` records through the directory's devices (two prepared segments) and
// recovers them.
void write_and_recover(const fs::path& path, UringDirOptions opts, bool expect_uring) {
  auto dir = UringSegmentDir::open(path.string(), true, opts);
  ASSERT_TRUE(dir.has_value()) << dir.error();
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 2 * 1024 * 1024;
  Prng nonces(7);
  SegmentPreparer prep(*dir, nonces, kDay, kSeg);
  JournalWriterOptions wo;
  wo.day = kDay;
  Writer w(wo);
  dir->set_fixed_buffers(w.batch_buffers());
  w.start(ChainState{});
  for (int k = 0; k < 2; ++k) {
    auto p = prep.create();
    ASSERT_TRUE(p.has_value()) << "segment preparation failed (" << static_cast<int>(p.error()) << ") on "
                               << (dir->count() != 0 ? dir->device(dir->count() - 1).describe() : std::string("?"));
    ASSERT_TRUE(w.add_prepared(dir->device(p->handle), p->handle, p->header));
  }
  ASSERT_EQ(dir->count(), 2u);
  if (dir->fixed_buffer_failures() != 0) std::printf("%s\n", dir->fixed_buffer_note().c_str());
  for (std::size_t i = 0; i < dir->count(); ++i) {
    EXPECT_EQ(dir->device(i).is_io_uring(), expect_uring) << dir->device(i).describe() << " " << dir->fallback_reason();
    std::printf("segment %zu: %s\n", i, dir->device(i).describe().c_str());
  }
  if (!expect_uring) EXPECT_FALSE(dir->fallback_reason().empty());
  RecordStream s(5);
  bool failed = false;
  for (int i = 0; i < 30000 && !failed; ++i) {  // ~3 MiB of records: crosses into the second segment
    const auto rec = s.next();
    for (;;) {
      const auto st = w.append(rec, s.sealer());
      if (st == Writer::Status::Ok) break;
      if (st != Writer::Status::Busy) {
        failed = true;
        break;
      }
      (void)w.flush();
      (void)w.poll();
    }
  }
  while (!failed && !w.failed() && (w.batch_used() != 0 || w.in_flight() != 0)) {
    (void)w.flush();
    (void)w.poll();
  }
  ASSERT_FALSE(failed);
  ASSERT_FALSE(w.failed()) << "result " << w.error().result;
  EXPECT_EQ(w.durable_index(), s.size());
  const RecoveryResult r = recover(path.string());
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, s.size());
  // Reopened, the directory finds the segments again and recovery through it agrees.
  auto again = UringSegmentDir::open(path.string(), false, opts);
  ASSERT_TRUE(again.has_value());
  RecoveryOptions ro;
  ro.day = kDay;
  ro.repair = false;
  const RecoveryResult r2 = recover(*again, ro);
  EXPECT_EQ(r2.chain.last_index, s.size());
}

TEST(UringSegmentDir, WriterRunsOnIoUringWhereAvailable) {
  const fs::path d = test_dir("auto");
  write_and_recover(d, UringDirOptions{}, LLE_JOURNAL_URING_DIR_HAS_URING != 0);
  fs::remove_all(d);
}

// IOPOLL, opt-in: only where the device has polled queues (LLE_URING_IOPOLL=1; the lab's
// NVMe hosts). Elsewhere a ring may accept IOPOLL and fail real writes.
TEST(UringSegmentDir, IoPollWhereTheDeviceHasPolledQueues) {
  if (std::getenv("LLE_URING_IOPOLL") == nullptr || LLE_JOURNAL_URING_DIR_HAS_URING == 0)
    GTEST_SKIP() << "set LLE_URING_IOPOLL=1 on a host with NVMe polled queues";
  const fs::path d = test_dir("iopoll");
  UringDirOptions o;
  o.uring.iopoll = true;
  write_and_recover(d, o, true);
  fs::remove_all(d);
}

TEST(UringSegmentDir, PosixWhenIoUringIsOff) {
  const fs::path d = test_dir("posix");
  UringDirOptions o;
  o.use_io_uring = false;
  write_and_recover(d, o, false);
  fs::remove_all(d);
}

#if LLE_JOURNAL_URING_DIR_HAS_URING
// io_uring on a buffered fd (the fallback for a file system without O_DIRECT; forced
// here, since tmpfs accepts O_DIRECT on recent kernels): writes still RWF_DSYNC.
TEST(UringSegmentDir, BufferedIoUring) {
  const fs::path d = test_dir("buffered");
  UringDirOptions o;
  o.uring.direct = false;
  write_and_recover(d, o, true);
  auto dir = UringSegmentDir::open(d.string(), false, o);
  ASSERT_TRUE(dir.has_value());
  EXPECT_NE(dir->device(0).describe().find("buffered"), std::string::npos) << dir->device(0).describe();
  fs::remove_all(d);
}

// tmpfs (the VM's /tmp and /dev/shm): the node's test runs keep their journals there.
TEST(UringSegmentDir, IoUringOnTmpfs) {
  if (!fs::exists("/dev/shm")) GTEST_SKIP() << "no /dev/shm";
  const fs::path d = fs::path("/dev/shm") / ("lle_uring_dir_shm_" + std::to_string(::getpid()));
  fs::remove_all(d);
  write_and_recover(d, UringDirOptions{}, true);
  fs::remove_all(d);
}
#endif

}  // namespace
}  // namespace lle::journal

// IoUringJournalDevice (Linux, liburing): the writer runs end to end on a prepared
// segment through io_uring (WRITE_FIXED + RWF_DSYNC on O_DIRECT, IOPOLL when the device
// supports it) and recovery reads the result back. LLE_IO_URING_DIR selects the
// directory (default /var/tmp; O_DIRECT needs a real file system, not tmpfs).
#include <gtest/gtest.h>

#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "journal/io_uring_journal_device.h"
#include "journal/journal_writer.h"
#include "journal/posix_segment_dir.h"
#include "journal/recovery.h"
#include "journal/segment_preparer.h"
#include "journal_test_util.h"

namespace lle::journal {
namespace {

namespace fs = std::filesystem;
using testing::kDay;
using testing::RecordStream;

// WRITE_FIXED needs the buffers registered, which pins them against the user's
// RLIMIT_MEMLOCK; every process of the user shares that limit, so tests running in
// parallel can exhaust it. Then the writer runs with plain writes (the device's
// fallback), and the test says why instead of failing.
void register_or_explain(IoUringJournalDevice& dev, std::span<const std::span<std::byte>> bufs) {
  if (dev.register_buffers(bufs)) return;
  rlimit rl{};
  ::getrlimit(RLIMIT_MEMLOCK, &rl);
  const int e = -dev.register_error();
  std::printf("register_buffers refused (%s; RLIMIT_MEMLOCK %llu KiB, shared by this user's processes): "
              "plain writes\n",
              std::strerror(e), static_cast<unsigned long long>(rl.rlim_cur / 1024));
  EXPECT_TRUE(e == ENOMEM || e == EAGAIN) << "unexpected registration error " << e;
}

TEST(IoUringJournalDevice, WriterRunsAndRecovers) {
  const char* env = std::getenv("LLE_IO_URING_DIR");
  const fs::path dir = fs::path(env != nullptr ? env : "/var/tmp") / ("lle_uring_" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir);
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 4 * 1024 * 1024;
  std::size_t handle = 0;
  SegmentHeader header;
  {
    auto d = PosixSegmentDir::open(dir.string());
    ASSERT_TRUE(d.has_value());
    Prng nonces(1);
    SegmentPreparer prep(*d, nonces, kDay, kSeg);
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    handle = p->handle;
    header = p->header;
  }
  const std::string file = (dir / prepared_file_name(0)).string();
  IoUringOptions o;
  auto dev = IoUringJournalDevice::open(file, o);
  if (!dev) {  // e.g. no O_DIRECT on this file system
    o.direct = false;
    dev = IoUringJournalDevice::open(file, o);
  }
  ASSERT_TRUE(dev.has_value()) << "io_uring setup failed: " << -dev.error();
  JournalWriterOptions wo;
  wo.day = kDay;
  JournalWriter<IoUringJournalDevice> w(wo);
  register_or_explain(*dev, w.batch_buffers());
  std::printf("io_uring: iopoll=%d defer_taskrun=%d fixed_buffers=%d direct=%d\n", dev->iopoll_active(),
              dev->defer_taskrun_active(), dev->fixed_buffers(), o.direct);
  w.start(ChainState{});
  ASSERT_TRUE(w.add_prepared(*dev, handle, header));
  RecordStream s(3);
  bool failed = false;
  for (int i = 0; i < 20000 && !failed; ++i) {
    const auto rec = s.next();
    for (;;) {
      const auto st = w.append(rec, s.sealer());
      if (st == JournalWriter<IoUringJournalDevice>::Status::Ok) break;
      if (st != JournalWriter<IoUringJournalDevice>::Status::Busy) {
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
  ASSERT_FALSE(w.failed()) << "result " << w.error().result;
  EXPECT_EQ(w.durable_index(), s.size());
  const RecoveryResult r = recover(dir.string());
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, s.size());
  fs::remove_all(dir);
}

TEST(IoUringJournalDevice, InterruptDrivenFallback) {
  const char* env = std::getenv("LLE_IO_URING_DIR");
  const fs::path dir = fs::path(env != nullptr ? env : "/var/tmp") / ("lle_uring_fb_" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir);
  constexpr std::uint64_t kSeg = kSegmentHeaderBytes + 1024 * 1024;
  std::size_t handle = 0;
  SegmentHeader header;
  {
    auto d = PosixSegmentDir::open(dir.string());
    ASSERT_TRUE(d.has_value());
    Prng nonces(2);
    SegmentPreparer prep(*d, nonces, kDay, kSeg);
    auto p = prep.create();
    ASSERT_TRUE(p.has_value());
    handle = p->handle;
    header = p->header;
  }
  IoUringOptions o;
  o.iopoll = false;
  auto dev = IoUringJournalDevice::open((dir / prepared_file_name(0)).string(), o);
  if (!dev) {
    o.direct = false;
    dev = IoUringJournalDevice::open((dir / prepared_file_name(0)).string(), o);
  }
  ASSERT_TRUE(dev.has_value());
  JournalWriterOptions wo;
  wo.day = kDay;
  JournalWriter<IoUringJournalDevice> w(wo);
  register_or_explain(*dev, w.batch_buffers());
  w.start(ChainState{});
  ASSERT_TRUE(w.add_prepared(*dev, handle, header));
  RecordStream s(4);
  for (int i = 0; i < 5000; ++i) {
    const auto rec = s.next();
    while (w.append(rec, s.sealer()) != JournalWriter<IoUringJournalDevice>::Status::Ok) {
      ASSERT_FALSE(w.failed()) << w.error().result;
      (void)w.flush();
      (void)w.poll();
    }
  }
  while (w.batch_used() != 0 || w.in_flight() != 0) {
    ASSERT_FALSE(w.failed()) << w.error().result;
    (void)w.flush();
    (void)w.poll();
  }
  EXPECT_EQ(w.durable_index(), s.size());
  EXPECT_EQ(sync_device(*dev), 0);
  const RecoveryResult r = recover(dir.string());
  ASSERT_EQ(r.status, RecoveryStatus::Ok) << r.detail;
  EXPECT_EQ(r.chain.last_index, s.size());
  fs::remove_all(dir);
}

}  // namespace
}  // namespace lle::journal

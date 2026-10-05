// The journal tools (06 §11) run as processes against journals on disk.
#include <gtest/gtest.h>

#include <sys/wait.h>

#include <cstdio>
#include <string>
#include <vector>

#include "posix_test_util.h"

namespace lle::journal {
namespace {

using testing::TempDir;
using testing::write_journal;

struct RunResult {
  int status = -1;
  std::string out;
};

RunResult run_cmd(const std::string& cmd) {
  RunResult r;
  FILE* p = ::popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) return r;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), p)) != 0) r.out.append(buf, n);
  const int st = ::pclose(p);
  r.status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
  return r;
}

TEST(JournalTools, InspectDiffReplay) {
  TempDir a, b;
  (void)write_journal(a.path, 3000, 5);
  (void)write_journal(b.path, 3000, 5);  // same records, different nonces and files
  const std::string inspect = LLE_JOURNAL_INSPECT;
  const std::string diff = LLE_JOURNAL_DIFF;
  const std::string replay = LLE_JOURNAL_REPLAY;

  RunResult r = run_cmd(inspect + " schema");
  EXPECT_EQ(r.status, 0);
  EXPECT_NE(r.out.find("LLEJRNL1"), std::string::npos);
  r = run_cmd(inspect + " verify " + a.path.string());
  EXPECT_EQ(r.status, 0) << r.out;
  EXPECT_NE(r.out.find("status:      ok"), std::string::npos) << r.out;
  r = run_cmd(inspect + " stats " + a.path.string());
  EXPECT_EQ(r.status, 0) << r.out;
  EXPECT_NE(r.out.find("OuchInbound"), std::string::npos);
  r = run_cmd(inspect + " dump " + a.path.string() + " --from 10 --to 12");
  EXPECT_EQ(r.status, 0) << r.out;
  EXPECT_NE(r.out.find("# 3 records"), std::string::npos) << r.out;
  r = run_cmd(replay + " " + a.path.string() + " --to 1500");
  EXPECT_EQ(r.status, 0) << r.out;
  EXPECT_NE(r.out.find("replayed 1500 records"), std::string::npos) << r.out;

  r = run_cmd(diff + " " + a.path.string() + " " + b.path.string());
  EXPECT_EQ(r.status, 0) << r.out;
  EXPECT_NE(r.out.find("identical: 3000 records"), std::string::npos) << r.out;

  // b diverges: a different journal from index 1.
  TempDir c;
  (void)write_journal(c.path, 1000, 6);
  r = run_cmd(diff + " " + a.path.string() + " " + c.path.string());
  EXPECT_EQ(r.status, 1) << r.out;
  EXPECT_NE(r.out.find("diverge at record 1"), std::string::npos) << r.out;
  // A prefix: the first 1500 records of the same stream.
  TempDir p;
  (void)write_journal(p.path, 1500, 5);
  r = run_cmd(diff + " " + a.path.string() + " " + p.path.string());
  EXPECT_EQ(r.status, 1) << r.out;
  EXPECT_NE(r.out.find("prefix: b ends after 1500 equal records"), std::string::npos) << r.out;

  // Corruption far from the tail makes verify fail (read-only: the file is unchanged).
  auto d = PosixSegmentDir::open(a.path.string());
  ASSERT_TRUE(d.has_value());
  std::vector<std::byte> junk(16, std::byte{0x77});
  ASSERT_EQ(write_sync(d->device(0), kSegmentHeaderBytes + 64, junk), 16);
  r = run_cmd(inspect + " verify " + a.path.string());
  EXPECT_EQ(r.status, 1) << r.out;
  EXPECT_NE(r.out.find("corruption"), std::string::npos) << r.out;
}

}  // namespace
}  // namespace lle::journal

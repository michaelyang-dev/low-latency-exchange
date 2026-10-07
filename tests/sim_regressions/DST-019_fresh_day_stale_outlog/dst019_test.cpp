// DST-019 (sim/ledger/bugs.yaml): a node starting the day afresh numbered its output from
// the output log an earlier start of the day had left. In the seed a paired node started
// the day, could not write its incarnation file (a disk error), served anyway (md sent
// the day start's messages 1..6 on its line) and stopped. Its restart found the day
// start without an EpochStart and refused; the runbook (exchange-node.md §8) moved the
// journal's segments aside, and with no incarnation file to keep the node started the day
// afresh. Its journal was empty, but its output log still held messages 1..6: their count
// set the MoldUDP64 and SoupBinTCP positions, so the new day start's messages went out as
// 7..12, and line B carried other bytes than line A for sequence 7 (O-LINE).
//
// The fix: a fresh day start resets the day's output log (nothing in it derives from an
// empty journal), and a paired node writes its incarnation file before it sequences or
// serves anything, or does not start.
//
// Production pieces: the exchanged binary, its output log and journal files.
#include <gtest/gtest.h>

#include <sys/socket.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "harness.h"
#include "verify.h"

namespace lle::exch::test {
namespace {

void wait_for_itch(const Exchange& ex) {
  const auto end = std::chrono::steady_clock::now() + 10s;
  while (slurp(ex.outlog_dir() + "/itch.bin").empty() && std::chrono::steady_clock::now() < end)
    std::this_thread::sleep_for(10ms);
}

// A solo node started the day and wrote the day start's messages to its output log; its
// journal is then gone (moved aside). The day started again must leave an output log equal
// to what its journal regenerates: the day start once, from sequence 1.
TEST(DST019FreshDay, TheOutputLogStartsFromTheJournal) {
  const auto dir = fresh_dir("dst019-solo");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "d19";
  spec.data_dir = (dir / "data").string();
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_NE(ex.sync(), 0u);
  wait_for_itch(ex);
  ASSERT_EQ(ex.stop(), 0) << ex.output();
  const Bytes first = slurp(ex.outlog_dir() + "/itch.bin");
  ASSERT_FALSE(first.empty()) << "the day start's messages never reached the output log";

  std::filesystem::create_directories(dir / "aside");
  for (const auto& e : std::filesystem::directory_iterator(ex.journal_dir()))
    if (e.path().extension() == ".seg") std::filesystem::rename(e.path(), dir / "aside" / e.path().filename());

  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_NE(ex.sync(), 0u);
  wait_for_itch(ex);
  ASSERT_EQ(ex.stop(), 0) << ex.output();
  const Regenerated r = regenerate(ex.journal_dir(), dir / "regen");
  ASSERT_EQ(r.exit_code, 0) << r.report;
  const Bytes now = slurp(ex.outlog_dir() + "/itch.bin");
  EXPECT_TRUE(now == framed(r.itch)) << "itch.bin holds " << now.size() << " bytes, the journal regenerates "
                                     << framed(r.itch).size() << " (the earlier start's " << first.size()
                                     << " bytes kept and the new day start numbered after them)";
}

// A paired node that cannot write its incarnation file at the day start must not start:
// served without it, a restart that finds its journal empty starts the day again.
TEST(DST019FreshDay, APairedNodeWithoutItsIncarnationFileDoesNotStart) {
  const auto dir = fresh_dir("dst019-paired");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "d19p";
  spec.data_dir = (dir / "data").string();
  spec.mode = "paired";
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  spec.extra = {"[ha]",
                "bind = 127.0.0.1:" + std::to_string(free_port(SOCK_DGRAM)),
                "peer = 127.0.0.1:" + std::to_string(free_port(SOCK_DGRAM)),
                "witness = 127.0.0.1:" + std::to_string(free_port(SOCK_DGRAM)),
                "primary = 0"};
  Exchange ex(spec, dir);
  // The incarnation file cannot be written: its temporary name is taken by a directory.
  std::filesystem::create_directories(ex.journal_dir() + "/incarnation.tmp");
  ex.launch();
  const bool ready = ex.wait_ready(10s);
  const std::string out = ex.output();
  EXPECT_FALSE(ready) << out;
  EXPECT_NE(out.find("incarnation"), std::string::npos) << out;
  if (ex.running()) (void)ex.stop();
}

}  // namespace
}  // namespace lle::exch::test

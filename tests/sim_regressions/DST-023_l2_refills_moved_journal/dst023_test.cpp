// DST-023 (sim/ledger/bugs.yaml): a start journaled what its L2 file held beyond L3 and
// left the ring's bytes valid, so a later start restored the same records again into a
// journal that had been moved aside since. In the seed (exchange_ha_split, an L2 file) a
// node joining from an empty journal stopped on a disk error with records 1..4 copied to
// L2 only; its restart journaled them, found the day start without an EpochStart and
// refused. The runbook the refusal names (exchange-node.md §8) moved the journal's
// segments aside, and the next start journaled records 1..4 from L2 again and refused
// again, at every start: the node never rejoined (O-LIVE).
//
// The fix: once a start has journaled what the ring held (or found it all in L3), the
// ring gets a fresh nonce, so nothing an earlier image left validates again.
//
// Production pieces: the exchanged binary, its journal and its L2 file.
#include <gtest/gtest.h>

#include <filesystem>
#include <string>

#include "harness.h"

namespace lle::exch::test {
namespace {

void move_journal_aside(const Exchange& ex, const std::filesystem::path& to) {
  std::filesystem::create_directories(to);
  for (const auto& e : std::filesystem::directory_iterator(ex.journal_dir()))
    if (e.path().extension() == ".seg") std::filesystem::rename(e.path(), to / e.path().filename());
}

// A node with an L2 file starts the day and stops. Its journal is moved aside, as the
// runbook for an incomplete day start moves a paired node's: the next start finds the day
// start in L2 only and journals it again (L2 cannot tell a moved journal from records a
// crash kept from L3). The journal is moved aside once more: this time the start must
// begin from an empty journal, not journal the same records from L2 again.
TEST(DST023L2Restore, RecordsJournaledFromL2AreNotRestoredAgain) {
  const auto dir = fresh_dir("dst023");
  const ScopedDir cleanup(dir);
  MoldSubscriber sub;
  NodeSpec spec;
  spec.name = "d23";
  spec.data_dir = (dir / "data").string();
  spec.line_a = sub.port_a();
  spec.line_b = sub.port_b();
  spec.overrides = {"journal.l2_path = " + (dir / "l2").string()};
  Exchange ex(spec, dir);
  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_NE(ex.sync(), 0u);
  ASSERT_EQ(ex.stop(), 0) << ex.output();

  move_journal_aside(ex, dir / "aside1");
  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_NE(ex.sync(), 0u);
  const std::string second = ex.output();
  ASSERT_EQ(ex.stop(), 0) << second;
  ASSERT_NE(second.find("L2: restored"), std::string::npos) << "L2 held no records to restore:\n" << second;

  move_journal_aside(ex, dir / "aside2");
  ASSERT_TRUE(ex.start()) << ex.output();
  ASSERT_NE(ex.sync(), 0u);
  const std::string third = ex.output();
  ASSERT_EQ(ex.stop(), 0) << third;
  EXPECT_EQ(third.find("L2: restored"), std::string::npos)
      << "records an earlier start journaled from L2 were journaled again:\n"
      << third;
  EXPECT_NE(third.find("day 20261001 started"), std::string::npos) << "the day did not start afresh:\n" << third;
}

}  // namespace
}  // namespace lle::exch::test

// DST-021 regression test (scripted, seed-independent): a rejoining replica that cannot
// read back the record at its truncation point yet must ask again, not take it for a
// divergence. Found by `exsim --world=exchange_ha_split` (O-HA-INTERNAL); see
// sim/ledger/bugs.yaml.
//
// exchanged's record log keeps its newest records in memory and reads older ones back
// from L3, so a record that left memory before the journal made it durable cannot be
// read for a while. In the seed a backup catching up from a solo primary had copied its
// records to 2172 while its own journal was durable only to 696. The primary failed with
// 1188 durable (solo mode had released no more), resumed, and on the backup's rejoin
// named 1188 the end of their common epoch. The backup could not read its record 1188
// (out of memory, not in L3 yet), took the failed read for a mismatch, raised a
// divergence alarm and threw its whole journal away (truncation to 0).
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

TEST(DST021, AnUnreadableTruncationPointIsAskedAgainNotTakenForADivergence) {
  Cluster c;
  c.sequence(kA, 4);  // 2..5
  c.run(3 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 5u);
  // 6..9 are sequenced by A but never reach B, then A crashes (process: its L2 keeps them).
  c.data_filter = [&](int dir, const Bytes&) { return dir != 0; };
  c.sequence(kA, 4);
  c.step();
  ASSERT_EQ(c.host(kA).log.size(), 9u);
  c.crash(kA);
  c.data_filter = [](int, const Bytes&) { return true; };
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary && c.rep(kB).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kB, 3);  // epoch 2 from 6: A's 6..9 diverge, the truncation point is 5
  c.run(1 * kMs);

  // A restarts with its journal durable only to 1 and its newest two records in memory:
  // record 5 cannot be read back until the journal reaches it.
  FakeHost& a = c.host(kA);
  a.flush_on_request = false;
  a.durable = 1;
  a.arena = 2;
  c.restart(kA);
  c.run(30 * kMs);
  EXPECT_FALSE(a.has_alarm(Alarm::kDiverged)) << "A took a record it could not read yet for a divergence";
  EXPECT_TRUE(a.truncations.empty()) << "A truncated before it could check its truncation point";
  EXPECT_EQ(c.rep(kA).role(), Role::kRecovering);

  // The journal catches up: record 5 can be read, and the rejoin goes on as it would have.
  a.durable = a.log.size();
  a.flush_on_request = true;
  ASSERT_TRUE(c.run_until([&] { return c.n[kA].up && c.rep(kA).role() == Role::kBackup; }, 100 * kMs));
  EXPECT_EQ(a.truncations, std::vector<std::uint64_t>{5});
  EXPECT_FALSE(a.has_alarm(Alarm::kDiverged));
  c.sequence(kB, 5);
  c.run(5 * kMs);
  EXPECT_EQ(a.log, c.host(kB).log);
}

}  // namespace
}  // namespace lle::repl::test

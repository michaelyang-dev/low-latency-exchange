// DST-011 regression test (scripted, seed-independent): a catching-up joiner must release
// what its primary has released, so that a catch-up longer than its egress ring and its
// L2 together can still reach zero lag. Found by `exsim --world=exchange_ha` (O-LIVE);
// see sim/ledger/bugs.yaml.
//
// A joiner applies up to the primary's announced release. Its node puts every output of
// an applied record in the egress ring, where it waits until the node's own release
// watermark covers it, and the L2 cursor follows the applier. At the found tree a
// recovering joiner's release stayed 0 until it became the backup. Once the egress ring
// was full the applier stopped, then L2 filled and refused the catch-up: the joiner never
// reached zero lag, no JOIN was relayed, and the primary ran without a partner for the
// rest of the day. The catch-up in the simulator was 17,559 records long: the primary had
// run solo while the joiner was down, and the gap was small when the joiner started, so
// no snapshot was sent.
//
// FakeHost models both rings in records: l2_cap (appends refused once the joiner holds
// that many records past what it applied) and egress_cap (the applier stays within that
// many records of the release watermark), as exchanged's ReplStage and engine stage do.
#include <gtest/gtest.h>

#include <cstdint>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

TEST(DST011, AJoinerReleasesWhatItsPrimaryReleasedWhileItCatchesUp) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  // A runs solo for a while: far more than B's L2 and egress ring hold together. Its
  // journal keeps up, so it releases everything.
  c.sequence(kA, 300);
  c.host(kA).durable = c.host(kA).log.size();
  c.run(1 * kMs);
  ASSERT_EQ(c.rep(kA).release_watermark(), c.host(kA).log.size());
  FakeHost& b = c.host(kB);
  b.l2_cap = 50;
  b.egress_cap = 20;
  ASSERT_GT(c.host(kA).log.size(), b.log.size() + b.l2_cap + b.egress_cap);
  c.restart(kB);
  EXPECT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 500 * kMs))
      << "B's applier stopped at " << b.applied << " with release " << c.rep(kB).release_watermark()
      << ": the outputs of what it applied wait for a release a joiner never had, so its L2 (" << b.log.size()
      << " of " << c.host(kA).log.size() << ") refuses the catch-up";
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  // Paired: both release what both hold, and B mirrors A's log.
  c.sequence(kA, 5);
  c.run(20 * kMs);
  EXPECT_EQ(c.host(kA).log, b.log);
  EXPECT_EQ(c.rep(kA).release_watermark(), c.host(kA).log.size());
  EXPECT_EQ(c.rep(kB).release_watermark(), b.log.size());
}

}  // namespace
}  // namespace lle::repl::test

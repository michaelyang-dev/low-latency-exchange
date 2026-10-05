// DST-009 regression test (scripted, seed-independent): the JOIN window must not freeze
// a solo primary's release while a joiner can only drain to zero lag by applying records
// that release is holding back. Found by `exsim --world=exchange_ha` (O-LIVE); see
// sim/ledger/bugs.yaml.
//
// A solo primary's release follows its durable index (10 §4). Its disk stalls, so release
// stops while it sequences on. A restarted node catches up. A recovering joiner applies
// only up to the primary's announced release, so the records it holds past that point
// stay in its L2. When the joiner got within the JOIN lag of the tail, the window opened
// and paused sequencing and release (10 §5 step 5). At the found tree release stayed paused
// even after the stall ended. The joiner's L2 was full of records it could not apply, so
// it could not take the last ones, never reached zero lag, and no JOIN was ever sent: the
// primary released nothing for the rest of the day.
//
// The joiner's L2 is modelled by refusing its appends once it holds `cap` records past
// what it applied (FakeHost::refuse_appends: a full L2 ring), as exchanged's ReplStage does.
#include <gtest/gtest.h>

#include <cstdint>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

TEST(DST009, TheJoinWindowLetsAJoinerWithASmallL2Drain) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  // A's disk stalls: nothing more becomes durable, so a solo primary releases nothing more.
  FakeHost& a = c.host(kA);
  a.durable = a.log.size();
  a.flush_on_request = false;
  c.run(1 * kMs);
  const std::uint64_t released = c.rep(kA).release_watermark();
  ASSERT_EQ(released, a.log.size());
  // A sequences on. Records of about a datagram each, so the joiner's L2 limit below
  // holds record by record.
  constexpr int kRecords = 60;
  for (int i = 0; i < kRecords; ++i) (void)a.sequence_big(static_cast<std::uint32_t>(c.rep(kA).epoch()), 1000);
  const std::uint64_t tail = a.log.size();
  // B's L2 holds 55 records past what it applied: enough to get within the JOIN lag of
  // A's tail, not enough to reach it while A's release stays where it is.
  constexpr std::uint64_t kCap = 55;
  ASSERT_LT(released + kCap, tail);
  ASSERT_GE(released + kCap + c.n[kA].cfg.join_lag_records, tail);
  FakeHost& b = c.host(kB);
  c.data_filter = [&](int dir, const Bytes&) {
    if (dir == 0) b.refuse_appends = b.log.size() >= b.applied + kCap;  // before each A->B datagram
    return true;
  };
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).join_window(); }, 200 * kMs)) << "B never got within the JOIN lag";
  c.run(20 * kMs);
  ASSERT_EQ(c.rep(kB).role(), Role::kRecovering);
  ASSERT_LT(b.log.size(), tail) << "B's L2 is full";
  // The stall ends: A's journal catches up.
  a.durable = a.log.size();
  a.flush_on_request = true;
  EXPECT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 300 * kMs))
      << "the JOIN window froze A's release at " << c.rep(kA).release_watermark() << " of " << a.log.size()
      << ": B cannot apply, so it never reaches zero lag and no JOIN is sent";
  // Paired again: A releases what both hold, B mirrors A's log.
  c.sequence(kA, 5);
  c.run(20 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kA).release_watermark(), a.log.size());
  EXPECT_EQ(a.log, b.log);
}

}  // namespace
}  // namespace lle::repl::test

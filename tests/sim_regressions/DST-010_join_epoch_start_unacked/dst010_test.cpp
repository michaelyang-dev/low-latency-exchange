// DST-010 regression test (scripted, seed-independent): a node that becomes the backup
// after a JOIN must acknowledge the new epoch's EpochStart even when nothing follows it.
// Found by `exsim --world=exchange_ha` (O-LIVE); see sim/ledger/bugs.yaml.
//
// After the close nothing more is sequenced (06 §10), so the JOIN epoch's EpochStart is
// the primary's last record. The primary counts the backup's ACKs of the new epoch from
// the joiner's catch-up position, with T_ack running from the grant. The joiner appends
// its own copy of the EpochStart when it learns of the grant, so the primary's APPEND of
// it arrives as a duplicate, and a duplicate is acknowledged only once rto/4 has passed
// since the last ACK, which the joiner had just sent on the catch-up stream. At the found
// tree the primary heard nothing until its retransmission, one rto later; with rto close
// to T_ack the ACK came back after T_ack. The primary went solo, the witness's SOLO
// deposed the new backup, and every rejoin went the same way for the rest of the day.
#include <gtest/gtest.h>

#include <cstdint>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

TEST(DST010, AJoinerAcknowledgesTheJoinEpochStartWhenNothingFollowsIt) {
  Cluster c;
  // Retransmission just inside T_ack, as the exchange_ha world can draw them (rto from
  // [1, 4) ms, T_ack from 4 ms), and a link with some latency.
  for (const NodeId i : {kA, kB}) {
    c.n[i].cfg.t_ack = 4 * kMs;
    c.n[i].cfg.rto_ns = 3900 * kUs;
    c.n[i].rep = std::make_unique<R>(c.n[i].cfg, c.host(i));
    c.rep(i).start_paired(1, kA, 0, c.now);
  }
  c.data_delay = 200 * kUs;
  c.sequence(kA, 3);
  c.run(5 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kA, 20);
  c.run(1 * kMs);
  // The day is over: A sequences nothing more. B restarts and rejoins.
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kPrimary && c.rep(kB).role() == Role::kBackup; },
                          300 * kMs))
      << "B never rejoined";
  const std::uint64_t epoch = c.rep(kA).epoch();
  const std::uint64_t es = c.host(kA).log.size();  // the JOIN epoch's EpochStart
  c.run(50 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary)
      << "A heard no ACK of the EpochStart at " << es << " within T_ack (its ACK stayed at " << c.rep(kA).backup_ack()
      << ") and went solo";
  EXPECT_TRUE(c.n[kB].up && c.n[kB].rep && c.rep(kB).role() == Role::kBackup) << "B was deposed";
  EXPECT_EQ(c.rep(kA).epoch(), epoch);
  EXPECT_EQ(c.rep(kA).backup_ack(), es);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

}  // namespace
}  // namespace lle::repl::test

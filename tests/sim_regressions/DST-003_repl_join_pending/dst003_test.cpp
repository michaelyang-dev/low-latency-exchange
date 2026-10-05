// DST-003 regression test (scripted, seed-independent): a solo primary must keep a JOIN
// pending until W answers it, and must learn W's epoch from a GRANT of any JOIN it
// relayed in that epoch. Found by `exsim --world=ha --seed=0x29d` (O-LIVE); see
// sim/ledger/bugs.yaml.
//
// The first JOIN of the solo epoch names a joiner incarnation that then dies. W, having
// heard the next incarnation, refuses it, and the primary relays a JOIN for that
// incarnation in the same epoch. W grants it; the GRANT to the primary is lost and a
// late duplicate of the first refusal arrives instead. A REJECT names neither the joiner
// nor its incarnation, so the primary cannot attribute it. At the found tree the
// primary gave the granted JOIN up on that refusal, resumed solo sequencing and release
// in the old epoch, and never asked W again: W's tie-break kept refusing the joiner's
// PROMOTE (livelock), and had the primary then crashed, the joiner would have been
// promoted without the records released in the old epoch.
#include <gtest/gtest.h>

#include <variant>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

TEST(DST003, PrimaryAppliesTheGrantAfterALateRefusalOfAnEarlierJoin) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  const std::uint64_t solo_epoch = c.w->state().epoch;

  bool hold_joins = true;
  c.to_w_filter = [&](NodeId from, const Bytes& b) {
    const auto m = witness::decode(b);
    return !(hold_joins && from == kA && m && std::holds_alternative<witness::Join>(*m));
  };
  Bytes refusal;
  bool drop_grant = false;
  bool grant_dropped = false;
  c.from_w_filter = [&](NodeId to, Bytes& b) {
    const auto m = witness::decode(b);
    if (to != kA || !m) return true;
    if (const auto* r = std::get_if<witness::Reject>(&*m); r != nullptr && r->request == witness::MsgType::kJoin) {
      if (refusal.empty()) refusal = b;
    }
    if (const auto* g = std::get_if<witness::Grant>(&*m); g != nullptr && g->request == witness::MsgType::kJoin) {
      if (drop_grant && !grant_dropped) {
        grant_dropped = true;
        return false;
      }
    }
    return true;
  };

  // First joiner incarnation at zero lag; its JOIN is held back from W.
  c.restart(kB);
  const std::uint64_t first = c.rep(kB).incarnation();
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).join_view().sent && c.rep(kA).join_view().inc == first; }, 200 * kMs));
  // It dies; W hears the next incarnation and refuses the first JOIN.
  c.crash(kB);
  c.restart(kB);
  const std::uint64_t second = c.rep(kB).incarnation();
  c.run(2 * kMs);
  hold_joins = false;
  drop_grant = true;
  ASSERT_TRUE(c.run_until([&] { return !refusal.empty(); }, 50 * kMs));
  // A second JOIN in the same epoch, granted by W; its GRANT to the primary is lost.
  ASSERT_TRUE(c.run_until([&] { return grant_dropped; }, 300 * kMs));
  ASSERT_EQ(c.w->state().epoch, solo_epoch + 1);
  ASSERT_EQ(c.rep(kA).join_view().inc, second);
  const std::uint64_t join_last = c.host(kA).log.size();
  const std::uint64_t released = c.rep(kA).release_watermark();

  // The late duplicate of the first refusal.
  c.rep(kA).on_witness(refusal, c.now);
  EXPECT_FALSE(c.rep(kA).sequencing_allowed()) << "gave up a JOIN that W may have granted";
  EXPECT_EQ(c.rep(kA).role(), Role::kSoloPrimary);
  c.sequence(kA, 3);  // refused while the JOIN is pending
  EXPECT_EQ(c.host(kA).log.size(), join_last);

  // Retransmitted, the JOIN is answered from W's last grant.
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kPrimary; }, 100 * kMs))
      << "the primary never learned W's epoch";
  EXPECT_EQ(c.rep(kA).epoch(), solo_epoch + 1);
  EXPECT_EQ(c.rep(kA).release_watermark(), released) << "nothing released in the old epoch after the JOIN";
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 100 * kMs));
  c.sequence(kA, 3);
  c.run(10 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
  // The joiner W recorded can take over: kill the primary.
  c.crash(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 200 * kMs));
  EXPECT_EQ(c.w->state().primary, kB);
}

// The same interleaving, then the primary crashes. Every record it ever released must be
// on the joiner that W promotes (leader completeness, O-NO-LOST-FILL). At the found tree
// the primary resumed solo service in the old epoch after the late refusal and released
// records the joiner never received; W then promoted the joiner without them.
TEST(DST003, NoReleasedRecordIsLostWhenThePrimaryDiesAfterTheJoin) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  bool hold_joins = true;
  c.to_w_filter = [&](NodeId from, const Bytes& b) {
    const auto m = witness::decode(b);
    return !(hold_joins && from == kA && m && std::holds_alternative<witness::Join>(*m));
  };
  Bytes refusal;
  bool drop_grants = false;
  bool grant_dropped = false;
  c.from_w_filter = [&](NodeId to, Bytes& b) {
    const auto m = witness::decode(b);
    if (to != kA || !m) return true;
    if (const auto* r = std::get_if<witness::Reject>(&*m); r != nullptr && r->request == witness::MsgType::kJoin) {
      if (refusal.empty()) refusal = b;
    }
    if (const auto* g = std::get_if<witness::Grant>(&*m); g != nullptr && g->request == witness::MsgType::kJoin) {
      if (drop_grants) {
        grant_dropped = true;
        return false;  // every GRANT of the JOIN to the primary is lost
      }
    }
    return true;
  };
  c.restart(kB);
  const std::uint64_t first = c.rep(kB).incarnation();
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).join_view().sent && c.rep(kA).join_view().inc == first; }, 200 * kMs));
  c.crash(kB);
  c.restart(kB);
  c.run(2 * kMs);
  hold_joins = false;
  drop_grants = true;
  ASSERT_TRUE(c.run_until([&] { return !refusal.empty(); }, 50 * kMs));
  ASSERT_TRUE(c.run_until([&] { return grant_dropped; }, 300 * kMs));
  c.rep(kA).on_witness(refusal, c.now);
  // The primary's gateway keeps submitting and its journal writer keeps flushing; whatever
  // it sequences and releases now must survive its death.
  for (int i = 0; i < 20; ++i) {
    c.sequence(kA, 1);
    c.host(kA).durable = c.host(kA).log.size();
    c.step(500 * kUs);
  }
  const std::uint64_t released = c.rep(kA).release_watermark();
  std::vector<Bytes> released_records(c.host(kA).log.begin(),
                                      c.host(kA).log.begin() + static_cast<std::ptrdiff_t>(released));
  c.crash(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 300 * kMs));
  ASSERT_GE(c.host(kB).log.size(), released);
  for (std::uint64_t i = 1; i <= released; ++i) {
    ASSERT_EQ(c.host(kB).log[i - 1], released_records[i - 1]) << "released record " << i << " lost at the takeover";
  }
}

}  // namespace
}  // namespace lle::repl::test

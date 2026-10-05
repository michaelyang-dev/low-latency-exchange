// Replication core (10 §3–§5): the named evidence tests of plan 10 §8 that belong to
// lle::repl, plus the paths around them. Two Replica instances run against FakeHosts
// and the real witness core; the network is in memory and controlled by each test.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "common/prng.h"
#include "repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kA = 0;
constexpr NodeId kB = 1;

// The primary's sequencer turns injected (forwarded) inbound into journal records.
std::size_t sequence_injected(Cluster& c, NodeId p, std::size_t& consumed) {
  FakeHost& h = c.host(p);
  std::size_t n = 0;
  while (consumed < h.injected.size() && c.rep(p).sequencing_allowed()) {
    const ForwardCopy& f = h.injected[consumed++];
    h.sequence(static_cast<std::uint32_t>(c.rep(p).epoch()), f.session, f.instance, f.account, f.bytes, f.flags);
    ++n;
  }
  return n;
}

wire::Forward make_forward(std::uint32_t session, std::uint16_t instance, std::uint8_t tag,
                           std::vector<std::byte>& storage) {
  storage = {std::byte{'O'}, static_cast<std::byte>(tag), std::byte{0x10}, std::byte{0x20}};
  wire::Forward f;
  f.session_id = session;
  f.instance = instance;
  f.account = 100 + session;
  f.kind = wire::ForwardKind::kOuch;
  f.bytes = storage;
  return f;
}

// ---- normal operation -------------------------------------------------------------------

TEST(Repl, PairedReplicationCommitsAndReleases) {
  Cluster c;
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kB).role(), Role::kBackup);
  for (int round = 0; round < 20; ++round) {
    c.sequence(kA, 3);
    c.step();
  }
  c.run(5 * kMs);
  const std::uint64_t tail = c.host(kA).log.size();
  EXPECT_EQ(tail, 61u);
  EXPECT_EQ(c.host(kB).log, c.host(kA).log);
  EXPECT_EQ(c.rep(kA).commit_index(), tail);
  EXPECT_EQ(c.rep(kA).release_watermark(), tail);
  EXPECT_EQ(c.rep(kB).release_watermark(), tail);  // mirror sessions release at the announced commit
  EXPECT_EQ(c.host(kB).applied, tail);
  EXPECT_EQ(c.host(kB).state, c.host(kA).state);
  EXPECT_FALSE(c.rep(kB).unpromotable());
  EXPECT_GT(c.rep(kB).stats().hash_checks, 0u);
}

// 10 §3 step 3 and the Output Rule (ADR-005): nothing is released before the backup's
// cumulative ACK covers it, and every released index is held in the backup's L2.
TEST(Repl, OutputRuleBlocksUntilAck) {
  Cluster c;
  c.run(2 * kMs);
  ASSERT_EQ(c.rep(kA).release_watermark(), 1u);
  bool acks_blocked = true;
  c.data_filter = [&](int dir, const Bytes&) { return !(dir == 1 && acks_blocked); };
  c.sequence(kA, 5);
  for (int i = 0; i < 40; ++i) {  // 4 ms: below T_ack
    c.step();
    EXPECT_EQ(c.rep(kA).release_watermark(), 1u);
    EXPECT_EQ(c.rep(kA).commit_index(), 1u);
  }
  EXPECT_EQ(c.host(kB).log.size(), 6u) << "the backup holds the records but its ACKs are lost";
  EXPECT_EQ(c.rep(kB).release_watermark(), 1u) << "the backup's mirror release follows the primary's commit";
  acks_blocked = false;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).release_watermark() == 6; }, 5 * kMs));
  // Ground truth at every step from here: released <= what the backup actually holds.
  for (int i = 0; i < 50; ++i) {
    c.sequence(kA, 1);
    c.step();
    EXPECT_LE(c.rep(kA).release_watermark(), c.host(kB).log.size());
    EXPECT_LE(c.rep(kA).release_watermark(), c.rep(kA).backup_ack());
  }
  EXPECT_EQ(c.host(kA).count(TraceKind::kRelease) > 0, true);
}

// 10 §4 step 1 (mutant AckWhileCandidate): after freezing, a candidate never appends or
// acknowledges an epoch-e APPEND, so the old primary cannot commit past last_index.
TEST(Repl, CandidateStopsAcking) {
  Cluster c;
  c.sequence(kA, 4);
  c.run(3 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 5u);
  // The primary's APPENDs and heartbeats stop reaching B for longer than T_d; W keeps
  // hearing A (tie-break), so B's PROMOTE is not granted and B stays frozen.
  // B's heartbeats keep reaching A, and A has nothing outstanding, so A does not
  // suspect B while B's T_d runs out.
  bool a_to_b = false;
  c.data_filter = [&](int dir, const Bytes&) { return dir == 1 || a_to_b; };
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kCandidate; }, 30 * kMs));
  ASSERT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kB).frozen_last(), 5u);
  EXPECT_EQ(c.host(kB).count(TraceKind::kFreeze), 1u);
  // The link heals before A gives up on B (T_ack after B fell silent): A sends 6..8 in epoch 1.
  a_to_b = true;
  c.host(kB).to_peer.clear();
  const std::uint64_t acks_before = c.rep(kB).stats().acks_sent;
  c.sequence(kA, 3);
  for (int i = 0; i < 40; ++i) {
    c.step();
    ASSERT_TRUE(c.n[kB].up);
    for (const Bytes& b : c.host(kB).to_peer) EXPECT_FALSE(is_type(b, wire::MsgType::kAck)) << "a candidate ACKed";
  }
  EXPECT_EQ(c.host(kB).log.size(), 5u) << "a candidate appended an epoch-e record";
  EXPECT_EQ(c.rep(kB).stats().acks_sent, acks_before);
  EXPECT_GT(c.rep(kB).stats().frozen_dropped, 0u);
  EXPECT_LE(c.rep(kA).commit_index(), 5u);
  EXPECT_LE(c.rep(kA).release_watermark(), 5u);
  EXPECT_EQ(c.rep(kB).role(), Role::kCandidate);
  // PROMOTE carried last_index = 5 and was rejected by the tie-break while A is heard.
  EXPECT_EQ(c.host(kB).count(TraceKind::kRequestPromote), 1u);
  // A gets no ACK progress for T_ack: it flushes and goes solo; B's PROMOTE is now stale
  // and B, no longer a member, exits as deposed.
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary; }, 40 * kMs));
  EXPECT_EQ(c.rep(kA).epoch(), 2u);
  ASSERT_TRUE(c.run_until([&] { return !c.n[kB].up; }, 40 * kMs));
  EXPECT_TRUE(c.host(kB).deposed_flag || !c.n[kB].up);
}

// Day start: the backup mirrors and applies nothing, not even the day-start EpochStart,
// until its primary announces a release. A primary that dies before its first release
// leaves index 1 to the new primary, which releases from there without a gap.
TEST(Repl, BackupMirrorsNothingBeforeThePrimaryReleases) {
  Cluster c;
  c.crash(kA);  // before its first poll
  c.run(1 * kMs);
  EXPECT_EQ(c.rep(kB).release_watermark(), 0u);
  EXPECT_EQ(c.rep(kB).apply_limit(), 0u);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary && c.rep(kB).release_watermark() >= 2; },
                          100 * kMs));
}

// The candidate's EpochStart goes right after its frozen last_index, and the takeover
// releases only what is durable (10 §4 steps 2–4).
TEST(Repl, PromotionAppendsEpochStartAfterFrozenLast) {
  Cluster c;
  c.sequence(kA, 4);
  c.run(3 * kMs);
  // A dies silently (no data, no witness heartbeats): B takes over.
  c.crash(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 60 * kMs));
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).sequencing_allowed(); }, 5 * kMs));
  EXPECT_EQ(c.rep(kB).epoch(), 2u);
  ASSERT_EQ(c.host(kB).log.size(), 6u);
  EXPECT_TRUE(c.host(kB).is_epoch_start(6));
  EXPECT_EQ(c.host(kB).epoch_of(6), 2u);
  EXPECT_EQ(c.host(kB).instance_downs, std::vector<NodeId>{kA});
  EXPECT_EQ(c.w->state().primary, kB);
  EXPECT_EQ(c.w->state().members, witness::member_bit(kB));
  // Solo release follows L3.
  c.host(kB).flush_on_request = false;
  c.host(kB).durable = 6;
  c.step();
  c.sequence(kB, 3);
  c.run(2 * kMs);
  EXPECT_EQ(c.rep(kB).release_watermark(), 6u);
  c.host(kB).durable = 8;
  c.step();
  EXPECT_EQ(c.rep(kB).release_watermark(), 8u);
}

// 10 §2: nodes ignore messages from older epochs; a peer primary in a newer epoch, or a
// stale-epoch REJECT, deposes a node; GRANTs for another incarnation are ignored.
TEST(Repl, StaleEpochRejected) {
  Cluster c;
  c.sequence(kA, 2);
  c.run(2 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 3u);
  FakeHost forged;
  forged.log = c.host(kA).log;
  forged.sequence_n(1, 1);
  const Bytes rec4 = forged.log[3];
  // An APPEND from epoch 0 (older than B's epoch 1) with the right next record.
  wire::Append stale;
  stale.from = kA;
  stale.epoch = 0;
  stale.first_index = 4;
  stale.first_len = static_cast<std::uint32_t>(rec4.size());
  stale.commit_index = 4;
  stale.records = rec4;
  Bytes dg(wire::kMaxDatagram);
  dg.resize(wire::encode(stale, dg));
  c.rep(kB).on_peer(dg, c.now);
  EXPECT_EQ(c.host(kB).log.size(), 3u) << "an APPEND from an older epoch was accepted";
  EXPECT_GT(c.rep(kB).stats().stale_dropped, 0u);
  // An ACK from an older epoch does not move the primary's commit.
  const std::uint64_t ack = c.rep(kA).backup_ack();
  c.host(kA).sequence_n(1, 1);
  Bytes ackdg(wire::kMaxDatagram);
  ackdg.resize(wire::encode(wire::Ack{kB, false, 0, 4, 0, 0, 0}, ackdg));
  c.rep(kA).on_peer(ackdg, c.now);
  EXPECT_EQ(c.rep(kA).backup_ack(), ack);
  // A GRANT for B's (non-existent) PROMOTE, and one for a different incarnation: ignored.
  witness::Grant g{2, kB, witness::member_bit(kB), witness::MsgType::kPromote, kB, 7, 1};
  c.rep(kB).on_witness(witness::encode(g).span(), c.now);
  EXPECT_EQ(c.rep(kB).role(), Role::kBackup);
  EXPECT_GT(c.rep(kB).stats().ignored_grants, 0u);
  // A HEARTBEAT from a primary in a newer epoch deposes the backup (it was dropped).
  wire::Heartbeat hb;
  hb.from = kA;
  hb.epoch = 5;
  hb.role = static_cast<std::uint8_t>(Role::kSoloPrimary);
  hb.build_id = kBuild;
  hb.members = witness::member_bit(kA);
  hb.primary = kA;
  Bytes hbdg(wire::kMaxDatagram);
  hbdg.resize(wire::encode(hb, hbdg));
  c.rep(kB).on_peer(hbdg, c.now);
  EXPECT_EQ(c.rep(kB).role(), Role::kDeposed);
  EXPECT_TRUE(c.host(kB).deposed_flag);
}

TEST(Repl, GrantForAnotherIncarnationIsIgnored) {
  Cluster c;
  c.sequence(kA, 2);
  c.run(2 * kMs);
  c.crash(kA);
  // B freezes and asks; W's GRANT is rewritten to another incarnation: B must not act.
  c.from_w_filter = [&](NodeId to, Bytes& b) {
    (void)to;
    auto m = witness::decode(b);
    if (m && std::holds_alternative<witness::Grant>(*m)) {
      auto g = std::get<witness::Grant>(*m);
      g.incarnation += 1;
      const auto e = witness::encode(g);
      b.assign(e.span().begin(), e.span().end());
    }
    return true;
  };
  c.run(60 * kMs);
  EXPECT_EQ(c.rep(kB).role(), Role::kCandidate);
  EXPECT_GT(c.rep(kB).stats().ignored_grants, 0u);
  EXPECT_EQ(c.host(kB).count(TraceKind::kGrantApplied), 0u);
}

// ---- backup loss and solo mode ------------------------------------------------------------

// 10 §4 "Backup loss" (TLA RequestSolo, mutant SoloReleaseFromL2): stop releasing, flush
// the whole log, then SOLO; the solo primary releases only L3-durable records.
TEST(Repl, SoloReleasesOnlyDurable) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(3 * kMs);
  ASSERT_EQ(c.rep(kA).release_watermark(), 4u);
  FakeHost& a = c.host(kA);
  a.flush_on_request = false;
  a.durable = 4;
  c.ab_cut = true;
  c.sequence(kA, 2);  // 5, 6: never acknowledged
  ASSERT_TRUE(c.run_until([&] { return !c.rep(kA).sequencing_allowed(); }, 20 * kMs));
  // Losing the backup: no SOLO before the whole log is durable, no release meanwhile.
  c.run(5 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(a.count(TraceKind::kRequestSolo), 0u);
  EXPECT_EQ(c.rep(kA).release_watermark(), 4u);
  a.durable = 6;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          10 * kMs));
  EXPECT_EQ(c.rep(kA).epoch(), 2u);
  ASSERT_EQ(a.log.size(), 7u);
  EXPECT_TRUE(a.is_epoch_start(7));
  // Nothing is released until the EpochStart itself is durable.
  c.run(2 * kMs);
  EXPECT_EQ(c.rep(kA).release_watermark(), 4u);
  a.durable = 7;
  c.step();
  EXPECT_EQ(c.rep(kA).release_watermark(), 7u);
  // New solo records: released at durable_index, never at the L2 tail.
  c.sequence(kA, 5);  // 8..12
  for (std::uint64_t d = 7; d <= 12; ++d) {
    a.durable = d;
    c.step();
    EXPECT_EQ(c.rep(kA).release_watermark(), d);
  }
  // Every RELEASE trace event of the solo primary is at or below durable at the time.
  for (const TraceEvent& e : a.traces) {
    if (e.kind == TraceKind::kRelease && e.b == 1) EXPECT_LE(e.a, 12u);
  }
}

TEST(Repl, BackupComesBackBeforeSoloIsSent) {
  Cluster c;
  c.sequence(kA, 2);
  c.run(2 * kMs);
  c.host(kA).flush_on_request = false;
  c.host(kA).durable = 3;
  bool cut = true;
  c.data_filter = [&](int, const Bytes&) { return !cut; };
  c.sequence(kA, 2);
  ASSERT_TRUE(c.run_until([&] { return !c.rep(kA).sequencing_allowed(); }, 20 * kMs));
  cut = false;  // before T_d: B never froze, and A's L3 flush has not finished
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).sequencing_allowed(); }, 10 * kMs));
  c.step();
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kA).epoch(), 1u);
  EXPECT_EQ(c.rep(kA).stats().solo_cancelled, 1u);
  EXPECT_EQ(c.rep(kA).release_watermark(), 5u);
}

// A cut A–B link with both nodes alive yields solo mode on A, never a takeover (10 §4).
TEST(Repl, CutLinkYieldsSoloOnPrimary) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.ab_cut = true;
  c.run(80 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kSoloPrimary);
  EXPECT_EQ(c.w->state().primary, kA);
  EXPECT_EQ(c.w->state().members, witness::member_bit(kA));
  EXPECT_FALSE(c.n[kB].up && c.rep(kB).role() == Role::kSoloPrimary);
}

// ---- restart: RESUME and rejoin ------------------------------------------------------------

TEST(Repl, RestartedSoloPrimaryResumes) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.ab_cut = true;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kA, 3);
  c.run(2 * kMs);
  const std::uint64_t before = c.host(kA).log.size();
  c.crash(kA);
  c.restart(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          20 * kMs));
  EXPECT_EQ(c.rep(kA).epoch(), 3u);
  EXPECT_EQ(c.w->state().inc[kA], 1u);
  EXPECT_EQ(c.host(kA).log.size(), before + 1);  // the whole log kept, plus EpochStart(3)
  EXPECT_TRUE(c.host(kA).is_epoch_start(before + 1));
  EXPECT_EQ(c.host(kA).reloads.back(), before);
}

// The solo primary of record lost its GRANT and the EpochStart never reached L3: on
// restart it adopts W's epoch from the REJECT and resumes (liveness fix, 10 §4).
TEST(Repl, ResumeAdoptsTheWitnessEpoch) {
  Cluster c;
  c.ab_cut = true;
  c.host(kA).flush_on_request = true;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary; }, 60 * kMs));
  c.run(1 * kMs);
  ASSERT_EQ(c.w->state().epoch, 2u);
  // A host crash before EpochStart(2) is durable: the log ends in epoch 1 again.
  c.host(kA).durable = 1;
  c.host_crash(kA);
  ASSERT_EQ(c.host(kA).log.size(), 1u);
  c.restart(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary; }, 20 * kMs));
  EXPECT_EQ(c.rep(kA).epoch(), 3u);
  EXPECT_EQ(c.host(kA).count(TraceKind::kAdoptEpoch), 1u);
}

// 10 §5 (mutant NoTruncate): a restarted node truncates its divergent tail by epoch,
// reloads its state at the truncation point, catches up and rejoins through JOIN.
TEST(Repl, RejoinTruncatesAndReloads) {
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
  c.sequence(kB, 3);  // epoch 2: ES at 6, then 7..9 diverge from A's 6..9
  c.run(1 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 9u);
  ASSERT_NE(c.host(kA).crc_of(6), c.host(kB).crc_of(6));
  c.restart(kA);
  ASSERT_TRUE(c.run_until([&] { return c.n[kA].up && c.rep(kA).role() == Role::kBackup; }, 100 * kMs));
  EXPECT_EQ(c.host(kA).truncations, std::vector<std::uint64_t>{5});
  ASSERT_FALSE(c.host(kA).reloads.empty());
  EXPECT_EQ(c.host(kA).reloads.front(), 5u);
  EXPECT_EQ(c.host(kA).count(TraceKind::kTruncate), 1u);
  EXPECT_EQ(c.rep(kB).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kB).epoch(), 3u);
  EXPECT_EQ(c.rep(kA).epoch(), 3u);
  EXPECT_EQ(c.w->state().members, 0b11);
  EXPECT_EQ(c.w->state().inc[kA], 1u);
  c.sequence(kB, 5);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
  EXPECT_EQ(c.rep(kB).release_watermark(), c.host(kB).log.size());
  EXPECT_EQ(c.host(kA).state, c.host(kB).state);
}

TEST(Repl, JoinPausesSequencingAndRelease) {
  Cluster c;
  c.sequence(kA, 2);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary; }, 60 * kMs));
  // Keep the primary busy while B catches up; record every step's view.
  c.restart(kB);
  bool saw_pause = false;
  bool saw_join = false;
  bool joined = false;
  // When the JOIN leaves, the primary has released its whole log (DST-009), so from the
  // JOIN on it neither sequences nor releases.
  c.to_w_filter = [&](NodeId from, const Bytes& b) {
    const auto m = witness::decode(b);
    if (from == kA && m && std::holds_alternative<witness::Join>(*m)) {
      saw_join = true;
      EXPECT_EQ(std::get<witness::Join>(*m).last_index, c.host(kA).log.size());
      EXPECT_EQ(c.rep(kA).release_watermark(), c.host(kA).log.size());
    }
    return true;
  };
  for (int i = 0; i < 2000 && !joined; ++i) {
    c.sequence(kA, 1);
    c.step();
    if (c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).join_window()) {
      // Draining: sequencing is paused; release may still catch up with the paused tail.
      saw_pause = true;
      EXPECT_FALSE(c.rep(kA).sequencing_allowed());
      EXPECT_LE(c.rep(kA).release_watermark(), c.host(kA).log.size());
    }
    joined = c.rep(kA).role() == Role::kPrimary;
  }
  ASSERT_TRUE(joined);
  EXPECT_TRUE(saw_pause);
  EXPECT_TRUE(saw_join);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 10 * kMs));
  c.run(3 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// 10 §5: W also sends its JOIN grant to the joiner, addressed to the incarnation it
// recorded. The primary dies before its own GRANT (and so before any relay) reaches it:
// the joiner still becomes the backup of the new epoch, appends the epoch's EpochStart,
// and takes over through the normal path (freeze, flush, PROMOTE with W's epoch; W's
// tie-break ignores the restarted primary's new incarnation).
TEST(Repl, JoinerAdmittedByWitnessTakesOverAfterThePrimaryDies) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kA, 4);
  bool granted = false;
  c.from_w_filter = [&](NodeId to, Bytes& b) {
    const auto m = witness::decode(b);
    if (to == kA && m && std::holds_alternative<witness::Grant>(*m) &&
        std::get<witness::Grant>(*m).request == witness::MsgType::kJoin) {
      granted = true;
      return false;  // the primary never learns of the grant
    }
    return true;
  };
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return granted; }, 100 * kMs));
  const std::uint64_t join_last = c.host(kA).log.size();
  const std::uint64_t w_epoch = c.w->state().epoch;
  EXPECT_EQ(c.rep(kB).role(), Role::kBackup) << "W's copy of the grant admits the joiner at once";
  c.crash(kA);
  c.restart(kA);  // A restarts at once with a new incarnation: RESUME is refused (paired)
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 20 * kMs));
  EXPECT_EQ(c.rep(kB).epoch(), w_epoch);
  EXPECT_EQ(c.host(kB).count(TraceKind::kRejoinEpochStart), 1u);
  ASSERT_EQ(c.host(kB).log.size(), join_last + 1);
  EXPECT_TRUE(c.host(kB).is_epoch_start(join_last + 1));
  EXPECT_EQ(c.host(kB).epoch_of(join_last + 1), w_epoch);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 100 * kMs));
  EXPECT_EQ(c.host(kB).count(TraceKind::kFreeze), 1u);
  EXPECT_EQ(c.rep(kB).epoch(), w_epoch + 1);
  EXPECT_EQ(c.w->state().primary, kB);
  EXPECT_TRUE(c.host(kB).is_epoch_start(join_last + 2));
  // A rejoins B; its log never had the JOIN epoch's EpochStart.
  c.from_w_filter = [](NodeId, Bytes&) { return true; };
  ASSERT_TRUE(c.run_until([&] { return c.n[kA].up && c.rep(kA).role() == Role::kBackup; }, 300 * kMs));
  c.sequence(kB, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// Neither the primary's relay nor W's copy of the grant reaches the joiner: its probe
// of W after the primary falls silent returns a REJECT whose configuration pairs it with
// that primary in the next epoch, and it continues as the backup from there.
TEST(Repl, JoinerLearnsAdmissionFromAReject) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  bool granted = false;
  c.from_w_filter = [&](NodeId, Bytes& b) {
    const auto m = witness::decode(b);
    if (m && std::holds_alternative<witness::Grant>(*m) && std::get<witness::Grant>(*m).request == witness::MsgType::kJoin) {
      granted = true;
      return false;  // lost on the way to both nodes
    }
    return true;
  };
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return granted; }, 100 * kMs));
  const std::uint64_t w_epoch = c.w->state().epoch;
  c.crash(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 100 * kMs));
  EXPECT_EQ(c.rep(kB).epoch(), w_epoch);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 100 * kMs));
  EXPECT_EQ(c.w->state().primary, kB);
}

// W's copy of a JOIN grant is held up on its way; nothing else tells the joiner of its
// admission, so the primary never hears an ACK in the new epoch and goes solo. The
// joiner re-handshakes with the solo epoch and catches up. When the old copy finally
// arrives it belongs to a JOIN of an earlier catch-up session and is ignored: the joiner
// stays recovering and later joins the solo epoch's primary normally.
TEST(Repl, StaleJoinGrantCopyIsIgnored) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  const std::uint64_t solo_epoch = c.w->state().epoch;
  Bytes held;
  bool blocked = false;
  c.from_w_filter = [&](NodeId to, Bytes& b) {
    const auto m = witness::decode(b);
    if (to == kB && held.empty() && m && std::holds_alternative<witness::Grant>(*m) &&
        std::get<witness::Grant>(*m).request == witness::MsgType::kJoin) {
      held = b;
      blocked = true;
    }
    return !(blocked && to == kB);  // nor a retransmitted copy or a REJECT naming the new configuration
  };
  c.data_filter = [&](int dir, const Bytes&) { return !(blocked && dir == 0); };  // nor the relay
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return blocked; }, 100 * kMs));
  ASSERT_EQ(c.w->state().epoch, solo_epoch + 1);
  // The primary hears no ACK in the JOIN epoch and goes solo.
  ASSERT_TRUE(c.run_until([&] { return c.w->state().epoch == solo_epoch + 2; }, 100 * kMs));
  ASSERT_EQ(c.rep(kB).role(), Role::kRecovering);
  blocked = false;
  // The joiner learns the solo configuration from W, re-handshakes and catches up.
  ASSERT_TRUE(c.run_until([&] { return c.host(kB).epoch_of(c.host(kB).log.size()) == solo_epoch + 2; },
                          200 * kMs));
  ASSERT_EQ(c.rep(kB).role(), Role::kRecovering);
  const std::size_t len = c.host(kB).log.size();
  ASSERT_FALSE(held.empty());
  c.rep(kB).on_witness(held, c.now);
  EXPECT_EQ(c.rep(kB).role(), Role::kRecovering);
  EXPECT_EQ(c.host(kB).log.size(), len);
  EXPECT_EQ(c.host(kB).count(TraceKind::kRejoinEpochStart), 0u);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs))
      << "B up " << c.n[kB].up << " role " << static_cast<int>(c.rep(kB).role()) << " A role "
      << static_cast<int>(c.rep(kA).role()) << " W epoch " << c.w->state().epoch << " A log "
      << c.host(kA).log.size() << " B log " << c.host(kB).log.size();
  EXPECT_EQ(c.rep(kB).epoch(), solo_epoch + 3);
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// A solo primary streams catch-up records from its whole log, including records not yet
// in its L3. A host crash takes those, and the primary resumes in a new epoch. The
// joiner's catch-up session belonged to the handshake with the old epoch: the primary
// refuses it (no divergence alarm), the joiner hand-shakes again and truncates the
// records the primary lost by epoch, then joins.
TEST(Repl, CatchupSessionEndsWithThePrimarysEpoch) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  const std::uint64_t solo_epoch = c.w->state().epoch;
  const std::uint64_t durable = c.host(kA).log.size();
  c.host(kA).durable = durable;
  c.host(kA).flush_on_request = false;  // nothing more reaches A's L3
  c.sequence(kA, 4);
  // A's JOIN for B never reaches W, so A stays solo while B catches up to its tail.
  c.to_w_filter = [](NodeId from, const Bytes& b) {
    const auto m = witness::decode(b);
    return !(from == kA && m && std::holds_alternative<witness::Join>(*m));
  };
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.host(kB).log.size() == c.host(kA).log.size(); }, 200 * kMs));
  ASSERT_EQ(c.rep(kB).role(), Role::kRecovering);
  ASSERT_GT(c.host(kB).log.size(), durable);
  c.host_crash(kA);  // A loses the 4 records B already copied
  c.to_w_filter = [](NodeId, const Bytes&) { return true; };
  c.host(kA).flush_on_request = true;
  c.restart(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          100 * kMs));
  EXPECT_EQ(c.rep(kA).epoch(), solo_epoch + 1);
  // A's new epoch grows past B's tail, so B's next CATCHUP_REQ names a point A holds,
  // with a record there that differs from B's.
  c.sequence(kA, 10);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 300 * kMs));
  EXPECT_FALSE(c.host(kA).has_alarm(Alarm::kDiverged));
  EXPECT_FALSE(c.host(kB).has_alarm(Alarm::kDiverged));
  ASSERT_FALSE(c.host(kB).truncations.empty());
  EXPECT_EQ(c.host(kB).truncations.back(), durable);
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// A refused CATCHUP_REQ names the session it refuses. A refusal of an earlier session
// (the joiner has since hand-shaken with the primary's current epoch), delivered late,
// is ignored: it is neither a reason to hand-shake again nor a divergence.
TEST(Repl, LateRefusalOfAnEarlierSessionIsIgnored) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  const std::uint64_t solo_epoch = c.w->state().epoch;
  c.to_w_filter = [](NodeId from, const Bytes& b) {  // B stays a joiner: A's JOIN never reaches W
    const auto m = witness::decode(b);
    return !(from == kA && m && std::holds_alternative<witness::Join>(*m));
  };
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.host(kB).log.size() == c.host(kA).log.size(); }, 200 * kMs));
  ASSERT_EQ(c.rep(kB).role(), Role::kRecovering);
  const std::size_t len = c.host(kB).log.size();
  const std::size_t truncations = c.host(kB).truncations.size();
  wire::EpochEnd late;
  late.from = kA;
  late.refused = true;
  late.query_epoch = solo_epoch - 1;  // a session of an earlier epoch of A
  late.primary_epoch = solo_epoch;
  Bytes buf(wire::kMaxDatagram);
  buf.resize(wire::encode(late, buf));
  c.rep(kB).on_peer(buf, c.now);
  c.run(2 * kMs);
  EXPECT_FALSE(c.host(kB).has_alarm(Alarm::kDiverged));
  EXPECT_FALSE(c.host(kA).has_alarm(Alarm::kDiverged));
  EXPECT_EQ(c.host(kB).truncations.size(), truncations);
  EXPECT_EQ(c.host(kB).log.size(), len);
  c.to_w_filter = [](NodeId, const Bytes&) { return true; };
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs));
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// DST-003. A JOIN stays pending until W answers it (10 §5), with sequencing and release
// paused. The first JOIN of a solo epoch names a joiner incarnation that then dies; W,
// having heard the next incarnation, refuses it, and the primary relays a JOIN for that
// incarnation in the same epoch. W grants it, but the GRANT is lost and a late duplicate
// of W's first refusal arrives instead. A REJECT names neither the joiner nor its
// incarnation, so it cannot be told from a refusal of the second JOIN: the primary
// keeps that JOIN pending and retransmits it, and applies the GRANT W repeats from its
// last grant. It cannot tell either which JOIN that GRANT is for, so it pairs with the
// backup once the backup proves that W's own copy of the grant admitted it.
TEST(Repl, JoinStaysPendingThroughALateRefusalOfAnEarlierJoin) {
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
  // The joiner's first incarnation reaches zero lag; its JOIN is held back from W.
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
  // The primary relays a JOIN for the second incarnation in the same epoch; W grants it,
  // and the GRANT to the primary is lost.
  ASSERT_TRUE(c.run_until([&] { return grant_dropped; }, 300 * kMs));
  ASSERT_EQ(c.w->state().epoch, solo_epoch + 1);
  ASSERT_EQ(c.rep(kA).epoch(), solo_epoch);
  ASSERT_EQ(c.rep(kA).join_view().inc, second);
  // A late duplicate of the first refusal reaches the primary.
  c.rep(kA).on_witness(refusal, c.now);
  EXPECT_FALSE(c.rep(kA).sequencing_allowed()) << "the second JOIN stays pending";
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kPrimary; }, 100 * kMs))
      << "the primary never learned W's epoch";
  EXPECT_EQ(c.rep(kA).epoch(), solo_epoch + 1);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 100 * kMs));
  c.sequence(kA, 3);
  c.run(10 * kMs);
  EXPECT_EQ(c.w->state().epoch, solo_epoch + 1) << "paired on the admission proof, without a SOLO round";
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.rep(kA).backup_ack(), c.host(kA).log.size());
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// A rejoin completes when the A–B round trip is longer than the retransmission interval
// of EPOCH_END_QUERY and CATCHUP_REQ (an ASan build of real processes measured about
// 8 ms against 5 ms). Every retransmission of a query carries the same query id, so the
// answer to any copy of it is accepted; an answer to an earlier query is not.
TEST(Repl, RejoinCompletesWhenTheRoundTripExceedsTheRetransmitInterval) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kA, 20);
  c.data_delay = 3 * kMs;  // RTT 6 ms > rejoin_retry_ns 5 ms, still < T_ack 10 ms
  ASSERT_GT(2 * c.data_delay, c.n[kB].cfg.rejoin_retry_ns);
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 500 * kMs))
      << "the rejoin never completed";
  c.sequence(kA, 5);
  c.run(20 * kMs);
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
  EXPECT_EQ(c.rep(kA).backup_ack(), c.host(kA).log.size());
}

// DST-009. A joiner applies only what its primary has released, so the records between
// the primary's release and its tail must fit in the joiner's L2 (its cursor follows the
// applier). A disk stall holds the solo primary's durable index, and so its release,
// back while it sequences on; the joiner gets within the JOIN lag but its L2 fills up.
// The primary pauses sequencing to drain the joiner and keeps releasing as its disk
// catches up, so the joiner can apply, reach zero lag and be joined. When the window
// also froze the release, neither side could move again.
TEST(Repl, JoinWindowDrainsAJoinerWhoseL2HoldsLessThanTheUnreleasedTail) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  // A's disk stalls: nothing more becomes durable, so nothing more is released.
  FakeHost& a = c.host(kA);
  a.durable = a.log.size();
  a.flush_on_request = false;
  c.run(1 * kMs);
  const std::uint64_t released = c.rep(kA).release_watermark();
  ASSERT_EQ(released, a.log.size());
  c.sequence(kA, 60);
  const std::uint64_t tail = a.log.size();
  // B's L2 holds 55 records past what it applied: enough to get within the JOIN lag (8)
  // of the tail, not enough to reach it while A's release stays where it is.
  c.host(kB).l2_cap = 55;
  ASSERT_LT(released + c.host(kB).l2_cap, tail);
  ASSERT_GE(released + c.host(kB).l2_cap + c.n[kA].cfg.join_lag_records, tail);
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).join_window(); }, 200 * kMs)) << "B never got within the JOIN lag";
  c.run(20 * kMs);
  EXPECT_EQ(c.rep(kB).role(), Role::kRecovering);
  EXPECT_LT(c.host(kB).log.size(), tail) << "B's L2 is full";
  // The stall ends.
  a.durable = a.log.size();
  a.flush_on_request = true;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 300 * kMs))
      << "the JOIN window froze A's release: B cannot apply, so it never reaches zero lag";
  EXPECT_EQ(c.rep(kA).role(), Role::kPrimary);
  c.sequence(kA, 5);
  c.run(20 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
  EXPECT_EQ(c.rep(kA).release_watermark(), a.log.size());
}

// The primary went silent before ever relaying a JOIN: the witness's REJECT of the
// joiner's probe shows the old configuration, so the joiner does not speculate; it
// keeps catching up and rejoins once the primary is back.
TEST(Repl, JoinerDoesNotTakeOverWithoutAJoin) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  // A keeps sequencing far ahead so B never reaches the JOIN lag, then A vanishes.
  c.restart(kB);
  for (int i = 0; i < 30; ++i) {
    c.sequence(kA, 20);
    c.step(20 * kUs);
  }
  ASSERT_EQ(c.rep(kA).role(), Role::kSoloPrimary);
  ASSERT_FALSE(c.rep(kA).join_window());
  const std::uint64_t w_epoch = c.w->state().epoch;
  c.n[kA].up = false;  // paused: silent to B and to W
  c.run(100 * kMs);
  EXPECT_EQ(c.host(kB).count(TraceKind::kRejoinEpochStart), 0u);
  EXPECT_EQ(c.w->state().epoch, w_epoch);
  EXPECT_EQ(c.rep(kB).role(), Role::kRecovering);
  // A resumes; B rejoins it.
  c.n[kA].up = true;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs));
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// A rejoining node whose log holds a run of an epoch that does not start where the
// primary's run of it does (here an EpochStart(2) that no grant made real, while the
// primary got epoch 2 by a SOLO): the EPOCH_END handshake drops the run and truncates by
// epoch as usual. No path of the current protocol writes such a record (the speculative
// takeover that did was removed, design §6); the check is defence in depth.
TEST(Repl, RejoinDropsAForeignRunOfAnEpoch) {
  Cluster c;
  c.sequence(kA, 3);  // 2..4
  c.run(2 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 4u);
  c.crash(kB);
  // B's log gains an EpochStart(2) at 5 that no grant made real.
  {
    FakeHost& b = c.host(kB);
    journal::RecordBuilder rb(canonical_sealer(), b.log_tail());
    rb.set_epoch(2);
    Bytes buf(128);
    const journal::ChainState t = b.log_tail();
    const auto r = rb.append(std::span<std::byte>(buf), t.last_ts + 1, journal::EpochStart{2, kA, 0});
    buf.resize(r.size());
    b.log.push_back(buf);
    b.durable = b.log.size();
  }
  // Meanwhile A goes solo: its own EpochStart(2) is at a later index.
  c.sequence(kA, 2);  // 5, 6
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  ASSERT_TRUE(c.host(kA).is_epoch_start(7));
  ASSERT_EQ(c.host(kA).epoch_of(7), 2u);
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs));
  EXPECT_EQ(c.host(kB).truncations.front(), 4u);
  EXPECT_FALSE(c.host(kB).has_alarm(Alarm::kDiverged));
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// KIP-279: a rejoining node whose last epoch is one the primary holds no record of
// (here an EpochStart(3), while the primary went solo in epoch 2) drops every record
// above the epoch the primary answers with and asks again. Like the check above, no
// path of the current protocol writes such a record; this is defence in depth.
TEST(Repl, RejoinDropsAnEpochThePrimaryNeverHad) {
  Cluster c;
  c.sequence(kA, 3);  // 2..4
  c.run(2 * kMs);
  ASSERT_EQ(c.host(kB).log.size(), 4u);
  c.crash(kB);
  {
    FakeHost& b = c.host(kB);
    journal::RecordBuilder rb(canonical_sealer(), b.log_tail());
    rb.set_epoch(3);
    Bytes buf(128);
    const journal::ChainState t = b.log_tail();
    const auto r = rb.append(std::span<std::byte>(buf), t.last_ts + 1, journal::EpochStart{3, kB, 0});
    buf.resize(r.size());
    b.log.push_back(buf);
    b.durable = b.log.size();
  }
  c.sequence(kA, 2);  // 5, 6
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  ASSERT_EQ(c.host(kA).epoch_of(7), 2u);
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs));
  ASSERT_FALSE(c.host(kB).truncations.empty());
  EXPECT_EQ(c.host(kB).truncations.front(), 4u);
  EXPECT_FALSE(c.host(kB).has_alarm(Alarm::kDiverged));
  c.sequence(kA, 2);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kA).log, c.host(kB).log);
}

// ---- mirror sessions: FORWARD ----------------------------------------------------------------

// A mirror-session packet that arrived truncated (longer than any legal OUCH message) is
// forwarded with the journal record flag the gateway gave it, so the primary sequences
// it exactly as a direct submission of the same packet: same flags, same payload.
TEST(Repl, ForwardedMalformedInputKeepsItsRecordFlags) {
  Cluster c;
  c.run(1 * kMs);
  std::size_t consumed = 0;
  std::vector<std::byte> s1;
  wire::Forward f = make_forward(5, 0x8001, 1, s1);
  f.record_flags = journal::kFlagMalformedInput;
  ASSERT_EQ(c.rep(kB).forward(f, c.now), R::ForwardStatus::kAccepted);
  for (int i = 0; i < 50 && consumed == 0; ++i) {
    c.step();
    sequence_injected(c, kA, consumed);
  }
  ASSERT_EQ(c.host(kA).injected.size(), 1u);
  EXPECT_EQ(c.host(kA).injected[0].flags, journal::kFlagMalformedInput);
  const journal::RecordView forwarded{std::span<const std::byte>(c.host(kA).log.back())};
  // The same packet submitted directly on the primary's own gateway.
  const std::uint64_t direct_index = c.host(kA).sequence(static_cast<std::uint32_t>(c.rep(kA).epoch()), 5, 0x8001,
                                                         f.account, s1, journal::kFlagMalformedInput);
  const journal::RecordView direct{std::span<const std::byte>(c.host(kA).log[direct_index - 1])};
  EXPECT_EQ(forwarded.type(), journal::RecordType::OuchInbound);
  EXPECT_EQ(forwarded.flags(), direct.flags());
  EXPECT_EQ(forwarded.flags(), journal::kFlagMalformedInput);
  EXPECT_TRUE(std::ranges::equal(forwarded.payload(), direct.payload()));
  // Replicated with its flags, and the backup's FORWARD is settled by it.
  c.run(5 * kMs);
  ASSERT_GE(c.host(kB).log.size(), direct_index);
  const journal::RecordView at_b{std::span<const std::byte>(c.host(kB).log[direct_index - 2])};
  EXPECT_EQ(at_b.flags(), journal::kFlagMalformedInput);
  EXPECT_EQ(c.rep(kB).pending_forwards(), 0u);
}

// 10 §3 step 5: inbound from a mirror-session instance on the backup is forwarded to the
// primary and sequenced exactly once, despite loss, duplication and retransmission; on a
// takeover, what the old primary never committed is injected into the new primary.
TEST(Repl, ForwardedInboundSequencedOnce) {
  Cluster c;
  c.run(1 * kMs);
  std::size_t consumed = 0;
  // Duplicate every data datagram and drop the first two FORWARDs.
  c.duplicate_data = true;
  int dropped = 0;
  c.data_filter = [&](int dir, const Bytes& b) {
    if (dir == 1 && is_type(b, wire::MsgType::kForward) && dropped < 2) {
      ++dropped;
      return false;
    }
    return true;
  };
  std::vector<std::byte> s1, s2, s3;
  ASSERT_EQ(c.rep(kB).forward(make_forward(5, 0x8001, 1, s1), c.now), R::ForwardStatus::kAccepted);
  ASSERT_EQ(c.rep(kB).forward(make_forward(5, 0x8001, 2, s2), c.now), R::ForwardStatus::kAccepted);
  ASSERT_EQ(c.rep(kB).forward(make_forward(6, 0x8001, 3, s3), c.now), R::ForwardStatus::kAccepted);
  for (int i = 0; i < 100; ++i) {
    c.step();
    sequence_injected(c, kA, consumed);
  }
  // Each (session, instance) stream is injected once, in its own order; streams of
  // different sessions may interleave (the first FORWARDs of session 5 were lost).
  const auto& inj = c.host(kA).injected;
  ASSERT_EQ(inj.size(), 3u);
  std::vector<int> s5_tags;
  for (const ForwardCopy& f : inj) {
    if (f.session == 5) {
      EXPECT_EQ(f.seq, s5_tags.size() + 1);
      s5_tags.push_back(static_cast<int>(f.bytes[1]));
    } else {
      EXPECT_EQ(f.session, 6u);
      EXPECT_EQ(f.seq, 1u);
    }
  }
  EXPECT_EQ(s5_tags, (std::vector<int>{1, 2}));
  EXPECT_GT(c.rep(kA).stats().forwards_duplicate, 0u);
  EXPECT_EQ(c.rep(kB).pending_forwards(), 0u) << "the backup saw every forward in the replicated journal";
  // The journal holds each exactly once.
  int count = 0;
  for (std::uint64_t i = 1; i <= c.host(kA).log.size(); ++i) {
    const journal::RecordView v{std::span<const std::byte>(c.host(kA).log[i - 1])};
    if (v.type() == journal::RecordType::OuchInbound) ++count;
  }
  EXPECT_EQ(count, 3);
  EXPECT_EQ(c.host(kB).log, c.host(kA).log);

  // Takeover with forwards in flight: A sequences f4 but its record never reaches B; f5
  // never reaches A. After the takeover, B's own sequencer gets f4 and f5, once each.
  c.duplicate_data = false;
  bool a_to_b = false;
  c.data_filter = [&](int dir, const Bytes& b) {
    if (dir == 0) return a_to_b;
    return !(is_type(b, wire::MsgType::kForward) && c.host(kA).injected.size() >= 4);
  };
  std::vector<std::byte> s4, s5;
  ASSERT_EQ(c.rep(kB).forward(make_forward(5, 0x8001, 4, s4), c.now), R::ForwardStatus::kAccepted);
  ASSERT_EQ(c.rep(kB).forward(make_forward(5, 0x8001, 5, s5), c.now), R::ForwardStatus::kAccepted);
  for (int i = 0; i < 10; ++i) {
    c.step();
    sequence_injected(c, kA, consumed);
  }
  ASSERT_EQ(c.host(kA).injected.size(), 4u);
  c.crash(kA);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary && c.rep(kB).sequencing_allowed(); },
                          60 * kMs));
  c.step();
  const auto& binj = c.host(kB).injected;
  ASSERT_EQ(binj.size(), 2u);
  EXPECT_EQ(binj[0].seq, 3u);  // the third and fourth message of session 5's instance
  EXPECT_EQ(static_cast<int>(binj[0].bytes[1]), 4);
  EXPECT_EQ(binj[1].seq, 4u);
  EXPECT_EQ(static_cast<int>(binj[1].bytes[1]), 5);
  EXPECT_EQ(c.rep(kB).stats().forwards_reinjected, 2u);
  EXPECT_EQ(c.rep(kB).pending_forwards(), 0u);
}

TEST(Repl, ForwardRefusedOnAPrimaryAndWhenFull) {
  Cluster c;
  std::vector<std::byte> s;
  EXPECT_EQ(c.rep(kA).forward(make_forward(1, 1, 1, s), c.now), R::ForwardStatus::kNotForwarding);
  std::vector<std::byte> big(kMaxForwardInline + 1, std::byte{1});
  wire::Forward f = make_forward(1, 1, 1, s);
  f.bytes = big;
  EXPECT_EQ(c.rep(kB).forward(f, c.now), R::ForwardStatus::kTooLarge);
}

// ---- determinism safeguards (R-07) -----------------------------------------------------------

TEST(Repl, StateHashMismatchMakesTheBackupUnpromotable) {
  Cluster c;
  c.host(kB).corrupt_hash_at = 3;
  for (int i = 0; i < 10; ++i) {
    c.sequence(kA, 2);
    c.step();
  }
  c.run(5 * kMs);
  EXPECT_TRUE(c.rep(kB).unpromotable());
  EXPECT_TRUE(c.host(kB).has_alarm(Alarm::kStateHashMismatch));
  EXPECT_TRUE(c.host(kA).has_alarm(Alarm::kStateHashMismatch));
  // An unpromotable backup does not take over: it alarms instead.
  c.crash(kA);
  c.run(60 * kMs);
  EXPECT_EQ(c.rep(kB).role(), Role::kBackup);
  EXPECT_TRUE(c.host(kB).has_alarm(Alarm::kUnpromotableSuspect));
  EXPECT_EQ(c.w->state().epoch, 1u);
}

TEST(Repl, BuildIdMismatchAlarmsAndBlocksPromotion) {
  Cluster c;
  c.n[kA].cfg.build_id = kBuild + 1;
  c.n[kA].rep = std::make_unique<R>(c.n[kA].cfg, c.host(kA));
  c.rep(kA).start_paired(1, kA, 0, c.now);
  c.run(3 * kMs);
  EXPECT_TRUE(c.host(kB).has_alarm(Alarm::kBuildMismatch));
  EXPECT_TRUE(c.host(kA).has_alarm(Alarm::kBuildMismatch));
  EXPECT_TRUE(c.rep(kB).unpromotable());
}

// ---- data plane details --------------------------------------------------------------------

TEST(Repl, LargeRecordsAreFragmentedAndReassembled) {
  Cluster c;
  c.host(kA).sequence_big(1, 5000);
  c.host(kA).sequence_n(1, 2);
  c.host(kA).sequence_big(1, 3000);
  c.duplicate_data = true;
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kB).log, c.host(kA).log);
  EXPECT_EQ(c.rep(kA).release_watermark(), c.host(kA).log.size());
}

TEST(Repl, LossReorderAndDuplicationConverge) {
  for (std::uint64_t seed = 1; seed <= 20; ++seed) {
    Cluster c;
    Prng rng(seed);
    std::deque<std::pair<int, Bytes>> held;
    c.data_filter = [&](int dir, const Bytes& b) {
      const std::uint64_t r = rng.below(100);
      if (r < 15) return false;  // loss
      if (r < 25) {              // reorder: deliver later
        held.emplace_back(dir, b);
        return false;
      }
      return true;
    };
    for (int i = 0; i < 300; ++i) {
      if (i < 200 && rng.below(3) == 0) c.host(kA).sequence_big(1, static_cast<std::size_t>(rng.below(3000)));
      else if (i < 200) c.sequence(kA, 1);
      c.step(50 * kUs);
      while (!held.empty() && rng.below(2) == 0) {
        auto [dir, b] = held.front();
        held.pop_front();
        const NodeId dst = dir == 0 ? kB : kA;
        if (c.n[dst].up && c.n[dst].rep) c.rep(dst).on_peer(b, c.now);
      }
      ASSERT_LE(c.rep(kA).release_watermark(), c.host(kB).log.size()) << "seed " << seed;
    }
    c.data_filter = [](int, const Bytes&) { return true; };
    c.run(10 * kMs);
    ASSERT_EQ(c.rep(kA).role(), Role::kPrimary) << "seed " << seed;
    EXPECT_EQ(c.host(kB).log, c.host(kA).log) << "seed " << seed;
    EXPECT_EQ(c.rep(kA).release_watermark(), c.host(kA).log.size()) << "seed " << seed;
  }
}

TEST(Repl, SnapshotCatchupForALargeGap) {
  Cluster c;
  c.n[kA].cfg.snapshot_threshold = 10;
  c.n[kA].rep = std::make_unique<R>(c.n[kA].cfg, c.host(kA));
  c.rep(kA).start_paired(1, kA, 0, c.now);
  c.run(1 * kMs);
  c.crash(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kA).role() == Role::kSoloPrimary && c.rep(kA).sequencing_allowed(); },
                          60 * kMs));
  c.sequence(kA, 40);
  c.run(1 * kMs);
  // A's snapshot: the fold state at its applied index, padded to many chunks.
  FakeHost& a = c.host(kA);
  a.offer = SnapshotOffer{a.applied, 5000};
  a.offer_image.assign(5000, std::byte{0x77});
  for (std::size_t i = 0; i < 8; ++i) a.offer_image[i] = static_cast<std::byte>(a.state >> (8 * i));
  const std::uint64_t snap_at = a.applied;
  c.restart(kB);
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kBackup; }, 200 * kMs));
  EXPECT_EQ(c.host(kB).installed_index, snap_at);
  EXPECT_EQ(a.released_snapshots, 1u);
  c.sequence(kA, 3);
  c.run(5 * kMs);
  EXPECT_EQ(c.host(kB).log, a.log);
  EXPECT_EQ(c.host(kB).state, a.state);
}

TEST(Repl, DeposedPrimaryExitsAfterTakeover) {
  Cluster c;
  c.sequence(kA, 3);
  c.run(2 * kMs);
  // A "pauses": no polls, nothing sent or received, while B takes over.
  c.n[kA].up = false;
  ASSERT_TRUE(c.run_until([&] { return c.rep(kB).role() == Role::kSoloPrimary; }, 60 * kMs));
  const std::uint64_t released = c.rep(kA).release_watermark();
  c.n[kA].up = true;  // resume
  c.sequence(kA, 3);
  ASSERT_TRUE(c.run_until([&] { return !c.n[kA].up; }, 60 * kMs));
  EXPECT_TRUE(c.host(kA).deposed_flag);
  EXPECT_LE(released, 4u);
}

}  // namespace
}  // namespace lle::repl::test

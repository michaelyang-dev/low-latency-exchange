// Witness: control codec (golden bytes from an independent Python CRC32C),
// durable slots, the grant rules (10 §2; HotStandby.tla), persist-before-reply,
// the incarnation-aware tie-break (HotStandbyLive.tla), and a seeded model test
// with torn slot writes and crashes.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "common/assert.h"
#include "common/prng.h"
#include "witness/control.h"
#include "witness/witness.h"

namespace lle::witness {
namespace {

constexpr Nanos kTw = 5'000'000;
const env::Endpoint kA{0x0A000001, 7000};
const env::Endpoint kB{0x0A000002, 7000};

std::vector<std::byte> bytes(std::initializer_list<int> v) {
  std::vector<std::byte> out;
  for (int x : v) out.push_back(static_cast<std::byte>(x));
  return out;
}

// ---- codec ------------------------------------------------------------------

TEST(WitnessControl, GoldenPromote) {
  const auto expect = bytes({0x4c, 0x57, 0x43, 0x31, 0x01, 0x02, 0x20, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x23, 0xf9, 0x8f, 0xda});
  const Encoded e = encode(Promote{3, 1, 7, 0x11'2233'4455});
  ASSERT_EQ(e.size, expect.size());
  EXPECT_TRUE(std::equal(expect.begin(), expect.end(), e.bytes.begin()));
  const auto d = decode(expect);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(std::get<Promote>(*d), (Promote{3, 1, 7, 0x11'2233'4455}));
}

TEST(WitnessControl, GoldenGrant) {
  const auto expect = bytes({0x4c, 0x57, 0x43, 0x31, 0x01, 0x06, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x01, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x37, 0xc8, 0x6f});
  const Grant g{4, 1, 0b10, MsgType::kPromote, 1, 7, 3};
  const Encoded e = encode(g);
  ASSERT_EQ(e.size, expect.size());
  EXPECT_TRUE(std::equal(expect.begin(), expect.end(), e.bytes.begin()));
}

TEST(WitnessControl, RoundTripEveryType) {
  const std::vector<Message> all = {
      Heartbeat{1, Role::kSoloPrimary, 9, 12},
      Promote{5, 0, 2, 100},
      Solo{6, 1, 3},
      Join{7, 0, 1, 4, 5, 1234},
      Resume{8, 1, 6},
      Grant{9, 0, 0b01, MsgType::kSolo, 0, 3, 8},
      Reject{10, 1, 0b11, MsgType::kJoin, RejectReason::kAlreadyMember, 0, 2, 9},
  };
  for (const Message& m : all) {
    const Encoded e = encode(m);
    const auto d = decode(e.span());
    ASSERT_TRUE(d.has_value()) << to_string(type_of(m));
    EXPECT_EQ(*d, m) << to_string(type_of(m));
  }
}

TEST(WitnessControl, RejectsNonCanonicalInput) {
  const Encoded good = encode(Promote{3, 1, 7, 9});
  auto mutated = [&](std::size_t off, std::byte v) {
    std::array<std::byte, kMaxDatagram> b = good.bytes;
    b[off] = v;
    return decode(std::span<const std::byte>(b.data(), good.size));
  };
  EXPECT_EQ(decode(std::span<const std::byte>(good.bytes.data(), 5)).error(), DecodeError::kShort);
  EXPECT_EQ(mutated(0, std::byte{0}).error(), DecodeError::kMagic);
  EXPECT_EQ(mutated(4, std::byte{2}).error(), DecodeError::kVersion);
  EXPECT_EQ(mutated(5, std::byte{9}).error(), DecodeError::kType);
  EXPECT_EQ(mutated(6, std::byte{31}).error(), DecodeError::kLength);
  EXPECT_EQ(decode(std::span<const std::byte>(good.bytes.data(), good.size - 1)).error(), DecodeError::kLength);
  EXPECT_EQ(mutated(20, std::byte{1}).error(), DecodeError::kCrc);  // padding byte, CRC now wrong

  // Every single-bit flip of a valid datagram is rejected.
  for (std::size_t i = 0; i < good.size; ++i)
    for (int bit = 0; bit < 8; ++bit) {
      std::array<std::byte, kMaxDatagram> b = good.bytes;
      b[i] ^= static_cast<std::byte>(1 << bit);
      EXPECT_FALSE(decode(std::span<const std::byte>(b.data(), good.size)).has_value()) << i << ":" << bit;
    }
}

TEST(WitnessControl, RejectsBadFieldsEvenWithValidCrc) {
  // Encode messages whose fields are out of range; the CRC is valid but the decoder refuses.
  EXPECT_EQ(decode(encode(Promote{1, 2, 0, 0}).span()).error(), DecodeError::kField);       // node 2
  EXPECT_EQ(decode(encode(Join{1, 1, 1, 0, 0, 0}).span()).error(), DecodeError::kField);    // joiner == primary
  EXPECT_EQ(decode(encode(Grant{1, 0, 0, MsgType::kSolo, 0, 0, 0}).span()).error(), DecodeError::kField);  // no members
  EXPECT_EQ(decode(encode(Grant{1, 0, 0b10, MsgType::kSolo, 0, 0, 0}).span()).error(),
            DecodeError::kField);  // primary not a member
  EXPECT_EQ(decode(encode(Grant{1, 0, 0b01, MsgType::kGrant, 0, 0, 0}).span()).error(),
            DecodeError::kField);  // not a request type
}

// ---- slots ------------------------------------------------------------------

State paired(NodeId primary = 0) {
  State s;
  s.epoch = 1;
  s.primary = primary;
  s.members = 0b11;
  return s;
}

TEST(WitnessSlots, RoundTripAndChooseNewest) {
  State s = paired(1);
  s.epoch = 42;
  s.inc = {3, 9};
  s.last_grant = LastGrant{MsgType::kResume, 1, 41, 9, true};
  const SlotImage a = encode_slot(s, 7);
  const auto d = decode_slot(a, 1);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->state, s);
  EXPECT_EQ(d->generation, 7u);
  EXPECT_EQ(d->slot, 1u);

  State older = s;
  older.epoch = 41;
  const SlotImage b = encode_slot(older, 6);
  EXPECT_EQ(choose(b, a)->generation, 7u);
  EXPECT_EQ(choose(a, b)->generation, 7u);
  const SlotImage none{};
  EXPECT_EQ(choose(none, a)->generation, 7u);
  EXPECT_FALSE(choose(none, none).has_value());  // W must refuse to start
}

TEST(WitnessSlots, AnyCorruptionInvalidatesTheSlot) {
  const SlotImage good = encode_slot(paired(), 3);
  for (std::size_t i = 0; i < kSlotBytes; i += 97) {
    SlotImage bad = good;
    bad[i] ^= std::byte{0x40};
    EXPECT_FALSE(decode_slot(bad, 0).has_value()) << i;
  }
  // A torn write: a prefix of a new image over an old one. (A 1-byte prefix
  // copies the identical first magic byte, so the old image stays valid.)
  State next = paired();
  next.epoch = 2;
  const SlotImage newer = encode_slot(next, 4);
  EXPECT_TRUE(decode_slot(good, 0).has_value());
  for (std::size_t cut : {std::size_t{20}, std::size_t{40}, std::size_t{4000}, kSlotBytes - 1}) {
    SlotImage torn = good;
    std::copy(newer.begin(), newer.begin() + static_cast<std::ptrdiff_t>(cut), torn.begin());
    EXPECT_FALSE(decode_slot(torn, 0).has_value()) << cut;
  }
}

// ---- core -------------------------------------------------------------------

struct Rig {
  std::array<SlotImage, kSlots> disk{};
  Nanos now = 1'000'000'000;
  std::optional<Witness> w;
  std::vector<std::pair<env::Endpoint, Message>> sent;

  explicit Rig(State s = paired()) {
    disk[0] = encode_slot(s, 1);
    start();
  }
  void start() {
    const auto d = choose(disk[0], disk[1]);
    LLE_ASSERT(d.has_value(), "no valid slot");
    w.emplace(Config{kTw}, *d, now);
  }
  void persist_all() {
    while (auto job = w->begin_write()) {
      disk[job->slot] = job->image;
      w->on_persisted(job->generation);
    }
  }
  std::vector<Message> deliver(const Message& m, const env::Endpoint& from = kA) {
    w->handle(m, from, now);
    persist_all();
    return drain();
  }
  std::vector<Message> drain() {
    std::vector<Message> out;
    w->drain([&](const env::Endpoint& to, std::span<const std::byte> b) {
      auto d = decode(b);
      LLE_ASSERT(d.has_value(), "W sent an undecodable datagram");
      sent.emplace_back(to, *d);
      out.push_back(*d);
    });
    return out;
  }
  void after_tie_break() { now += 2 * kTw; }
};

template <class T>
T only(const std::vector<Message>& v) {
  LLE_ASSERT(v.size() == 1, "expected exactly one reply");
  return std::get<T>(v[0]);
}

TEST(Witness, PromoteGrantedWhenPrimarySilent) {
  Rig r;
  r.after_tie_break();
  const Grant g = only<Grant>(r.deliver(Promote{1, 1, 0, 10}, kB));
  EXPECT_EQ(g.epoch, 2u);
  EXPECT_EQ(g.primary, 1);
  EXPECT_EQ(g.members, member_bit(1));
  EXPECT_EQ(g.to_node, 1);
  EXPECT_EQ(r.w->state().epoch, 2u);
}

TEST(Witness, OneGrantPerEpoch) {
  Rig r;
  r.after_tie_break();
  // The backup's PROMOTE and the primary's SOLO race on the same epoch: only the first wins.
  EXPECT_EQ(only<Grant>(r.deliver(Solo{1, 0, 0}, kA)).epoch, 2u);
  const Reject rj = only<Reject>(r.deliver(Promote{1, 1, 0, 10}, kB));
  EXPECT_EQ(rj.reason, RejectReason::kStaleEpoch);
  EXPECT_EQ(rj.epoch, 2u);
  EXPECT_EQ(r.w->stats().grants, 1u);
}

TEST(Witness, PersistBeforeReply) {
  Rig r;
  r.after_tie_break();
  r.w->handle(Promote{1, 1, 0, 10}, kB, r.now);
  EXPECT_TRUE(r.drain().empty());  // nothing durable yet
  auto job = r.w->begin_write();
  ASSERT_TRUE(job.has_value());
  EXPECT_FALSE(r.w->begin_write().has_value());  // one write in flight at a time
  EXPECT_TRUE(r.drain().empty());                // still not durable
  // A REJECT created while the grant is unpersisted also waits (it shows the new epoch).
  r.w->handle(Solo{1, 0, 0}, kA, r.now);
  EXPECT_TRUE(r.drain().empty());
  r.disk[job->slot] = job->image;
  r.w->on_persisted(job->generation);
  const auto out = r.drain();
  ASSERT_EQ(out.size(), 2u);
  EXPECT_TRUE(std::holds_alternative<Grant>(out[0]));
  EXPECT_TRUE(std::holds_alternative<Reject>(out[1]));
}

TEST(Witness, WritesNeverOverwriteTheNewestDurableSlot) {
  Rig r;  // generation 1 in slot 0
  r.after_tie_break();
  r.w->handle(Solo{1, 0, 0}, kA, r.now);  // generation 2
  auto j1 = r.w->begin_write();
  ASSERT_TRUE(j1.has_value());
  EXPECT_EQ(j1->slot, 1u);
  // Two more changes while the write is in flight.
  r.w->handle(Resume{2, 0, 1}, kA, r.now);  // generation 3
  r.w->handle(Resume{3, 0, 2}, kA, r.now);  // generation 4
  r.disk[j1->slot] = j1->image;
  r.w->on_persisted(j1->generation);
  auto j2 = r.w->begin_write();
  ASSERT_TRUE(j2.has_value());
  EXPECT_EQ(j2->generation, 4u);  // only the newest state is written
  EXPECT_EQ(j2->slot, 0u);        // not slot 1, which holds the newest durable image
}

TEST(Witness, RejectsRestartedIncarnation) {
  State s = paired();
  s.inc = {4, 6};
  Rig r(s);
  r.after_tie_break();
  EXPECT_EQ(only<Reject>(r.deliver(Promote{1, 1, 7, 0}, kB)).reason, RejectReason::kWrongIncarnation);
  EXPECT_EQ(only<Reject>(r.deliver(Solo{1, 0, 5}, kA)).reason, RejectReason::kWrongIncarnation);
  EXPECT_EQ(only<Grant>(r.deliver(Promote{1, 1, 6, 0}, kB)).incarnation, 6u);
}

TEST(Witness, PromoteSafetyChecks) {
  State s = paired();
  s.members = member_bit(0);  // solo on node 0
  Rig r(s);
  r.after_tie_break();
  EXPECT_EQ(only<Reject>(r.deliver(Promote{1, 1, 0, 0}, kB)).reason, RejectReason::kNotMember);
  EXPECT_EQ(only<Reject>(r.deliver(Promote{1, 0, 0, 0}, kA)).reason, RejectReason::kIsPrimary);
  EXPECT_EQ(only<Reject>(r.deliver(Promote{0, 1, 0, 0}, kB)).reason, RejectReason::kStaleEpoch);
}

TEST(Witness, TieBreakPrefersLivePrimary) {
  Rig r;
  r.after_tie_break();
  r.deliver(Heartbeat{0, Role::kPrimary, 0, 1}, kA);
  r.now += kTw / 2;
  EXPECT_EQ(only<Reject>(r.deliver(Promote{1, 1, 0, 0}, kB)).reason, RejectReason::kPrimaryAlive);
  r.now += kTw;  // silence for > T_w
  EXPECT_EQ(only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB)).epoch, 2u);
}

TEST(Witness, TieBreakIgnoresRestartedPrimary) {
  // HotStandbyLive mutant LiteralTieBreak: heartbeats from the primary's newer
  // incarnation must not block the takeover.
  Rig r;
  r.after_tie_break();
  r.deliver(Heartbeat{0, Role::kRecovering, 1, 1}, kA);  // restarted primary, incarnation 1 != W.inc[0] == 0
  EXPECT_EQ(only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB)).primary, 1);
}

TEST(Witness, StartupGraceBeforeJudgingSilence) {
  Rig r;  // W just started: it has not heard anyone yet
  EXPECT_EQ(only<Reject>(r.deliver(Promote{1, 1, 0, 0}, kB)).reason, RejectReason::kPrimaryAlive);
  r.after_tie_break();
  EXPECT_EQ(only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB)).epoch, 2u);
}

TEST(Witness, SoloJoinResumeLifecycle) {
  Rig r;
  // Backup lost: primary 0 goes solo.
  const Grant s = only<Grant>(r.deliver(Solo{1, 0, 0}, kA));
  EXPECT_EQ(s.members, member_bit(0));
  // Node 1 restarted (incarnation 3), caught up; the primary relays JOIN.
  EXPECT_EQ(only<Reject>(r.deliver(Join{2, 1, 0, 0, 3, 50}, kB)).reason, RejectReason::kNotPrimary);
  const Grant j = only<Grant>(r.deliver(Join{2, 0, 1, 0, 3, 50}, kA));
  EXPECT_EQ(j.members, 0b11);
  EXPECT_EQ(r.w->state().inc[1], 3u);
  EXPECT_EQ(only<Reject>(r.deliver(Join{3, 0, 1, 0, 3, 50}, kA)).reason, RejectReason::kAlreadyMember);
  // Paired again: RESUME is only for a solo primary of record.
  EXPECT_EQ(only<Reject>(r.deliver(Resume{3, 0, 1}, kA)).reason, RejectReason::kNotSoloOfRecord);
  only<Grant>(r.deliver(Solo{3, 0, 0}, kA));
  EXPECT_EQ(only<Reject>(r.deliver(Resume{4, 0, 0}, kA)).reason, RejectReason::kWrongIncarnation);  // not newer
  const Grant rs = only<Grant>(r.deliver(Resume{4, 0, 1}, kA));
  EXPECT_EQ(rs.epoch, 5u);
  EXPECT_EQ(r.w->state().inc[0], 1u);
  EXPECT_EQ(only<Reject>(r.deliver(Resume{5, 1, 9}, kB)).reason, RejectReason::kNotPrimary);
}

// DST-001 (found by exsim, witness world): the JOIN dedupe key left out the
// joiner's incarnation. A JOIN relayed again for a joiner that restarted after
// the first JOIN was granted (its GRANT lost) got the old grant, so the primary
// paired with an incarnation W had never recorded and the backup could never
// be promoted. It must be a new request instead: stale, so rejected.
TEST(Witness, RetransmittedJoinForARestartedJoinerIsNotTheOldGrant) {
  Rig r;
  only<Grant>(r.deliver(Solo{1, 0, 0}, kA));
  const Grant j = only<Grant>(r.deliver(Join{2, 0, 1, 0, 3, 50}, kA));  // GRANT lost on the way
  EXPECT_EQ(only<Grant>(r.deliver(Join{2, 0, 1, 0, 3, 50}, kA)), j);  // a true retransmission
  const Reject rj = only<Reject>(r.deliver(Join{2, 0, 1, 0, 4, 50}, kA));  // joiner restarted: inc 4
  EXPECT_EQ(rj.reason, RejectReason::kStaleEpoch);
  EXPECT_EQ(rj.epoch, 3u);
  EXPECT_EQ(r.w->state().inc[1], 3u);
  // The primary resyncs to epoch 3, goes solo, and joins the new incarnation.
  only<Grant>(r.deliver(Solo{3, 0, 0}, kA));
  EXPECT_EQ(only<Grant>(r.deliver(Join{4, 0, 1, 0, 4, 50}, kA)).epoch, 5u);
  EXPECT_EQ(r.w->state().inc[1], 4u);
  // ... and after a W restart the old JOIN is not answered with a grant either.
  r.start();
  EXPECT_EQ(only<Reject>(r.deliver(Join{2, 0, 1, 0, 3, 50}, kA)).reason, RejectReason::kStaleEpoch);
}

TEST(Witness, JoinGrantAlsoReachesTheJoiner) {
  Rig r;
  only<Grant>(r.deliver(Solo{1, 0, 0}, kA));  // epoch 2, solo on node 0
  // Node 1 restarted (incarnation 3) and heartbeats W from kB.
  r.deliver(Heartbeat{1, Role::kRecovering, 3, 2}, kB);
  const auto out = r.deliver(Join{2, 0, 1, 0, 3, 50}, kA);
  ASSERT_EQ(out.size(), 2u);
  const Grant to_primary = std::get<Grant>(out[0]);
  const Grant to_joiner = std::get<Grant>(out[1]);
  EXPECT_EQ(to_primary.to_node, 0);
  EXPECT_EQ(to_primary.incarnation, 0u);
  EXPECT_EQ(to_joiner.to_node, 1);
  EXPECT_EQ(to_joiner.incarnation, 3u);  // the incarnation W recorded for the joiner
  EXPECT_EQ(to_joiner.members, 0b11);
  EXPECT_EQ(to_joiner.request, MsgType::kJoin);
  ASSERT_GE(r.sent.size(), 2u);
  EXPECT_EQ(r.sent[r.sent.size() - 1].first, kB);  // at the joiner's heartbeat endpoint
  // A joiner W never heard from gets no direct grant.
  Rig q;
  only<Grant>(q.deliver(Solo{1, 0, 0}, kA));
  EXPECT_EQ(q.deliver(Join{2, 0, 1, 0, 3, 50}, kA).size(), 1u);
}

TEST(Witness, RefusesRequestsFromSupersededIncarnations) {
  Rig r;
  only<Grant>(r.deliver(Solo{1, 0, 0}, kA));  // epoch 2, solo on node 0
  // The joiner restarted twice: W hears incarnation 4, then a JOIN relayed for
  // its dead incarnation 3 arrives late.
  r.deliver(Heartbeat{1, Role::kRecovering, 4, 2}, kB);
  const Reject rj = only<Reject>(r.deliver(Join{2, 0, 1, 0, 3, 50}, kA));
  EXPECT_EQ(rj.reason, RejectReason::kWrongIncarnation);
  EXPECT_EQ(r.w->state().members, member_bit(0));  // not admitted
  // The relay for the live incarnation is granted (to the primary and, since W
  // has heard the joiner, to the joiner as well).
  const auto out = r.deliver(Join{2, 0, 1, 0, 4, 50}, kA);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(std::get<Grant>(out[0]).members, 0b11);
  EXPECT_EQ(std::get<Grant>(out[1]).incarnation, 4u);
  // A RESUME from an incarnation older than the one heard is refused too.
  Rig q;
  only<Grant>(q.deliver(Solo{1, 0, 0}, kA));
  q.deliver(Heartbeat{0, Role::kRecovering, 7, 2}, kA);
  EXPECT_EQ(only<Reject>(q.deliver(Resume{2, 0, 6}, kA)).reason, RejectReason::kWrongIncarnation);
  EXPECT_EQ(only<Grant>(q.deliver(Resume{2, 0, 7}, kA)).epoch, 3u);
}

TEST(Witness, RetransmittedRequestGetsTheSameGrant) {
  Rig r;
  r.after_tie_break();
  const Grant first = only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB));
  const Grant again = only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB));  // the first GRANT was lost
  EXPECT_EQ(first, again);
  EXPECT_EQ(r.w->state().epoch, 2u);
  EXPECT_EQ(r.w->stats().duplicate_grants, 1u);
  // ... also after W restarts (last_grant is durable).
  r.start();
  EXPECT_EQ(only<Grant>(r.deliver(Promote{1, 1, 0, 0}, kB)), first);
}

TEST(Witness, RestartRecoversDurableStateOnly) {
  Rig r;
  r.after_tie_break();
  r.deliver(Solo{1, 0, 0}, kA);                // durable, epoch 2
  r.w->handle(Resume{2, 0, 1}, kA, r.now);     // epoch 3 in memory only
  auto job = r.w->begin_write();
  ASSERT_TRUE(job.has_value());
  // Crash with the write torn: half the new image lands.
  std::copy(job->image.begin(), job->image.begin() + 2000, r.disk[job->slot].begin());
  r.start();
  EXPECT_EQ(r.w->state().epoch, 2u);  // the RESUME grant was never sent, so nothing regressed
  EXPECT_TRUE(r.drain().empty());
}

// ---- seeded model test --------------------------------------------------------
// Random requests (mostly plausible, some stale or forged), random persist
// completions, torn writes and crashes. Checks the safety properties a node can
// observe from the outside.
TEST(Witness, ModelTestWithTornWritesAndCrashes) {
  for (std::uint64_t seed = 1; seed <= 1000; ++seed) {
    Prng rng(seed);
    Rig r;
    // epoch -> the configuration decreed for it. A JOIN grant goes to two
    // recipients (primary and joiner), so recipient fields are not compared.
    std::map<std::uint64_t, Grant> granted;
    std::uint64_t max_announced = 1;         // highest epoch W has put in any sent reply
    std::uint64_t max_durable = 1;
    std::optional<SlotWrite> job;
    for (int step = 0; step < 300; ++step) {
      r.now += static_cast<Nanos>(rng.below(3 * static_cast<std::uint64_t>(kTw)));
      const State& st = r.w->state();
      const std::uint64_t e = st.epoch - (rng.chance(1, 5) ? std::min<std::uint64_t>(st.epoch - 1, 1) : 0);
      const auto n = static_cast<NodeId>(rng.below(2));
      const std::uint64_t inc = rng.chance(4, 5) ? st.inc[n] + (rng.chance(1, 3) ? 1 : 0) : rng.below(4);
      const auto other = static_cast<NodeId>(1 - st.primary);
      const bool solo = st.members == member_bit(st.primary);
      if (rng.chance(1, 2)) {
        // A request that is valid for the current state (grants are what we are testing).
        switch (rng.below(4)) {
          case 0: r.w->handle(Solo{st.epoch, st.primary, st.inc[st.primary]}, kA, r.now); break;
          case 1:
            if (solo) r.w->handle(Resume{st.epoch, st.primary, st.inc[st.primary] + 1}, kA, r.now);
            else r.w->handle(Promote{st.epoch, other, st.inc[other], 0}, kB, r.now);
            break;
          case 2:
            if (solo) r.w->handle(Join{st.epoch, st.primary, other, st.inc[st.primary], st.inc[other] + 1, 0}, kA, r.now);
            break;
          default: r.w->handle(Promote{st.epoch, other, st.inc[other], 0}, kB, r.now); break;
        }
      } else switch (rng.below(6)) {
        case 0: r.w->handle(Heartbeat{n, Role::kPrimary, inc, e}, kA, r.now); break;
        case 1: r.w->handle(Promote{e, n, inc, 0}, kB, r.now); break;
        case 2: r.w->handle(Solo{e, n, inc}, kA, r.now); break;
        case 3: r.w->handle(Join{e, n, static_cast<NodeId>(1 - n), st.inc[n], inc, 0}, kA, r.now); break;
        case 4: r.w->handle(Resume{e, n, inc}, kA, r.now); break;
        default: break;
      }
      // Disk: complete, stay in flight (replies created meanwhile must wait),
      // tear and crash, or crash before the write lands.
      if (!job) job = r.w->begin_write();
      if (job) {
        const std::uint64_t roll = rng.below(10);
        if (roll < 5) {
          r.disk[job->slot] = job->image;
          r.w->on_persisted(job->generation);
          job.reset();
        } else if (roll < 7) {
          // still in flight
        } else if (roll < 9) {
          const auto cut = static_cast<std::ptrdiff_t>(rng.below(kSlotBytes));
          std::copy(job->image.begin(), job->image.begin() + cut, r.disk[job->slot].begin());
          job.reset();
          r.start();  // crash
        } else {
          job.reset();
          r.start();  // crash before the write began
        }
      }
      if (!job && rng.chance(1, 50)) r.start();  // crash between operations
      for (const Message& m : r.drain()) {
        if (const auto* g = std::get_if<Grant>(&m)) {
          max_announced = std::max(max_announced, g->epoch);
          auto [it, fresh] = granted.emplace(g->epoch, *g);
          const Grant& f = it->second;
          ASSERT_TRUE(fresh || (f.primary == g->primary && f.members == g->members && f.request == g->request &&
                                f.from_epoch == g->from_epoch))
              << "seed " << seed << ": two different configurations for epoch " << g->epoch;
          switch (g->request) {
            case MsgType::kPromote:
              ASSERT_EQ(g->primary, g->to_node);
              ASSERT_EQ(g->members, member_bit(g->to_node));
              break;
            case MsgType::kSolo:
            case MsgType::kResume: ASSERT_EQ(g->members, member_bit(g->primary)); break;
            case MsgType::kJoin: ASSERT_EQ(g->members, 0b11); break;
            default: FAIL();
          }
        } else if (const auto* rj = std::get_if<Reject>(&m)) {
          max_announced = std::max(max_announced, rj->epoch);
        }
      }
      // The durable state never regresses and covers every epoch W has announced.
      const auto d = choose(r.disk[0], r.disk[1]);
      ASSERT_TRUE(d.has_value()) << "seed " << seed << ": no valid slot";
      ASSERT_GE(d->state.epoch, max_durable) << "seed " << seed;
      ASSERT_GE(d->state.epoch, max_announced) << "seed " << seed;
      max_durable = d->state.epoch;
    }
  }
}

}  // namespace
}  // namespace lle::witness

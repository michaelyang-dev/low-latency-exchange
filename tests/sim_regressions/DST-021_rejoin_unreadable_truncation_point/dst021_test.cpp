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
//
// One replica is driven by hand: the witness's answer to its RESUME names the primary,
// and the primary's EPOCH_END names record 5 the end of their common epoch.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

#include "../../unit/repl/repl_harness.h"

namespace lle::repl::test {
namespace {

constexpr NodeId kPrimary = 0;
constexpr NodeId kSelf = 1;

// exchanged's record log: the newest `arena` records are in memory, older ones are read
// back from L3, so one outside the arena that is not durable yet cannot be read.
struct ArenaHost : FakeHost {
  std::size_t arena = 2;
  std::uint32_t log_read(std::uint64_t idx, std::span<std::byte> out) const {
    if (idx != 0 && idx + arena <= log.size() && idx > durable) return 0;
    return FakeHost::log_read(idx, out);
  }
};

std::optional<wire::EpochEndQuery> last_query(const ArenaHost& h) {
  std::optional<wire::EpochEndQuery> q;
  for (const Bytes& b : h.to_peer) {
    const auto m = wire::decode(b);
    if (m && std::holds_alternative<wire::EpochEndQuery>(*m)) q = std::get<wire::EpochEndQuery>(*m);
  }
  return q;
}

TEST(DST021, AnUnreadableTruncationPointIsAskedAgainNotTakenForADivergence) {
  // Records 1..9 of epoch 1, durable only to 1: records 2..7 cannot be read back yet.
  ArenaHost h;
  day_start(h, kPrimary);
  (void)h.sequence_n(1, 8);
  ASSERT_EQ(h.log.size(), 9u);
  h.flush_on_request = false;
  h.durable = 1;

  Nanos now = 0;
  Replica<ArenaHost> rep(node_config(kSelf, 2), h);
  rep.start_recovering(now);
  // W's answer to the RESUME: the configuration has another primary, so hand-shake with it.
  const witness::Encoded rej = witness::encode(witness::Reject{2, kPrimary, witness::member_bit(kPrimary),
                                                               witness::MsgType::kResume, witness::RejectReason::kStaleEpoch,
                                                               kSelf, 2, 1});
  rep.on_witness(rej.span(), now);
  const std::optional<wire::EpochEndQuery> q = last_query(h);
  ASSERT_TRUE(q.has_value()) << "no EPOCH_END query after the witness named the primary";

  // The primary: epoch 1 ends at record 5 in its history (6..9 never reached it).
  wire::EpochEnd e;
  e.from = kPrimary;
  e.query_epoch = q->epoch;
  e.query_id = q->query_id;
  e.end_index = 5;
  e.end_crc = h.crc_of(5);
  e.end_epoch = 1;
  e.primary_epoch = 2;
  e.tail = 7;
  e.start_index = 1;
  e.start_crc = h.crc_of(1);
  std::array<std::byte, wire::kMaxDatagram> buf{};
  const std::size_t n = wire::encode(wire::Message{e}, buf);
  ASSERT_NE(n, 0u);
  rep.on_peer(std::span<const std::byte>(buf.data(), n), now);
  EXPECT_FALSE(h.has_alarm(Alarm::kDiverged)) << "a record not readable yet was taken for a divergence";
  EXPECT_TRUE(h.truncations.empty()) << "the replica truncated before it could check its truncation point";
  EXPECT_EQ(rep.role(), Role::kRecovering);

  // The journal catches up: record 5 can be read; the query goes out again and its answer
  // now truncates the divergent tail, 6..9.
  h.durable = h.log.size();
  h.to_peer.clear();
  for (int i = 0; i < 20 && !last_query(h); ++i) {
    now += 1 * kMs;
    (void)rep.poll(now);
  }
  const std::optional<wire::EpochEndQuery> again = last_query(h);
  ASSERT_TRUE(again.has_value()) << "the replica did not ask again";
  e.query_id = again->query_id;
  const std::size_t n2 = wire::encode(wire::Message{e}, buf);
  rep.on_peer(std::span<const std::byte>(buf.data(), n2), now);
  EXPECT_EQ(h.truncations, std::vector<std::uint64_t>{5});
  EXPECT_FALSE(h.has_alarm(Alarm::kDiverged));
}

}  // namespace
}  // namespace lle::repl::test

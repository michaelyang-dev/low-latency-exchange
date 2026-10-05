// FeedHandler over lossy dual lines in virtual time (03-protocols §7-§9, T10):
// the reconstructed book equals a direct replay, with re-requests and snapshot
// joins, for a range of seeds.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include "client/replay_state.h"
#include "client/report.h"
#include "proto/glimpse/snapshot_server.h"
#include "itch_gen.h"
#include "virtual_feed.h"

namespace lle::client {
namespace {

test::VirtualFeedConfig base_config(std::uint64_t seed) {
  test::VirtualFeedConfig c;
  c.feed.seed = seed;
  c.feed.heartbeat_interval = 1'000'000;
  c.feed.end_of_session_linger = 50'000'000;
  c.client.book.reserve_orders = 1 << 14;
  c.client.arbiter.reorder_capacity = 1 << 14;
  c.client.arbiter.gap_timeout = 20'000;
  c.client.arbiter.request_timeout = 1'000'000;
  c.client.arbiter.snapshot_gap_messages = 2'000;
  c.client.checkpoints.every = 5'000;
  return c;
}

void expect_exactly_once(const test::VirtualFeedResult& r) {
  for (std::size_t i = 1; i < r.order.size(); ++i) ASSERT_GT(r.order[i], r.order[i - 1]) << "at " << i;
}

void expect_matches_direct(const test::VirtualFeed::Msgs& msgs, const test::VirtualFeedResult& r,
                           const test::VirtualFeedConfig& c) {
  CheckpointConfig dc = c.client.checkpoints;
  for (const Checkpoint& k : r.client_checkpoints)
    if (k.splice) dc.extra.push_back(k.seq);
  const auto direct = test::VirtualFeed::direct_checkpoints(msgs, dc);
  const CompareResult cmp = compare_checkpoints(r.client_checkpoints, direct);
  EXPECT_TRUE(cmp.ok) << (cmp.details.empty() ? "" : cmp.details[0]) << " missing " << cmp.missing_in_reference;
  EXPECT_EQ(r.client_digest, r.direct_digest);
}

TEST(FeedHandler, CleanLinesDeliverEverythingOnce) {
  const auto msgs = test::ItchGen(1).make(20'000);
  auto c = base_config(1);
  const auto r = test::VirtualFeed(c, msgs).run();
  ASSERT_TRUE(r.ended);
  EXPECT_EQ(r.delivered, msgs.size());
  EXPECT_EQ(r.snapshots, 0u);
  EXPECT_EQ(r.metrics.requests_sent[0] + r.metrics.requests_sent[1], 0u);
  expect_exactly_once(r);
  expect_matches_direct(msgs, r, c);
  // Both lines contributed first arrivals (A is faster, B fills nothing without loss).
  EXPECT_GT(r.metrics.first_arrivals[0], 0u);
  EXPECT_GT(r.metrics.partial_overlaps[1] + r.metrics.duplicate_packets[1], 0u);
}

TEST(FeedHandler, IndependentLossIsRecoveredFromTheOtherLineAndReRequests) {
  const auto msgs = test::ItchGen(2).make(30'000);
  std::uint64_t by_line = 0, by_rerequest = 0;
  for (std::uint64_t seed = 1; seed <= 6; ++seed) {
    auto c = base_config(seed);
    c.feed.impair[0].loss_ppm = 50'000;  // 5%
    c.feed.impair[1].loss_ppm = 20'000;  // 2%
    c.feed.impair[0].dup_ppm = c.feed.impair[1].dup_ppm = 5'000;
    c.feed.impair[0].reorder_ppm = c.feed.impair[1].reorder_ppm = 5'000;
    const auto r = test::VirtualFeed(c, msgs).run();
    ASSERT_TRUE(r.ended) << "seed " << seed;
    EXPECT_EQ(r.delivered, msgs.size()) << "seed " << seed;
    expect_exactly_once(r);
    expect_matches_direct(msgs, r, c);
    by_line += r.metrics.gaps_filled_by_line[0] + r.metrics.gaps_filled_by_line[1];
    by_rerequest += r.metrics.gaps_filled_by_rerequest;
  }
  EXPECT_GT(by_line, 0u);
  EXPECT_GT(by_rerequest, 0u);  // losses on both lines at once happen over the seeds
}

TEST(FeedHandler, TotalOutageJoinsFromSnapshotAndRebuildsTheSameBook) {
  const auto msgs = test::ItchGen(3).make(40'000);
  auto c = base_config(7);
  c.feed.impair[0].loss_ppm = 10'000;
  c.feed.impair[1].loss_ppm = 10'000;
  c.feed.outages = {Outage{10'000, 5'000}, Outage{25'000, 3'000}};
  const auto r = test::VirtualFeed(c, msgs).run();
  ASSERT_TRUE(r.ended);
  EXPECT_EQ(r.snapshots, 2u);
  EXPECT_EQ(r.spins_served, 2u);
  EXPECT_LT(r.delivered, msgs.size());  // the outage ranges were covered by the snapshots
  expect_exactly_once(r);
  expect_matches_direct(msgs, r, c);
  std::size_t splices = 0;
  for (const auto& k : r.client_checkpoints) splices += k.splice ? 1 : 0;
  EXPECT_EQ(splices, 2u);
}

TEST(FeedHandler, NoSnapshotServiceMeansTheGapIsNeverClosed) {
  const auto msgs = test::ItchGen(4).make(8'000);
  auto c = base_config(3);
  c.snapshot_service = false;
  c.feed.outages = {Outage{3'000, 3'000}};
  c.time_limit = 200'000'000;
  const auto r = test::VirtualFeed(c, msgs).run();
  EXPECT_FALSE(r.ended);
  EXPECT_LT(r.delivered, 3'000u);
}

TEST(FeedHandler, SnapshotBelowDeliveredStreamIsRejected) {
  // A G below what was already delivered must not rewind the stream.
  FeedConfig cfg;
  cfg.book.reserve_orders = 1024;
  cfg.arbiter.reorder_capacity = 1024;
  FeedHandler<> fh(cfg);
  struct Down {
    int needed = 0;
    void on_book_message(SeqNo, std::span<const std::byte>) {}
    void on_snapshot_message(std::span<const std::byte>) {}
    void send_request(mold::Server, std::span<const std::byte>) {}
    void on_snapshot_needed(SeqNo, SeqNo) { ++needed; }
    void on_end_of_session(SeqNo) {}
  } down;
  std::array<std::byte, glimpse::kEndOfSnapshotLen> g{};
  (void)glimpse::encode_end_of_snapshot(g, 5);
  // Not awaiting a snapshot: rejected, a fresh one is asked for.
  EXPECT_EQ(fh.on_snapshot_payload(g, 0, down), FeedHandler<>::SpinResult::Rejected);
  EXPECT_EQ(down.needed, 1);
  EXPECT_EQ(fh.stats().snapshots_rejected, 1u);
}

// A snapshot session that dies before End of Snapshot leaves a partial book; the
// next spin must start from an empty book, not on top of it. (Found by the T10
// comparison on S120925: a spin applied over a partial one left stale orders.)
TEST(FeedHandler, AbortedSpinIsDiscardedByTheNextOne) {
  const auto msgs = test::ItchGen(9).make(6'000);
  ReplayBookState early, late;
  SeqNo seq = 0;
  for (const auto& m : msgs) {
    ++seq;
    if (seq <= 3'000) early.apply(seq, m);
    late.apply(seq, m);
  }
  auto spin_of = [](const ReplayBookState& st) {
    std::vector<std::vector<std::byte>> out;
    (void)glimpse::SnapshotServer{}.emit(st, [&](std::span<const std::byte> m) { out.emplace_back(m.begin(), m.end()); });
    return out;
  };
  FeedConfig cfg;
  cfg.book.reserve_orders = 1 << 14;
  cfg.arbiter.reorder_capacity = 1 << 14;
  cfg.arbiter.first_seq = 0;  // late join: the feed starts by waiting for a snapshot
  FeedHandler<> fh(cfg);
  struct Down {
    void on_book_message(SeqNo, std::span<const std::byte>) {}
    void on_snapshot_message(std::span<const std::byte>) {}
    void send_request(mold::Server, std::span<const std::byte>) {}
    void on_snapshot_needed(SeqNo, SeqNo) {}
    void on_end_of_session(SeqNo) {}
  } down;
  const auto partial = spin_of(early);
  fh.begin_snapshot();
  for (std::size_t i = 0; i + 1 < partial.size() / 2; ++i) fh.on_snapshot_payload(partial[i], 0, down);
  fh.abort_snapshot();
  EXPECT_EQ(fh.stats().snapshots_aborted, 1u);
  const auto full = spin_of(late);
  fh.begin_snapshot();
  for (const auto& m : full) (void)fh.on_snapshot_payload(m, 0, down);
  EXPECT_EQ(fh.stats().snapshots_applied, 1u);
  EXPECT_EQ(fh.book().books_digest(), late.books_digest());
  EXPECT_EQ(fh.book().live_orders(), late.live_orders());
  EXPECT_EQ(fh.stats().book_status[static_cast<std::size_t>(book::Status::kDuplicateRef)], 0u);

  // Without an explicit begin: after an abort the next spin's first payload starts afresh.
  FeedHandler<> fh2(cfg);
  for (std::size_t i = 0; i + 1 < partial.size() / 2; ++i) fh2.on_snapshot_payload(partial[i], 0, down);
  fh2.abort_snapshot();
  for (const auto& m : full) (void)fh2.on_snapshot_payload(m, 0, down);
  EXPECT_EQ(fh2.book().books_digest(), late.books_digest());
}

// A stream that ends inside a snapshot splice: the book is at S(P), and the
// final checkpoint is labelled S(P), once (not the last message delivered
// before the join; found when a slow client's last join reached the end).
TEST(FeedHandler, FinalCheckpointAfterASpliceAtTheEnd) {
  const auto msgs = test::ItchGen(10).make(3'000);
  ReplayBookState st;
  SeqNo seq = 0;
  for (const auto& m : msgs) st.apply(++seq, m);
  FeedConfig cfg;
  cfg.book.reserve_orders = 1 << 14;
  cfg.arbiter.reorder_capacity = 1 << 14;
  cfg.arbiter.first_seq = 0;
  cfg.checkpoints.every = 1'000;
  FeedHandler<> fh(cfg);
  struct Down {
    void on_book_message(SeqNo, std::span<const std::byte>) {}
    void on_snapshot_message(std::span<const std::byte>) {}
    void send_request(mold::Server, std::span<const std::byte>) {}
    void on_snapshot_needed(SeqNo, SeqNo) {}
    void on_end_of_session(SeqNo) {}
  } down;
  (void)glimpse::SnapshotServer{}.emit(st, [&](std::span<const std::byte> m) { (void)fh.on_snapshot_payload(m, 0, down); });
  fh.finish();
  const auto& l = fh.checkpoints().list();
  ASSERT_EQ(l.size(), 1u);
  EXPECT_EQ(l[0].seq, 3'000u);
  EXPECT_TRUE(l[0].splice);
  EXPECT_EQ(l[0].books_digest, st.books_digest());
  EXPECT_EQ(fh.stats().book_seq, 3'000u);
  EXPECT_EQ(fh.stats().last_seq, 0u);
}

}  // namespace
}  // namespace lle::client

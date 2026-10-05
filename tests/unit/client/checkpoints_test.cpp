// Checkpoints, their file format and comparison (T10 evidence), the replay
// state's snapshot spin, and the command-line parsers.
#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "client/checkpoints.h"
#include "client/cli.h"
#include "client/replay_state.h"
#include "client/report.h"
#include "itch_gen.h"
#include "proto/glimpse/snapshot_server.h"

namespace lle::client {
namespace {

std::vector<Checkpoint> record(const std::vector<std::vector<std::byte>>& msgs,
                               CheckpointConfig cfg, SeqNo skip_from = 0, SeqNo skip_to = 0) {
  book::OptBook<> b;
  CheckpointRecorder ck(cfg);
  SeqNo seq = 0;
  for (const auto& m : msgs) {
    ++seq;
    (void)book::apply_itch(b, m.data(), m.size());
    if (skip_from != 0 && seq >= skip_from && seq < skip_to) {
      if (seq == skip_to - 1) ck.on_splice(skip_from, skip_to, b, 0);
      continue;
    }
    ck.on_message(seq, m, b, 0);
  }
  ck.finish(seq, b, 0);
  return ck.list();
}

TEST(Checkpoints, PlannedAndExtraSequences) {
  const auto msgs = test::ItchGen(1).make(1'000);
  CheckpointConfig c;
  c.every = 300;
  c.extra = {50, 450, 50};
  const auto list = record(msgs, c);
  std::vector<SeqNo> seqs;
  for (const auto& k : list) seqs.push_back(k.seq);
  EXPECT_EQ(seqs, (std::vector<SeqNo>{50, 300, 450, 600, 900, 1000}));
  for (const auto& k : list) EXPECT_FALSE(k.tainted);
}

TEST(Checkpoints, SpliceSkipsPlannedCheckpointsAndComparesWithTheReference) {
  const auto msgs = test::ItchGen(2).make(1'000);
  CheckpointConfig c;
  c.every = 200;
  // The client "joined from a snapshot" covering [350, 700): the book after
  // message 699 is what a spin at P=699 rebuilds.
  const auto client = record(msgs, c, 350, 700);
  std::vector<SeqNo> seqs;
  for (const auto& k : client) seqs.push_back(k.seq);
  EXPECT_EQ(seqs, (std::vector<SeqNo>{200, 699, 800, 1000}));
  EXPECT_TRUE(client[1].splice && client[1].tainted);
  CheckpointConfig rc = c;
  rc.extra = {699};
  const auto ref = record(msgs, rc);
  const CompareResult r = compare_checkpoints(client, ref);
  EXPECT_TRUE(r.ok) << (r.details.empty() ? "" : r.details[0]);
  EXPECT_EQ(r.compared_books, 4u);
  EXPECT_EQ(r.compared_streams, 3u);  // the splice interval is not comparable
  // Without the splice sequence in the reference the comparison is incomplete.
  EXPECT_FALSE(compare_checkpoints(client, record(msgs, c)).ok);
}

TEST(Checkpoints, AnyDifferenceIsAMismatch) {
  const auto msgs = test::ItchGen(3).make(600);
  CheckpointConfig c;
  c.every = 100;
  auto a = record(msgs, c);
  auto b = a;
  b[2].books_digest ^= 1;
  b[4].stream_hash ^= 1;
  const CompareResult r = compare_checkpoints(a, b);
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.mismatches, 2u);
}

TEST(Checkpoints, ClientThatStoppedEarlyNeverMatches) {
  const auto msgs = test::ItchGen(5).make(600);
  CheckpointConfig c;
  c.every = 100;
  const auto ref = record(msgs, c);
  auto client = ref;
  ASSERT_TRUE(compare_checkpoints(client, ref).ok);
  client.pop_back();  // a matching prefix, but the stream's end is missing
  const CompareResult r = compare_checkpoints(client, ref);
  EXPECT_FALSE(r.reached_end);
  EXPECT_FALSE(r.ok);
  EXPECT_EQ(r.mismatches, 0u);
}

TEST(Checkpoints, FileRoundTrip) {
  const auto msgs = test::ItchGen(4).make(500);
  CheckpointConfig c;
  c.every = 100;
  auto a = record(msgs, c, 150, 260);
  const std::string path = ::testing::TempDir() + "/lle_client_ck.txt";
  ASSERT_TRUE(write_checkpoints(path, a));
  std::vector<Checkpoint> b;
  std::string err;
  ASSERT_TRUE(read_checkpoints(path, b, &err)) << err;
  ASSERT_EQ(a.size(), b.size());
  for (std::size_t i = 0; i < a.size(); ++i) {
    EXPECT_EQ(a[i].seq, b[i].seq);
    EXPECT_EQ(a[i].books_digest, b[i].books_digest);
    EXPECT_EQ(a[i].stream_hash, b[i].stream_hash);
    EXPECT_EQ(a[i].live_orders, b[i].live_orders);
    EXPECT_EQ(a[i].tainted, b[i].tainted);
    EXPECT_EQ(a[i].splice, b[i].splice);
  }
  std::remove(path.c_str());
}

TEST(ReplayState, SpinRebuildsTheSameBook) {
  const auto msgs = test::ItchGen(5).make(5'000);
  ReplayBookState st;
  SeqNo seq = 0;
  for (const auto& m : msgs) st.apply(++seq, m);
  std::vector<std::vector<std::byte>> spin;
  const auto stats = glimpse::SnapshotServer{}.emit(st, [&](std::span<const std::byte> m) { spin.emplace_back(m.begin(), m.end()); });
  EXPECT_EQ(stats.next_seq, msgs.size() + 1);
  ASSERT_GE(spin.size(), 2u);
  EXPECT_EQ(static_cast<char>(spin.back()[0]), 'G');
  book::OptBook<> rebuilt;
  for (std::size_t i = 0; i + 1 < spin.size(); ++i) (void)book::apply_itch(rebuilt, spin[i].data(), spin[i].size());
  EXPECT_EQ(rebuilt.books_digest(), st.books_digest());
  EXPECT_EQ(rebuilt.live_orders(), st.live_orders());
  EXPECT_EQ(stats.by_type[static_cast<unsigned char>('R')], 20u);
  EXPECT_EQ(stats.by_type[static_cast<unsigned char>('S')], 2u);
  EXPECT_EQ(stats.by_type[static_cast<unsigned char>('A')], st.live_orders());
}

TEST(Cli, Probabilities) {
  EXPECT_EQ(cli::parse_ppm("0.01"), 10'000u);
  EXPECT_EQ(cli::parse_ppm("2%"), 20'000u);
  EXPECT_EQ(cli::parse_ppm("0.1%"), 1'000u);
  EXPECT_EQ(cli::parse_ppm("5%"), 50'000u);
  EXPECT_EQ(cli::parse_ppm("1"), 1'000'000u);
  EXPECT_FALSE(cli::parse_ppm("1.5").has_value());
  EXPECT_FALSE(cli::parse_ppm("x").has_value());
}

TEST(Cli, DurationsAndPrices) {
  EXPECT_EQ(cli::parse_duration("250us"), 250'000);
  EXPECT_EQ(cli::parse_duration("10ms"), 10'000'000);
  EXPECT_EQ(cli::parse_duration("2s"), 2'000'000'000);
  EXPECT_EQ(cli::parse_duration("7"), 7);
  EXPECT_FALSE(cli::parse_duration("ms").has_value());
  EXPECT_EQ(cli::parse_price("12.3456"), 123'456);
  EXPECT_EQ(cli::parse_price("150"), 1'500'000);
  EXPECT_EQ(cli::parse_price("0.01"), 100);
  EXPECT_FALSE(cli::parse_price("1.23456").has_value());
}

}  // namespace
}  // namespace lle::client

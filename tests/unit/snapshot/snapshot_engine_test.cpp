// Snapshot equivalence (T05; 06 §9): an engine restored from a snapshot taken
// at any journal position behaves exactly like the engine that never stopped.
// For generated record streams (fuzz/engine/gen.hpp: orders, cancels,
// replaces, crosses, halts, risk, reserve, pegs, ...) and random cut points,
// the snapshot goes through the real container (snap::Writer in memory ->
// snap::Reader -> load_engine); the restored engine must reproduce the
// payload bytes at the cut, then every output byte of the next records and the
// same state hash at the end. Also the file path: save_engine, find_latest,
// MappedSnapshot, load_engine.
#include <gtest/gtest.h>

#include <cstdint>
#include <deque>
#include <set>
#include <string>
#include <vector>

#include "common/prng.h"
#include "engine/engine.h"
#include "gen.hpp"
#include "snapshot/engine_section.h"
#include "snapshot_test_util.h"

namespace lle::snap {
namespace {

using engine::Engine;
using engine::InputRecord;

engine::EngineConfig small_config() {
  engine::EngineConfig c;
  c.book.reserve_orders = std::size_t{1} << 12;
  c.book.reserve_levels = std::size_t{1} << 10;
  c.book.levels_per_side = 16;
  c.urn_capacity = std::size_t{1} << 13;
  c.scratch = 256;
  return c;
}

// One record's output: the messages concatenated, and their lengths (with the
// destination: OUCH lengths carry the session id in the high bits).
struct Bytes {
  std::vector<std::byte> v;
  std::vector<std::uint64_t> lens;
  void itch(std::uint64_t, std::span<const std::byte> b) {
    v.insert(v.end(), b.begin(), b.end());
    lens.push_back(b.size());
  }
  void ouch(std::uint64_t, std::uint32_t s, std::span<const std::byte> b) {
    v.insert(v.end(), b.begin(), b.end());
    lens.push_back((std::uint64_t{s} << 32) | b.size());
  }
  void audit(std::uint64_t, const engine::AuditEvent&) {}
  friend bool operator==(const Bytes&, const Bytes&) = default;
};

constexpr std::uint64_t kSeeds = 200;
constexpr std::size_t kRecords = 1'000;
constexpr std::size_t kCutsPerSeed = 50;
constexpr std::size_t kSuffix = 60;

TEST(SnapshotEngine, RestoredEngineContinuesIdentically) {
  std::uint64_t cases = 0, compared_records = 0, compared_messages = 0;
  for (std::uint64_t seed = 1; seed <= kSeeds; ++seed) {
    // The stream, with stable payload storage.
    engine::gen::Generator g(seed);
    std::deque<std::vector<std::byte>> payloads;
    std::vector<InputRecord> recs;
    recs.reserve(kRecords);
    for (std::size_t i = 0; i < kRecords; ++i) {
      InputRecord r = g.next();
      payloads.emplace_back(r.payload.begin(), r.payload.end());
      r.payload = std::span<const std::byte>(payloads.back());
      recs.push_back(r);
    }
    // Cut points: the snapshot is taken after record `cut - 1`.
    Prng rng(seed * 7919);
    std::set<std::size_t> cut_set;
    while (cut_set.size() < kCutsPerSeed) cut_set.insert(1 + rng.below(kRecords - 1));
    // The reference pass: outputs per record, images at the cuts, hashes at the ends.
    Engine a(small_config());
    std::vector<Bytes> outs(kRecords);
    std::vector<std::vector<std::byte>> images(kRecords), payload_at(kRecords);
    std::vector<std::uint64_t> hash_after(kRecords, 0);
    std::set<std::size_t> ends;
    for (std::size_t c : cut_set) ends.insert(std::min(c + kSuffix, kRecords) - 1);
    for (std::size_t i = 0; i < kRecords; ++i) {
      if (cut_set.count(i) != 0) {
        EngineSnapshotIds ids;
        ids.epoch = recs[i - 1].epoch;
        ids.index = recs[i - 1].index;
        ids.snapshot_id = i;
        auto img = engine_image(a, ids, WriterOptions{.chunk_bytes = kMinChunkBytes});
        ASSERT_TRUE(img.has_value()) << to_string(img.error());
        images[i] = std::move(*img);
        a.snapshot(payload_at[i]);
      }
      a.apply(recs[i], outs[i]);
      if (ends.count(i) != 0) hash_after[i] = a.state_hash();
    }
    // Each cut: load the image into a fresh engine and replay the suffix.
    for (std::size_t c : cut_set) {
      auto rd = Reader::open(images[c]);
      ASSERT_TRUE(rd.has_value()) << to_string(rd.error());
      EXPECT_EQ(rd->meta().index, recs[c - 1].index);
      Engine b(small_config());
      const auto ok = load_engine(*rd, b);
      ASSERT_TRUE(ok.has_value()) << "seed " << seed << " cut " << c << ": " << to_string(ok.error());
      std::vector<std::byte> now;
      b.snapshot(now);
      ASSERT_EQ(now, payload_at[c]) << "seed " << seed << " cut " << c;
      const std::size_t end = std::min(c + kSuffix, kRecords);
      for (std::size_t i = c; i < end; ++i) {
        Bytes s;
        b.apply(recs[i], s);
        ASSERT_TRUE(s == outs[i]) << "seed " << seed << " cut " << c << " record " << i;
        compared_messages += s.lens.size();
        ++compared_records;
      }
      ASSERT_EQ(b.state_hash(), hash_after[end - 1]) << "seed " << seed << " cut " << c;
      std::string err;
      ASSERT_TRUE(b.check(&err)) << err;
      ++cases;
    }
  }
  EXPECT_GE(cases, 10'000u);
  EXPECT_GT(compared_records, 500'000u);
  EXPECT_GT(compared_messages, 250'000u);
}

TEST(SnapshotEngine, FileRoundTripThroughFindLatest) {
  test::TempDir dir;
  engine::gen::Generator g(4242);
  Engine a(small_config());
  Bytes sink;
  std::deque<std::vector<std::byte>> keep;
  std::uint64_t last = 0;
  for (int i = 0; i < 3'000; ++i) {
    const InputRecord& r = g.next();
    a.apply(r, sink);
    last = r.index;
    if (i == 999 || i == 1999) {
      EngineSnapshotIds ids;
      ids.index = last;
      ids.snapshot_id = static_cast<std::uint64_t>(i);
      ASSERT_TRUE(save_engine(a, ids, dir.path()).has_value());
    }
  }
  const auto info = find_latest(dir.path(), last);
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->meta.snapshot_id, 1999u);
  auto mapped = MappedSnapshot::open(info->path);
  ASSERT_TRUE(mapped.has_value());
  Engine b(small_config());
  ASSERT_TRUE(load_engine(mapped->reader(), b).has_value());
  EXPECT_EQ(b.state_hash(), info->meta.state_hash);
  EXPECT_EQ(b.itch_count(), info->meta.mold_seq);
}

TEST(SnapshotEngine, RejectsForeignAndTamperedPayloads) {
  // Not an engine payload.
  const std::vector<std::byte> junk(64, std::byte{7});
  auto img = encode_image(test::sample_meta(), {}, junk, kMinChunkBytes);
  ASSERT_TRUE(img.has_value());
  auto rd = Reader::open(*img);
  ASSERT_TRUE(rd.has_value());
  Engine e(small_config());
  EXPECT_EQ(load_engine(*rd, e).error(), EngineLoadError::NotEngine);
  // A valid engine payload under a header whose state hash does not match.
  Engine a(small_config());
  engine::gen::Generator g(9);
  Bytes sink;
  for (int i = 0; i < 500; ++i) a.apply(g.next(), sink);
  std::vector<std::byte> payload;
  a.snapshot(payload);
  SnapshotMeta m = engine_meta(a, EngineSnapshotIds{});
  m.state_hash ^= 1;
  auto bad = encode_image(m, engine_sessions(a), payload, kMinChunkBytes);
  ASSERT_TRUE(bad.has_value());
  auto rb = Reader::open(*bad);
  ASSERT_TRUE(rb.has_value());
  EXPECT_EQ(load_engine(*rb, e).error(), EngineLoadError::StateHash);
  EXPECT_EQ(e.live_orders(), 0u);  // reset after a failed load
}

}  // namespace
}  // namespace lle::snap

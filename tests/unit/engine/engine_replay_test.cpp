// Determinism and recovery (05-matching-engine §8, E-06):
//  - replaying the same records twice gives identical outputs and state;
//  - snapshot(S) + replay(S+1..N) == replay(1..N), state hash and outputs;
//  - state_hash() == FNV-1a(snapshot payload).
// Records come from the enginediff swarm generator (fuzz/engine/gen.hpp).
#include <gtest/gtest.h>

#include <cstdlib>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "common/prng.h"
#include "engine/engine.h"
#include "gen.hpp"

namespace lle::engine {
namespace {

struct Stream {
  std::deque<std::vector<std::byte>> payloads;
  std::vector<InputRecord> recs;
};

Stream make_stream(std::uint64_t seed, std::size_t n) {
  Stream s;
  gen::Generator g(seed);
  for (std::size_t i = 0; i < n; ++i) {
    InputRecord r = g.next();
    s.payloads.emplace_back(r.payload.begin(), r.payload.end());
    r.payload = std::span<const std::byte>(s.payloads.back());
    s.recs.push_back(r);
  }
  return s;
}

struct Out {
  std::uint64_t index;
  Dest dest;
  std::uint32_t session;
  std::vector<std::byte> bytes;
  bool operator==(const Out&) const = default;
};

void run(Engine& e, const Stream& s, std::size_t from, std::size_t to, std::vector<Out>& out) {
  BufferSink sink;
  for (std::size_t i = from; i < to; ++i) {
    sink.clear();
    e.apply(s.recs[i], sink);
    for (const auto& en : sink.entries()) {
      const auto b = sink.bytes(en);
      out.push_back(Out{en.index, en.dest, en.session, {b.begin(), b.end()}});
      EXPECT_EQ(en.index, s.recs[i].index) << "every output carries its source journal index";
    }
  }
}

TEST(Replay, IdenticalRunsGiveIdenticalOutputsAndState) {
  for (std::uint64_t seed : {11u, 12u, 13u}) {
    const Stream s = make_stream(seed, 6'000);
    Engine a, b;
    std::vector<Out> oa, ob;
    run(a, s, 0, s.recs.size(), oa);
    run(b, s, 0, s.recs.size(), ob);
    EXPECT_FALSE(oa.empty());
    EXPECT_TRUE(oa == ob) << "seed " << seed;
    EXPECT_EQ(a.state_hash(), b.state_hash());
    std::string err;
    EXPECT_TRUE(a.check(&err)) << err;
  }
}

TEST(Replay, SnapshotThenReplayEqualsFullReplay) {
  for (std::uint64_t seed : {21u, 22u, 23u, 24u}) {
    const Stream s = make_stream(seed, 8'000);
    const std::size_t n = s.recs.size();
    Engine full;
    std::vector<Out> of;
    run(full, s, 0, n, of);
    for (std::size_t cut : {std::size_t{1}, n / 3, n / 2, n - 1}) {
      Engine head;
      std::vector<Out> oh;
      run(head, s, 0, cut, oh);
      std::vector<std::byte> snap;
      head.snapshot(snap);
      Fnv1a64 f;
      f.bytes(snap);
      EXPECT_EQ(f.value(), head.state_hash());
      auto tail = std::make_unique<Engine>();
      ASSERT_TRUE(tail->restore(snap)) << "seed " << seed << " cut " << cut;
      EXPECT_EQ(tail->state_hash(), head.state_hash());
      std::vector<Out> ot;
      run(*tail, s, cut, n, ot);
      EXPECT_EQ(tail->state_hash(), full.state_hash()) << "seed " << seed << " cut " << cut;
      std::vector<Out> expect(of.begin() + static_cast<std::ptrdiff_t>(oh.size()), of.end());
      EXPECT_TRUE(ot == expect) << "seed " << seed << " cut " << cut;
      std::string err;
      EXPECT_TRUE(tail->check(&err)) << err;
    }
  }
}

TEST(Replay, RestoreRejectsCorruptPayloads) {
  const Stream s = make_stream(31, 3'000);
  Engine e;
  std::vector<Out> o;
  run(e, s, 0, s.recs.size(), o);
  std::vector<std::byte> snap;
  e.snapshot(snap);
  Engine r;
  for (std::size_t cut : {std::size_t{0}, std::size_t{11}, snap.size() / 2, snap.size() - 1}) {
    EXPECT_FALSE(r.restore(std::span<const std::byte>(snap).first(cut)));
  }
  auto bad = snap;
  bad[0] = std::byte{0};  // magic
  EXPECT_FALSE(r.restore(bad));
  auto extra = snap;
  extra.push_back(std::byte{0});  // trailing bytes
  EXPECT_FALSE(r.restore(extra));
  EXPECT_TRUE(r.restore(snap));
  EXPECT_EQ(r.state_hash(), e.state_hash());
}

// Snapshots arrive through a CRC-checked container whose engine section also
// carries the state hash, so a damaged payload should never reach restore();
// restore() must still survive one. Random byte damage, field-sized overwrites
// with extreme values, truncation and insertion: restore either fails, or the
// restored engine passes check() and keeps running (ASan/UBSan builds check the
// absence of out-of-bounds reads and overflow).
TEST(Replay, RestoreSurvivesMutatedPayloads) {
  // LLE_RESTORE_MUTATIONS=N raises the per-snapshot count for a deeper local run.
  const char* env = std::getenv("LLE_RESTORE_MUTATIONS");
  const int per_snap = env != nullptr ? std::atoi(env) : 400;
  // LLE_RESTORE_SEED=S runs only stream S (to spread a deep run over processes).
  const char* only = std::getenv("LLE_RESTORE_SEED");
  std::vector<std::uint64_t> seeds = {41, 42, 43, 44};
  if (only != nullptr) seeds = {std::strtoull(only, nullptr, 10)};
  std::size_t accepted = 0, total = 0;
  for (std::uint64_t seed : seeds) {
    const Stream s = make_stream(seed, 6'000);
    for (std::size_t cut : {std::size_t{1'500}, std::size_t{4'000}}) {
      Engine e;
      std::vector<Out> o;
      run(e, s, 0, cut, o);
      std::vector<std::byte> snap;
      e.snapshot(snap);
      lle::Prng rng(seed * 1'000 + cut);
      for (int m = 0; m < per_snap; ++m) {
        std::vector<std::byte> bad = snap;
        std::string what;
        switch (rng.below(4)) {
          case 0:  // a few random bytes
            for (std::uint64_t k = 1 + rng.below(4); k > 0; --k) {
              const std::size_t at = rng.below(bad.size());
              bad[at] = std::byte(rng.below(256));
              what += " byte@" + std::to_string(at) + "=" + std::to_string(static_cast<int>(bad[at]));
            }
            break;
          case 1: {  // a field-sized overwrite with an extreme value
            const std::size_t w = std::size_t{1} << rng.below(4);
            if (bad.size() <= w) break;
            const std::size_t at = rng.below(bad.size() - w);
            static constexpr std::uint64_t kVals[] = {0, 1, 0xFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, ~0ull, 1ull << 63};
            const std::uint64_t v = rng.chance(1, 2) ? kVals[rng.below(8)] : rng.next_u64();
            for (std::size_t b = 0; b < w; ++b) bad[at + b] = std::byte((v >> (8 * b)) & 0xFF);
            what = " field@" + std::to_string(at) + " width " + std::to_string(w) + " = " + std::to_string(v);
            break;
          }
          case 2:  // truncation
            bad.resize(rng.below(bad.size()));
            what = " truncated to " + std::to_string(bad.size());
            break;
          default: {  // insertion
            const std::size_t at = rng.below(bad.size());
            bad.insert(bad.begin() + static_cast<std::ptrdiff_t>(at), static_cast<std::size_t>(1 + rng.below(8)),
                       std::byte(rng.below(256)));
            what = " insertion@" + std::to_string(at);
            break;
          }
        }
        ++total;
        Engine r;
        if (!r.restore(bad)) continue;
        ++accepted;
        std::string err;
        ASSERT_TRUE(r.check(&err)) << "seed " << seed << " cut " << cut << " mutation " << m << what << ": " << err;
        std::vector<Out> tail;
        run(r, s, cut, std::min(cut + 300, s.recs.size()), tail);
        ASSERT_TRUE(r.check(&err)) << "seed " << seed << " cut " << cut << " mutation " << m << what
                                   << " after replay: " << err;
      }
    }
  }
  EXPECT_EQ(total, 2 * seeds.size() * static_cast<std::size_t>(per_snap));
  EXPECT_LT(accepted, total);  // most damage is detected
}

}  // namespace
}  // namespace lle::engine

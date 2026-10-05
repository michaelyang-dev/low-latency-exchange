#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/prng.h"
#include "lob/arena.h"
#include "lob/index.h"

namespace lle::lob {
namespace {

// ---- every index policy, same contract --------------------------------------------
template <class I>
struct IndexContract : ::testing::Test {
  static IndexConfig config() {
    IndexConfig c;
    c.capacity = 16;              // force growth paths
    c.max_direct_ref = 1u << 15;  // PagedIndex: 4 pages direct, rest fallback
    return c;
  }
};

using Indexes = ::testing::Types<StdIndex, FlatIndex<FibonacciHash>, FlatIndex<IdentityHash>, FlatIndex<MixHash>,
                                 FlatIndex<FibonacciHash, ArenaBacking<HugePages::kTransparent, false>>,
                                 PagedIndex<>, PagedIndex<StdIndex>, PagedIndex<FlatIndex<IdentityHash>>>;
TYPED_TEST_SUITE(IndexContract, Indexes);

TYPED_TEST(IndexContract, InsertFindErase) {
  TypeParam idx(this->config());
  EXPECT_EQ(idx.find(5), kNil32);
  EXPECT_TRUE(idx.insert(5, 50));
  EXPECT_FALSE(idx.insert(5, 51));  // duplicate: no change
  EXPECT_EQ(idx.find(5), 50u);
  EXPECT_EQ(idx.size(), 1u);
  EXPECT_EQ(idx.erase(6), kNil32);
  EXPECT_EQ(idx.erase(5), 50u);
  EXPECT_EQ(idx.find(5), kNil32);
  EXPECT_EQ(idx.erase(5), kNil32);
  EXPECT_EQ(idx.size(), 0u);
  std::string err;
  EXPECT_TRUE(idx.check(&err)) << err;
}

TYPED_TEST(IndexContract, EdgeKeys) {
  TypeParam idx(this->config());
  const std::uint64_t keys[] = {0,
                                1,
                                8191,
                                8192,
                                (1u << 15) - 1,
                                1u << 15,
                                (1ull << 32) - 1,
                                1ull << 32,
                                (1ull << 32) + 1,
                                1ull << 63,
                                ~0ull - 1,
                                ~0ull};
  Handle32 v = 0;
  for (std::uint64_t k : keys) ASSERT_TRUE(idx.insert(k, v++)) << k;
  v = 0;
  for (std::uint64_t k : keys) EXPECT_EQ(idx.find(k), v++) << k;
  std::string err;
  EXPECT_TRUE(idx.check(&err)) << err;
  v = 0;
  for (std::uint64_t k : keys) EXPECT_EQ(idx.erase(k), v++) << k;
  EXPECT_EQ(idx.size(), 0u);
  EXPECT_TRUE(idx.check(&err)) << err;
}

TYPED_TEST(IndexContract, HandleRangeIncludesLargestStorable) {
  TypeParam idx(this->config());
  EXPECT_TRUE(idx.insert(3, kNil32 - 1));
  EXPECT_EQ(idx.find(3), kNil32 - 1);
  EXPECT_TRUE(idx.insert(1ull << 40, 0));
  EXPECT_EQ(idx.find(1ull << 40), 0u);
}

// Random differential against std::unordered_map, with keys mixing dense,
// clustered, sparse and huge values.
TYPED_TEST(IndexContract, RandomDifferential) {
  TypeParam idx(this->config());
  std::unordered_map<std::uint64_t, Handle32> ref;
  std::vector<std::uint64_t> keys;
  Prng rng(1234);
  auto draw = [&]() -> std::uint64_t {
    switch (rng.below(5)) {
      case 0: return rng.below(1 << 15);                    // direct range
      case 1: return (1u << 15) + rng.below(1 << 12);      // just above the direct max
      case 2: return rng.below(64) * 1024;                 // identity-hash collisions
      case 3: return (1ull << 32) + rng.below(1 << 10);
      default: return rng.next_u64();
    }
  };
  for (int i = 0; i < 60'000; ++i) {
    const std::uint64_t r = rng.below(10);
    if (r < 5 || keys.empty()) {
      const std::uint64_t k = draw();
      const auto v = static_cast<Handle32>(rng.below(kNil32));
      const bool fresh = ref.find(k) == ref.end();
      ASSERT_EQ(idx.insert(k, v), fresh);
      if (fresh) {
        ref[k] = v;
        keys.push_back(k);
      }
    } else if (r < 8) {
      const std::size_t j = static_cast<std::size_t>(rng.below(keys.size()));
      const std::uint64_t k = keys[j];
      ASSERT_EQ(idx.erase(k), ref[k]);
      ref.erase(k);
      keys[j] = keys.back();
      keys.pop_back();
    } else {
      const std::uint64_t k = rng.chance(1, 2) && !keys.empty() ? keys[rng.below(keys.size())] : draw();
      auto it = ref.find(k);
      ASSERT_EQ(idx.find(k), it == ref.end() ? kNil32 : it->second);
    }
    ASSERT_EQ(idx.size(), ref.size());
    if (i % 5'000 == 0) {
      std::string err;
      ASSERT_TRUE(idx.check(&err)) << err;
    }
  }
  for (std::uint64_t k : keys) ASSERT_EQ(idx.find(k), ref[k]);
  std::string err;
  EXPECT_TRUE(idx.check(&err)) << err;
}

// ---- FlatIndex specifics -----------------------------------------------------------
TEST(FlatIndex, BackwardShiftDeletionKeepsClusterFindable) {
  // Identity hash on 16 slots (capacity 8 -> 16 slots): keys congruent mod 16
  // share a home slot and form one cluster.
  IndexConfig c;
  c.capacity = 8;
  FlatIndex<IdentityHash> idx(c);
  ASSERT_TRUE(idx.insert(3, 0));
  ASSERT_TRUE(idx.insert(19, 1));  // home 3 -> slot 4
  ASSERT_TRUE(idx.insert(35, 2));  // home 3 -> slot 5
  ASSERT_TRUE(idx.insert(4, 3));   // home 4, probes past the richer residents -> slot 6
  ASSERT_TRUE(idx.insert(15, 4));  // home 15
  ASSERT_TRUE(idx.insert(31, 5));  // home 15 -> wraps to slot 0
  std::string err;
  ASSERT_TRUE(idx.check(&err)) << err;
  EXPECT_EQ(idx.erase(3), 0u);  // head of the cluster: everyone shifts back
  EXPECT_TRUE(idx.check(&err)) << err;
  EXPECT_EQ(idx.find(19), 1u);
  EXPECT_EQ(idx.find(35), 2u);
  EXPECT_EQ(idx.find(4), 3u);
  EXPECT_EQ(idx.erase(15), 4u);  // wrapped cluster
  EXPECT_EQ(idx.find(31), 5u);
  EXPECT_TRUE(idx.check(&err)) << err;
  EXPECT_EQ(idx.size(), 4u);
}

TEST(FlatIndex, PreSizedTableDoesNotRehash) {
  IndexConfig c;
  c.capacity = 100'000;
  FlatIndex<> idx(c);
  EXPECT_GE(idx.capacity(), 100'000u);
  for (std::uint64_t k = 0; k < 100'000; ++k) ASSERT_TRUE(idx.insert(k * 4 + 92, static_cast<Handle32>(k)));
  EXPECT_EQ(idx.rehashes(), 0u);
  for (std::uint64_t k = 0; k < 100'000; ++k) ASSERT_EQ(idx.erase(k * 4 + 92), static_cast<Handle32>(k));
  EXPECT_EQ(idx.rehashes(), 0u);
}

TEST(FlatIndex, GrowsWhenFull) {
  IndexConfig c;
  c.capacity = 8;
  FlatIndex<> idx(c);
  for (std::uint64_t k = 0; k < 10'000; ++k) ASSERT_TRUE(idx.insert(k, static_cast<Handle32>(k)));
  EXPECT_GT(idx.rehashes(), 0u);
  for (std::uint64_t k = 0; k < 10'000; ++k) ASSERT_EQ(idx.find(k), static_cast<Handle32>(k));
  std::string err;
  EXPECT_TRUE(idx.check(&err)) << err;
}

// ---- PagedIndex specifics ----------------------------------------------------------
TEST(PagedIndex, PagesAreLazyAndRecycled) {
  IndexConfig c;
  c.max_direct_ref = 1u << 20;
  PagedIndex<> idx(c);
  EXPECT_EQ(idx.pages_in_use(), 0u);
  EXPECT_EQ(idx.chunks(), 0u);
  ASSERT_TRUE(idx.insert(8191, 1));  // page 0
  ASSERT_TRUE(idx.insert(8192, 2));  // page 1
  EXPECT_EQ(idx.pages_in_use(), 2u);
  EXPECT_EQ(idx.chunks(), 1u);
  EXPECT_EQ(idx.erase(8191), 1u);
  EXPECT_EQ(idx.pages_in_use(), 1u);  // page 0 released when its last entry left
  ASSERT_TRUE(idx.insert(5 * 8192 + 7, 3));  // reuses the released page
  EXPECT_EQ(idx.pages_in_use(), 2u);
  EXPECT_EQ(idx.find(5 * 8192 + 7), 3u);
  EXPECT_EQ(idx.find(5 * 8192 + 6), kNil32);
  EXPECT_EQ(idx.find(1), kNil32);  // the recycled page was zeroed for its new range
  EXPECT_EQ(idx.find(0), kNil32);
  std::string err;
  EXPECT_TRUE(idx.check(&err)) << err;
}

TEST(PagedIndex, RefsAboveMaxUseFallback) {
  IndexConfig c;
  c.max_direct_ref = 10'000;  // rounded up to 2 pages = 16384
  PagedIndex<> idx(c);
  EXPECT_EQ(idx.max_direct_ref(), 16'384u);
  ASSERT_TRUE(idx.insert(16'383, 1));
  ASSERT_TRUE(idx.insert(16'384, 2));
  ASSERT_TRUE(idx.insert(1ull << 32, 3));
  ASSERT_TRUE(idx.insert(~0ull, 4));
  EXPECT_EQ(idx.direct_size(), 1u);
  EXPECT_EQ(idx.fallback_size(), 3u);
  EXPECT_FALSE(idx.insert(~0ull, 5));
  EXPECT_EQ(idx.find(~0ull), 4u);
  EXPECT_EQ(idx.erase(1ull << 32), 3u);
  EXPECT_EQ(idx.size(), 3u);
}

TEST(PagedIndex, SteadyStateReusesChunks) {
  IndexConfig c;
  c.max_direct_ref = 1ull << 32;
  PagedIndex<> idx(c);
  // A sliding window of 20,000 live refs over 2M refs: pages are released
  // behind the window and reused ahead of it.
  std::uint64_t lo = 0, hi = 0;
  for (; hi < 20'000; ++hi) ASSERT_TRUE(idx.insert(hi, static_cast<Handle32>(hi)));
  const std::size_t chunks = idx.chunks();
  for (; hi < 2'000'000; ++hi, ++lo) {
    ASSERT_EQ(idx.erase(lo), static_cast<Handle32>(lo));
    ASSERT_TRUE(idx.insert(hi, static_cast<Handle32>(hi)));
  }
  EXPECT_EQ(idx.chunks(), chunks);
  EXPECT_LE(idx.pages_in_use(), 4u);
}

}  // namespace
}  // namespace lle::lob

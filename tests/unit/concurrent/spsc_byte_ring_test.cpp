#include "concurrent/spsc_byte_ring.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "common/prng.h"

namespace lle::conc {
namespace {

struct Storage {
  explicit Storage(std::size_t n) : words(n / 8) {}
  std::byte* data() { return reinterpret_cast<std::byte*>(words.data()); }
  std::vector<std::uint64_t> words;  // 8-byte aligned
};

void fill(std::byte* p, std::uint32_t len, std::uint8_t seed) {
  for (std::uint32_t i = 0; i < len; ++i) p[i] = static_cast<std::byte>(seed + i);
}
bool check(const std::byte* p, std::uint32_t len, std::uint8_t seed) {
  for (std::uint32_t i = 0; i < len; ++i) {
    if (p[i] != static_cast<std::byte>(seed + i)) return false;
  }
  return true;
}

bool push(SpscByteRing& q, std::uint32_t len, std::uint8_t seed) {
  std::byte* p = q.try_reserve(len);
  if (p == nullptr) return false;
  fill(p, len, seed);
  q.commit();
  return true;
}

detail::RecordHeader header_at_offset(Storage& s, std::size_t off) {
  detail::RecordHeader h{};
  std::memcpy(&h, s.data() + off, sizeof(h));
  return h;
}

TEST(SpscByteRing, EmptyAndUninitialized) {
  SpscByteRing un;
  EXPECT_EQ(un.try_reserve(0), nullptr);
  EXPECT_EQ(un.capacity(), 0u);

  Storage s(64);
  SpscByteRing q;
  q.init(s.data(), 64);
  EXPECT_EQ(q.capacity(), 64u);
  EXPECT_EQ(q.max_payload(), 24u);
  std::uint32_t len = 99;
  EXPECT_EQ(q.peek(len), nullptr);
  EXPECT_EQ(q.drain([](const std::byte*, std::uint32_t) {}, 10), 0u);
}

TEST(SpscByteRing, RoundTripVariableSizes) {
  Storage s(1024);
  SpscByteRing q;
  q.init(s.data(), 1024);
  for (std::uint32_t len = 0; len <= 64; ++len) {
    ASSERT_TRUE(push(q, len, static_cast<std::uint8_t>(len)));
    std::uint32_t got = 0;
    const std::byte* p = q.peek(got);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(got, len);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(p) % 8, 0u);
    EXPECT_TRUE(check(p, len, static_cast<std::uint8_t>(len)));
    EXPECT_EQ(q.peek(got), p);  // peek is idempotent until release
    q.release();
  }
  std::uint32_t got = 0;
  EXPECT_EQ(q.peek(got), nullptr);
}

TEST(SpscByteRing, ReserveIsInvisibleUntilCommit) {
  Storage s(64);
  SpscByteRing q;
  q.init(s.data(), 64);
  std::byte* p = q.try_reserve(8);
  ASSERT_NE(p, nullptr);
  std::uint32_t got = 0;
  EXPECT_EQ(q.peek(got), nullptr);
  fill(p, 8, 1);
  q.commit();
  ASSERT_NE(q.peek(got), nullptr);
  EXPECT_EQ(got, 8u);
}

TEST(SpscByteRing, FullThenFreed) {
  Storage s(64);
  SpscByteRing q;
  q.init(s.data(), 64);
  // 16-byte records (8 header + 8 payload): exactly four fit.
  for (int i = 0; i < 4; ++i) ASSERT_TRUE(push(q, 8, static_cast<std::uint8_t>(i)));
  EXPECT_EQ(q.used_bytes_approx(), 64u);
  EXPECT_EQ(q.try_reserve(0), nullptr);
  std::uint32_t got = 0;
  ASSERT_NE(q.peek(got), nullptr);
  q.release();
  EXPECT_TRUE(push(q, 8, 9));
  EXPECT_EQ(q.try_reserve(0), nullptr);
}

TEST(SpscByteRing, WrapWritesPadRecord) {
  Storage s(64);
  SpscByteRing q;
  q.init(s.data(), 64);
  // A 24-byte payload (32-byte record) then a 16-byte payload (24-byte record):
  // positions 0..32 and 32..56. Consume both; the producer is at 56.
  ASSERT_TRUE(push(q, 24, 1));
  ASSERT_TRUE(push(q, 16, 2));
  EXPECT_EQ(q.drain([](const std::byte*, std::uint32_t) {}, 10), 2u);
  // Next 16-byte payload needs 24 bytes; only 8 remain before the end, so a pad record
  // covers 56..64 and the record lands at offset 0.
  ASSERT_TRUE(push(q, 16, 3));
  const auto pad = header_at_offset(s, 56);
  EXPECT_EQ(pad.flags & detail::kPadFlag, detail::kPadFlag);
  EXPECT_EQ(pad.len, 0u);
  const auto rec = header_at_offset(s, 0);
  EXPECT_EQ(rec.len, 16u);
  EXPECT_EQ(rec.flags, 0u);
  std::uint32_t got = 0;
  const std::byte* p = q.peek(got);
  ASSERT_EQ(p, s.data() + 8);  // consumer skipped the pad
  EXPECT_EQ(got, 16u);
  EXPECT_TRUE(check(p, 16, 3));
  q.release();
  EXPECT_EQ(q.used_bytes_approx(), 0u);
}

TEST(SpscByteRing, PadAndRecordNeedSpaceTogether) {
  Storage s(64);
  SpscByteRing q;
  q.init(s.data(), 64);
  ASSERT_TRUE(push(q, 24, 1));  // 0..32
  ASSERT_TRUE(push(q, 16, 2));  // 32..56
  std::uint32_t got = 0;
  ASSERT_NE(q.peek(got), nullptr);
  q.release();  // r = 32
  // Wrapping record: pad 56..64 + record 64..88 needs end - r = 56 <= 64: fits.
  ASSERT_TRUE(push(q, 16, 3));
  // A further 24-byte record would end at 112: 112 - 32 > 64.
  EXPECT_EQ(q.try_reserve(16), nullptr);
  ASSERT_NE(q.peek(got), nullptr);
  EXPECT_EQ(got, 16u);
  q.release();  // r = 56
  ASSERT_TRUE(push(q, 16, 4));  // 88..112
  std::vector<std::uint8_t> seeds;
  q.drain([&](const std::byte* p, std::uint32_t len) { seeds.push_back(static_cast<std::uint8_t>(p[0])); EXPECT_EQ(len, 16u); }, 10);
  ASSERT_EQ(seeds.size(), 2u);
  EXPECT_EQ(seeds[0], 3);
  EXPECT_EQ(seeds[1], 4);
}

TEST(SpscByteRing, MaxPayloadAlwaysFitsWhenDrained) {
  // Records up to max_payload() fit into a drained ring at any wrap position.
  Storage s(128);
  SpscByteRing q;
  q.init(s.data(), 128);
  const std::uint32_t maxp = q.max_payload();
  EXPECT_EQ(maxp, 56u);
  EXPECT_EQ(q.try_reserve(maxp + 1), nullptr);
  for (std::uint32_t step = 0; step < 40; ++step) {
    ASSERT_TRUE(push(q, (step * 8) % 40, 7));  // move the write position around
    ASSERT_EQ(q.drain([](const std::byte*, std::uint32_t) {}, 4), 1u);
    ASSERT_TRUE(push(q, maxp, static_cast<std::uint8_t>(step)));
    std::uint32_t got = 0;
    const std::byte* p = q.peek(got);
    ASSERT_NE(p, nullptr);
    ASSERT_EQ(got, maxp);
    ASSERT_TRUE(check(p, maxp, static_cast<std::uint8_t>(step)));
    q.release();
  }
}

TEST(SpscByteRing, DrainBatchesAcrossWrap) {
  Storage s(256);
  SpscByteRing q;
  q.init(s.data(), 256);
  Prng rng(42);
  std::uint64_t pushed = 0, popped = 0;
  for (int round = 0; round < 2000; ++round) {
    while (true) {
      const auto len = static_cast<std::uint32_t>(rng.below(q.max_payload() + 1));
      std::byte* p = q.try_reserve(len);
      if (p == nullptr) break;
      fill(p, len, static_cast<std::uint8_t>(pushed));
      // The first 8 payload bytes (when present) carry the sequence number.
      if (len >= 8) std::memcpy(p, &pushed, 8);
      q.commit();
      ++pushed;
    }
    const std::size_t max = 1 + rng.below(5);
    const std::size_t n = q.drain(
        [&](const std::byte* p, std::uint32_t len) {
          if (len >= 8) {
            std::uint64_t seq = 0;
            std::memcpy(&seq, p, 8);
            EXPECT_EQ(seq, popped);
          } else {
            EXPECT_TRUE(check(p, len, static_cast<std::uint8_t>(popped)));
          }
          ++popped;
        },
        max);
    EXPECT_LE(n, max);
  }
  while (q.drain([&](const std::byte*, std::uint32_t) { ++popped; }, 100) != 0) {
  }
  EXPECT_EQ(pushed, popped);
  EXPECT_GT(pushed, 2000u);
}

#if !defined(__SANITIZE_THREAD__) && !(defined(__has_feature) && __has_feature(thread_sanitizer))
TEST(SpscByteRingDeathTest, RejectsBadCapacity) {
  Storage s(256);
  SpscByteRing q;
  EXPECT_DEATH(q.init(s.data(), 48), "");
  EXPECT_DEATH(q.init(s.data(), 16), "");
  EXPECT_DEATH(q.init(s.data() + 4, 64), "");
}
#endif

}  // namespace
}  // namespace lle::conc

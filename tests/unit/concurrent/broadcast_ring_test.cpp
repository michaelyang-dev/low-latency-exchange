#include "concurrent/broadcast_ring.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "common/cache.h"

namespace lle::conc {
namespace {

struct Storage {
  explicit Storage(std::size_t n) : words(n / 8) {}
  std::byte* data() { return reinterpret_cast<std::byte*>(words.data()); }
  std::vector<std::uint64_t> words;
};

template <std::size_t N>
bool push_seq(BroadcastRing<N>& q, std::uint64_t seq, std::uint32_t len = 8) {
  std::byte* p = q.try_reserve(len);
  if (p == nullptr) return false;
  std::memset(p, 0xAB, len);
  if (len >= 8) std::memcpy(p, &seq, 8);
  q.commit();
  return true;
}

template <std::size_t N>
std::vector<std::uint64_t> read_all(BroadcastRing<N>& q, std::size_t c) {
  // drain() stops at the consumer's cached write position (one batch per refresh), so
  // loop until it reports nothing new.
  std::vector<std::uint64_t> out;
  while (q.drain(
             c,
             [&](const std::byte* p, std::uint32_t len) {
               std::uint64_t v = 0;
               if (len >= 8) std::memcpy(&v, p, 8);
               out.push_back(v);
             },
             1000) != 0) {
  }
  return out;
}

TEST(BroadcastRing, EveryCursorSeesEveryRecord) {
  Storage s(256);
  BroadcastRing<3> q;
  q.init(s.data(), 256);
  for (std::uint64_t i = 0; i < 5; ++i) ASSERT_TRUE(push_seq(q, i));
  for (std::size_t c = 0; c < 3; ++c) {
    const auto got = read_all(q, c);
    ASSERT_EQ(got.size(), 5u) << "cursor " << c;
    for (std::uint64_t i = 0; i < 5; ++i) EXPECT_EQ(got[i], i);
  }
}

TEST(BroadcastRing, CursorsAreIndependent) {
  Storage s(256);
  BroadcastRing<2> q;
  q.init(s.data(), 256);
  for (std::uint64_t i = 0; i < 4; ++i) ASSERT_TRUE(push_seq(q, i));
  // Consumer 0 reads two records one at a time; consumer 1 has read nothing.
  std::uint32_t len = 0;
  for (std::uint64_t i = 0; i < 2; ++i) {
    const std::byte* p = q.peek(0, len);
    ASSERT_NE(p, nullptr);
    std::uint64_t v = 0;
    std::memcpy(&v, p, 8);
    EXPECT_EQ(v, i);
    q.release(0);
  }
  EXPECT_EQ(q.cursor_position(0), 32u);
  EXPECT_EQ(q.cursor_position(1), 0u);
  const std::byte* p1 = q.peek(1, len);
  ASSERT_NE(p1, nullptr);
  std::uint64_t v = 99;
  std::memcpy(&v, p1, 8);
  EXPECT_EQ(v, 0u);  // consumer 1 starts at the beginning
  const auto rest0 = read_all(q, 0);
  ASSERT_EQ(rest0.size(), 2u);
  EXPECT_EQ(rest0[0], 2u);
  const auto all1 = read_all(q, 1);
  ASSERT_EQ(all1.size(), 4u);
  EXPECT_EQ(q.write_position(), 64u);
}

TEST(BroadcastRing, SlowestCursorGatesProducer) {
  Storage s(64);
  BroadcastRing<2> q;
  q.init(s.data(), 64);
  for (std::uint64_t i = 0; i < 4; ++i) ASSERT_TRUE(push_seq(q, i));  // 4 x 16 bytes: full
  EXPECT_FALSE(push_seq(q, 4));
  // Consumer 0 drains everything; consumer 1 still holds all bytes.
  EXPECT_EQ(read_all(q, 0).size(), 4u);
  EXPECT_FALSE(push_seq(q, 4));
  // Consumer 1 frees one record: exactly one more fits.
  std::uint32_t len = 0;
  ASSERT_NE(q.peek(1, len), nullptr);
  q.release(1);
  EXPECT_TRUE(push_seq(q, 4));
  EXPECT_FALSE(push_seq(q, 5));
  const auto got1 = read_all(q, 1);
  ASSERT_EQ(got1.size(), 4u);
  EXPECT_EQ(got1.front(), 1u);
  EXPECT_EQ(got1.back(), 4u);
  // Consumer 0 is behind by one record (seq 4), consumer 1 is caught up.
  const auto got0 = read_all(q, 0);
  ASSERT_EQ(got0.size(), 1u);
  EXPECT_EQ(got0[0], 4u);
}

TEST(BroadcastRing, WrapWithPadIsSeenByAllCursors) {
  Storage s(64);
  BroadcastRing<2> q;
  q.init(s.data(), 64);
  ASSERT_TRUE(push_seq(q, 0, 24));  // 0..32
  ASSERT_TRUE(push_seq(q, 1, 16));  // 32..56
  EXPECT_EQ(read_all(q, 0).size(), 2u);
  EXPECT_EQ(read_all(q, 1).size(), 2u);
  ASSERT_TRUE(push_seq(q, 2, 16));  // pad 56..64, record 64..88
  for (std::size_t c = 0; c < 2; ++c) {
    std::uint32_t len = 0;
    const std::byte* p = q.peek(c, len);
    ASSERT_EQ(p, s.data() + 8);
    EXPECT_EQ(len, 16u);
    std::uint64_t v = 0;
    std::memcpy(&v, p, 8);
    EXPECT_EQ(v, 2u);
    q.release(c);
    EXPECT_EQ(q.cursor_position(c), 88u);
  }
}

TEST(BroadcastRing, LongRunWithLaggingCursor) {
  Storage s(512);
  BroadcastRing<3> q;
  q.init(s.data(), 512);
  std::uint64_t next = 0;
  std::uint64_t expect[3] = {0, 0, 0};
  for (int round = 0; round < 3000; ++round) {
    while (push_seq(q, next, static_cast<std::uint32_t>(8 + 8 * (next % 7)))) ++next;
    // Cursor 0 drains everything, cursor 1 a few records, cursor 2 only every 5th round.
    const std::size_t max[3] = {1000, 3, (round % 5 == 0) ? 1000u : 0u};
    for (std::size_t c = 0; c < 3; ++c) {
      q.drain(
          c,
          [&](const std::byte* p, std::uint32_t) {
            std::uint64_t v = 0;
            std::memcpy(&v, p, 8);
            EXPECT_EQ(v, expect[c]);
            ++expect[c];
          },
          max[c]);
    }
  }
  EXPECT_GT(next, 3000u);
  for (std::size_t c = 0; c < 3; ++c) EXPECT_LE(expect[c], next);
}

TEST(BroadcastRing, CursorsOnSeparateLines) {
  using Q = BroadcastRing<4>;
  EXPECT_EQ(alignof(Q), kFalseSharingBytes);
  // config, w_, producer, 4 cursors, 4 consumer-local lines.
  EXPECT_GE(sizeof(Q), 11 * kFalseSharingBytes);
}

}  // namespace
}  // namespace lle::conc

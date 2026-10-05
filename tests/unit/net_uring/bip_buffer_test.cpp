// BipBuffer: contiguous reservations, in-order consumption, wrap into region B.
#include "net/uring/bip_buffer.h"

#include <gtest/gtest.h>

#include <array>
#include <cstring>

namespace lle::net::uring {
namespace {

TEST(BipBuffer, ContiguousReservationsAndWrap) {
  std::array<std::byte, 100> mem{};
  BipBuffer b;
  b.reset(mem.data(), 100);
  EXPECT_EQ(b.max_reserve(), 100u);
  EXPECT_EQ(b.reserve(101), nullptr);
  std::byte* p = b.reserve(60);
  ASSERT_EQ(p, mem.data());
  b.commit(60);
  EXPECT_EQ(b.max_reserve(), 40u);
  EXPECT_EQ(b.reserve(50), nullptr) << "tail too short and nothing consumed yet";
  b.consume(30);  // [30, 60) still pending
  // Tail has 40, head has 30: a 35-byte record goes at the tail.
  ASSERT_EQ(b.reserve(35), mem.data() + 60);
  b.commit(35);
  // Tail 5, head 30: a 20-byte record wraps to region B at 0.
  ASSERT_EQ(b.reserve(20), mem.data());
  b.commit(20);
  EXPECT_EQ(b.size(), 30u + 35u + 20u);
  EXPECT_EQ(b.front().data(), mem.data() + 30);
  EXPECT_EQ(b.front().size(), 65u) << "front covers region A only";
  EXPECT_EQ(b.reserve(11), nullptr) << "B may only grow up to A's start (30 - 20 = 10)";
  ASSERT_NE(b.reserve(10), nullptr);
  b.commit(10);
  b.consume(65);  // A drained: B becomes A
  EXPECT_EQ(b.front().data(), mem.data());
  EXPECT_EQ(b.front().size(), 30u);
  b.consume(30);
  EXPECT_TRUE(b.empty());
  EXPECT_EQ(b.max_reserve(), 100u);
  EXPECT_EQ(b.reserve(100), mem.data()) << "empty buffer restarts at offset 0";
}

TEST(BipBuffer, PreservesByteOrderAcrossManyCycles) {
  std::array<std::byte, 64> mem{};
  BipBuffer b;
  b.reset(mem.data(), 64);
  std::uint8_t next_in = 0, next_out = 0;
  for (int round = 0; round < 1000; ++round) {
    const auto n = static_cast<std::uint32_t>(1 + (round * 7) % 23);
    if (std::byte* p = b.reserve(n); p != nullptr) {
      for (std::uint32_t i = 0; i < n; ++i) p[i] = static_cast<std::byte>(next_in++);
      b.commit(n);
    }
    const auto f = b.front();
    const auto take = static_cast<std::uint32_t>(f.size() < 9 ? f.size() : 9);
    for (std::uint32_t i = 0; i < take; ++i) ASSERT_EQ(f[i], static_cast<std::byte>(next_out++));
    b.consume(take);
  }
}

}  // namespace
}  // namespace lle::net::uring

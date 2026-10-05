// RecordWindow: the retransmission buffer of the replication sender.
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "common/prng.h"
#include "repl/window.h"

namespace lle::repl {
namespace {

std::vector<std::byte> rec(std::uint64_t index, std::size_t len) {
  std::vector<std::byte> r(len);
  for (std::size_t i = 0; i < len; ++i) r[i] = static_cast<std::byte>((index * 31 + i) & 0xFF);
  return r;
}

TEST(ReplWindow, PushGetPopAcrossTheWrap) {
  RecordWindow w;
  w.init(64 * 1024, 64);
  w.clear(10);
  EXPECT_TRUE(w.empty());
  EXPECT_EQ(w.last(), 9u);
  Prng rng(3);
  std::uint64_t next = 10;
  std::uint64_t first = 10;
  for (int step = 0; step < 5000; ++step) {
    const std::size_t len = 40 + 8 * static_cast<std::size_t>(rng.below(600));
    if (w.has_room(len) && rng.below(3) != 0) {
      const auto r = rec(next, len);
      ASSERT_TRUE(w.push(r));
      ++next;
    } else if (!w.empty()) {
      const std::uint64_t to = first + rng.below(next - first);
      w.pop_through(to);
      first = to + 1;
    }
    ASSERT_EQ(w.first(), first);
    ASSERT_EQ(w.last(), next - 1);
    for (std::uint64_t i = first; i < next; ++i) {
      const auto got = w.get(i);
      const auto want = rec(i, got.size());
      ASSERT_FALSE(got.empty());
      ASSERT_TRUE(std::equal(got.begin(), got.end(), want.begin()));
    }
    ASSERT_TRUE(w.get(first - 1).empty());
    ASSERT_TRUE(w.get(next).empty());
    ASSERT_LE(w.bytes_used(), w.capacity());
  }
}

TEST(ReplWindow, RefusesWhenFull) {
  RecordWindow w;
  w.init(64 * 1024, 16);
  w.clear(1);
  for (int i = 1; i <= 16; ++i) ASSERT_TRUE(w.push(rec(static_cast<std::uint64_t>(i), 40)));
  EXPECT_FALSE(w.has_room(40));
  EXPECT_FALSE(w.push(rec(17, 40)));
  w.pop_through(1);
  EXPECT_TRUE(w.push(rec(17, 40)));
  EXPECT_FALSE(w.push(rec(18, 70 * 1024)));
}

}  // namespace
}  // namespace lle::repl

// Hot path: record encoding into the thread ring, every argument kind, string
// truncation, drop-on-full accounting and registration rules. Records are read
// back with MemorySink (the in-memory consumer).
#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <thread>

#include "log/memory_sink.h"
#include "log/nlog.h"
#include "log/record.h"
#include "test_util.h"

namespace lle::nlog {
namespace {

enum class SideU8 : std::uint8_t { kBuy = 'B', kSell = 'S' };
enum class Signed16 : std::int16_t { kNeg = -5 };
enum class Big : std::uint64_t { kMax = ~std::uint64_t{0} };

class NlogHotPath : public ::testing::Test {
 protected:
  void SetUp() override { test::drain_and_discard(); }
};

TEST_F(NlogHotPath, EveryArgumentKindRoundTripsThroughTheRing) {
  ThreadScope scope({.ring_bytes = 1 << 16, .name = "kinds"});
  ASSERT_TRUE(scope.ok());
  NLOG_INFO("u {} {} {} {}", std::uint8_t{255}, std::uint16_t{65535}, std::uint32_t{4294967295u},
            std::numeric_limits<std::uint64_t>::max());
  NLOG_INFO("i {} {} {} {}", std::int8_t{-128}, std::int16_t{-32768}, std::numeric_limits<std::int32_t>::min(),
            std::numeric_limits<std::int64_t>::min());
  NLOG_INFO("misc {} {} {} {} {} {}", true, false, 'Z', SideU8::kSell, Signed16::kNeg, Big::kMax);
  NLOG_INFO("fp {} {} {} {}", -1.5e-7, 0.25f, std::numeric_limits<double>::infinity(),
            std::numeric_limits<double>::quiet_NaN());
  const std::string owned = "owned";
  const char* cstr = "cstr";
  NLOG_INFO("str {} {} {} {}", std::string_view{"view"}, cstr, owned, "literal");

  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 5u);
  const auto& r = sink.records();
  EXPECT_EQ(r[0].arg(0).u, 255u);
  EXPECT_EQ(r[0].arg(1).u, 65535u);
  EXPECT_EQ(r[0].arg(2).u, 4294967295u);
  EXPECT_EQ(r[0].arg(3).u, std::numeric_limits<std::uint64_t>::max());
  EXPECT_EQ(r[1].arg(0).i, -128);
  EXPECT_EQ(r[1].arg(1).i, -32768);
  EXPECT_EQ(r[1].arg(2).i, std::numeric_limits<std::int32_t>::min());
  EXPECT_EQ(r[1].arg(3).i, std::numeric_limits<std::int64_t>::min());
  EXPECT_EQ(r[2].arg(0).u, 1u);
  EXPECT_EQ(r[2].arg(1).u, 0u);
  EXPECT_EQ(r[2].arg(2).u, static_cast<std::uint64_t>('Z'));
  EXPECT_EQ(r[2].arg(3).kind, ArgKind::kU8);
  EXPECT_EQ(r[2].arg(3).u, static_cast<std::uint64_t>('S'));
  EXPECT_EQ(r[2].arg(4).kind, ArgKind::kI16);
  EXPECT_EQ(r[2].arg(4).i, -5);
  EXPECT_EQ(r[2].arg(5).u, ~std::uint64_t{0});
  EXPECT_EQ(r[3].arg(0).d, -1.5e-7);
  EXPECT_EQ(r[3].arg(1).d, 0.25);
  EXPECT_TRUE(std::isinf(r[3].arg(2).d));
  EXPECT_TRUE(std::isnan(r[3].arg(3).d));
  EXPECT_EQ(r[4].arg(0).s, "view");
  EXPECT_EQ(r[4].arg(1).s, "cstr");
  EXPECT_EQ(r[4].arg(2).s, "owned");
  EXPECT_EQ(r[4].arg(3).s, "literal");
  for (const MemRecord& m : r) {
    EXPECT_EQ(m.thread_id, scope.thread_id());
    EXPECT_EQ(m.flags & kFlagEventTs, 0);
    EXPECT_EQ(m.flags & kFlagTruncated, 0);
  }
  EXPECT_EQ(MemorySink::format(r[2]).substr(MemorySink::format(r[2]).find("misc")), "misc true false Z 83 -5 " +
                                                                                       std::to_string(~0ull));
}

TEST_F(NlogHotPath, StringsAreCopiedAndTruncatedAt64Bytes) {
  ThreadScope scope({.ring_bytes = 1 << 16});
  const std::string s64(64, 'a');
  const std::string s65(65, 'b');
  const std::string s100(100, 'c');
  const char unterminated[4] = {'w', 'x', 'y', 'z'};  // char array without NUL: never read past it
  const char* null_str = nullptr;
  std::string mutated = "before";
  NLOG_INFO("s {} {}", s64, std::string_view{});
  NLOG_INFO("s {}", s65.c_str());
  NLOG_INFO("s {} {}", std::string_view{s100}, unterminated);
  NLOG_INFO("s {} {}", null_str, mutated);
  mutated = "after!";  // the record holds a copy

  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 4u);
  const auto& r = sink.records();
  EXPECT_EQ(r[0].arg(0).s, s64);
  EXPECT_FALSE(r[0].arg(0).truncated);
  EXPECT_EQ(r[0].arg(1).s, "");
  EXPECT_EQ(r[0].flags & kFlagTruncated, 0);
  EXPECT_EQ(r[1].arg(0).s, std::string(64, 'b'));
  EXPECT_TRUE(r[1].arg(0).truncated);
  EXPECT_NE(r[1].flags & kFlagTruncated, 0);
  EXPECT_EQ(r[2].arg(0).s, std::string(64, 'c'));
  EXPECT_TRUE(r[2].arg(0).truncated);
  EXPECT_EQ(r[2].arg(1).s, "wxyz");
  EXPECT_FALSE(r[2].arg(1).truncated);
  EXPECT_EQ(r[3].arg(0).s, "");
  EXPECT_EQ(r[3].arg(1).s, "before");
  const std::string text = MemorySink::format(r[1]);
  EXPECT_TRUE(text.ends_with("s " + std::string(64, 'b') + "...")) << text;
}

TEST_F(NlogHotPath, EventTimestampIsStoredVerbatimAndFlagged) {
  ThreadScope scope({.ring_bytes = 1 << 16});
  NLOG_EV(123456789u, "ev {}", 1);
  NLOG_EV_AT(Level::kError, 5, "ev-error {}", 2);
  NLOG_INFO("now {}", 3);
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 3u);
  EXPECT_EQ(sink.records()[0].tsc, 123456789u);
  EXPECT_NE(sink.records()[0].flags & kFlagEventTs, 0);
  EXPECT_EQ(sink.records()[1].tsc, 5u);
  EXPECT_EQ(sink.records()[1].site->level, Level::kError);
  EXPECT_EQ(sink.records()[2].flags & kFlagEventTs, 0);
}

TEST_F(NlogHotPath, FullRingDropsAndCountsWithoutBlocking) {
  ThreadScope scope({.ring_bytes = 4096});
  ASSERT_TRUE(scope.ok());
  std::uint64_t accepted = 0;
  while (thread_drops() == 0) {
    NLOG_INFO("drop-test {}", accepted);
    if (thread_drops() == 0) ++accepted;
    ASSERT_LT(accepted, 4096u) << "a 4 KiB ring cannot hold this many records";
  }
  EXPECT_GT(accepted, 0u);
  for (int i = 0; i < 37; ++i) NLOG_INFO("drop-test {}", std::uint64_t{999});
  EXPECT_EQ(thread_drops(), 38u);

  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  EXPECT_EQ(sink.drain(), accepted);
  EXPECT_EQ(sink.drops(scope.thread_id()), 38u);
  for (std::uint64_t i = 0; i < accepted; ++i) EXPECT_EQ(sink.records()[i].arg(0).u, i);
  // Space is back after the drain.
  NLOG_INFO("drop-test {}", std::uint64_t{7});
  EXPECT_EQ(thread_drops(), 38u);
  EXPECT_EQ(sink.drain(), 1u);
}

TEST_F(NlogHotPath, BlockPolicyWithoutConsumerFallsBackToDropping) {
  ThreadScope scope({.ring_bytes = 4096, .policy = FullPolicy::kBlock});
  for (int i = 0; i < 1000; ++i) NLOG_INFO("block-no-consumer {}", i);  // must not hang
  EXPECT_GT(thread_drops(), 0u);
}

TEST_F(NlogHotPath, UnregisteredThreadsAreDroppedAndCounted) {
  const std::uint64_t before = unregistered_drops();
  std::thread t([] {
    EXPECT_EQ(current_thread_id(), 0u);
    NLOG_INFO("unregistered {}", 1);
    NLOG_WARN("unregistered {}", 2);
  });
  t.join();
  EXPECT_EQ(unregistered_drops() - before, 2u);
}

TEST_F(NlogHotPath, RegistrationRules) {
  EXPECT_EQ(register_thread({.ring_bytes = 1000}).error(), RegisterError::kBadRingSize);
  EXPECT_EQ(register_thread({.ring_bytes = 2048}).error(), RegisterError::kBadRingSize);
  const auto id = register_thread({.ring_bytes = 8192});
  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(current_thread_id(), *id);
  EXPECT_EQ(register_thread().error(), RegisterError::kAlreadyRegistered);
  unregister_thread();
  EXPECT_EQ(current_thread_id(), 0u);
  const auto id2 = register_thread({.ring_bytes = 8192});
  ASSERT_TRUE(id2.has_value());
  EXPECT_GT(*id2, *id) << "thread IDs are never reused";
  unregister_thread();
}

TEST_F(NlogHotPath, ExitingThreadIsUnregisteredAndItsRingDrainedThenFreed) {
  std::uint32_t tid = 0;
  std::thread t([&tid] {
    tid = *register_thread({.ring_bytes = 8192});
    NLOG_INFO("exiting-thread {}", 42);
  });  // no explicit unregister: the TLS exit guard does it
  t.join();
  MemorySink sink;
  ASSERT_TRUE(sink.attach());
  ASSERT_EQ(sink.drain(), 1u);
  EXPECT_EQ(sink.records()[0].thread_id, tid);
  EXPECT_EQ(sink.records()[0].arg(0).i, 42);
  EXPECT_EQ(sink.drain(), 0u);
}

TEST_F(NlogHotPath, OnlyOneConsumerAtATime) {
  MemorySink a;
  MemorySink b;
  ASSERT_TRUE(a.attach());
  EXPECT_FALSE(b.attach());
  a.detach();
  EXPECT_TRUE(b.attach());
}

TEST_F(NlogHotPath, MemorySinkIsDeterministic) {
  auto run = [] {
    ThreadScope scope({.ring_bytes = 1 << 16});
    for (std::uint64_t i = 0; i < 50; ++i) NLOG_EV(1000 + i, "det {} {} {}", i, static_cast<double>(i) / 4, "s");
    MemorySink sink;
    EXPECT_TRUE(sink.attach());
    sink.drain();
    // Thread IDs differ between the two runs (never reused), everything else must not.
    std::string text;
    for (const MemRecord& r : sink.records()) {
      const std::string line = MemorySink::format(r);
      text += line.substr(0, line.find(" t")) + line.substr(line.find(' ', line.find(" t") + 1)) + "\n";
    }
    return std::pair{text, sink.hash(false)};
  };
  const auto [text1, hash1] = run();
  const auto [text2, hash2] = run();
  EXPECT_EQ(hash1, hash2);
  EXPECT_EQ(text1, text2);
  const std::string first_line = text1.substr(0, text1.find('\n'));
  EXPECT_TRUE(first_line.starts_with("1000 INFO  hot_path_test.cpp:")) << first_line;
  EXPECT_TRUE(first_line.ends_with(" det 0 0 s")) << first_line;
}

}  // namespace
}  // namespace lle::nlog

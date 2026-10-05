// LineComparator (T10 HA line consistency): equal streams in different packetizations
// compare clean; any byte, length or session difference is a mismatch; loss on one line
// is unmatched, not a mismatch.
#include "proto/moldudp64/line_comparator.h"

#include <gtest/gtest.h>

#include "mold_test_util.h"

namespace lle::mold {
namespace {

using test::Bytes;
using test::control_packet;
using test::data_packet;

// Feeds [first, last) to `line` in packets of `per` messages.
void feed(LineComparator& c, int line, SeqNo first, SeqNo last, std::uint16_t per, const Session& s = test::kSession) {
  for (SeqNo q = first; q < last; q += per) {
    const auto n = static_cast<std::uint16_t>(std::min<SeqNo>(per, last - q));
    c.on_packet(line, data_packet(q, n, s));
  }
}

TEST(LineComparator, SameStreamDifferentPacketizationIsConsistent) {
  LineComparator c(8192);  // larger than the lines' skew (all of A before B)
  feed(c, 0, 1, 5001, 7);
  feed(c, 1, 1, 5001, 13);
  c.on_packet(0, control_packet(5001, true));
  c.on_packet(1, control_packet(5001, true));
  c.finish();
  const auto& st = c.stats();
  EXPECT_TRUE(c.consistent());
  EXPECT_EQ(st.compared, 5000u);
  EXPECT_EQ(st.unmatched[0] + st.unmatched[1], 0u);
  EXPECT_TRUE(st.ended[0] && st.ended[1]);
}

TEST(LineComparator, InterleavedLinesAreCompared) {
  LineComparator c(64);
  for (SeqNo q = 1; q < 2001; q += 5) {
    c.on_packet(0, data_packet(q, 5));
    c.on_packet(1, data_packet(q, 5));
  }
  c.finish();
  EXPECT_TRUE(c.consistent());
  EXPECT_EQ(c.stats().compared, 2000u);
}

TEST(LineComparator, ChangedByteIsAMismatch) {
  LineComparator c(1024);
  feed(c, 0, 1, 101, 10);
  for (SeqNo q = 1; q < 101; q += 10) {
    Bytes p = data_packet(q, 10);
    if (q == 41) p[kHeaderLen + kBlockPrefixLen] ^= std::byte{1};  // first byte of message 41
    c.on_packet(1, p);
  }
  EXPECT_FALSE(c.consistent());
  EXPECT_EQ(c.stats().mismatches, 1u);
  EXPECT_EQ(c.stats().first_mismatch, 41u);
}

TEST(LineComparator, DifferentLengthIsAMismatch) {
  LineComparator c(16);
  Bytes a(256), b(256);
  PacketBuilder pa(a, test::kSession, 1), pb(b, test::kSession, 1);
  const std::byte m[3] = {std::byte{1}, std::byte{2}, std::byte{3}};
  pa.add(std::span<const std::byte>(m, 3));
  pb.add(std::span<const std::byte>(m, 2));  // the same prefix, one byte short
  const auto ka = pa.finish();
  const auto kb = pb.finish();
  c.on_packet(0, Bytes(ka.begin(), ka.end()));
  c.on_packet(1, Bytes(kb.begin(), kb.end()));
  EXPECT_EQ(c.stats().mismatches, 1u);
}

TEST(LineComparator, LossOnOneLineIsUnmatchedNotAMismatch) {
  LineComparator c(2048);
  feed(c, 0, 1, 1001, 10);
  for (SeqNo q = 1; q < 1001; q += 10)
    if (q != 501) c.on_packet(1, data_packet(q, 10));  // line B lost one packet
  c.finish();
  const auto& st = c.stats();
  EXPECT_TRUE(c.consistent());
  EXPECT_EQ(st.compared, 990u);
  EXPECT_EQ(st.unmatched[0], 10u);
  EXPECT_EQ(st.unmatched[1], 0u);
}

TEST(LineComparator, DuplicatesMustRepeatTheSameBytes) {
  LineComparator c(1024);
  feed(c, 0, 1, 51, 10);
  feed(c, 1, 1, 51, 10);
  c.on_packet(1, data_packet(21, 10));  // a re-request response, identical
  EXPECT_TRUE(c.consistent());
  EXPECT_EQ(c.stats().duplicates[1], 10u);
  Bytes p = data_packet(21, 10);
  p[kHeaderLen + kBlockPrefixLen] ^= std::byte{0x80};
  c.on_packet(0, p);  // a repeat with different bytes
  EXPECT_FALSE(c.consistent());
  EXPECT_EQ(c.stats().first_mismatch, 21u);
}

TEST(LineComparator, SessionMismatchAndMalformedPacketsAreCounted) {
  LineComparator c(64);
  c.on_packet(0, data_packet(1, 5));
  c.on_packet(1, data_packet(1, 5, Session("OTHER00001")));
  EXPECT_EQ(c.stats().session_mismatches, 1u);
  EXPECT_FALSE(c.consistent());
  Bytes bad = data_packet(6, 3);
  bad.pop_back();  // truncated block
  c.on_packet(0, bad);
  EXPECT_EQ(c.stats().malformed[0], 1u);
}

TEST(LineComparator, DifferentEndOfSessionIsAMismatch) {
  LineComparator c(64);
  c.on_packet(0, control_packet(101, true));
  c.on_packet(1, control_packet(100, true));
  EXPECT_EQ(c.stats().mismatches, 1u);
}

TEST(LineComparator, MessagesOlderThanTheWindowAreStale) {
  LineComparator c(32);
  feed(c, 0, 1, 201, 10);
  c.on_packet(1, data_packet(1, 10));  // far behind line A
  EXPECT_EQ(c.stats().stale[1], 10u);
  EXPECT_TRUE(c.consistent());
}

}  // namespace
}  // namespace lle::mold

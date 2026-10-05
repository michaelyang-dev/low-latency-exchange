#include <gtest/gtest.h>

#include <vector>

#include "mold_test_util.h"
#include "proto/moldudp64/depacketizer.h"
#include "proto/moldudp64/packetizer.h"

namespace lle::mold {
namespace {

using test::Bytes;

struct Capture {
  std::vector<Bytes> packets;
  void operator()(std::span<const std::byte> p) { packets.emplace_back(p.begin(), p.end()); }
  [[nodiscard]] PacketHeader header(std::size_t i) const { return decode_header(packets.at(i).data()); }
};

PacketizerConfig cfg(std::size_t max_packet = 100) {
  PacketizerConfig c;
  c.session = test::kSession;
  c.max_packet = max_packet;
  c.heartbeat_interval = 1'000;
  c.end_of_session_linger = 5'000;
  return c;
}

TEST(Packetizer, BatchesUntilTheNextMessageDoesNotFit) {
  Packetizer p(cfg(100));  // 80 payload bytes after the header
  Capture out;
  const Bytes m30(30);  // 32 bytes with the length prefix: two fit, the third does not
  EXPECT_EQ(p.append(m30, 10, std::ref(out)), Packetizer::AppendResult::Ok);
  EXPECT_EQ(p.append(m30, 11, std::ref(out)), Packetizer::AppendResult::Ok);
  EXPECT_TRUE(out.packets.empty());
  EXPECT_EQ(p.pending_messages(), 2);
  EXPECT_EQ(p.append(m30, 12, std::ref(out)), Packetizer::AppendResult::Ok);
  ASSERT_EQ(out.packets.size(), 1u);
  EXPECT_EQ(out.packets[0].size(), 20u + 64u);
  EXPECT_EQ(out.header(0), (PacketHeader{test::kSession, 1, 2}));
  EXPECT_EQ(p.next_expected(), 3u);
  EXPECT_EQ(p.next_seq(), 4u);
  // Input queue empty: flush now, no timer.
  EXPECT_TRUE(p.flush(13, std::ref(out)));
  EXPECT_FALSE(p.flush(13, std::ref(out)));
  ASSERT_EQ(out.packets.size(), 2u);
  EXPECT_EQ(out.header(1), (PacketHeader{test::kSession, 3, 1}));
  EXPECT_EQ(p.stats().data_packets, 2u);
  EXPECT_EQ(p.stats().messages, 3u);
}

TEST(Packetizer, ExactFitAndTooLarge) {
  Packetizer p(cfg(100));
  Capture out;
  const Bytes m78(78);  // 20 + 2 + 78 = 100: exactly one per packet
  EXPECT_EQ(p.append(m78, 0, std::ref(out)), Packetizer::AppendResult::Ok);
  EXPECT_EQ(p.append(m78, 0, std::ref(out)), Packetizer::AppendResult::Ok);
  ASSERT_EQ(out.packets.size(), 1u);
  EXPECT_EQ(out.packets[0].size(), 100u);
  const Bytes m79(79);
  EXPECT_EQ(p.append(m79, 0, std::ref(out)), Packetizer::AppendResult::TooLarge);
  EXPECT_EQ(p.stats().rejected_too_large, 1u);
  EXPECT_EQ(p.next_seq(), 3u);  // a refused message takes no sequence number
}

TEST(Packetizer, HeartbeatAfterIdleCarriesNextExpected) {
  Packetizer p(cfg());
  Capture out;
  const Bytes m(5);
  p.append(m, 0, std::ref(out));
  p.flush(100, std::ref(out));
  EXPECT_EQ(p.next_deadline(), 1'100);
  EXPECT_FALSE(p.on_timer(1'099, std::ref(out)));
  EXPECT_TRUE(p.on_timer(1'100, std::ref(out)));
  ASSERT_EQ(out.packets.size(), 2u);
  EXPECT_EQ(out.header(1), (PacketHeader{test::kSession, 2, kHeartbeatCount}));
  EXPECT_EQ(out.packets[1].size(), kHeaderLen);
  EXPECT_EQ(p.next_deadline(), 2'100);
  EXPECT_EQ(p.stats().heartbeats, 1u);
  // A never-flushed open packet goes out at the heartbeat deadline instead of a heartbeat.
  p.append(m, 1'500, std::ref(out));
  EXPECT_EQ(p.next_deadline(), 2'100);
  EXPECT_FALSE(p.on_timer(1'600, std::ref(out)));
  EXPECT_TRUE(p.on_timer(2'100, std::ref(out)));
  ASSERT_EQ(out.packets.size(), 3u);
  EXPECT_EQ(out.header(2), (PacketHeader{test::kSession, 2, 1}));
  EXPECT_EQ(p.stats().heartbeats, 1u);
}

TEST(Packetizer, EndOfSessionRepeatsThenStops) {
  Packetizer p(cfg());
  Capture out;
  const Bytes m(5);
  p.append(m, 0, std::ref(out));
  p.end_session(10, std::ref(out));
  ASSERT_EQ(out.packets.size(), 2u);  // flushed data, then the first EOS
  EXPECT_EQ(out.header(0).count, 1);
  EXPECT_EQ(out.header(1), (PacketHeader{test::kSession, 2, kEndOfSessionCount}));
  EXPECT_EQ(p.append(m, 20, std::ref(out)), Packetizer::AppendResult::SessionEnded);
  Nanos t = 10;
  int repeats = 0;
  while (!p.done()) {
    t = p.next_deadline();
    if (p.on_timer(t, std::ref(out))) ++repeats;
  }
  // EOS at 10, then every 1 us until the 5 us linger expires: 1010 .. 4010.
  EXPECT_EQ(repeats, 4);
  EXPECT_EQ(p.stats().end_of_session_packets, 5u);
  for (std::size_t i = 1; i < out.packets.size(); ++i) EXPECT_TRUE(out.header(i).is_end_of_session());
  EXPECT_EQ(p.next_deadline(), Packetizer::kNever);
}

TEST(Packetizer, OutputParsesAndDepacketizesToTheInput) {
  Packetizer p(cfg(1472));
  Capture out;
  for (SeqNo s = 1; s <= 1000; ++s) p.append(test::msg_for(s), static_cast<Nanos>(s), std::ref(out));
  p.end_session(2000, std::ref(out));
  struct Sink {
    std::vector<std::pair<SeqNo, Bytes>> got;
    SeqNo end = 0;
    void on_message(SeqNo s, std::span<const std::byte> m) { got.emplace_back(s, Bytes(m.begin(), m.end())); }
    void on_gap(SeqNo, SeqNo) { ADD_FAILURE() << "gap"; }
    void on_end_of_session(SeqNo e) { end = e; }
  } sink;
  Depacketizer d(DepacketizerConfig{});
  for (const auto& pkt : out.packets) {
    ASSERT_TRUE(PacketView::parse(pkt).has_value());
    ASSERT_LE(pkt.size(), 1472u);
    d.on_packet(pkt, sink);
  }
  ASSERT_EQ(sink.got.size(), 1000u);
  for (SeqNo s = 1; s <= 1000; ++s) {
    EXPECT_EQ(sink.got[s - 1].first, s);
    EXPECT_EQ(sink.got[s - 1].second, test::msg_for(s));
  }
  EXPECT_EQ(sink.end, 1001u);
  EXPECT_TRUE(d.session_known());
  EXPECT_EQ(d.session(), test::kSession);
}

struct DSink {
  std::vector<SeqNo> got;
  std::vector<std::pair<SeqNo, SeqNo>> gaps;
  std::vector<SeqNo> ends;
  void on_message(SeqNo s, std::span<const std::byte>) { got.push_back(s); }
  void on_gap(SeqNo a, SeqNo b) { gaps.emplace_back(a, b); }
  void on_end_of_session(SeqNo e) { ends.push_back(e); }
};

TEST(Depacketizer, DuplicateOverlapGapAndEnd) {
  Depacketizer d(DepacketizerConfig{test::kSession, 1, GapPolicy::Drop});
  DSink s;
  using R = Depacketizer::Result;
  EXPECT_EQ(d.on_packet(test::data_packet(1, 3), s), R::Delivered);
  EXPECT_EQ(d.on_packet(test::data_packet(1, 3), s), R::Duplicate);
  EXPECT_EQ(d.on_packet(test::data_packet(2, 4), s), R::Delivered);  // partial overlap: delivers 4, 5
  EXPECT_EQ(d.on_packet(test::data_packet(8, 2), s), R::Gap);        // dropped; caller re-requests [6, 8)
  EXPECT_EQ(d.on_packet(test::data_packet(6, 4), s), R::Delivered);  // the re-requested range
  EXPECT_EQ(d.on_packet(test::control_packet(10, false), s), R::Heartbeat);
  EXPECT_EQ(d.on_packet(test::control_packet(12, false), s), R::Gap);  // tail gap
  EXPECT_EQ(d.on_packet(test::data_packet(10, 2), s), R::Delivered);
  EXPECT_EQ(d.on_packet(test::control_packet(12, true), s), R::EndOfSession);
  EXPECT_EQ(d.on_packet(test::control_packet(12, true), s), R::EndOfSession);
  EXPECT_EQ(s.got, (std::vector<SeqNo>{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}));
  EXPECT_EQ(s.gaps, (std::vector<std::pair<SeqNo, SeqNo>>{{6, 8}, {10, 12}}));
  EXPECT_EQ(s.ends, (std::vector<SeqNo>{12}));
  EXPECT_EQ(d.stats().duplicates, 1u);
  EXPECT_EQ(d.stats().partial_overlaps, 1u);
  EXPECT_EQ(d.on_packet(test::data_packet(1, 1, Session("OTHER")), s), R::WrongSession);
  Bytes bad = test::data_packet(12, 1);
  bad.pop_back();
  EXPECT_EQ(d.on_packet(bad, s), R::Malformed);
}

TEST(Depacketizer, SkipPolicyJumpsGaps) {
  Depacketizer d(DepacketizerConfig{Session(), 1, GapPolicy::Skip});
  DSink s;
  d.on_packet(test::data_packet(1, 2), s);
  d.on_packet(test::data_packet(5, 2), s);
  d.on_packet(test::control_packet(9, false), s);
  EXPECT_EQ(s.got, (std::vector<SeqNo>{1, 2, 5, 6}));
  EXPECT_EQ(d.next_expected(), 9u);
  EXPECT_EQ(d.stats().skipped_messages, 4u);
}

}  // namespace
}  // namespace lle::mold

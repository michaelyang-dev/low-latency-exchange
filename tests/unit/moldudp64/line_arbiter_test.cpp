// LineArbiter (03-protocols §7): duplicate drop, partial overlap with
// different packet boundaries, both-line loss recovered by re-request, server
// failover, snapshot fallback, heartbeat tail-gap detection, end of session,
// plus seeded end-to-end scenarios checked by the exactly-once oracle.
#include <gtest/gtest.h>

#include <vector>

#include "mold_test_util.h"
#include "proto/moldudp64/arbiter_scenario.h"
#include "proto/moldudp64/line_arbiter.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/rerequest_server.h"

namespace lle::mold {
namespace {

using test::ArbiterSink;
using test::Bytes;
using test::control_packet;
using test::data_packet;

constexpr Nanos kGap = 50'000;
constexpr Nanos kReqTimeout = 1'000'000;

LineArbiterConfig small_cfg() {
  LineArbiterConfig c;
  c.session = test::kSession;
  c.reorder_capacity = 1024;
  c.gap_timeout = kGap;
  c.request_timeout = kReqTimeout;
  c.snapshot_gap_messages = 500;
  return c;
}

class LineArbiterTest : public ::testing::Test {
 protected:
  LineArbiterTest() : store_(1 << 16, 1 << 22) {
    for (SeqNo s = 1; s <= 50'000; ++s) store_.append(test::msg_for(s));
    RerequestConfig rc;
    rc.session = test::kSession;
    rc.max_packet = 1472;
    rc.bucket_capacity = 1'000'000;
    server_.emplace(rc, store_);
  }

  // Answers the sink's re-requests [from_index, end) through the real server
  // and feeds the replies back as `reply_src` (default: the server asked).
  void answer_requests(LineArbiter& arb, ArbiterSink& sink, std::size_t from_index, Nanos now) {
    const std::size_t end = sink.requests.size();
    for (std::size_t i = from_index; i < end; ++i) {
      const auto& [srv, req] = sink.requests[i];
      Bytes b(kRequestLen);
      encode_request(b, req);
      server_->on_request(b, env::Endpoint{1, 1}, now, [&](const env::Endpoint&, std::span<const std::byte> pkt) {
        arb.on_packet(reply_source(srv), pkt, now, sink);
      });
    }
  }

  MessageRing store_;
  std::optional<RerequestServer<MessageRing>> server_;
};

TEST_F(LineArbiterTest, InOrderDeliveryAndDuplicateDrop) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 3), 100, sink);
  arb.on_packet(Source::LineB, data_packet(1, 3), 350, sink);  // duplicate on B, 250 ns later
  arb.on_packet(Source::LineA, data_packet(4, 3), 400, sink);
  arb.on_packet(Source::LineB, data_packet(4, 3), 900, sink);
  EXPECT_TRUE(sink.delivered_range(1, 7));
  const auto& m = arb.metrics();
  EXPECT_EQ(m.duplicate_packets[1], 2u);
  EXPECT_EQ(m.first_arrivals[0], 6u);
  EXPECT_EQ(m.first_arrival_ppm(Source::LineA), 1'000'000u);
  EXPECT_EQ(m.skew_ns.count(), 2u);
  EXPECT_EQ(m.skew_ns.min(), 250u);
  EXPECT_EQ(m.skew_ns.max(), 500u);
  EXPECT_EQ(m.skew_a_ahead, 2u);
  EXPECT_EQ(m.gaps_opened, 0u);
  EXPECT_TRUE(sink.requests.empty());
  EXPECT_EQ(arb.next_deadline(), LineArbiter::kNever);
}

TEST_F(LineArbiterTest, PartialOverlapWithDifferentPacketBoundaries) {
  // A packetizes 1-5, 6-10, 11-15; B packetizes 1-3, 4-8, 9-15. A loses 6-10.
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  arb.on_packet(Source::LineB, data_packet(1, 3), 10, sink);
  arb.on_packet(Source::LineA, data_packet(11, 5), 20, sink);  // gap [6, 11): parked
  EXPECT_EQ(sink.delivered.size(), 5u);
  EXPECT_EQ(arb.buffered(), 5u);
  EXPECT_TRUE(arb.in_gap());
  EXPECT_EQ(arb.next_deadline(), 20 + kGap);
  arb.on_packet(Source::LineB, data_packet(4, 5), 30, sink);  // skips 4, 5; delivers 6-8
  EXPECT_EQ(sink.delivered.size(), 8u);
  arb.on_packet(Source::LineB, data_packet(9, 7), 40, sink);  // delivers 9, 10, then 11-15 from the buffer
  EXPECT_TRUE(sink.delivered_range(1, 16));
  const auto& m = arb.metrics();
  EXPECT_EQ(m.partial_overlaps[1], 1u);  // B 4-8 (B 1-3 is a full duplicate)
  EXPECT_EQ(m.gaps_opened, 1u);
  EXPECT_EQ(m.gaps_filled_by_line[1], 1u);
  EXPECT_EQ(m.first_arrivals[0], 10u);  // 1-5 and 11-15
  EXPECT_EQ(m.first_arrivals[1], 5u);   // 6-10
  EXPECT_EQ(m.reorder_high_water, 5u);
  EXPECT_FALSE(arb.in_gap());
  EXPECT_EQ(arb.buffered(), 0u);
  arb.on_timer(20 + kGap, sink);
  EXPECT_TRUE(sink.requests.empty());  // the other line filled the gap before the timer
}

TEST_F(LineArbiterTest, BothLineLossRecoveredByRerequest) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  arb.on_packet(Source::LineB, data_packet(1, 5), 5, sink);
  arb.on_packet(Source::LineA, data_packet(11, 5), 100, sink);  // 6-10 lost on both lines
  arb.on_packet(Source::LineB, data_packet(11, 5), 120, sink);
  arb.on_timer(100 + kGap - 1, sink);
  EXPECT_TRUE(sink.requests.empty());
  arb.on_timer(100 + kGap, sink);
  ASSERT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(sink.requests[0].first, Server::A);
  EXPECT_EQ(sink.requests[0].second, (RequestPacket{test::kSession, 6, 5}));
  EXPECT_EQ(arb.outstanding_requests(), 1u);
  answer_requests(arb, sink, 0, 100 + kGap + 30'000);
  EXPECT_TRUE(sink.delivered_range(1, 16));
  const auto& m = arb.metrics();
  EXPECT_EQ(m.gaps_filled_by_rerequest, 1u);
  EXPECT_EQ(m.recovered_messages, 5u);
  EXPECT_EQ(m.first_arrivals[2], 5u);
  EXPECT_EQ(m.requests_sent[0], 1u);
  EXPECT_EQ(m.rtt_ns.count(), 1u);
  EXPECT_EQ(m.rtt_ns.max(), 30'000u);
  EXPECT_EQ(arb.outstanding_requests(), 0u);
  EXPECT_EQ(arb.suggested_request_timeout(7), 1'000'000);  // 2 x 32767 rounds up to the 1 ms floor
}

TEST_F(LineArbiterTest, ChunkedRequestsWithBoundedOutstanding) {
  LineArbiterConfig c = small_cfg();
  c.request_max_count = 40;
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 1), 0, sink);
  arb.on_packet(Source::LineA, data_packet(302, 1), 10, sink);  // 300 missing: 2..301
  arb.on_timer(10 + kGap, sink);
  ASSERT_EQ(sink.requests.size(), 4u);  // at most 4 outstanding
  for (std::size_t i = 0; i < 4; ++i) EXPECT_EQ(sink.requests[i].second, (RequestPacket{test::kSession, 2 + 40 * i, 40}));
  // Replies come back one packet each; freed slots request the remaining ranges.
  std::size_t answered = 0;
  Nanos t = 10 + kGap;
  while (answered < sink.requests.size() && sink.delivered.size() < 302) {
    t += 1'000;
    const std::size_t upto = sink.requests.size();
    answer_requests(arb, sink, answered, t);
    answered = upto;
    arb.on_timer(t, sink);
  }
  EXPECT_TRUE(sink.delivered_range(1, 303));
  EXPECT_GE(sink.requests.size(), 8u);
  for (const auto& [srv, r] : sink.requests) {
    EXPECT_EQ(srv, Server::A);
    EXPECT_LE(r.count, 40);
  }
  EXPECT_EQ(arb.metrics().gaps_filled_by_rerequest, 1u);
}

TEST_F(LineArbiterTest, ServerFailoverAfterTimeout) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  arb.on_packet(Source::LineA, data_packet(9, 2), 10, sink);
  arb.on_timer(10 + kGap, sink);
  ASSERT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(sink.requests[0].first, Server::A);
  // Server A never answers.
  arb.on_timer(10 + kGap + kReqTimeout - 1, sink);
  EXPECT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(arb.next_deadline(), 10 + kGap + kReqTimeout);
  arb.on_timer(10 + kGap + kReqTimeout, sink);
  ASSERT_EQ(sink.requests.size(), 2u);
  EXPECT_EQ(sink.requests[1].first, Server::B);
  EXPECT_EQ(sink.requests[1].second, (RequestPacket{test::kSession, 6, 3}));
  answer_requests(arb, sink, 1, 10 + kGap + kReqTimeout + 20'000);
  EXPECT_TRUE(sink.delivered_range(1, 11));
  const auto& m = arb.metrics();
  EXPECT_EQ(m.request_timeouts[0], 1u);
  EXPECT_EQ(m.failovers, 1u);
  EXPECT_EQ(m.requests_sent[1], 1u);
  EXPECT_EQ(m.first_arrivals[3], 3u);
  EXPECT_EQ(m.gaps_filled_by_rerequest, 1u);
  EXPECT_TRUE(sink.snapshots.empty());
}

TEST_F(LineArbiterTest, OldServerFailureExpiresWithinOneGapEpisode) {
  LineArbiterConfig c = small_cfg();
  c.server_fail_hold = 3 * kReqTimeout;
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  arb.on_packet(Source::LineA, data_packet(9, 2), 10, sink);  // hole [6, 9)
  const Nanos t1 = 10 + kGap;
  arb.on_timer(t1, sink);
  ASSERT_EQ(sink.requests.size(), 1u);  // R1 to A
  arb.on_timer(t1 + kReqTimeout, sink);  // A times out: R1 fails over to B
  ASSERT_EQ(sink.requests.size(), 2u);
  EXPECT_EQ(sink.requests[1].first, Server::B);
  const Nanos t2 = t1 + kReqTimeout + 100;
  arb.on_packet(Source::LineA, data_packet(15, 2), t2, sink);  // a second hole [11, 15)
  answer_requests(arb, sink, 1, t2 + 10);  // B answers R1: the episode goes on (hole 2)
  ASSERT_EQ(sink.requests.size(), 2u);
  arb.on_timer(t2 + kGap, sink);  // R2 goes to B: A failed recently. Its reply is lost.
  ASSERT_EQ(sink.requests.size(), 3u);
  EXPECT_EQ(sink.requests[2].first, Server::B);
  EXPECT_EQ(sink.requests[2].second, (RequestPacket{test::kSession, 11, 4}));
  // R2 times out on B long after A's single timeout: A is no longer failed, so R2
  // fails over to A instead of escalating to a snapshot.
  const Nanos t3 = t1 + 5 * kReqTimeout;
  arb.on_timer(t3, sink);
  EXPECT_TRUE(sink.snapshots.empty());
  ASSERT_EQ(sink.requests.size(), 4u);
  EXPECT_EQ(sink.requests[3].first, Server::A);
  answer_requests(arb, sink, 3, t3 + 10);
  EXPECT_TRUE(sink.delivered_range(1, 17));
  EXPECT_TRUE(sink.snapshots.empty());
}

TEST_F(LineArbiterTest, RequestScanIsBounded) {
  LineArbiterConfig c = small_cfg();
  c.reorder_capacity = 1 << 16;
  c.snapshot_gap_messages = 0;
  c.request_scan_budget = 1000;
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 1), 0, sink);
  // A hole at 2, 5,000 buffered messages, then a hole at 5,003 and more buffered.
  for (SeqNo q = 3; q < 5'003; q += 100) arb.on_packet(Source::LineA, data_packet(q, 100), 1, sink);
  arb.on_packet(Source::LineA, data_packet(5'004, 10), 2, sink);
  arb.on_timer(2 + kGap, sink);
  // Only the hole within the scan budget is requested now.
  ASSERT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(sink.requests[0].second, (RequestPacket{test::kSession, 2, 1}));
  answer_requests(arb, sink, 0, 2 + kGap + 10);  // next_ advances to 5,003
  ASSERT_EQ(sink.requests.size(), 2u);           // the far hole is requested once in budget
  EXPECT_EQ(sink.requests[1].second, (RequestPacket{test::kSession, 5'003, 1}));
  answer_requests(arb, sink, 1, 2 + kGap + 20);
  EXPECT_TRUE(sink.delivered_range(1, 5'014));
}

TEST_F(LineArbiterTest, BothServersFailTriggersSnapshotThenSplice) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  arb.on_packet(Source::LineA, data_packet(9, 2), 10, sink);
  arb.on_timer(10 + kGap, sink);
  arb.on_timer(10 + kGap + kReqTimeout, sink);      // A timed out: retry on B
  arb.on_timer(10 + kGap + 2 * kReqTimeout, sink);  // B timed out too
  ASSERT_EQ(sink.snapshots.size(), 1u);
  EXPECT_EQ(sink.snapshots[0], std::make_pair(SeqNo{6}, SeqNo{11}));
  EXPECT_EQ(arb.state(), LineArbiter::State::AwaitingSnapshot);
  EXPECT_EQ(arb.next_deadline(), LineArbiter::kNever);
  // Live stream keeps flowing and is buffered meanwhile.
  arb.on_packet(Source::LineB, data_packet(11, 10), 3'000'000, sink);
  EXPECT_EQ(sink.delivered.size(), 5u);
  // The snapshot covers everything below 13 (GLIMPSE G = S(P)+1 = 13).
  arb.resume_from_snapshot(13, 3'100'000, sink);
  EXPECT_EQ(arb.state(), LineArbiter::State::Live);
  EXPECT_TRUE(sink.delivered_range(13, 21, 5));
  EXPECT_EQ(arb.metrics().gaps_filled_by_snapshot, 1u);
  EXPECT_EQ(arb.metrics().snapshot_signals, 1u);
  EXPECT_FALSE(arb.in_gap());
}

TEST_F(LineArbiterTest, LargeGapTriggersSnapshotImmediately) {
  LineArbiter arb(small_cfg());  // snapshot above 500 missing messages
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 2), 0, sink);
  arb.on_packet(Source::LineA, data_packet(600, 3), 10, sink);  // 597 missing
  ASSERT_EQ(sink.snapshots.size(), 1u);
  EXPECT_TRUE(sink.requests.empty());
  arb.on_packet(Source::LineB, data_packet(603, 4), 20, sink);
  arb.resume_from_snapshot(601, 30, sink);  // snapshot taken at S(P) = 600
  EXPECT_TRUE(sink.delivered_range(601, 607, 2));
  EXPECT_EQ(arb.next_expected(), 607u);
}

TEST_F(LineArbiterTest, SnapshotBelowBufferedLeavesGapForRerequest) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 2), 0, sink);
  arb.on_packet(Source::LineA, data_packet(700, 5), 10, sink);
  ASSERT_EQ(sink.snapshots.size(), 1u);
  arb.resume_from_snapshot(690, 100, sink);  // snapshot older than the buffered live data
  EXPECT_EQ(sink.delivered.size(), 2u);
  EXPECT_TRUE(arb.in_gap());
  arb.on_timer(100 + kGap, sink);
  ASSERT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(sink.requests[0].second, (RequestPacket{test::kSession, 690, 10}));
  answer_requests(arb, sink, 0, 200'000);
  EXPECT_TRUE(sink.delivered_range(690, 705, 2));
}

TEST_F(LineArbiterTest, GapAgeBoundTriggersSnapshot) {
  LineArbiterConfig c = small_cfg();
  c.max_gap_age = 2'000'000;
  c.request_timeout = 10'000'000;
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 1), 0, sink);
  arb.on_packet(Source::LineA, data_packet(5, 1), 1'000, sink);
  arb.on_timer(1'000 + kGap, sink);
  EXPECT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(arb.next_deadline(), 1'000 + 2'000'000);
  arb.on_timer(1'000 + 2'000'000, sink);
  EXPECT_EQ(sink.snapshots.size(), 1u);
}

TEST_F(LineArbiterTest, ReorderWindowOverflowTriggersSnapshot) {
  LineArbiterConfig c = small_cfg();
  c.snapshot_gap_messages = 0;  // only the window bound applies
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 1), 0, sink);
  arb.on_packet(Source::LineA, data_packet(2000, 1), 10, sink);  // beyond 1 + 1024
  EXPECT_EQ(arb.metrics().buffer_overflows, 1u);
  EXPECT_EQ(sink.snapshots.size(), 1u);
}

TEST_F(LineArbiterTest, HeartbeatExposesTailGap) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 5), 0, sink);
  // 6 and 7 were lost on both lines; the stream then goes quiet. Heartbeats carry next = 8.
  arb.on_packet(Source::LineA, control_packet(8, false), 1'000'000, sink);
  EXPECT_TRUE(arb.in_gap());
  EXPECT_EQ(arb.known_end(), 8u);
  arb.on_packet(Source::LineB, control_packet(8, false), 1'000'100, sink);
  arb.on_timer(1'000'000 + kGap, sink);
  ASSERT_EQ(sink.requests.size(), 1u);
  EXPECT_EQ(sink.requests[0].second, (RequestPacket{test::kSession, 6, 2}));
  answer_requests(arb, sink, 0, 1'100'000);
  EXPECT_TRUE(sink.delivered_range(1, 8));
  EXPECT_EQ(arb.metrics().heartbeats, 2u);
  EXPECT_FALSE(arb.in_gap());
}

TEST_F(LineArbiterTest, EndOfSessionAfterLastMessage) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  arb.on_packet(Source::LineA, data_packet(1, 3), 0, sink);
  arb.on_packet(Source::LineA, control_packet(6, true), 10, sink);  // 4, 5 still missing
  EXPECT_TRUE(sink.ends.empty());
  arb.on_packet(Source::LineB, data_packet(1, 5), 20, sink);
  ASSERT_EQ(sink.ends.size(), 1u);
  EXPECT_EQ(sink.ends[0], 6u);
  EXPECT_TRUE(sink.delivered_range(1, 6));
  EXPECT_EQ(arb.state(), LineArbiter::State::Ended);
  arb.on_packet(Source::LineB, control_packet(6, true), 30, sink);  // repeats are ignored
  EXPECT_EQ(sink.ends.size(), 1u);
  EXPECT_EQ(arb.metrics().ignored_after_end, 1u);
  EXPECT_EQ(arb.metrics().gaps_filled_by_line[1], 1u);
}

TEST_F(LineArbiterTest, LateJoinBuffersUntilSnapshot) {
  LineArbiterConfig c = small_cfg();
  c.first_seq = 0;
  LineArbiter arb(c);
  ArbiterSink sink;
  EXPECT_EQ(arb.state(), LineArbiter::State::AwaitingSnapshot);
  arb.on_packet(Source::LineA, data_packet(5000, 10), 0, sink);
  arb.on_packet(Source::LineB, data_packet(5004, 10), 5, sink);
  EXPECT_TRUE(sink.delivered.empty());
  EXPECT_EQ(arb.buffered(), 14u);
  arb.resume_from_snapshot(5003, 10, sink);
  EXPECT_TRUE(sink.delivered_range(5003, 5014));
  EXPECT_TRUE(sink.snapshots.empty());
}

TEST_F(LineArbiterTest, SnapshotWindowSlidesWithLiveStream) {
  LineArbiterConfig c = small_cfg();
  c.first_seq = 0;
  LineArbiter arb(c);  // window of 1024 messages
  ArbiterSink sink;
  for (SeqNo s = 1; s <= 3000; s += 10) arb.on_packet(Source::LineA, data_packet(s, 10), static_cast<Nanos>(s), sink);
  EXPECT_EQ(arb.buffered(), 1024u);
  EXPECT_GT(arb.metrics().snapshot_window_drops, 0u);
  arb.resume_from_snapshot(2500, 4000, sink);
  EXPECT_TRUE(sink.delivered_range(2500, 3001));
}

TEST_F(LineArbiterTest, MalformedAndWrongSessionAreCounted) {
  LineArbiter arb(small_cfg());
  ArbiterSink sink;
  Bytes bad = data_packet(1, 3);
  bad.resize(bad.size() - 1);
  arb.on_packet(Source::LineA, bad, 0, sink);
  arb.on_packet(Source::LineB, data_packet(1, 3, Session("OTHER")), 0, sink);
  EXPECT_TRUE(sink.delivered.empty());
  EXPECT_EQ(arb.metrics().malformed[0], 1u);
  EXPECT_EQ(arb.metrics().wrong_session, 1u);
}

TEST_F(LineArbiterTest, LearnsSessionFromFirstPacket) {
  LineArbiterConfig c = small_cfg();
  c.session = Session();
  LineArbiter arb(c);
  ArbiterSink sink;
  arb.on_packet(Source::LineB, data_packet(1, 2, Session("LEARNED")), 0, sink);
  arb.on_packet(Source::LineA, data_packet(3, 2, test::kSession), 0, sink);
  EXPECT_EQ(arb.session().view(), "LEARNED");
  EXPECT_EQ(sink.delivered.size(), 2u);
  EXPECT_EQ(arb.metrics().wrong_session, 1u);
}

// End-to-end: Packetizer A/B (different boundaries) -> lossy lines -> arbiter,
// with re-request servers and a snapshot service. Oracle: exactly once, in order.
struct ScenarioCase {
  const char* name;
  scenario::ScenarioConfig cfg;
};

std::vector<ScenarioCase> scenario_cases() {
  std::vector<ScenarioCase> v;
  scenario::ScenarioConfig base;
  base.messages = 4'000;
  base.arbiter.reorder_capacity = 4096;
  base.arbiter.snapshot_gap_messages = 2'000;
  {
    auto c = base;
    v.push_back({"clean", c});
  }
  {
    auto c = base;
    c.loss_ppm_a = 100'000;
    c.loss_ppm_b = 100'000;
    c.dup_ppm = 50'000;
    c.reorder_ppm = 50'000;
    v.push_back({"independent_loss_dup_reorder", c});
  }
  {
    auto c = base;
    c.loss_ppm_a = 300'000;
    c.loss_ppm_b = 300'000;
    c.reply_loss_ppm = 200'000;
    v.push_back({"heavy_loss_lossy_replies", c});
  }
  {
    auto c = base;
    c.loss_ppm_a = 200'000;
    c.loss_ppm_b = 200'000;
    c.server_a_up = false;
    v.push_back({"server_a_down", c});
  }
  {
    auto c = base;
    c.loss_ppm_a = 100'000;
    c.loss_ppm_b = 100'000;
    c.server_a_up = false;
    c.server_b_up = false;
    v.push_back({"both_servers_down_snapshot", c});
  }
  {
    auto c = base;
    c.outage_every = 200;
    c.outage_len = 150;  // long outages on both lines: gaps > snapshot threshold
    c.max_batch = 32;
    v.push_back({"line_outages_snapshot", c});
  }
  return v;
}

TEST(LineArbiterScenario, ExactlyOnceInOrderAcrossSeeds) {
  for (const auto& sc : scenario_cases()) {
    for (std::uint64_t seed = 1; seed <= 6; ++seed) {
      auto cfg = sc.cfg;
      cfg.seed = seed;
      const auto r = scenario::run_scenario(cfg);
      ASSERT_TRUE(r.ok) << sc.name << " seed " << seed << ": " << r.error;
      EXPECT_TRUE(r.ended);
      EXPECT_EQ(r.delivered + r.snapshot_covered, cfg.messages);
      if (std::string(sc.name) == "clean") {
        EXPECT_EQ(r.snapshots, 0u);
        EXPECT_EQ(r.metrics.requests_sent[0] + r.metrics.requests_sent[1], 0u);
      }
      if (std::string(sc.name) == "independent_loss_dup_reorder") {
        EXPECT_GT(r.metrics.gaps_filled_by_line[0] + r.metrics.gaps_filled_by_line[1], 0u);
        EXPECT_GT(r.metrics.partial_overlaps[0] + r.metrics.partial_overlaps[1], 0u);
      }
      if (std::string(sc.name) == "server_a_down") {
        EXPECT_EQ(r.metrics.requests_sent[0] > 0, r.metrics.failovers > 0);
      }
      if (std::string(sc.name) == "both_servers_down_snapshot" || std::string(sc.name) == "line_outages_snapshot") {
        EXPECT_GT(r.snapshots, 0u) << sc.name << " seed " << seed;
      }
    }
  }
}

}  // namespace
}  // namespace lle::mold

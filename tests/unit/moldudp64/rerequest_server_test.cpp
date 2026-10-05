#include <gtest/gtest.h>

#include <vector>

#include "mold_test_util.h"
#include "proto/moldudp64/message_store.h"
#include "proto/moldudp64/rerequest_server.h"

namespace lle::mold {
namespace {

using test::Bytes;

struct Replies {
  std::vector<std::pair<env::Endpoint, Bytes>> sent;
  void operator()(const env::Endpoint& e, std::span<const std::byte> p) { sent.emplace_back(e, Bytes(p.begin(), p.end())); }
};

Bytes request(SeqNo seq, std::uint16_t count, const Session& s = test::kSession) {
  Bytes b(kRequestLen);
  encode_request(b, RequestPacket{s, seq, count});
  return b;
}

class RerequestServerTest : public ::testing::Test {
 protected:
  RerequestServerTest() : store_(1000, 1 << 16) {
    for (SeqNo s = 1; s <= 200; ++s) store_.append(test::msg_for(s));
  }
  RerequestConfig cfg(std::size_t max_packet = 200) {
    RerequestConfig c;
    c.session = test::kSession;
    c.max_packet = max_packet;
    return c;
  }
  MessageRing store_;
  const env::Endpoint src_{0x0A000001, 5000};
};

TEST_F(RerequestServerTest, ServesWholeMessagesUpToMaxPacket) {
  RerequestServer<MessageRing> srv(cfg(200), store_);
  Replies out;
  EXPECT_EQ(srv.on_request(request(10, 100), src_, 0, std::ref(out)), RequestOutcome::Served);
  ASSERT_EQ(out.sent.size(), 1u);
  EXPECT_EQ(out.sent[0].first, src_);
  const auto pv = PacketView::parse(out.sent[0].second);
  ASSERT_TRUE(pv.has_value());
  EXPECT_LE(out.sent[0].second.size(), 200u);
  EXPECT_EQ(pv->seq(), 10u);
  // msg_for(s) is 4 + s % 20 bytes; count how many whole messages fit from 10.
  std::size_t used = kHeaderLen, expect = 0;
  for (SeqNo s = 10; used + 2 + test::msg_for(s).size() <= 200; ++s, ++expect) used += 2 + test::msg_for(s).size();
  EXPECT_EQ(pv->message_count(), expect);
  pv->for_each([&](SeqNo s, std::span<const std::byte> m) { EXPECT_EQ(Bytes(m.begin(), m.end()), test::msg_for(s)); });
  EXPECT_EQ(srv.stats().served, 1u);
  EXPECT_EQ(srv.stats().messages_served, expect);
}

TEST_F(RerequestServerTest, ClampsToHighestAndRequestedCount) {
  RerequestServer<MessageRing> srv(cfg(1472), store_);
  Replies out;
  srv.on_request(request(199, 50), src_, 0, std::ref(out));
  srv.on_request(request(5, 2), src_, 0, std::ref(out));
  ASSERT_EQ(out.sent.size(), 2u);
  EXPECT_EQ(PacketView::parse(out.sent[0].second)->message_count(), 2);  // 199, 200
  EXPECT_EQ(PacketView::parse(out.sent[1].second)->message_count(), 2);  // 5, 6
}

TEST_F(RerequestServerTest, InvalidRequestsAreDroppedAndCounted) {
  RerequestServer<MessageRing> srv(cfg(), store_);
  Replies out;
  Bytes short_req = request(1, 1);
  short_req.pop_back();
  EXPECT_EQ(srv.on_request(short_req, src_, 0, std::ref(out)), RequestOutcome::Malformed);
  EXPECT_EQ(srv.on_request(request(1, 1, Session("OTHER")), src_, 0, std::ref(out)), RequestOutcome::WrongSession);
  EXPECT_EQ(srv.on_request(request(0, 1), src_, 0, std::ref(out)), RequestOutcome::BadSequence);
  EXPECT_EQ(srv.on_request(request(201, 1), src_, 0, std::ref(out)), RequestOutcome::BadSequence);
  EXPECT_EQ(srv.on_request(request(5, 0), src_, 0, std::ref(out)), RequestOutcome::ZeroCount);
  EXPECT_TRUE(out.sent.empty());
  EXPECT_EQ(srv.stats().invalid(), 5u);
  EXPECT_EQ(srv.stats().requests, 5u);
}

TEST_F(RerequestServerTest, EvictedSequencesAreUnavailable) {
  MessageRing small(10, 1 << 12);
  for (SeqNo s = 1; s <= 50; ++s) small.append(test::msg_for(s));
  RerequestServer<MessageRing> srv(cfg(), small);
  Replies out;
  EXPECT_EQ(srv.on_request(request(30, 5), src_, 0, std::ref(out)), RequestOutcome::Unavailable);
  EXPECT_EQ(srv.on_request(request(41, 5), src_, 0, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.stats().unavailable, 1u);
}

TEST_F(RerequestServerTest, PerSourceTokenBucket) {
  RerequestConfig c = cfg();
  c.bucket_capacity = 3;
  c.refill_interval = 1'000;
  RerequestServer<MessageRing> srv(c, store_);
  Replies out;
  const env::Endpoint other{0x0A000002, 5000};
  for (int i = 0; i < 3; ++i) EXPECT_EQ(srv.on_request(request(1, 1), src_, 0, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.on_request(request(1, 1), src_, 999, std::ref(out)), RequestOutcome::RateLimited);
  // Another source has its own bucket.
  EXPECT_EQ(srv.on_request(request(1, 1), other, 999, std::ref(out)), RequestOutcome::Served);
  // One token per microsecond; bursts are capped at capacity.
  EXPECT_EQ(srv.on_request(request(1, 1), src_, 1'000, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.on_request(request(1, 1), src_, 1'500, std::ref(out)), RequestOutcome::RateLimited);
  for (int i = 0; i < 3; ++i)
    EXPECT_EQ(srv.on_request(request(1, 1), src_, 1'000'000, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.on_request(request(1, 1), src_, 1'000'000, std::ref(out)), RequestOutcome::RateLimited);
  EXPECT_EQ(srv.stats().rate_limited, 3u);
}

TEST_F(RerequestServerTest, SourceTableOverflowSharesOneBucket) {
  RerequestConfig c = cfg();
  c.max_sources = 2;
  c.bucket_capacity = 1;
  c.refill_interval = kNsPerSec;
  RerequestServer<MessageRing> srv(c, store_);
  Replies out;
  for (std::uint32_t ip = 1; ip <= 2; ++ip)
    EXPECT_EQ(srv.on_request(request(1, 1), env::Endpoint{ip, 1}, 0, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.on_request(request(1, 1), env::Endpoint{3, 1}, 0, std::ref(out)), RequestOutcome::Served);
  EXPECT_EQ(srv.on_request(request(1, 1), env::Endpoint{4, 1}, 0, std::ref(out)), RequestOutcome::RateLimited);
  EXPECT_EQ(srv.stats().sources_overflowed, 2u);
}

}  // namespace
}  // namespace lle::mold

// HA order entry (10 §3 step 5): one instance at a time, pending messages
// re-sent in order after a takeover, responses deduplicated across instances.
// Two sans-I/O SoupBinTCP server sessions share one sequenced store, as the
// primary's and the backup's mirror instances share one byte-identical stream;
// a fake engine applies the UserRefNum filter (OUCH 5.0 §1.2).
#include <gtest/gtest.h>

#include <array>
#include <deque>
#include <memory>
#include <vector>

#include "client/order_entry.h"
#include "common/endian.h"
#include "proto/ouch50/ouch50.h"
#include "proto/soupbin/sequenced_store.h"
#include "proto/soupbin/server_session.h"

namespace lle::client {
namespace {

struct Policy {
  soup::LoginDecision authorize(const soup::LoginRequest&) { return soup::LoginDecision::Accept; }
};
using Server = soup::ServerSession<soup::MemorySequencedStore, Policy>;

std::vector<std::byte> enter(UserRefNum u) {
  ouch50::in::EnterOrder m;
  m.user_ref_num = u;
  m.side = ouch50::Side::Buy;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 1'000'000;
  m.time_in_force = ouch50::TimeInForce::Ioc;
  m.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
  std::vector<std::byte> b(ouch50::in::EnterOrder::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

std::vector<std::byte> cancel(UserRefNum u) {
  ouch50::in::CancelOrder m;
  m.user_ref_num = u;
  m.quantity = 0;
  std::vector<std::byte> b(64);
  b.resize(ouch50::encode(b, m));
  return b;
}

// Outbound messages injected straight into HaOrderEntry::on_response.
template <class M>
std::vector<std::byte> out(const M& m) {
  std::vector<std::byte> b(M::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}
std::vector<std::byte> canceled(UserRefNum u, ouch50::CancelReason why) {
  ouch50::out::OrderCanceled m;
  m.user_ref_num = u;
  m.reason = why;
  return out(m);
}
std::vector<std::byte> cancel_pending(UserRefNum u) {
  ouch50::out::CancelPending m;
  m.user_ref_num = u;
  return out(m);
}
std::vector<std::byte> cancel_reject(UserRefNum u) {
  ouch50::out::CancelReject m;
  m.user_ref_num = u;
  return out(m);
}
std::vector<std::byte> aiq_canceled(UserRefNum u) {
  ouch50::out::AiqCanceled m;
  m.user_ref_num = u;
  return out(m);
}
std::vector<std::byte> rejected(UserRefNum u) {
  ouch50::out::Rejected m;
  m.user_ref_num = u;
  return out(m);
}

// The exchange side: both nodes' gateways feed one engine; outputs go to the
// shared stream that both instances replay.
struct Exchange {
  soup::MemorySequencedStore stream{100'000, 10'000'000};
  Policy policy;
  std::array<std::unique_ptr<Server>, 2> srv;
  UserRefNum last_urn = 0;
  std::vector<UserRefNum> applied;  // Enter UserRefNums the engine accepted, in order
  std::uint64_t resends_ignored = 0, cancels = 0;
  bool silent = false;              // apply without responding

  void connect(std::size_t i, Nanos now) {
    soup::ServerConfig c;
    c.session = soup::SessionId::from("S1");
    srv[i] = std::make_unique<Server>(c, stream, policy, now);
  }
  void apply(std::span<const std::byte> m, Nanos now) {
    if (static_cast<char>(m[0]) == 'O') {
      const UserRefNum u = load_be32(m.data() + 1);
      if (u <= last_urn) {
        ++resends_ignored;  // benign resend
        return;
      }
      last_urn = u;
      applied.push_back(u);
      if (silent) return;
      ouch50::out::OrderAccepted a;
      a.user_ref_num = u;
      a.symbol = Symbol8("AAPL");
      a.order_state = ouch50::OrderState::Dead;
      std::array<std::byte, 128> b{};
      const std::size_t n = ouch50::encode(std::span<std::byte>(b), a);
      ASSERT_TRUE(stream.append(std::span<const std::byte>(b.data(), n)));
    } else if (static_cast<char>(m[0]) == 'X') {
      ++cancels;  // the order is gone: ignored without a response
    }
    (void)now;
  }
};

struct Rig {
  OrderEntryConfig cfg;
  std::unique_ptr<HaOrderEntry> oe;
  Exchange ex;
  std::array<bool, 2> up{false, false};
  std::vector<SeqNo> responses;
  Nanos now = 1'000;

  Rig() {
    cfg.session.username = Alpha<6>("U00001");
    cfg.session.password = Alpha<10>("pw");
    cfg.pending_capacity = 1024;
    oe = std::make_unique<HaOrderEntry>(cfg);
  }
  void connect(std::size_t i) {
    ex.connect(i, now);
    up[i] = true;
    oe->on_connected(i, now);
    pump();
  }
  // Moves bytes both ways until quiet.
  void pump() {
    for (int round = 0; round < 50; ++round) {
      bool moved = false;
      for (std::size_t i = 0; i < 2; ++i) {
        if (!up[i]) continue;
        const auto tx = oe->tx(i);
        if (!tx.empty()) {
          const std::vector<std::byte> copy(tx.begin(), tx.end());
          oe->consume_tx(i, copy.size());
          const soup::Actions& a = ex.srv[i]->on_bytes(copy, now);
          for (const auto& d : a.delivered) ex.apply(d.data, now);
          moved = true;
        }
        const soup::Actions& t = ex.srv[i]->on_timer(now);
        (void)t;
        const auto w = ex.srv[i]->actions().write;
        if (!w.empty()) {
          const std::vector<std::byte> copy(w.begin(), w.end());
          (void)ex.srv[i]->consume_tx(copy.size());
          oe->on_bytes(i, copy, now, [&](SeqNo s, std::span<const std::byte>) { responses.push_back(s); });
          moved = true;
        }
      }
      if (!moved) break;
    }
  }
  // The node dies: whatever the client wrote on it and the node did not read is lost.
  void kill(std::size_t i) {
    up[i] = false;
    ex.srv[i].reset();
    const auto tx = oe->tx(i);
    oe->consume_tx(i, tx.size());
    oe->on_closed(i, now);
    pump();
  }
};

TEST(OrderEntry, SendsOnTheActiveInstanceOnlyAndDeduplicatesResponses) {
  Rig r;
  r.connect(0);
  r.connect(1);
  ASSERT_EQ(r.oe->active(), 0);
  for (int k = 0; k < 10; ++k) ASSERT_TRUE(r.oe->send(enter(r.oe->next_urn()), r.now));
  // Before pumping, nothing was queued on the standby.
  EXPECT_TRUE(r.oe->tx(1).empty());
  r.pump();
  ASSERT_EQ(r.ex.applied.size(), 10u);
  for (std::size_t k = 0; k < 10; ++k) EXPECT_EQ(r.ex.applied[k], k + 1);
  EXPECT_EQ(r.oe->pending(), 0u);
  EXPECT_EQ(r.oe->stats().responses, 10u);
  EXPECT_EQ(r.oe->stats().duplicate_responses, 10u);  // the same stream on the mirror instance
  EXPECT_EQ(r.responses.size(), 10u);
  for (std::size_t k = 0; k < r.responses.size(); ++k) EXPECT_EQ(r.responses[k], k + 1);
}

TEST(OrderEntry, TakeoverResendsPendingInOriginalOrderExactlyOnce) {
  Rig r;
  r.connect(0);
  r.connect(1);
  for (int k = 0; k < 5; ++k) r.oe->send(enter(r.oe->next_urn()), r.now);
  r.pump();
  ASSERT_EQ(r.oe->pending(), 0u);
  // Three more reach the primary's gateway and the engine, but the responses
  // are lost with the node; two more never leave the client's socket buffer.
  r.ex.silent = true;
  for (int k = 0; k < 3; ++k) r.oe->send(enter(r.oe->next_urn()), r.now);
  r.pump();
  r.ex.silent = false;
  for (int k = 0; k < 2; ++k) r.oe->send(enter(r.oe->next_urn()), r.now);
  EXPECT_EQ(r.oe->pending(), 5u);
  r.kill(0);
  EXPECT_EQ(r.oe->active(), 1);
  EXPECT_EQ(r.oe->stats().takeovers, 1u);
  EXPECT_EQ(r.oe->stats().resent, 5u);
  // The engine saw 1..10 once each, in order; the three it already had were
  // ignored as benign resends (UserRefNum filter).
  ASSERT_EQ(r.ex.applied.size(), 10u);
  for (std::size_t k = 0; k < 10; ++k) EXPECT_EQ(r.ex.applied[k], k + 1);
  EXPECT_EQ(r.ex.resends_ignored, 3u);
  EXPECT_EQ(r.oe->pending(), 0u);
  // New messages go to the survivor.
  r.oe->send(enter(r.oe->next_urn()), r.now);
  r.pump();
  EXPECT_EQ(r.ex.applied.back(), 11u);
}

TEST(OrderEntry, ResponseToALaterMessageReleasesSilentEarlierOnes) {
  Rig r;
  r.connect(0);
  r.oe->send(enter(1), r.now);
  r.oe->send(cancel(1), r.now);  // ignored by the engine: no response
  r.oe->send(enter(2), r.now);
  r.pump();
  EXPECT_EQ(r.ex.cancels, 1u);
  EXPECT_EQ(r.oe->pending(), 0u);
  EXPECT_EQ(r.oe->stats().acked, 3u);
}

TEST(OrderEntry, MessagesWaitWithoutAnInstanceAndGoOutOnLogin) {
  Rig r;
  r.oe->send(enter(1), r.now);
  r.oe->send(enter(2), r.now);
  EXPECT_EQ(r.oe->active(), -1);
  r.connect(1);  // only the backup comes up
  EXPECT_EQ(r.oe->active(), 1);
  ASSERT_EQ(r.ex.applied.size(), 2u);
  EXPECT_EQ(r.oe->pending(), 0u);
}

TEST(OrderEntry, BothInstancesDownThenReconnectResumesTheStream) {
  Rig r;
  r.connect(0);
  for (int k = 0; k < 4; ++k) r.oe->send(enter(r.oe->next_urn()), r.now);
  r.pump();
  r.kill(0);
  EXPECT_EQ(r.oe->active(), -1);
  r.oe->send(enter(r.oe->next_urn()), r.now);
  r.connect(0);  // reconnect: login requests the next unprocessed sequence
  EXPECT_EQ(r.oe->next_seq(), 6u);
  EXPECT_EQ(r.oe->stats().duplicate_responses, 0u);
  EXPECT_EQ(r.ex.applied.size(), 5u);
}

TEST(OrderEntry, ThePrimaryIsPreferredWhileItIsComing) {
  Rig r;
  r.oe->on_connecting(0);
  r.oe->on_connecting(1);
  r.connect(1);  // the backup logs in first
  EXPECT_EQ(r.oe->active(), -1);
  r.oe->send(enter(1), r.now);
  EXPECT_TRUE(r.ex.applied.empty());  // waits for the primary
  r.connect(0);
  EXPECT_EQ(r.oe->active(), 0);
  r.pump();
  EXPECT_EQ(r.ex.applied.size(), 1u);
  EXPECT_EQ(r.oe->stats().takeovers, 0u);
}

TEST(OrderEntry, APrimaryThatNeverComesLetsTheBackupGoAhead) {
  Rig r;
  r.oe->on_connecting(0);
  r.oe->on_connecting(1);
  r.connect(1);
  r.oe->send(enter(1), r.now);
  EXPECT_EQ(r.oe->active(), -1);
  r.oe->on_closed(0, r.now);  // the primary's connect failed
  EXPECT_EQ(r.oe->active(), 1);
  r.pump();
  EXPECT_EQ(r.ex.applied.size(), 1u);
}

TEST(OrderEntry, PendingRingBoundsAndOversizeMessages) {
  OrderEntryConfig c;
  c.pending_capacity = 2;
  HaOrderEntry oe(c);
  EXPECT_TRUE(oe.send(enter(1), 0));
  EXPECT_TRUE(oe.send(enter(2), 0));
  EXPECT_FALSE(oe.send(enter(3), 0));
  EXPECT_EQ(oe.stats().pending_full, 1u);
  std::vector<std::byte> big(HaOrderEntry::kMaxMsg + 1, std::byte{'O'});
  EXPECT_FALSE(oe.send(big, 0));
}

// DST-007 (exchange_ha seed 0x18): an unsolicited cancel-on-disconnect 'Z' of an
// order with a pending Cancel released every message before that Cancel, here the
// Enters queued behind it in the node; the node failed with them unprocessed and the
// takeover re-sent from after them. An unsolicited cancel proves nothing about them.
TEST(OrderEntry, UnsolicitedCancelOfAnOrderWithAPendingCancelReleasesNothing) {
  Rig r;
  r.connect(0);
  r.connect(1);
  ASSERT_TRUE(r.oe->send(enter(1), r.now));
  r.pump();
  ASSERT_EQ(r.oe->pending(), 0u);
  // Enters 2..6 then a Cancel of order 1 reach the primary; nothing is answered yet.
  r.ex.silent = true;
  for (UserRefNum u = 2; u <= 6; ++u) ASSERT_TRUE(r.oe->send(enter(u), r.now));
  ASSERT_TRUE(r.oe->send(cancel(1), r.now));
  r.pump();
  ASSERT_EQ(r.oe->pending(), 6u);
  for (const auto why : {ouch50::CancelReason::System, ouch50::CancelReason::Closed,
                         ouch50::CancelReason::ImmediateOrCancel, ouch50::CancelReason::HaltedAfterOpen,
                         ouch50::CancelReason::SelfMatchPrevention, ouch50::CancelReason::Supervisory}) {
    r.oe->on_response(canceled(1, why));
    EXPECT_EQ(r.oe->pending(), 6u) << "reason " << static_cast<char>(why);
  }
  r.oe->on_response(aiq_canceled(1));
  EXPECT_EQ(r.oe->pending(), 6u);
  EXPECT_EQ(r.oe->stats().acked, 1u);  // only Enter 1's Accepted
  // The primary dies: all six go out again on the backup, in order.
  r.ex.silent = false;
  r.kill(0);
  EXPECT_EQ(r.oe->active(), 1);
  EXPECT_EQ(r.oe->stats().resent, 6u);
  ASSERT_EQ(r.ex.applied.size(), 6u);
  for (std::size_t k = 0; k < 6; ++k) EXPECT_EQ(r.ex.applied[k], k + 1);
  EXPECT_EQ(r.ex.resends_ignored, 5u);  // the Enters the primary had applied, ignored as resends
}

// DST-007, the solicited form: a Cancel answered by Cancel Pending, then a second
// Cancel of the same order behind two Enters; the order's final Canceled (User
// Requested) completes the first Cancel. It answers one Cancel, not the Enters before
// the second one, which a takeover must still re-send.
TEST(OrderEntry, CanceledAfterCancelPendingAnswersOneCancelOnly) {
  Rig r;
  r.connect(0);
  r.connect(1);
  ASSERT_TRUE(r.oe->send(enter(1), r.now));
  r.pump();
  r.ex.silent = true;
  ASSERT_TRUE(r.oe->send(cancel(1), r.now));
  r.pump();
  r.oe->on_response(cancel_pending(1));
  EXPECT_EQ(r.oe->pending(), 0u);  // the Cancel answered at the head: released
  ASSERT_TRUE(r.oe->send(enter(2), r.now));
  ASSERT_TRUE(r.oe->send(enter(3), r.now));
  ASSERT_TRUE(r.oe->send(cancel(1), r.now));
  r.pump();
  r.oe->on_response(canceled(1, ouch50::CancelReason::UserRequested));
  EXPECT_EQ(r.oe->pending(), 3u);  // Enters 2 and 3 still pending, the second Cancel answered
  r.ex.silent = false;
  r.kill(0);
  EXPECT_EQ(r.oe->stats().resent, 2u);  // the Enters; the answered Cancel is not sent again
  ASSERT_EQ(r.ex.applied.size(), 3u);
  EXPECT_EQ(r.ex.applied[1], 2u);
  EXPECT_EQ(r.ex.applied[2], 3u);
  EXPECT_EQ(r.ex.resends_ignored, 2u);  // the engine already had both: exactly once by UserRefNum
}

TEST(OrderEntry, CancelAnswersAckTheirOwnEntryAndConsumingResponsesStayCumulative) {
  OrderEntryConfig c;
  c.pending_capacity = 16;
  HaOrderEntry oe(c);
  ASSERT_TRUE(oe.send(cancel(7), 0));   // pos 0
  ASSERT_TRUE(oe.send(cancel(8), 0));   // pos 1
  ASSERT_TRUE(oe.send(enter(20), 0));   // pos 2
  ASSERT_TRUE(oe.send(cancel(9), 0));   // pos 3
  ASSERT_TRUE(oe.send(enter(21), 0));   // pos 4
  // Cancel Reject of order 8 answers the second Cancel only; the head stays.
  oe.on_response(cancel_reject(8));
  EXPECT_EQ(oe.pending(), 5u);
  // Cancel Pending of order 7 answers the head: it advances over both answered Cancels.
  oe.on_response(cancel_pending(7));
  EXPECT_EQ(oe.pending(), 3u);
  // Rejected names Enter 20's UserRefNum: it and everything before it are released.
  oe.on_response(rejected(20));
  EXPECT_EQ(oe.pending(), 2u);
  // An unsolicited cancel of order 9 does not touch its pending Cancel.
  oe.on_response(canceled(9, ouch50::CancelReason::System));
  EXPECT_EQ(oe.pending(), 2u);
  // Accepted of Enter 21 releases the Cancel of 9 before it.
  ouch50::out::OrderAccepted a;
  a.user_ref_num = 21;
  oe.on_response(out(a));
  EXPECT_EQ(oe.pending(), 0u);
  EXPECT_EQ(oe.stats().acked, 5u);  // each entry counted once
}

}  // namespace
}  // namespace lle::client

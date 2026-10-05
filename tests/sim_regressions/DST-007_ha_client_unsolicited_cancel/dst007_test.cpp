// DST-007 regression test (scripted, seed-independent): refclient's HA order entry
// (client::HaOrderEntry, clients.md §2.4) must not take a cancel it did not ask for as
// the answer to a pending Cancel of the same order. Found by `exsim --world=exchange_ha`
// (O-EXACTLY-ONCE); see sim/ledger/bugs.yaml.
//
// A response to message k releases the messages before k: the engine applies a
// session's messages in order. A cancel-like message names an order, though, not a
// message. At the found tree an Order Canceled for an order with a pending Cancel
// released that Cancel and every message before it, even when the engine cancelled the
// order on its own (cancel-on-disconnect, the close, IOC, a halt) or the Canceled
// completed an earlier Cancel that Cancel Pending had already answered. The released
// messages had not been processed. When the node holding them in its queue then died,
// the client never sent them again: the orders were lost without a word.
#include <gtest/gtest.h>

#include <span>
#include <vector>

#include "client/order_entry.h"
#include "common/types.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client {
namespace {

std::vector<std::byte> enter(UserRefNum u) {
  ouch50::in::EnterOrder m;
  m.user_ref_num = u;
  m.side = ouch50::Side::Buy;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 1'000'000;
  m.time_in_force = ouch50::TimeInForce::Day;
  m.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
  std::vector<std::byte> b(ouch50::in::EnterOrder::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

std::vector<std::byte> cancel(UserRefNum order) {
  ouch50::in::CancelOrder m;
  m.user_ref_num = order;
  m.quantity = 0;
  std::vector<std::byte> b(64);
  b.resize(ouch50::encode(b, m));
  return b;
}

std::vector<std::byte> canceled(UserRefNum order, ouch50::CancelReason why) {
  ouch50::out::OrderCanceled m;
  m.user_ref_num = order;
  m.quantity = 100;
  m.reason = why;
  std::vector<std::byte> b(ouch50::out::OrderCanceled::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

std::vector<std::byte> cancel_pending(UserRefNum order) {
  ouch50::out::CancelPending m;
  m.user_ref_num = order;
  std::vector<std::byte> b(ouch50::out::CancelPending::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

// No instance is connected, so every message stays pending and nothing is written: the
// test watches only what the responses release.
TEST(DST007, AnUnsolicitedCancelReleasesNothing) {
  const ouch50::CancelReason unsolicited[] = {ouch50::CancelReason::System, ouch50::CancelReason::Closed,
                                              ouch50::CancelReason::ImmediateOrCancel,
                                              ouch50::CancelReason::HaltedAfterOpen,
                                              ouch50::CancelReason::Supervisory};
  for (const ouch50::CancelReason why : unsolicited) {
    HaOrderEntry e(OrderEntryConfig{});
    ASSERT_TRUE(e.send(enter(10), 0));   // queued in the node, not processed yet
    ASSERT_TRUE(e.send(cancel(7), 0));   // order 7 was entered earlier and is live
    ASSERT_TRUE(e.send(enter(11), 0));
    ASSERT_EQ(e.pending(), 3u);
    // The engine cancels order 7 by itself (cancel-on-disconnect sends reason 'Z').
    e.on_response(canceled(7, why));
    EXPECT_EQ(e.pending(), 3u) << "reason " << static_cast<char>(why)
                               << ": Enter Order 10 was released though the engine never saw it";
  }
}

TEST(DST007, CanceledAfterCancelPendingAnswersOneCancelOnly) {
  HaOrderEntry e(OrderEntryConfig{});
  ASSERT_TRUE(e.send(cancel(7), 0));  // order 7 is frozen in an auction: Cancel Pending
  e.on_response(cancel_pending(7));
  ASSERT_EQ(e.pending(), 0u);
  ASSERT_TRUE(e.send(enter(10), 0));
  ASSERT_TRUE(e.send(cancel(7), 0));  // a second Cancel of the same order
  // The cross completes the first Cancel: Order Canceled, User Requested.
  e.on_response(canceled(7, ouch50::CancelReason::UserRequested));
  EXPECT_GE(e.pending(), 1u) << "Enter Order 10 was released by the completion of an earlier Cancel";
}

}  // namespace
}  // namespace lle::client

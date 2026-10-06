// DST-014 regression test (scripted, seed-independent): refclient's HA order entry
// (client::HaOrderEntry, clients.md §2.4) must not take an Account Query Response as the
// response to a pending Enter Order. Reproduced by `exsim --world=exchange_ha`
// (O-EXACTLY-ONCE) once its clients send Account Query; see sim/ledger/bugs.yaml.
//
// A response naming the UserRefNum message k consumed proves k was processed, and with
// it every message before k. Account Query Response carries NextUserRefNum at the offset
// where other responses carry a UserRefNum: one above the last UserRefNum the account
// consumed, which is the UserRefNum of the next Enter Order still in the node's queue.
// At the found tree the client took it as that order's response and released the order
// unprocessed. When the node holding it then died, the client never sent it again: the
// order was lost without a word.
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

std::vector<std::byte> account_query() {
  std::vector<std::byte> b(64);
  b.resize(ouch50::encode(b, ouch50::in::AccountQuery{}));
  return b;
}

std::vector<std::byte> account_query_response(UserRefNum next) {
  ouch50::out::AccountQueryResponse m;
  m.next_user_ref_num = next;
  std::vector<std::byte> b(ouch50::out::AccountQueryResponse::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

std::vector<std::byte> accepted(UserRefNum u) {
  ouch50::out::OrderAccepted m;
  m.user_ref_num = u;
  m.side = ouch50::Side::Buy;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 1'000'000;
  m.time_in_force = ouch50::TimeInForce::Day;
  m.order_state = ouch50::OrderState::Live;
  std::vector<std::byte> b(ouch50::out::OrderAccepted::kMaxLen);
  b.resize(ouch50::encode(b, m));
  return b;
}

// No instance is connected, so every message stays pending and nothing is written: the
// test watches only what the responses release.
TEST(DST014, AnAccountQueryResponseReleasesNoEnterOrder) {
  HaOrderEntry e(OrderEntryConfig{});
  // The account consumed UserRefNums up to 9; the client resyncs, then enters order 10.
  ASSERT_TRUE(e.send(account_query(), 0));
  ASSERT_TRUE(e.send(enter(10), 0));  // queued in the node, not processed yet
  ASSERT_EQ(e.pending(), 2u);
  // The engine answers the query with NextUserRefNum 10 before it reaches order 10.
  e.on_response(account_query_response(10));
  EXPECT_GE(e.pending(), 1u) << "Enter Order 10 was released though the engine never saw it";
}

TEST(DST014, AQueryGoesWithTheMessagesBeforeTheNextResponse) {
  HaOrderEntry e(OrderEntryConfig{});
  ASSERT_TRUE(e.send(account_query(), 0));
  ASSERT_TRUE(e.send(enter(10), 0));
  ASSERT_TRUE(e.send(enter(11), 0));
  e.on_response(account_query_response(10));
  e.on_response(accepted(10));  // order 10 processed: the query before it was too
  EXPECT_EQ(e.pending(), 1u);
  e.on_response(accepted(11));
  EXPECT_EQ(e.pending(), 0u);
}

}  // namespace
}  // namespace lle::client

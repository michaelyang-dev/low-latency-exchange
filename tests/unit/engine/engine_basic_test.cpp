// Engine smoke and behavior tests (05-matching-engine §4). Byte-exact
// scenarios live in tests/golden/engine; these check state and structure.
#include <gtest/gtest.h>

#include "engine_test_util.h"

namespace lle::engine::testing {
namespace {

using ouch50::Side;
using ouch50::TimeInForce;

TEST_F(EngineFixture, ConfigEmitsStockDirectoryAndRegShoSpin) {
  ASSERT_EQ(setup_out_.size(), 6u);
  for (std::size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(setup_out_[i].dest, Dest::Itch);
    EXPECT_EQ(setup_out_[i].type(), 'R');
    const itch50::StockDirectoryView v(setup_out_[i].bytes.data());
    EXPECT_EQ(v.stock_locate(), i + 1);
    EXPECT_EQ(setup_out_[3 + i].type(), 'Y');  // Reg SHO state '0' (no restriction)
  }
  EXPECT_EQ(eng_.find_symbol(Symbol8("MSFT")), kMSFT);
  EXPECT_EQ(eng_.find_symbol(Symbol8("NOPE")), 0);
}

TEST_F(EngineFixture, RestThenFullFill) {
  auto o1 = a(enter_msg({.urn = 1, .side = Side::Sell, .qty = 300, .price = 1'000'100}));
  ASSERT_EQ(o1.size(), 2u);
  EXPECT_EQ(o1[0].type(), 'A');
  EXPECT_EQ(o1[1].type(), 'A');
  EXPECT_EQ(eng_.live_orders(), 1u);

  auto o2 = b(enter_msg({.urn = 1, .side = Side::Buy, .qty = 300, .price = 1'000'200}));
  ASSERT_EQ(o2.size(), 4u) << describe(o2);
  EXPECT_EQ(o2[0].type(), 'A');  // OUCH accepted first
  EXPECT_EQ(o2[1].session, kSessA);
  EXPECT_EQ(o2[1].type(), 'E');
  EXPECT_EQ(o2[2].session, kSessB);
  EXPECT_EQ(o2[3].dest, Dest::Itch);
  EXPECT_EQ(o2[3].type(), 'E');
  const ouch50::out::OrderExecutedView ex(o2[2].bytes);
  EXPECT_EQ(ex.price(), 1'000'100u);  // resting price
  EXPECT_EQ(ex.liquidity_flag(), ouch50::LiquidityFlag::Removed);
  EXPECT_EQ(eng_.live_orders(), 0u);
  EXPECT_EQ(eng_.next_match(), 2u);
}

TEST_F(EngineFixture, ResendIgnoredButCancelStillWorks) {
  (void)a(enter_msg({.urn = 5, .qty = 100}));
  auto dup = a(enter_msg({.urn = 5, .qty = 100}));
  EXPECT_TRUE(has_audit(dup, AuditCode::Resend));
  EXPECT_EQ(eng_.live_orders(), 1u);
  auto older = a(enter_msg({.urn = 4, .qty = 100}));
  EXPECT_TRUE(has_audit(older, AuditCode::Resend));
  auto c = a(cancel_msg(5, 0));
  ASSERT_EQ(c.size(), 2u);
  EXPECT_EQ(c[0].type(), 'C');
  EXPECT_EQ(c[1].type(), 'D');
  EXPECT_EQ(eng_.live_orders(), 0u);
}

TEST_F(EngineFixture, StateHashChangesAndSnapshotRoundTrips) {
  const std::uint64_t h0 = eng_.state_hash();
  (void)a(enter_msg({.urn = 1, .qty = 100}));
  (void)a(enter_msg({.urn = 2, .side = Side::Sell, .qty = 50, .price = 1'000'500}, tags_idx(3)));
  const std::uint64_t h1 = eng_.state_hash();
  EXPECT_NE(h0, h1);
  std::vector<std::byte> snap;
  eng_.snapshot(snap);
  EXPECT_EQ(Fnv1a64{}.value(), Fnv1a64::kOffset);
  Fnv1a64 f;
  f.bytes(snap);
  EXPECT_EQ(f.value(), h1);
  Engine e2;
  ASSERT_TRUE(e2.restore(snap));
  EXPECT_EQ(e2.state_hash(), h1);
  std::string err;
  EXPECT_TRUE(e2.check(&err)) << err;
  snap.pop_back();
  Engine e3;
  EXPECT_FALSE(e3.restore(snap));
}

}  // namespace
}  // namespace lle::engine::testing

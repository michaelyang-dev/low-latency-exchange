// The pre-registered T18 strategy (07 §3): triggers, the IOC Enter Order bytes,
// ClOrdID = MoldUDP64 sequence in decimal, strictly increasing UserRefNums.
#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "client/strategy.h"
#include "proto/itch50/itch50.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client {
namespace {

struct Out {
  UserRefNum urn = 100;
  bool accept = true;
  std::vector<std::vector<std::byte>> sent;
  UserRefNum next_urn() { return ++urn; }
  bool send(std::span<const std::byte> b) {
    if (!accept) return false;
    sent.emplace_back(b.begin(), b.end());
    return true;
  }
};

std::vector<std::byte> dir(Locate loc, const char* sym) {
  itch50::StockDirectory r;
  r.stock_locate = loc;
  r.stock = Symbol8(sym);
  std::vector<std::byte> b(itch50::StockDirectory::kLen);
  itch50::encode_unchecked(b.data(), r);
  return b;
}

std::vector<std::byte> add(Locate loc, Side s, PxE4 px, Qty q, bool mpid = false) {
  if (mpid) {
    itch50::AddOrderMpid a;
    a.stock_locate = loc;
    a.order_ref = 1;
    a.side = s;
    a.shares = q;
    a.price = px;
    a.attribution = Mpid4("ABCD");
    std::vector<std::byte> b(itch50::AddOrderMpid::kLen);
    itch50::encode_unchecked(b.data(), a);
    return b;
  }
  itch50::AddOrder a;
  a.stock_locate = loc;
  a.order_ref = 1;
  a.side = s;
  a.shares = q;
  a.price = px;
  std::vector<std::byte> b(itch50::AddOrder::kLen);
  itch50::encode_unchecked(b.data(), a);
  return b;
}

StrategyConfig cfg() {
  StrategyConfig c;
  c.symbol = Symbol8("AAPL");
  c.on_sell = true;
  c.sell_threshold = 1'500'000;  // $150.00
  c.on_buy = true;
  c.buy_threshold = 1'600'000;  // $160.00
  c.quantity = 200;
  return c;
}

TEST(Strategy, TriggersAtOrThroughTheThresholdOnly) {
  TriggerStrategy s(cfg());
  Out out;
  s.on_itch(1, dir(7, "AAPL"), out);
  ASSERT_TRUE(s.locate_known());
  EXPECT_EQ(s.locate(), 7);
  s.on_itch(2, add(7, Side::Sell, 1'500'100, 100), out);  // above the sell threshold
  s.on_itch(3, add(7, Side::Sell, 1'500'000, 100), out);  // at: trigger
  s.on_itch(4, add(7, Side::Sell, 1'400'000, 100, true), out);  // through (F): trigger
  s.on_itch(5, add(7, Side::Buy, 1'599'900, 100), out);   // below the buy threshold
  s.on_itch(6, add(7, Side::Buy, 1'600'000, 100), out);   // at: trigger
  s.on_itch(7, add(8, Side::Sell, 1, 100), out);          // another symbol
  EXPECT_EQ(s.stats().adds_seen, 5u);
  EXPECT_EQ(s.stats().triggers, 3u);
  ASSERT_EQ(out.sent.size(), 3u);
  // UserRefNum strictly increasing; side opposite to the trigger; IOC at the trigger price.
  const std::uint64_t want_px[3] = {1'500'000, 1'400'000, 1'600'000};
  const ouch50::Side want_side[3] = {ouch50::Side::Buy, ouch50::Side::Buy, ouch50::Side::Sell};
  const char* want_id[3] = {"3", "4", "6"};
  for (std::size_t i = 0; i < 3; ++i) {
    const auto v = ouch50::validate_inbound(out.sent[i]);
    ASSERT_TRUE(v.has_value()) << i;
    const auto m = ouch50::in::EnterOrder::decode_base(out.sent[i].data());
    EXPECT_EQ(m.user_ref_num, 101 + i);
    EXPECT_EQ(m.side, want_side[i]);
    EXPECT_EQ(m.price, want_px[i]);
    EXPECT_EQ(m.quantity, 200u);
    EXPECT_EQ(m.time_in_force, ouch50::TimeInForce::Ioc);
    EXPECT_EQ(m.symbol, Symbol8("AAPL"));
    EXPECT_EQ(m.cl_ord_id.view(), want_id[i]);
    EXPECT_EQ(m.inter_market_sweep_eligibility, ouch50::IsoEligibility::NotEligible);
    EXPECT_EQ(m.cross_type, ouch50::CrossType::Continuous);
  }
}

TEST(Strategy, NothingBeforeTheDirectoryAndSnapshotDirectoryCounts) {
  TriggerStrategy s(cfg());
  Out out;
  s.on_itch(1, add(7, Side::Sell, 1, 100), out);
  EXPECT_TRUE(out.sent.empty());
  s.on_directory(dir(9, "AAPL"));  // from a snapshot spin
  s.on_itch(2, add(9, Side::Sell, 1, 100), out);
  EXPECT_EQ(out.sent.size(), 1u);
}

TEST(Strategy, ClOrdIdIsTheFullDecimalSequenceAndQuantityZeroCopiesTheTrigger) {
  StrategyConfig c = cfg();
  c.quantity = 0;
  TriggerStrategy s(c);
  Out out;
  s.on_itch(1, dir(1, "AAPL"), out);
  s.on_itch(SeqNo{98'765'432'109'876}, add(1, Side::Sell, 10, 345), out);
  ASSERT_EQ(out.sent.size(), 1u);
  const auto m = ouch50::in::EnterOrder::decode_base(out.sent[0].data());
  EXPECT_EQ(m.cl_ord_id.view(), "98765432109876");
  EXPECT_EQ(m.quantity, 345u);
}

TEST(Strategy, GoldenBytes) {
  TriggerStrategy s(cfg());
  std::array<std::byte, TriggerStrategy::kEnterLen> b{};
  s.build(std::span<std::byte, TriggerStrategy::kEnterLen>(b), 0x01020304, 123, ouch50::Side::Buy, 0x64, 0x0102030405060708);
  const unsigned char want[] = {
      'O',  0x01, 0x02, 0x03, 0x04, 'B',  0x00, 0x00, 0x00, 0x64, 'A',  'A', 'P', 'L', ' ', ' ', ' ', ' ',
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, '3',  'Y',  'A',  'N', 'N', '1', '2', '3', ' ', ' ',
      ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  ' ',  0x00, 0x00};
  ASSERT_EQ(sizeof(want), b.size());
  for (std::size_t i = 0; i < b.size(); ++i) EXPECT_EQ(std::to_integer<unsigned char>(b[i]), want[i]) << "byte " << i;
}

TEST(Strategy, MaxOrdersAndRefusedSendsAreCounted) {
  StrategyConfig c = cfg();
  c.max_orders = 2;
  TriggerStrategy s(c);
  Out out;
  s.on_itch(1, dir(1, "AAPL"), out);
  for (SeqNo q = 2; q < 6; ++q) s.on_itch(q, add(1, Side::Sell, 1, 100), out);
  EXPECT_EQ(s.stats().orders, 2u);
  EXPECT_EQ(s.stats().suppressed, 2u);
  TriggerStrategy t(cfg());
  out.accept = false;
  t.on_itch(1, dir(1, "AAPL"), out);
  t.on_itch(2, add(1, Side::Sell, 1, 100), out);
  EXPECT_EQ(t.stats().send_failed, 1u);
  EXPECT_EQ(t.stats().orders, 0u);
}

}  // namespace
}  // namespace lle::client

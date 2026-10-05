// Golden vectors for all 25 OUCH 5.0 message types and all 26 tags (03-protocols
// s9, T07). Expected bytes are assembled by hand from the spec tables (OUCH 5.0
// rev 1.05 s2, s3, Appendix A); field offsets and widths are written out here,
// not taken from the generated layout.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <set>
#include <span>
#include <vector>

#include "proto/ouch50/ouch50.h"
#include "golden_util.h"

namespace lle::ouch50 {
namespace {

using test::B;
using test::Bytes;
using test::encode_plain;
using test::encode_with;
using test::to_hex;

constexpr std::uint64_t kTs = 34'200'000'000'123ull;  // 09:30:00.000000123 since midnight

std::span<const std::byte> sp(const Bytes& b) { return {b.data(), b.size()}; }

#define EXPECT_BYTES(actual, expected) EXPECT_EQ(to_hex(actual), to_hex(expected))

// ============================================================================ inbound (s2)

// R1b D3.2 example: UserRefIdx 5 encodes as 02 1C 05; an Enter Order carrying
// only that tag is 47 + 3 = 50 bytes with Appendage Length 3. Fully literal.
TEST(Ouch50Golden, EnterOrderWithUserRefIdxLiteral) {
  const Bytes expected = test::hexbytes({
      0x4F,                                            // Type 'O'
      0x00, 0x00, 0x00, 0x01,                          // UserRefNum 1
      0x42,                                            // Side 'B'
      0x00, 0x00, 0x00, 0x64,                          // Quantity 100
      0x41, 0x41, 0x50, 0x4C, 0x20, 0x20, 0x20, 0x20,  // Symbol "AAPL    "
      0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0xF0, 0xA8,  // Price 1503400 ($150.34)
      0x30,                                            // Time In Force '0' (Day)
      0x59,                                            // Display 'Y'
      0x41,                                            // Capacity 'A'
      0x4E,                                            // InterMarket Sweep Eligibility 'N'
      0x4E,                                            // CrossType 'N'
      0x43, 0x4C, 0x4F, 0x52, 0x44, 0x31, 0x20, 0x20,  // ClOrdID "CLORD1        "
      0x20, 0x20, 0x20, 0x20, 0x20, 0x20,              //
      0x00, 0x03,                                      // Appendage Length 3
      0x02, 0x1C, 0x05,                                // TagValue: len 2, tag 28 UserRefIdx, value 5
  });
  ASSERT_EQ(expected.size(), 50u);

  in::EnterOrder m;
  m.user_ref_num = 1;
  m.side = Side::Buy;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 1'503'400;
  m.time_in_force = TimeInForce::Day;
  m.display = Display::Visible;
  m.capacity = Capacity::Agency;
  m.inter_market_sweep_eligibility = IsoEligibility::NotEligible;
  m.cross_type = CrossType::Continuous;
  m.cl_ord_id = Alpha<14>("CLORD1");
  const Bytes got = encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 5); });
  EXPECT_BYTES(got, expected);

  // UserRefIdx 5 alone.
  std::array<std::byte, 8> tb{};
  TagValueWriter tw(tb);
  tw.put_u8(Tag::UserRefIdx, 5);
  EXPECT_BYTES(tw.bytes(), test::hexbytes({0x02, 0x1C, 0x05}));

  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->type(), 'O');
  EXPECT_TRUE(v->has_appendage_length());
  const auto o = v->as<in::EnterOrderView>();
  EXPECT_EQ(o.user_ref_num(), 1u);
  EXPECT_EQ(o.side(), Side::Buy);
  EXPECT_EQ(o.quantity(), 100u);
  EXPECT_EQ(o.symbol().view(), "AAPL");
  EXPECT_EQ(o.price(), 1'503'400u);
  EXPECT_EQ(o.time_in_force(), TimeInForce::Day);
  EXPECT_EQ(o.display(), Display::Visible);
  EXPECT_EQ(o.capacity(), Capacity::Agency);
  EXPECT_EQ(o.inter_market_sweep_eligibility(), IsoEligibility::NotEligible);
  EXPECT_EQ(o.cross_type(), CrossType::Continuous);
  EXPECT_EQ(o.cl_ord_id().view(), "CLORD1");
  EXPECT_EQ(o.appendage_length(), 3u);
  EXPECT_EQ(o.to_struct(), m);
  int n = 0;
  for (const TagValue& tv : o.tags()) {
    EXPECT_EQ(tv.tag, 28);
    EXPECT_EQ(tv.u8(), 5);
    ++n;
  }
  EXPECT_EQ(n, 1);
  EXPECT_EQ(peek_user_ref_idx(sp(expected)), 5);
  EXPECT_EQ(peek_new_user_ref_num(sp(expected)), 1u);
}

TEST(Ouch50Golden, EnterOrderNoTags) {
  // Appendage Length is "Req" on Enter Order: present and 0 with no tags (47 bytes).
  const Bytes expected = B()
                             .ch('O')
                             .be32(0x0A0B0C0D)
                             .ch('E')
                             .be32(999'999)
                             .alpha("BRK A", 8)
                             .be64(0x7FFFFFFF)
                             .ch('3')
                             .ch('N')
                             .ch('P')
                             .ch('Y')
                             .ch('O')
                             .alpha("ID-1", 14)
                             .be16(0);
  ASSERT_EQ(expected.size(), 47u);
  in::EnterOrder m;
  m.user_ref_num = 0x0A0B0C0D;
  m.side = Side::SellShortExempt;
  m.quantity = 999'999;
  m.symbol = Symbol8("BRK A");
  m.price = 0x7FFFFFFF;
  m.time_in_force = TimeInForce::Ioc;
  m.display = Display::Hidden;
  m.capacity = Capacity::Principal;
  m.inter_market_sweep_eligibility = IsoEligibility::Eligible;
  m.cross_type = CrossType::Opening;
  m.cl_ord_id = Alpha<14>("ID-1");
  EXPECT_BYTES(encode_plain(m), expected);
  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->as<in::EnterOrderView>().to_struct(), m);
  EXPECT_EQ(classify_price(v->as<in::EnterOrderView>().price()), PriceKind::Market);
}

TEST(Ouch50Golden, ReplaceOrder) {
  const Bytes expected = B()
                             .ch('U')
                             .be32(1)        // OrigUserRefNum (1/4)
                             .be32(2)        // UserRefNum (5/4)
                             .be32(500)      // Quantity (9/4)
                             .be64(1503500)  // Price (13/8)
                             .ch('6')        // TIF (21/1) GTT
                             .ch('A')        // Display (22/1)
                             .ch('N')        // ISO (23/1)
                             .alpha("REPL-2", 14)  // ClOrdID (24/14)
                             .be16(9)        // Appendage Length (38/2)
                             .hex({0x05, 0x0F, 0x00, 0x00, 0x0E, 0x10})  // ExpireTime 3600
                             .hex({0x02, 0x19, 0x4E});                   // SharesLocated 'N'
  ASSERT_EQ(expected.size(), 40u + 9u);
  in::ReplaceOrder m;
  m.orig_user_ref_num = 1;
  m.user_ref_num = 2;
  m.quantity = 500;
  m.price = 1'503'500;
  m.time_in_force = TimeInForce::Gtt;
  m.display = Display::Attributable;
  m.inter_market_sweep_eligibility = IsoEligibility::NotEligible;
  m.cl_ord_id = Alpha<14>("REPL-2");
  const Bytes got = encode_with(m, [](TagValueWriter& w) {
    w.put_u32(Tag::ExpireTime, 3600);
    w.put_enum(Tag::SharesLocated, SharesLocated::No);
  });
  EXPECT_BYTES(got, expected);
  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  const auto r = v->as<in::ReplaceOrderView>();
  EXPECT_EQ(r.orig_user_ref_num(), 1u);
  EXPECT_EQ(r.user_ref_num(), 2u);
  EXPECT_EQ(r.quantity(), 500u);
  EXPECT_EQ(r.price(), 1'503'500u);
  EXPECT_EQ(r.time_in_force(), TimeInForce::Gtt);
  EXPECT_EQ(r.display(), Display::Attributable);
  EXPECT_EQ(r.inter_market_sweep_eligibility(), IsoEligibility::NotEligible);
  EXPECT_EQ(r.cl_ord_id().view(), "REPL-2");
  EXPECT_EQ(r.to_struct(), m);
  TagSet ts;
  ASSERT_TRUE(parse_tags(r.tags(), ts));
  EXPECT_TRUE(ts.has(Tag::ExpireTime));
  EXPECT_EQ(ts.expire_time, 3600u);
  EXPECT_EQ(ts.shares_located, SharesLocated::No);
  EXPECT_EQ(peek_new_user_ref_num(sp(expected)), 2u);  // the replacement's UserRefNum
}

TEST(Ouch50Golden, CancelOrder) {
  // Appendage Length optional: 9 bytes without it.
  const Bytes bare = B().ch('X').be32(77).be32(0);
  in::CancelOrder m;
  m.user_ref_num = 77;
  m.quantity = 0;
  EXPECT_BYTES(encode_plain(m), bare);
  ASSERT_EQ(bare.size(), 9u);
  auto v = validate_inbound(sp(bare));
  ASSERT_TRUE(v.has_value());
  EXPECT_FALSE(v->has_appendage_length());
  EXPECT_EQ(v->as<in::CancelOrderView>().user_ref_num(), 77u);
  EXPECT_EQ(v->as<in::CancelOrderView>().quantity(), 0u);
  EXPECT_EQ(peek_new_user_ref_num(sp(bare)), std::nullopt);  // references an existing order

  // With UserRefIdx 7: 11 + 3 = 14 bytes.
  const Bytes tagged = B().ch('X').be32(77).be32(25).be16(3).hex({0x02, 0x1C, 0x07});
  m.quantity = 25;
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 7); }), tagged);
  v = validate_inbound(sp(tagged));
  ASSERT_TRUE(v.has_value());
  EXPECT_TRUE(v->has_appendage_length());
  EXPECT_EQ(peek_user_ref_idx(sp(tagged)), 7);

  // An explicit Appendage Length of 0 is also legal input (parse tolerantly).
  const Bytes zero = B().ch('X').be32(77).be32(25).be16(0);
  EXPECT_TRUE(validate_inbound(sp(zero)).has_value());
}

TEST(Ouch50Golden, ModifyOrder) {
  const Bytes bare = B().ch('M').be32(3).ch('T').be32(50);
  ASSERT_EQ(bare.size(), 10u);
  in::ModifyOrder m;
  m.user_ref_num = 3;
  m.side = Side::SellShort;
  m.quantity = 50;
  EXPECT_BYTES(encode_plain(m), bare);
  ASSERT_TRUE(validate_inbound(sp(bare)).has_value());

  const Bytes tagged = B()
                           .ch('M')
                           .be32(3)
                           .ch('T')
                           .be32(50)
                           .be16(9)
                           .hex({0x02, 0x19, 0x59})                    // SharesLocated 'Y'
                           .hex({0x05, 0x1A, 0x4C, 0x43, 0x54, 0x42});  // LocateBroker "LCTB"
  EXPECT_BYTES(encode_with(m,
                           [](TagValueWriter& w) {
                             w.put_enum(Tag::SharesLocated, SharesLocated::Yes);
                             w.put_alpha(Tag::LocateBroker, Alpha<4>("LCTB"));
                           }),
               tagged);
  auto v = validate_inbound(sp(tagged));
  ASSERT_TRUE(v.has_value());
  const auto mv = v->as<in::ModifyOrderView>();
  EXPECT_EQ(mv.side(), Side::SellShort);
  EXPECT_EQ(mv.quantity(), 50u);
  EXPECT_EQ(mv.to_struct(), m);
}

TEST(Ouch50Golden, MassCancel) {
  const Bytes expected = B()
                             .ch('C')
                             .be32(10)
                             .alpha("FIRM", 4)
                             .alpha("", 8)  // Symbol: spaces = all symbols
                             .be16(7)
                             .hex({0x03, 0x18, 0x00, 0x07})  // GroupID 7
                             .hex({0x02, 0x1B, 0x53});       // Side 'S'
  ASSERT_EQ(expected.size(), 26u);
  in::MassCancel m;
  m.user_ref_num = 10;
  m.firm = Mpid4("FIRM");
  m.symbol = Symbol8();
  TagSet ts;
  ts.set_group_id(7).set_side(Side::Sell);
  std::array<std::byte, 64> buf{};
  const std::size_t n = encode(std::span<std::byte>(buf), m, ts);
  EXPECT_BYTES(std::span<const std::byte>(buf.data(), n), expected);
  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  const auto c = v->as<in::MassCancelView>();
  EXPECT_EQ(c.user_ref_num(), 10u);
  EXPECT_EQ(c.firm().view(), "FIRM");
  EXPECT_TRUE(c.symbol().blank());
  TagSet back;
  ASSERT_TRUE(parse_tags(c.tags(), back));
  EXPECT_EQ(back, ts);
  EXPECT_EQ(peek_new_user_ref_num(sp(expected)), 10u);
}

TEST(Ouch50Golden, DisableOrderEntry) {
  const Bytes expected = B().ch('D').be32(11).alpha("FRMA", 4).be16(0);
  ASSERT_EQ(expected.size(), 11u);
  in::DisableOrderEntry m;
  m.user_ref_num = 11;
  m.firm = Mpid4("FRMA");
  EXPECT_BYTES(encode_plain(m), expected);
  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->as<in::DisableOrderEntryView>().firm().view(), "FRMA");
  EXPECT_EQ(peek_new_user_ref_num(sp(expected)), 11u);
}

TEST(Ouch50Golden, EnableOrderEntry) {
  const Bytes expected = B().ch('E').be32(12).alpha("FRMA", 4).be16(3).hex({0x02, 0x1C, 0x01});
  ASSERT_EQ(expected.size(), 14u);
  in::EnableOrderEntry m;
  m.user_ref_num = 12;
  m.firm = Mpid4("FRMA");
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 1); }), expected);
  auto v = validate_inbound(sp(expected));
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->as<in::EnableOrderEntryView>().user_ref_num(), 12u);
  EXPECT_EQ(peek_new_user_ref_num(sp(expected)), 12u);
}

TEST(Ouch50Golden, AccountQuery) {
  const Bytes bare = B().ch('Q');
  EXPECT_BYTES(encode_plain(in::AccountQuery{}), bare);
  ASSERT_TRUE(validate_inbound(sp(bare)).has_value());
  const Bytes tagged = B().ch('Q').be16(3).hex({0x02, 0x1C, 0x03});
  EXPECT_BYTES(encode_with(in::AccountQuery{}, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 3); }), tagged);
  ASSERT_TRUE(validate_inbound(sp(tagged)).has_value());
  EXPECT_EQ(peek_new_user_ref_num(sp(tagged)), std::nullopt);
}

// ============================================================================ outbound (s3)

template <class View>
View decode_out(const Bytes& b) {
  auto strict = validate_outbound(sp(b));
  EXPECT_TRUE(strict.has_value()) << (strict ? "" : std::string(to_string(strict.error().error)));
  auto v = OutboundDecoder::decode(sp(b));
  EXPECT_TRUE(v.has_value());
  EXPECT_EQ(v->type(), View::type());
  return v->template as<View>();
}

TEST(Ouch50Golden, SystemEvent) {
  const Bytes expected = B().ch('S').be64(kTs).ch('S');
  ASSERT_EQ(expected.size(), 10u);
  out::SystemEvent m;
  m.timestamp = kTs;
  m.event_code = EventCode::StartOfDay;
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::SystemEventView>(expected);
  EXPECT_EQ(v.timestamp(), kTs);
  EXPECT_EQ(v.event_code(), EventCode::StartOfDay);
  EXPECT_FALSE(v.has_appendage_length());
}

TEST(Ouch50Golden, OrderAccepted) {
  const Bytes expected = B()
                             .ch('A')
                             .be64(kTs)
                             .be32(1)            // UserRefNum (9/4)
                             .ch('B')            // Side (13/1)
                             .be32(100)          // Quantity (14/4)
                             .alpha("AAPL", 8)   // Symbol (18/8)
                             .be64(1503400)      // Price (26/8)
                             .ch('0')            // TIF (34/1)
                             .ch('Z')            // Display (35/1) conformant (outbound only)
                             .be64(123456789)    // Order Reference Number (36/8)
                             .ch('A')            // Capacity (44/1)
                             .ch('N')            // ISO (45/1)
                             .ch('C')            // CrossType (46/1)
                             .ch('L')            // Order State (47/1)
                             .alpha("CLORD1", 14)  // ClOrdID (48/14)
                             .be16(21)           // Appendage Length (62/2) = 6 + 3 + 6 + 3 + 3
                             .hex({0x05, 0x02, 0x46, 0x49, 0x52, 0x4D})  // Firm "FIRM"
                             .hex({0x02, 0x06, 0x4C})                    // PriceType 'L'
                             .hex({0x05, 0x0E, 0x52, 0x54, 0x45, 0x31})  // Route "RTE1"
                             .hex({0x02, 0x12, 0x32})                    // BBO Weight Indicator '2'
                             .hex({0x02, 0x1C, 0x05});                   // UserRefIdx 5
  ASSERT_EQ(expected.size(), 64u + 21u);
  out::OrderAccepted m;
  m.timestamp = kTs;
  m.user_ref_num = 1;
  m.side = Side::Buy;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 1'503'400;
  m.time_in_force = TimeInForce::Day;
  m.display = Display::Conformant;
  m.order_reference_number = 123'456'789;
  m.capacity = Capacity::Agency;
  m.inter_market_sweep_eligibility = IsoEligibility::NotEligible;
  m.cross_type = CrossType::Closing;
  m.order_state = OrderState::Live;
  m.cl_ord_id = Alpha<14>("CLORD1");
  TagSet ts;
  ts.set_firm(Mpid4("FIRM"))
      .set_price_type(PriceType::Limit)
      .set_route(Alpha<4>("RTE1"))
      .set_bbo_weight_indicator(BboWeightIndicator::Range1To2)
      .set_user_ref_idx(5);
  std::array<std::byte, 256> buf{};
  const std::size_t n = encode(std::span<std::byte>(buf), m, ts);
  EXPECT_BYTES(std::span<const std::byte>(buf.data(), n), expected);
  const auto v = decode_out<out::OrderAcceptedView>(expected);
  EXPECT_EQ(v.timestamp(), kTs);
  EXPECT_EQ(v.user_ref_num(), 1u);
  EXPECT_EQ(v.side(), Side::Buy);
  EXPECT_EQ(v.quantity(), 100u);
  EXPECT_EQ(v.symbol().view(), "AAPL");
  EXPECT_EQ(v.price(), 1'503'400u);
  EXPECT_EQ(v.time_in_force(), TimeInForce::Day);
  EXPECT_EQ(v.display(), Display::Conformant);
  EXPECT_EQ(v.order_reference_number(), 123'456'789u);
  EXPECT_EQ(v.capacity(), Capacity::Agency);
  EXPECT_EQ(v.inter_market_sweep_eligibility(), IsoEligibility::NotEligible);
  EXPECT_EQ(v.cross_type(), CrossType::Closing);
  EXPECT_EQ(v.order_state(), OrderState::Live);
  EXPECT_EQ(v.cl_ord_id().view(), "CLORD1");
  EXPECT_EQ(v.to_struct(), m);
  TagSet back;
  ASSERT_TRUE(parse_tags(v.tags(), back));
  EXPECT_EQ(back, ts);
}

TEST(Ouch50Golden, OrderReplaced) {
  const Bytes expected = B()
                             .ch('U')
                             .be64(kTs)
                             .be32(1)            // OrigUserRefNum (9/4)
                             .be32(2)            // UserRefNum (13/4)
                             .ch('S')            // Side (17/1)
                             .be32(400)          // Quantity (18/4)
                             .alpha("MSFT", 8)   // Symbol (22/8)
                             .be64(4000000)      // Price (30/8)
                             .ch('3')            // TIF (38/1)
                             .ch('N')            // Display (39/1)
                             .be64(123456790)    // Order Reference Number (40/8)
                             .ch('P')            // Capacity (48/1)
                             .ch('N')            // ISO (49/1)
                             .ch('N')            // CrossType (50/1)
                             .ch('D')            // Order State (51/1)
                             .alpha("CLORD2", 14)  // ClOrdID (52/14)
                             .be16(0);           // Appendage Length (66/2), Req
  ASSERT_EQ(expected.size(), 68u);
  out::OrderReplaced m;
  m.timestamp = kTs;
  m.orig_user_ref_num = 1;
  m.user_ref_num = 2;
  m.side = Side::Sell;
  m.quantity = 400;
  m.symbol = Symbol8("MSFT");
  m.price = 4'000'000;
  m.time_in_force = TimeInForce::Ioc;
  m.display = Display::Hidden;
  m.order_reference_number = 123'456'790;
  m.capacity = Capacity::Principal;
  m.inter_market_sweep_eligibility = IsoEligibility::NotEligible;
  m.cross_type = CrossType::Continuous;
  m.order_state = OrderState::Dead;
  m.cl_ord_id = Alpha<14>("CLORD2");
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::OrderReplacedView>(expected);
  EXPECT_EQ(v.orig_user_ref_num(), 1u);
  EXPECT_EQ(v.user_ref_num(), 2u);
  EXPECT_EQ(v.order_state(), OrderState::Dead);
  EXPECT_EQ(v.to_struct(), m);
}

TEST(Ouch50Golden, OrderCanceled) {
  // Opt*: no appendage unless the order carries a non-zero UserRefIdx.
  const Bytes bare = B().ch('C').be64(kTs).be32(2).be32(100).ch('U');
  ASSERT_EQ(bare.size(), 18u);
  out::OrderCanceled m;
  m.timestamp = kTs;
  m.user_ref_num = 2;
  m.quantity = 100;
  m.reason = CancelReason::UserRequested;
  EXPECT_BYTES(encode_plain(m), bare);
  EXPECT_EQ(decode_out<out::OrderCanceledView>(bare).reason(), CancelReason::UserRequested);

  // UserRefIdx 0 means "no channel": still omitted.
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 0); }), bare);

  const Bytes tagged = B().ch('C').be64(kTs).be32(2).be32(100).ch('U').be16(3).hex({0x02, 0x1C, 0x05});
  ASSERT_EQ(tagged.size(), 23u);
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 5); }), tagged);
  const auto v = decode_out<out::OrderCanceledView>(tagged);
  EXPECT_EQ(v.user_ref_num(), 2u);
  EXPECT_EQ(v.quantity(), 100u);
  EXPECT_EQ(v.to_struct(), m);
}

TEST(Ouch50Golden, AiqCanceled) {
  const Bytes expected = B()
                             .ch('D')
                             .be64(kTs)
                             .be32(4)        // UserRefNum (9/4)
                             .be32(100)      // Decrement Shares (13/4)
                             .ch('Q')        // Reason (17/1), always 'Q'
                             .be32(60)       // Quantity Prevented From Trading (18/4)
                             .be64(1503400)  // Execution Price (22/8)
                             .ch('R')        // Liquidity Flag (30/1)
                             .ch('O');       // AIQ Strategy (31/1)
  ASSERT_EQ(expected.size(), 32u);
  out::AiqCanceled m;
  m.timestamp = kTs;
  m.user_ref_num = 4;
  m.decrement_shares = 100;
  m.reason = CancelReason::SelfMatchPrevention;
  m.quantity_prevented_from_trading = 60;
  m.execution_price = 1'503'400;
  m.liquidity_flag = LiquidityFlag::Removed;
  m.aiq_strategy = AiqStrategy::FirmCancelOldest;
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::AiqCanceledView>(expected);
  EXPECT_EQ(v.decrement_shares(), 100u);
  EXPECT_EQ(v.quantity_prevented_from_trading(), 60u);
  EXPECT_EQ(v.execution_price(), 1'503'400u);
  EXPECT_EQ(v.liquidity_flag(), LiquidityFlag::Removed);
  EXPECT_EQ(v.aiq_strategy(), AiqStrategy::FirmCancelOldest);
  EXPECT_EQ(v.to_struct(), m);
  // Reason other than 'Q' violates the field definition.
  m.reason = CancelReason::UserRequested;
  const auto bad = validate_outbound(sp(encode_plain(m)));
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.error().error, Error::BadFieldValue);
  EXPECT_EQ(bad.error().offset, 17);
}

TEST(Ouch50Golden, OrderExecuted) {
  // Appendage Length is not marked optional on 'E': always emitted (R1b risk 2).
  const Bytes expected = B()
                             .ch('E')
                             .be64(kTs)
                             .be32(1)          // UserRefNum (9/4)
                             .be32(100)        // Quantity (13/4)
                             .be64(1503400)    // Price (17/8)
                             .ch('A')          // Liquidity Flag (25/1)
                             .be64(987654321)  // Match Number (26/8)
                             .be16(0);         // Appendage Length (34/2)
  ASSERT_EQ(expected.size(), 36u);
  out::OrderExecuted m;
  m.timestamp = kTs;
  m.user_ref_num = 1;
  m.quantity = 100;
  m.price = 1'503'400;
  m.liquidity_flag = LiquidityFlag::Added;
  m.match_number = 987'654'321;
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::OrderExecutedView>(expected);
  EXPECT_EQ(v.match_number(), 987'654'321u);
  EXPECT_EQ(v.liquidity_flag(), LiquidityFlag::Added);
  EXPECT_EQ(v.to_struct(), m);
  // Parse tolerantly: a 34-byte 'E' without Appendage Length decodes...
  const Bytes legacy(expected.begin(), expected.end() - 2);
  ASSERT_TRUE(OutboundDecoder::decode(sp(legacy)).has_value());
  // ...but is not what we emit.
  const auto strict = validate_outbound(sp(legacy));
  ASSERT_FALSE(strict.has_value());
  EXPECT_EQ(strict.error().error, Error::TooShort);
}

TEST(Ouch50Golden, BrokenTrade) {
  const Bytes expected = B().ch('B').be64(kTs).be32(1).be64(987654321).ch('E').alpha("CLORD1", 14);
  ASSERT_EQ(expected.size(), 36u);
  out::BrokenTrade m;
  m.timestamp = kTs;
  m.user_ref_num = 1;
  m.match_number = 987'654'321;
  m.reason = BrokenTradeReason::Erroneous;
  m.cl_ord_id = Alpha<14>("CLORD1");
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::BrokenTradeView>(expected);
  EXPECT_EQ(v.match_number(), 987'654'321u);
  EXPECT_EQ(v.reason(), BrokenTradeReason::Erroneous);
  EXPECT_EQ(v.cl_ord_id().view(), "CLORD1");
}

TEST(Ouch50Golden, Rejected) {
  const Bytes bare = B().ch('J').be64(kTs).be32(9).be16(0x001D).alpha("BADPX", 14);
  ASSERT_EQ(bare.size(), 29u);
  out::Rejected m;
  m.timestamp = kTs;
  m.user_ref_num = 9;
  m.reason = RejectReason::InvalidPrice;
  m.cl_ord_id = Alpha<14>("BADPX");
  EXPECT_BYTES(encode_plain(m), bare);
  EXPECT_EQ(decode_out<out::RejectedView>(bare).reason(), RejectReason::InvalidPrice);
  const Bytes tagged = B().append(bare).be16(3).hex({0x02, 0x1C, 0x02});
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 2); }), tagged);
  EXPECT_EQ(decode_out<out::RejectedView>(tagged).user_ref_num(), 9u);
  // An unassigned u16 code is not a valid Reason.
  m.reason = static_cast<RejectReason>(0x0034);
  const auto bad = validate_outbound(sp(encode_plain(m)));
  ASSERT_FALSE(bad.has_value());
  EXPECT_EQ(bad.error().error, Error::BadFieldValue);
  EXPECT_EQ(bad.error().offset, 13);
}

TEST(Ouch50Golden, CancelPending) {
  const Bytes expected = B().ch('P').be64(kTs).be32(5);
  ASSERT_EQ(expected.size(), 13u);
  out::CancelPending m;
  m.timestamp = kTs;
  m.user_ref_num = 5;
  EXPECT_BYTES(encode_plain(m), expected);
  EXPECT_EQ(decode_out<out::CancelPendingView>(expected).user_ref_num(), 5u);
}

TEST(Ouch50Golden, CancelReject) {
  const Bytes expected = B().ch('I').be64(kTs).be32(6).be16(3).hex({0x02, 0x1C, 0x09});
  ASSERT_EQ(expected.size(), 18u);
  out::CancelReject m;
  m.timestamp = kTs;
  m.user_ref_num = 6;
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 9); }), expected);
  EXPECT_EQ(decode_out<out::CancelRejectView>(expected).user_ref_num(), 6u);
}

TEST(Ouch50Golden, OrderPriorityUpdate) {
  const Bytes expected = B().ch('T').be64(kTs).be32(7).be64(1503300).ch('Y').be64(555);
  ASSERT_EQ(expected.size(), 30u);
  out::OrderPriorityUpdate m;
  m.timestamp = kTs;
  m.user_ref_num = 7;
  m.price = 1'503'300;
  m.display = Display::Visible;
  m.order_reference_number = 555;
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::OrderPriorityUpdateView>(expected);
  EXPECT_EQ(v.price(), 1'503'300u);
  EXPECT_EQ(v.order_reference_number(), 555u);
}

TEST(Ouch50Golden, OrderModified) {
  const Bytes bare = B().ch('M').be64(kTs).be32(3).ch('E').be32(50);
  ASSERT_EQ(bare.size(), 18u);
  out::OrderModified m;
  m.timestamp = kTs;
  m.user_ref_num = 3;
  m.side = Side::SellShortExempt;
  m.quantity = 50;
  EXPECT_BYTES(encode_plain(m), bare);
  // SharesLocated alone does not open the appendage on an Opt* type.
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_enum(Tag::SharesLocated, SharesLocated::Yes); }), bare);
  const Bytes tagged = B().append(bare).be16(6).hex({0x02, 0x19, 0x59}).hex({0x02, 0x1C, 0x04});
  EXPECT_BYTES(encode_with(m,
                           [](TagValueWriter& w) {
                             w.put_enum(Tag::SharesLocated, SharesLocated::Yes);
                             w.put_u8(Tag::UserRefIdx, 4);
                           }),
               tagged);
  const auto v = decode_out<out::OrderModifiedView>(tagged);
  EXPECT_EQ(v.side(), Side::SellShortExempt);
  EXPECT_EQ(v.quantity(), 50u);
}

TEST(Ouch50Golden, OrderRestated) {
  const Bytes expected = B()
                             .ch('R')
                             .be64(kTs)
                             .be32(8)
                             .ch('R')
                             .be16(16)
                             .hex({0x09, 0x01, 0, 0, 0, 0, 0, 0, 0x03, 0x09})  // SecondaryOrdRefNum 777
                             .hex({0x05, 0x16, 0, 0, 0, 0x64});                // Display Quantity 100
  ASSERT_EQ(expected.size(), 32u);
  out::OrderRestated m;
  m.timestamp = kTs;
  m.user_ref_num = 8;
  m.reason = RestatedReason::DisplayRefresh;
  TagSet ts;
  ts.set_secondary_ord_ref_num(777).set_display_quantity(100);
  std::array<std::byte, 64> buf{};
  const std::size_t n = encode(std::span<std::byte>(buf), m, ts);
  EXPECT_BYTES(std::span<const std::byte>(buf.data(), n), expected);
  const auto v = decode_out<out::OrderRestatedView>(expected);
  EXPECT_EQ(v.reason(), RestatedReason::DisplayRefresh);
  TagSet back;
  ASSERT_TRUE(parse_tags(v.tags(), back));
  EXPECT_EQ(back.secondary_ord_ref_num, 777u);
  EXPECT_EQ(back.display_quantity, 100u);
}

TEST(Ouch50Golden, MassCancelResponse) {
  const Bytes expected = B().ch('X').be64(kTs).be32(10).alpha("FIRM", 4).alpha("MSFT", 8).be16(0);
  ASSERT_EQ(expected.size(), 27u);
  out::MassCancelResponse m;
  m.timestamp = kTs;
  m.user_ref_num = 10;
  m.firm = Mpid4("FIRM");
  m.symbol = Symbol8("MSFT");
  EXPECT_BYTES(encode_plain(m), expected);
  const auto v = decode_out<out::MassCancelResponseView>(expected);
  EXPECT_EQ(v.symbol().view(), "MSFT");
  EXPECT_EQ(v.firm().view(), "FIRM");
}

TEST(Ouch50Golden, DisableOrderEntryResponse) {
  const Bytes expected = B().ch('G').be64(kTs).be32(11).alpha("FRMA", 4).be16(0);
  ASSERT_EQ(expected.size(), 19u);
  out::DisableOrderEntryResponse m;
  m.timestamp = kTs;
  m.user_ref_num = 11;
  m.firm = Mpid4("FRMA");
  EXPECT_BYTES(encode_plain(m), expected);
  EXPECT_EQ(decode_out<out::DisableOrderEntryResponseView>(expected).user_ref_num(), 11u);
}

TEST(Ouch50Golden, EnableOrderEntryResponse) {
  const Bytes expected = B().ch('K').be64(kTs).be32(12).alpha("FRMA", 4).be16(3).hex({0x02, 0x1C, 0x01});
  ASSERT_EQ(expected.size(), 22u);
  out::EnableOrderEntryResponse m;
  m.timestamp = kTs;
  m.user_ref_num = 12;
  m.firm = Mpid4("FRMA");
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 1); }), expected);
  EXPECT_EQ(decode_out<out::EnableOrderEntryResponseView>(expected).firm().view(), "FRMA");
}

TEST(Ouch50Golden, AccountQueryResponse) {
  const Bytes bare = B().ch('Q').be64(kTs).be32(13);
  ASSERT_EQ(bare.size(), 13u);
  out::AccountQueryResponse m;
  m.timestamp = kTs;
  m.next_user_ref_num = 13;
  EXPECT_BYTES(encode_plain(m), bare);
  EXPECT_EQ(decode_out<out::AccountQueryResponseView>(bare).next_user_ref_num(), 13u);
  const Bytes tagged = B().append(bare).be16(3).hex({0x02, 0x1C, 0x03});
  EXPECT_BYTES(encode_with(m, [](TagValueWriter& w) { w.put_u8(Tag::UserRefIdx, 3); }), tagged);
  EXPECT_EQ(decode_out<out::AccountQueryResponseView>(tagged).next_user_ref_num(), 13u);
}

// Direction typing: the same bytes mean different messages in each direction.
TEST(Ouch50Golden, DirectionTypedDecoding) {
  // 'E' inbound = Enable Order Entry (11 bytes); outbound = Order Executed (36).
  const Bytes enable = B().ch('E').be32(12).alpha("FRMA", 4).be16(0);
  EXPECT_TRUE(InboundDecoder::decode(sp(enable)).has_value());
  const auto as_out = OutboundDecoder::decode(sp(enable));
  ASSERT_FALSE(as_out.has_value());
  EXPECT_EQ(as_out.error().error, Error::TooShort);
  // Letters that exist in one direction only.
  EXPECT_EQ(InboundDecoder::decode(sp(B().ch('A').be64(0))).error().error, Error::UnknownType);
  EXPECT_EQ(OutboundDecoder::decode(sp(B().ch('O').be64(0))).error().error, Error::UnknownType);
}

// ============================================================================ tags (Appendix A)

struct TagCase {
  std::uint8_t tag;
  Bytes element;  // hand-assembled [len][tag][value]
};

std::vector<TagCase> all_tag_cases() {
  using test::hexbytes;
  return {
      {1, hexbytes({0x09, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})},  // SecondaryOrdRefNum
      {2, hexbytes({0x05, 0x02, 'A', 'B', 'C', 'D'})},                             // Firm "ABCD"
      {3, hexbytes({0x05, 0x03, 0x00, 0x00, 0x00, 0xC8})},                         // MinQty 200
      {4, hexbytes({0x02, 0x04, 'R'})},                                            // CustomerType R
      {5, hexbytes({0x05, 0x05, 0x00, 0x00, 0x00, 0x64})},                         // MaxFloor 100
      {6, hexbytes({0x02, 0x06, 'M'})},                                            // PriceType M
      {7, hexbytes({0x05, 0x07, 0xFF, 0xFF, 0xFF, 0x9C})},                         // PegOffset -100
      {9, hexbytes({0x09, 0x09, 0, 0, 0, 0, 0x00, 0x16, 0xE3, 0x60})},             // DiscretionPrice 1500000
      {10, hexbytes({0x02, 0x0A, 'P'})},                                           // DiscretionPriceType P
      {11, hexbytes({0x05, 0x0B, 0xFF, 0xFF, 0xFF, 0xFF})},                        // DiscretionPegOffset -1
      {12, hexbytes({0x02, 0x0C, 'P'})},                                           // PostOnly P
      {13, hexbytes({0x05, 0x0D, 0x00, 0x00, 0x01, 0x2C})},                        // RandomReserves 300
      {14, hexbytes({0x05, 0x0E, 'R', 'T', 'E', '1'})},                            // Route "RTE1"
      {15, hexbytes({0x05, 0x0F, 0x00, 0x00, 0x0E, 0x10})},                        // ExpireTime 3600
      {16, hexbytes({0x02, 0x10, 'Y'})},                                           // TradeNow Y
      {17, hexbytes({0x02, 0x11, 'I'})},                                           // HandleInst I
      {18, hexbytes({0x02, 0x12, '2'})},                                           // BBO Weight Indicator 2
      {22, hexbytes({0x05, 0x16, 0x00, 0x00, 0x00, 0x64})},                        // Display Quantity 100
      {23, hexbytes({0x09, 0x17, 0, 0, 0, 0, 0x00, 0x16, 0xF0, 0xA8})},            // Display Price 1503400
      {24, hexbytes({0x03, 0x18, 0x02, 0x01})},                                    // Group ID 513
      {25, hexbytes({0x02, 0x19, 'Y'})},                                           // Shares Located Y
      {26, hexbytes({0x05, 0x1A, 'L', 'C', 'T', 'B'})},                            // Locate Broker "LCTB"
      {27, hexbytes({0x02, 0x1B, 'T'})},                                           // Side T
      {28, hexbytes({0x02, 0x1C, 0x05})},                                          // UserRefIdx 5
      {29, hexbytes({0x02, 0x1D, 'O'})},                                           // AIQ Strategy O
      {30, hexbytes({0x03, 0x1E, 'A', 'B'})},                                      // AIQ Group ID "AB"
  };
}

// The same values, set through the typed TagSet.
TagSet tag_value_for(std::uint8_t tag) {
  TagSet s;
  switch (tag) {
    case 1: s.set_secondary_ord_ref_num(0x0102030405060708ull); break;
    case 2: s.set_firm(Mpid4("ABCD")); break;
    case 3: s.set_min_qty(200); break;
    case 4: s.set_customer_type(CustomerType::RetailDesignated); break;
    case 5: s.set_max_floor(100); break;
    case 6: s.set_price_type(PriceType::MidpointPeg); break;
    case 7: s.set_peg_offset(-100); break;
    case 9: s.set_discretion_price(1'500'000); break;
    case 10: s.set_discretion_price_type(DiscretionPriceType::MarketPeg); break;
    case 11: s.set_discretion_peg_offset(-1); break;
    case 12: s.set_post_only(PostOnly::PostOnly); break;
    case 13: s.set_random_reserves(300); break;
    case 14: s.set_route(Alpha<4>("RTE1")); break;
    case 15: s.set_expire_time(3600); break;
    case 16: s.set_trade_now(TradeNow::Yes); break;
    case 17: s.set_handle_inst(HandleInst::ImbalanceOnly); break;
    case 18: s.set_bbo_weight_indicator(BboWeightIndicator::Range1To2); break;
    case 22: s.set_display_quantity(100); break;
    case 23: s.set_display_price(1'503'400); break;
    case 24: s.set_group_id(513); break;
    case 25: s.set_shares_located(SharesLocated::Yes); break;
    case 26: s.set_locate_broker(Alpha<4>("LCTB")); break;
    case 27: s.set_side(Side::SellShort); break;
    case 28: s.set_user_ref_idx(5); break;
    case 29: s.set_aiq_strategy(AiqStrategy::FirmCancelOldest); break;
    case 30: s.set_aiq_group_id(Alpha<2>("AB")); break;
    default: ADD_FAILURE() << "no tag " << int{tag};
  }
  return s;
}

// Tag sizes from Appendix A ("Size" column), written out independently.
constexpr std::array<std::pair<int, int>, 26> kSpecTagSizes = {{
    {1, 8},  {2, 4},  {3, 4},  {4, 1},  {5, 4},  {6, 1},  {7, 4},  {9, 8},  {10, 1}, {11, 4}, {12, 1}, {13, 4}, {14, 4},
    {15, 4}, {16, 1}, {17, 1}, {18, 1}, {22, 4}, {23, 8}, {24, 2}, {25, 1}, {26, 4}, {27, 1}, {28, 1}, {29, 1}, {30, 2},
}};

TEST(Ouch50Golden, TagRegistryMatchesAppendixA) {
  std::set<int> known;
  for (auto [tag, size] : kSpecTagSizes) {
    const TagDesc* d = find_tag(static_cast<std::uint8_t>(tag));
    ASSERT_NE(d, nullptr) << tag;
    EXPECT_EQ(d->value_len, size) << tag;
    known.insert(tag);
  }
  EXPECT_EQ(kTagCount, 26u);
  for (int t = 0; t < 256; ++t)
    if (!known.contains(t)) EXPECT_EQ(find_tag(static_cast<std::uint8_t>(t)), nullptr) << t;
}

TEST(Ouch50Golden, AllTagsEncodeAndDecode) {
  const auto cases = all_tag_cases();
  ASSERT_EQ(cases.size(), 26u);
  for (const auto& c : cases) {
    SCOPED_TRACE(int{c.tag});
    const TagSet ts = tag_value_for(c.tag);
    // TagSet -> bytes.
    std::array<std::byte, 32> buf{};
    TagValueWriter w(buf);
    put_tags(w, ts);
    ASSERT_FALSE(w.overflow());
    EXPECT_BYTES(w.bytes(), c.element);
    // bytes -> element -> TagSet.
    TagValueRange range(sp(c.element));
    int n = 0;
    for (const TagValue& tv : range) {
      EXPECT_EQ(tv.tag, c.tag);
      EXPECT_EQ(tv.value.size(), c.element.size() - 2);
      EXPECT_EQ(tv.offset, 0u);
      ++n;
    }
    EXPECT_EQ(n, 1);
    TagSet back;
    ASSERT_TRUE(parse_tags(range, back));
    EXPECT_EQ(back, ts);
  }
}

TEST(Ouch50Golden, TypedTagReads) {
  const auto cases = all_tag_cases();
  auto first = [&](int tag) { return *TagValueRange(sp(cases[static_cast<std::size_t>(tag)].element)).begin(); };
  // Index into `cases` (ordered by tag, skipping 8 and 19-21).
  EXPECT_EQ(first(0).u64(), 0x0102030405060708ull);
  EXPECT_EQ(first(1).alpha<4>().view(), "ABCD");
  EXPECT_EQ(first(2).u32(), 200u);
  EXPECT_EQ(first(6).i32(), -100);
  EXPECT_EQ(first(9).i32(), -1);
  EXPECT_EQ(first(19).u16(), 513u);
  EXPECT_EQ(first(23).u8(), 5u);
  EXPECT_EQ(first(24).ch(), 'O');
}

// Every tag embedded in a message that allows it validates strictly.
TEST(Ouch50Golden, AllTagsValidateInAllowingMessages) {
  for (const auto& c : all_tag_cases()) {
    SCOPED_TRACE(int{c.tag});
    bool tested = false;
    if (layout::in::EnterOrder::kAllowedTags & (1u << c.tag)) {
      const Bytes msg = B()
                            .ch('O')
                            .be32(1)
                            .ch('B')
                            .be32(100)
                            .alpha("AAPL", 8)
                            .be64(1503400)
                            .ch('0')
                            .ch('Y')
                            .ch('A')
                            .ch('N')
                            .ch('N')
                            .alpha("X", 14)
                            .be16(static_cast<std::uint16_t>(c.element.size()))
                            .append(c.element);
      EXPECT_TRUE(validate_inbound(sp(msg)).has_value());
      tested = true;
    }
    if (layout::in::MassCancel::kAllowedTags & (1u << c.tag)) {
      const Bytes msg = B()
                            .ch('C')
                            .be32(1)
                            .alpha("FIRM", 4)
                            .alpha("", 8)
                            .be16(static_cast<std::uint16_t>(c.element.size()))
                            .append(c.element);
      EXPECT_TRUE(validate_inbound(sp(msg)).has_value());
      tested = true;
    }
    if (layout::out::OrderAccepted::kAllowedTags & (1u << c.tag)) {
      const Bytes msg = B()
                            .ch('A')
                            .be64(kTs)
                            .be32(1)
                            .ch('B')
                            .be32(100)
                            .alpha("AAPL", 8)
                            .be64(1503400)
                            .ch('0')
                            .ch('Y')
                            .be64(1)
                            .ch('A')
                            .ch('N')
                            .ch('N')
                            .ch('L')
                            .alpha("X", 14)
                            .be16(static_cast<std::uint16_t>(c.element.size()))
                            .append(c.element);
      EXPECT_TRUE(validate_outbound(sp(msg)).has_value());
      tested = true;
    }
    if (layout::out::OrderRestated::kAllowedTags & (1u << c.tag)) {
      const Bytes msg = B()
                            .ch('R')
                            .be64(kTs)
                            .be32(1)
                            .ch('P')
                            .be16(static_cast<std::uint16_t>(c.element.size()))
                            .append(c.element);
      EXPECT_TRUE(validate_outbound(sp(msg)).has_value());
      tested = true;
    }
    EXPECT_TRUE(tested);
  }
}

// ============================================================================ allowed-tag matrix

// Allowed-tag lists transcribed from the "available options" lists of each
// message section in the spec text (independently of the CSV).
struct AllowedCase {
  Direction dir;
  char type;
  std::vector<int> tags;
};

const std::vector<AllowedCase>& spec_allowed() {
  static const std::vector<AllowedCase> k = {
      // s2.1 Firm MinQty CustomerType MaxFloor PriceType PegOffset DiscretionPrice DiscretionPriceType
      // DiscretionPegOffset PostOnly RandomReserves ExpireTime TradeNow HandleInst GroupID SharesLocated
      // LocateBroker UserRefIdx AIQStrategy AIQGroupID
      {Direction::Inbound, 'O', {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 16, 17, 24, 25, 26, 28, 29, 30}},
      // s2.2 MinQty MaxFloor PriceType PostOnly ExpireTime TradeNow HandleInst RandomReserves PegOffset
      // DiscretionPrice DiscretionPriceType DiscretionPegOffset SharesLocated LocateBroker UserRefIdx Side
      // AIQStrategy AIQGroupID
      {Direction::Inbound, 'U', {3, 5, 6, 12, 15, 16, 17, 13, 7, 9, 10, 11, 25, 26, 28, 27, 29, 30}},
      {Direction::Inbound, 'X', {28}},
      {Direction::Inbound, 'M', {28, 25, 26}},
      {Direction::Inbound, 'C', {27, 24, 28}},
      {Direction::Inbound, 'D', {28}},
      {Direction::Inbound, 'E', {28}},
      {Direction::Inbound, 'Q', {28}},
      {Direction::Outbound, 'S', {}},
      // s3.2 Firm MinQty CustomerType MaxFloor PriceType PegOffset DiscretionPrice DiscretionPriceType
      // DiscretionPegOffset PostOnly RandomReserves Route ExpireTime TradeNow HandleInst BBOWeightIndicator
      // GroupID SharesLocated UserRefIdx AIQStrategy AIQGroupID
      {Direction::Outbound, 'A', {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 28, 29, 30}},
      // s3.3 Firm MinQty MaxFloor PriceType PostOnly ExpireTime TradeNow HandleInst BBOWeightIndicator
      // UserRefIdx AIQStrategy AIQGroupID
      {Direction::Outbound, 'U', {2, 3, 5, 6, 12, 15, 16, 17, 18, 28, 29, 30}},
      {Direction::Outbound, 'C', {28}},
      {Direction::Outbound, 'D', {28}},
      {Direction::Outbound, 'E', {28}},
      {Direction::Outbound, 'B', {28}},
      {Direction::Outbound, 'J', {28}},
      {Direction::Outbound, 'P', {28}},
      {Direction::Outbound, 'I', {28}},
      {Direction::Outbound, 'T', {28}},
      {Direction::Outbound, 'M', {28, 25, 26}},
      // s3.13 Display Quantity, Display Price, SecondaryOrdRefNum, UserRefIdx
      {Direction::Outbound, 'R', {22, 23, 1, 28}},
      {Direction::Outbound, 'X', {27, 24, 28}},
      {Direction::Outbound, 'G', {28}},
      {Direction::Outbound, 'K', {28}},
      {Direction::Outbound, 'Q', {28}},
  };
  return k;
}

// Fixed parts with valid field values, by hand (spec lengths: s2, s3).
Bytes fixed_part(Direction dir, char type) {
  if (dir == Direction::Inbound) {
    switch (type) {
      case 'O':
        return B().ch('O').be32(1).ch('B').be32(100).alpha("AAPL", 8).be64(1503400).ch('0').ch('Y').ch('A').ch('N').ch(
            'N').alpha("X", 14);
      case 'U': return B().ch('U').be32(1).be32(2).be32(100).be64(1503400).ch('0').ch('Y').ch('N').alpha("X", 14);
      case 'X': return B().ch('X').be32(1).be32(0);
      case 'M': return B().ch('M').be32(1).ch('S').be32(10);
      case 'C': return B().ch('C').be32(1).alpha("FIRM", 4).alpha("", 8);
      case 'D': return B().ch('D').be32(1).alpha("FIRM", 4);
      case 'E': return B().ch('E').be32(1).alpha("FIRM", 4);
      case 'Q': return B().ch('Q');
      default: break;
    }
  } else {
    B b;
    b.ch(type).be64(kTs);
    switch (type) {
      case 'S': return b.ch('E');
      case 'A':
        return b.be32(1).ch('B').be32(100).alpha("AAPL", 8).be64(1503400).ch('0').ch('Y').be64(1).ch('A').ch('N').ch(
            'N').ch('L').alpha("X", 14);
      case 'U':
        return b.be32(1).be32(2).ch('B').be32(100).alpha("AAPL", 8).be64(1503400).ch('0').ch('Y').be64(1).ch('A').ch(
            'N').ch('N').ch('L').alpha("X", 14);
      case 'C': return b.be32(1).be32(1).ch('U');
      case 'D': return b.be32(1).be32(1).ch('Q').be32(1).be64(1503400).ch('R').ch('Y');
      case 'E': return b.be32(1).be32(1).be64(1503400).ch('A').be64(1);
      case 'B': return b.be32(1).be64(1).ch('C').alpha("X", 14);
      case 'J': return b.be32(1).be16(0x000F).alpha("X", 14);
      case 'P':
      case 'I': return b.be32(1);
      case 'T': return b.be32(1).be64(1503400).ch('Y').be64(2);
      case 'M': return b.be32(1).ch('S').be32(1);
      case 'R': return b.be32(1).ch('P');
      case 'X': return b.be32(1).alpha("FIRM", 4).alpha("", 8);
      case 'G':
      case 'K': return b.be32(1).alpha("FIRM", 4);
      case 'Q': return b.be32(1);
      default: break;
    }
  }
  ADD_FAILURE() << "no fixed part for " << type;
  return {};
}

// Spec fixed lengths including Appendage Length (R1b D3.3/D3.4, spec s2/s3).
int spec_fixed_len(Direction dir, char type) {
  if (dir == Direction::Inbound) {
    switch (type) {
      case 'O': return 47;
      case 'U': return 40;
      case 'X': return 11;
      case 'M': return 12;
      case 'C': return 19;
      case 'D':
      case 'E': return 11;
      case 'Q': return 3;
      default: return -1;
    }
  }
  switch (type) {
    case 'S': return 10;
    case 'A': return 64;
    case 'U': return 68;
    case 'C': return 20;
    case 'D': return 34;
    case 'E': return 36;
    case 'B': return 38;
    case 'J': return 31;
    case 'P':
    case 'I': return 15;
    case 'T': return 32;
    case 'M': return 20;
    case 'R': return 16;
    case 'X': return 27;
    case 'G':
    case 'K': return 19;
    case 'Q': return 15;
    default: return -1;
  }
}

const MsgDesc* desc_of(Direction dir, char type) {
  return dir == Direction::Inbound ? find_inbound(static_cast<std::uint8_t>(type))
                                   : find_outbound(static_cast<std::uint8_t>(type));
}

// A correctly sized, valid value for any registry tag (the golden values).
Bytes element_for(int tag) {
  for (const auto& c : all_tag_cases())
    if (c.tag == tag) return c.element;
  // Unknown tag: one value byte.
  return test::hexbytes({0x02, static_cast<unsigned>(tag), 0x00});
}

std::expected<int, Failure> validate_dir(Direction dir, const Bytes& b) {
  if (dir == Direction::Inbound) {
    auto r = validate_inbound_detailed(sp(b));
    if (!r) return std::unexpected(r.error());
    return 0;
  }
  auto r = validate_outbound(sp(b));
  if (!r) return std::unexpected(r.error());
  return 0;
}

TEST(Ouch50Golden, MessageCatalogMatchesSpec) {
  EXPECT_EQ(kInboundMessages.size(), 8u);
  EXPECT_EQ(kOutboundMessages.size(), 17u);
  for (const auto& c : spec_allowed()) {
    SCOPED_TRACE(std::string(1, c.type) + (c.dir == Direction::Inbound ? " in" : " out"));
    const MsgDesc* d = desc_of(c.dir, c.type);
    ASSERT_NE(d, nullptr);
    std::uint32_t mask = 0;
    for (int t : c.tags) mask |= 1u << t;
    EXPECT_EQ(d->allowed_tags, mask);
    EXPECT_EQ(d->fixed_len, spec_fixed_len(c.dir, c.type));
    const Bytes fixed = fixed_part(c.dir, c.type);
    if (d->rule == AppendageRule::None) {
      EXPECT_EQ(static_cast<int>(fixed.size()), spec_fixed_len(c.dir, c.type));
    } else {
      EXPECT_EQ(static_cast<int>(fixed.size()) + 2, spec_fixed_len(c.dir, c.type));
    }
  }
}

// Negative tests per message: every known tag outside the allowed list is
// DisallowedTag; every unassigned tag number is UnknownTag; allowed tags pass.
TEST(Ouch50Golden, AllowedTagMatrixEnforced) {
  int checked = 0;
  for (const auto& c : spec_allowed()) {
    const MsgDesc* d = desc_of(c.dir, c.type);
    if (d->rule == AppendageRule::None) continue;
    const std::set<int> allowed(c.tags.begin(), c.tags.end());
    for (int tag = 0; tag < 256; ++tag) {
      SCOPED_TRACE(std::string(1, c.type) + " tag " + std::to_string(tag));
      const Bytes el = element_for(tag);
      B b;
      b.append(fixed_part(c.dir, c.type));
      Bytes elements = el;
      // Opt* outbound appendages must also carry a non-zero UserRefIdx to be
      // emitted; add it after the probed element (unless probing tag 28).
      const bool opt_star = d->rule == AppendageRule::OptionalUnlessUserRefIdx;
      if (opt_star && tag != 28) elements = B().append(el).hex({0x02, 0x1C, 0x05});
      b.be16(static_cast<std::uint16_t>(elements.size())).append(elements);
      const Bytes msg = b;
      const auto r = validate_dir(c.dir, msg);
      const TagDesc* td = find_tag(static_cast<std::uint8_t>(tag));
      if (td == nullptr) {
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().error, Error::UnknownTag);
        EXPECT_EQ(r.error().tag, tag);
        EXPECT_EQ(r.error().offset, d->fixed_len);
        EXPECT_EQ(r.error().reason, RejectReason::Other);
      } else if (!allowed.contains(tag)) {
        ASSERT_FALSE(r.has_value());
        EXPECT_EQ(r.error().error, Error::DisallowedTag);
        EXPECT_EQ(r.error().tag, tag);
        EXPECT_EQ(r.error().offset, d->fixed_len);
        EXPECT_EQ(r.error().reason, RejectReason::Other);
      } else {
        EXPECT_TRUE(r.has_value()) << (r ? "" : std::string(to_string(r.error().error)));
      }
      ++checked;
    }
  }
  EXPECT_EQ(checked, 24 * 256);
}

TEST(Ouch50Golden, DuplicateTagRejectedPerMessage) {
  for (const auto& c : spec_allowed()) {
    if (c.tags.empty()) continue;
    SCOPED_TRACE(std::string(1, c.type));
    const Bytes el = element_for(28);
    const Bytes msg = B()
                          .append(fixed_part(c.dir, c.type))
                          .be16(static_cast<std::uint16_t>(2 * el.size()))
                          .append(el)
                          .append(el);
    const auto r = validate_dir(c.dir, msg);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().error, Error::DuplicateTag);
    EXPECT_EQ(r.error().offset, fixed_part(c.dir, c.type).size() + 2 + el.size());
  }
}

TEST(Ouch50Golden, AppendageLengthMismatchPerMessage) {
  for (const auto& c : spec_allowed()) {
    if (c.tags.empty()) continue;
    SCOPED_TRACE(std::string(1, c.type));
    const Bytes el = element_for(28);
    const std::size_t base = fixed_part(c.dir, c.type).size();
    for (int delta : {-1, +1, +200}) {
      const Bytes msg = B()
                            .append(fixed_part(c.dir, c.type))
                            .be16(static_cast<std::uint16_t>(static_cast<int>(el.size()) + delta))
                            .append(el);
      const auto r = validate_dir(c.dir, msg);
      ASSERT_FALSE(r.has_value());
      EXPECT_EQ(r.error().error, Error::AppendageLengthMismatch);
      EXPECT_EQ(r.error().offset, base);
    }
    // Truncated fixed part (a 1-byte Account Query truncates to nothing).
    Bytes shortened = fixed_part(c.dir, c.type);
    shortened.pop_back();
    const auto r = validate_dir(c.dir, shortened);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().error, shortened.empty() ? Error::Empty : Error::TooShort);
  }
}

}  // namespace
}  // namespace lle::ouch50

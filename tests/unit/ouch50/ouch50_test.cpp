// Unit tests for the OUCH 5.0 codec behaviors beyond the golden vectors:
// validation order and reject codes, price and quantity domains, emission rules,
// TagValue reader/writer edge cases, kMaxInboundOuchLen.
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "../../golden/ouch50/golden_util.h"
#include "proto/ouch50/ouch50.h"

namespace lle::ouch50 {
namespace {

using test::B;
using test::Bytes;

std::span<const std::byte> sp(const Bytes& b) { return {b.data(), b.size()}; }

B enter_fixed() {
  return B()
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
      .alpha("CL", 14);
}

Bytes enter_with(const Bytes& app) {
  return enter_fixed().be16(static_cast<std::uint16_t>(app.size())).append(app);
}

Failure inbound_failure(const Bytes& b) {
  auto r = validate_inbound_detailed(sp(b));
  EXPECT_FALSE(r.has_value());
  return r ? Failure{} : r.error();
}

// ---------------------------------------------------------------------------- prices

TEST(Ouch50Price, Classification) {
  EXPECT_EQ(classify_price(0), PriceKind::Invalid);
  EXPECT_EQ(classify_price(1), PriceKind::Limit);
  EXPECT_EQ(classify_price(1'999'999'900), PriceKind::Limit);  // $199,999.9900 = 0x7735939C
  EXPECT_EQ(classify_price(0x7735939C), PriceKind::Limit);
  EXPECT_EQ(classify_price(1'999'999'901), PriceKind::Invalid);
  EXPECT_EQ(classify_price(1'999'999'999), PriceKind::Invalid);
  EXPECT_EQ(classify_price(2'000'000'000), PriceKind::Market);
  EXPECT_EQ(classify_price(2'000'000'001), PriceKind::Invalid);
  EXPECT_EQ(classify_price(0x7FFFFFFF), PriceKind::Market);
  EXPECT_EQ(classify_price(0x80000000), PriceKind::Invalid);
  EXPECT_EQ(classify_price(0xFFFFFFFFFFFFFFFFull), PriceKind::Invalid);
  EXPECT_EQ(classify_price(0x100000000ull + 100), PriceKind::Invalid);  // high word set
}

TEST(Ouch50Validate, PriceDomainOnEnterAndReplace) {
  for (std::uint64_t px : {0ull, 1'999'999'901ull, 2'147'483'648ull, 1ull << 40}) {
    Bytes b = enter_with({});
    store_be64(b.data() + 18, px);
    const Failure f = inbound_failure(b);
    EXPECT_EQ(f.error, Error::BadFieldValue);
    EXPECT_EQ(f.offset, 18);
    EXPECT_EQ(f.reason, RejectReason::InvalidPrice);
  }
  for (std::uint64_t px : {1ull, 1'999'999'900ull, 2'000'000'000ull, 0x7FFFFFFFull}) {
    Bytes b = enter_with({});
    store_be64(b.data() + 18, px);
    EXPECT_TRUE(validate_inbound(sp(b)).has_value()) << px;
  }
  Bytes r = B().ch('U').be32(1).be32(2).be32(100).be64(0).ch('0').ch('Y').ch('N').alpha("", 14).be16(0);
  const Failure f = inbound_failure(r);
  EXPECT_EQ(f.offset, 13);
  EXPECT_EQ(f.reason, RejectReason::InvalidPrice);
}

TEST(Ouch50Validate, QuantityDomain) {
  for (std::uint32_t q : {0u, 1'000'000u, 0xFFFFFFFFu}) {
    Bytes b = enter_with({});
    store_be32(b.data() + 6, q);
    const Failure f = inbound_failure(b);
    EXPECT_EQ(f.error, Error::BadFieldValue);
    EXPECT_EQ(f.offset, 6);
    EXPECT_EQ(f.reason, RejectReason::InvalidQuantity);
  }
  Bytes b = enter_with({});
  store_be32(b.data() + 6, 999'999);
  EXPECT_TRUE(validate_inbound(sp(b)).has_value());
  // Cancel and Modify quantities are intended sizes: any value, including 0.
  EXPECT_TRUE(validate_inbound(sp(B().ch('X').be32(1).be32(0))).has_value());
  EXPECT_TRUE(validate_inbound(sp(B().ch('X').be32(1).be32(0xFFFFFFFF))).has_value());
  EXPECT_TRUE(validate_inbound(sp(B().ch('M').be32(1).ch('S').be32(0))).has_value());
}

// ---------------------------------------------------------------------------- enums

TEST(Ouch50Validate, BadEnumRejectCodesPerField) {
  struct Case {
    std::size_t off;
    char bad;
    RejectReason reason;
  };
  const Case cases[] = {
      {5, 'X', RejectReason::InvalidSide},        // Side
      {26, '1', RejectReason::Other},             // Time In Force
      {27, 'Z', RejectReason::InvalidDisplay},    // Display: 'Z' is outbound-only
      {28, 'B', RejectReason::Other},             // Capacity
      {29, 'X', RejectReason::Other},             // ISO
      {30, 'X', RejectReason::InvalidCrossOrder},  // CrossType
  };
  for (const auto& c : cases) {
    Bytes b = enter_with({});
    b[c.off] = static_cast<std::byte>(c.bad);
    const Failure f = inbound_failure(b);
    EXPECT_EQ(f.error, Error::BadFieldValue) << c.off;
    EXPECT_EQ(f.offset, c.off);
    EXPECT_EQ(f.reason, c.reason);
  }
}

TEST(Ouch50Validate, ReplaceTimeInForceExcludesAfterHours) {
  // Enter lists TIF 0/3/5/6/E; Replace lists 0/3/5/6 only (s2.1, s2.2).
  Bytes enter = enter_with({});
  enter[26] = static_cast<std::byte>('E');
  EXPECT_TRUE(validate_inbound(sp(enter)).has_value());
  const Bytes repl = B().ch('U').be32(1).be32(2).be32(100).be64(100).ch('E').ch('Y').ch('N').alpha("", 14).be16(0);
  const Failure f = inbound_failure(repl);
  EXPECT_EQ(f.error, Error::BadFieldValue);
  EXPECT_EQ(f.offset, 21);
}

TEST(Ouch50Validate, EnumValidityHelpers) {
  EXPECT_TRUE(is_valid_inbound(Display::Visible));
  EXPECT_FALSE(is_valid_inbound(Display::Conformant));
  EXPECT_TRUE(is_valid_outbound(Display::Conformant));
  EXPECT_FALSE(is_valid_inbound(OrderState::Live));
  EXPECT_TRUE(is_valid_outbound(RejectReason::InvalidAiq));
  EXPECT_FALSE(is_valid_outbound(static_cast<RejectReason>(0x0034)));
  EXPECT_FALSE(is_valid_inbound(RejectReason::Other));  // reasons only travel outbound
  EXPECT_EQ(to_string(Side::SellShortExempt), "SellShortExempt");
  EXPECT_EQ(to_string(RejectReason::RiskMarketOrderNotAllowed), "RiskMarketOrderNotAllowed");
}

// ---------------------------------------------------------------------------- tag values

TEST(Ouch50Validate, TagValueChecks) {
  struct Case {
    Bytes el;
    Error error;
    RejectReason reason;
  };
  const Case cases[] = {
      {test::hexbytes({0x02, 0x06, 'X'}), Error::BadTagValue, RejectReason::InvalidPegType},        // PriceType
      {test::hexbytes({0x02, 0x0A, 'Q'}), Error::BadTagValue, RejectReason::InvalidPegType},        // DiscretionPriceType Q
      {test::hexbytes({0x02, 0x1D, '3'}), Error::BadTagValue, RejectReason::InvalidAiq},            // AIQ Strategy
      {test::hexbytes({0x02, 0x04, 'Y'}), Error::BadTagValue, RejectReason::Other},                 // CustomerType
      {test::hexbytes({0x05, 0x0F, 0x00, 0x01, 0x51, 0x80}), Error::BadTagValue, RejectReason::Other},  // ExpireTime 86400
      {test::hexbytes({0x09, 0x09, 0, 0, 0, 0, 0x77, 0x35, 0x93, 0x9D}), Error::BadTagValue,
       RejectReason::InvalidPrice},  // DiscretionPrice 1,999,999,901
      {test::hexbytes({0x03, 0x1C, 0x05, 0x00}), Error::BadTagLength, RejectReason::Other},  // UserRefIdx, 2 bytes
      {test::hexbytes({0x01, 0x1C}), Error::BadTagLength, RejectReason::Other},              // UserRefIdx, empty
  };
  for (const auto& c : cases) {
    const Failure f = inbound_failure(enter_with(c.el));
    EXPECT_EQ(f.error, c.error) << test::to_hex(c.el);
    EXPECT_EQ(f.reason, c.reason) << test::to_hex(c.el);
    EXPECT_EQ(f.offset, 47);
    EXPECT_EQ(f.tag, std::to_integer<std::uint8_t>(c.el[1]));
  }
  // Boundary values that pass.
  EXPECT_TRUE(validate_inbound(sp(enter_with(test::hexbytes({0x05, 0x0F, 0x00, 0x01, 0x51, 0x7F})))).has_value());
  EXPECT_TRUE(validate_inbound(sp(enter_with(test::hexbytes({0x09, 0x09, 0, 0, 0, 0, 0, 0, 0, 0})))).has_value());
  EXPECT_TRUE(validate_inbound(sp(enter_with(test::hexbytes({0x02, 0x04, ' '})))).has_value());  // port default
  EXPECT_TRUE(validate_inbound(sp(enter_with(test::hexbytes({0x02, 0x1C, 0x00})))).has_value());  // UserRefIdx 0
}

TEST(Ouch50Validate, MalformedElements) {
  // Element length 0.
  Failure f = inbound_failure(enter_with(test::hexbytes({0x02, 0x1C, 0x05, 0x00})));
  EXPECT_EQ(f.error, Error::MalformedTagValue);
  EXPECT_EQ(f.offset, 47 + 3);
  // Element overruns the appendage.
  f = inbound_failure(enter_with(test::hexbytes({0x05, 0x03, 0x00, 0x00})));
  EXPECT_EQ(f.error, Error::MalformedTagValue);
  EXPECT_EQ(f.offset, 47);
  // Malformed structure wins over an earlier unknown tag (framing first).
  f = inbound_failure(enter_with(test::hexbytes({0x02, 0x08, 0x00, 0x09, 0x01})));
  EXPECT_EQ(f.error, Error::MalformedTagValue);
}

// ---------------------------------------------------------------------------- order of checks

TEST(Ouch50Validate, CheckOrder) {
  EXPECT_EQ(inbound_failure({}).error, Error::Empty);
  EXPECT_EQ(inbound_failure(B().ch('Z')).error, Error::UnknownType);
  EXPECT_EQ(inbound_failure(B().ch('o')).error, Error::UnknownType);  // case matters
  EXPECT_EQ(inbound_failure(B().ch('O').be32(1)).error, Error::TooShort);
  // Framing beats a bad field: bad Side and a wrong Appendage Length.
  Bytes b = enter_with(test::hexbytes({0x02, 0x1C, 0x05}));
  b[5] = static_cast<std::byte>('X');
  b.push_back(std::byte{0});
  EXPECT_EQ(inbound_failure(b).error, Error::AppendageLengthMismatch);
  // Fixed fields (wire order) beat tag errors.
  b = enter_with(test::hexbytes({0x02, 0x14, 0x05}));  // tag 20 (removed in 2023): unknown
  b[30] = static_cast<std::byte>('X');                 // CrossType
  b[27] = static_cast<std::byte>('Q');                 // Display (earlier in the wire)
  Failure f = inbound_failure(b);
  EXPECT_EQ(f.error, Error::BadFieldValue);
  EXPECT_EQ(f.offset, 27);
  // Among elements, the first failing one wins.
  f = inbound_failure(enter_with(test::hexbytes({0x02, 0x1C, 0x05, 0x02, 0x12, '2', 0x02, 0x08, 0x00})));
  EXPECT_EQ(f.error, Error::DisallowedTag);  // BBO Weight Indicator is outbound-only
  EXPECT_EQ(f.tag, 18);
  EXPECT_EQ(f.offset, 50);
}

TEST(Ouch50Validate, OptionalAppendageLengthForms) {
  // Cancel: 9 bytes (no AppLen), 10 (truncated AppLen), 11 (AppLen 0).
  EXPECT_TRUE(validate_inbound(sp(B().ch('X').be32(1).be32(0))).has_value());
  Failure f = inbound_failure(B().ch('X').be32(1).be32(0).u8(0));
  EXPECT_EQ(f.error, Error::AppendageLengthMismatch);
  EXPECT_EQ(f.offset, 9);
  EXPECT_TRUE(validate_inbound(sp(B().ch('X').be32(1).be32(0).be16(0))).has_value());
  EXPECT_EQ(inbound_failure(B().ch('X').be32(1).be16(0)).error, Error::TooShort);
  // Account Query: 1, 2 (mismatch), 3.
  EXPECT_EQ(inbound_failure(B().ch('Q').u8(0)).error, Error::AppendageLengthMismatch);
  // Required types must carry it.
  EXPECT_EQ(inbound_failure(B().ch('D').be32(1).alpha("F", 4)).error, Error::TooShort);
}

TEST(Ouch50Validate, OutboundSystemEventExactLength) {
  const Bytes s = B().ch('S').be64(1).ch('E');
  EXPECT_TRUE(validate_outbound(sp(s)).has_value());
  Bytes longer = s;
  longer.push_back(std::byte{0});
  auto r = validate_outbound(sp(longer));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().error, Error::TooLong);
  EXPECT_EQ(OutboundDecoder::decode(sp(longer)).error().error, Error::TooLong);
  r = validate_outbound(sp(B().ch('S').be64(1).ch('X')));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().error, Error::BadFieldValue);
}

TEST(Ouch50Validate, OutboundOptStarAppendageRule) {
  const Bytes bare = B().ch('P').be64(1).be32(5);
  EXPECT_TRUE(validate_outbound(sp(bare)).has_value());
  // AppLen present but empty: not what the spec emits on an Opt* type.
  auto r = validate_outbound(sp(B().append(bare).be16(0)));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().error, Error::AppendageRule);
  EXPECT_EQ(r.error().offset, 13);
  // UserRefIdx 0 does not justify it either.
  r = validate_outbound(sp(B().append(bare).be16(3).hex({0x02, 0x1C, 0x00})));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().error, Error::AppendageRule);
  // The tolerant decoder accepts both.
  EXPECT_TRUE(OutboundDecoder::decode(sp(B().append(bare).be16(0))).has_value());
  EXPECT_TRUE(validate_outbound(sp(B().append(bare).be16(3).hex({0x02, 0x1C, 0x01}))).has_value());
}

TEST(Ouch50Decode, TolerantDecodersSkipUnknownTags) {
  // Clients skip unrecognized tags (FAQ Q8): framing-only decode succeeds.
  const Bytes msg = B().ch('C').be64(1).be32(2).be32(3).ch('U').be16(6).hex({0x02, 0x63, 0x01, 0x02, 0x1C, 0x05});
  auto v = OutboundDecoder::decode(sp(msg));
  ASSERT_TRUE(v.has_value());
  TagSet ts;
  ASSERT_TRUE(parse_tags(v->tags(), ts));
  EXPECT_EQ(ts.present, tag_bit(Tag::UserRefIdx));
  EXPECT_EQ(ts.user_ref_idx, 5);
  EXPECT_FALSE(validate_outbound(sp(msg)).has_value());
  // Same for inbound: decode passes, strict validation rejects.
  const Bytes in_msg = B().ch('Q').be16(3).hex({0x02, 0x63, 0x01});
  EXPECT_TRUE(InboundDecoder::decode(sp(in_msg)).has_value());
  EXPECT_EQ(inbound_failure(in_msg).error, Error::UnknownTag);
}

TEST(Ouch50Decode, ParseTagsRejectsWrongSizeKnownTag) {
  TagSet ts;
  EXPECT_FALSE(parse_tags(TagValueRange(sp(test::hexbytes({0x03, 0x1C, 0x05, 0x06}))), ts));
  EXPECT_FALSE(parse_tags(TagValueRange(sp(test::hexbytes({0x05, 0x1C, 0x05}))), ts));  // overrun
  EXPECT_TRUE(parse_tags(TagValueRange(sp(test::hexbytes({0x02, 0x1C, 0x05, 0x02, 0x1C, 0x07}))), ts));
  EXPECT_EQ(ts.user_ref_idx, 7);  // later duplicate wins in tolerant parsing
}

// ---------------------------------------------------------------------------- kMaxInboundOuchLen

TEST(Ouch50Limits, MaxInboundLength) {
  // Enter Order: 47 + 20 allowed tags: values 53 bytes + 20 * 2 headers = 140.
  EXPECT_EQ(kMaxInboundOuchLen, 140u);
  EXPECT_EQ(layout::in::EnterOrder::kMaxLen, 140u);
  EXPECT_EQ(layout::in::ReplaceOrder::kMaxLen, 123u);
  // Build the longest legal Enter Order and check it validates.
  std::array<std::byte, 256> buf{};
  in::EnterOrder m;
  m.user_ref_num = 1;
  m.quantity = 100;
  m.symbol = Symbol8("AAPL");
  m.price = 100;
  TagSet ts;
  ts.set_firm(Mpid4("FIRM"))
      .set_min_qty(100)
      .set_customer_type(CustomerType::NotRetailDesignated)
      .set_max_floor(100)
      .set_price_type(PriceType::Limit)
      .set_peg_offset(0)
      .set_discretion_price(0)
      .set_discretion_price_type(DiscretionPriceType::Limit)
      .set_discretion_peg_offset(0)
      .set_post_only(PostOnly::No)
      .set_random_reserves(0)
      .set_expire_time(0)
      .set_trade_now(TradeNow::No)
      .set_handle_inst(HandleInst::None)
      .set_group_id(1)
      .set_shares_located(SharesLocated::No)
      .set_locate_broker(Alpha<4>("LB"))
      .set_user_ref_idx(1)
      .set_aiq_strategy(AiqStrategy::PortDefault)
      .set_aiq_group_id(Alpha<2>("**"));
  const std::size_t n = encode(std::span<std::byte>(buf), m, ts);
  EXPECT_EQ(n, kMaxInboundOuchLen);
  EXPECT_TRUE(validate_inbound(std::span<const std::byte>(buf.data(), n)).has_value());
  // Any additional element must be a duplicate or disallowed, so it fails.
  TagValueWriter extra(std::span<std::byte>(buf).subspan(n));
  extra.put_u8(Tag::UserRefIdx, 2);
  store_be16(buf.data() + 45, static_cast<std::uint16_t>(n - 47 + extra.size()));
  EXPECT_FALSE(validate_inbound(std::span<const std::byte>(buf.data(), n + extra.size())).has_value());
  EXPECT_LE(kMaxOutboundOuchLen, 255u);
}

// ---------------------------------------------------------------------------- encoder rules

TEST(Ouch50Encode, BufferTooSmall) {
  std::array<std::byte, 46> small{};
  EXPECT_EQ(encode(std::span<std::byte>(small), in::EnterOrder{}), 0u);
  std::array<std::byte, 48> tight{};
  MessageWriter<in::EnterOrder> w(tight, in::EnterOrder{});
  w.tags().put_u8(Tag::UserRefIdx, 1);  // needs 3 bytes, 1 available
  EXPECT_TRUE(w.tags().overflow());
  EXPECT_EQ(w.finish(), 0u);
  std::array<std::byte, 47> exact{};
  EXPECT_EQ(encode(std::span<std::byte>(exact), in::EnterOrder{}), 47u);
}

TEST(Ouch50Encode, OptionalRuleOmitsEmptyAppendage) {
  std::array<std::byte, 64> buf{};
  EXPECT_EQ(encode(std::span<std::byte>(buf), in::CancelOrder{}), 9u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), in::ModifyOrder{}), 10u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), in::AccountQuery{}), 1u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), out::SystemEvent{}), 10u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), out::OrderExecuted{}), 36u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), out::OrderRestated{}), 16u);
  EXPECT_EQ(encode(std::span<std::byte>(buf), out::OrderCanceled{}), 18u);
}

TEST(Ouch50Encode, AllDefaultMessagesValidate) {
  // Default-constructed structs carry valid enum defaults; with valid numeric
  // fields every encoded message passes its strict validator.
  std::array<std::byte, 256> buf{};
  auto check_in = [&](auto m) {
    const std::size_t n = encode(std::span<std::byte>(buf), m);
    ASSERT_GT(n, 0u);
    const auto r = validate_inbound_detailed(std::span<const std::byte>(buf.data(), n));
    EXPECT_TRUE(r.has_value()) << decltype(m)::kName << " " << (r ? "" : std::string(to_string(r.error().error)));
  };
  auto check_out = [&](auto m) {
    const std::size_t n = encode(std::span<std::byte>(buf), m);
    ASSERT_GT(n, 0u);
    const auto r = validate_outbound(std::span<const std::byte>(buf.data(), n));
    EXPECT_TRUE(r.has_value()) << decltype(m)::kName << " " << (r ? "" : std::string(to_string(r.error().error)));
  };
  in::EnterOrder o;
  o.quantity = 1;
  o.price = 1;
  in::ReplaceOrder u;
  u.quantity = 1;
  u.price = 1;
  check_in(o);
  check_in(u);
  check_in(in::CancelOrder{});
  check_in(in::ModifyOrder{});
  check_in(in::MassCancel{});
  check_in(in::DisableOrderEntry{});
  check_in(in::EnableOrderEntry{});
  check_in(in::AccountQuery{});
  out::Rejected j;
  j.reason = RejectReason::Other;
  out::AiqCanceled d;
  d.reason = CancelReason::SelfMatchPrevention;
  check_out(out::SystemEvent{});
  check_out(out::OrderAccepted{});
  check_out(out::OrderReplaced{});
  check_out(out::OrderCanceled{});
  check_out(d);
  check_out(out::OrderExecuted{});
  check_out(out::BrokenTrade{});
  check_out(j);
  check_out(out::CancelPending{});
  check_out(out::CancelReject{});
  check_out(out::OrderPriorityUpdate{});
  check_out(out::OrderModified{});
  check_out(out::OrderRestated{});
  check_out(out::MassCancelResponse{});
  check_out(out::DisableOrderEntryResponse{});
  check_out(out::EnableOrderEntryResponse{});
  check_out(out::AccountQueryResponse{});
}

// ---------------------------------------------------------------------------- TagValue reader/writer

TEST(Ouch50TagValue, IteratorStopsAtMalformed) {
  const Bytes app = test::hexbytes({0x02, 0x1C, 0x05, 0x03, 0x18});
  TagValueIterator it(sp(app));
  ASSERT_NE(it, std::default_sentinel);
  EXPECT_EQ(it->tag, 28);
  ++it;
  EXPECT_EQ(it, std::default_sentinel);
  EXPECT_TRUE(it.malformed());
  EXPECT_EQ(it.position(), 3u);
  EXPECT_FALSE(TagValueRange(sp(app)).well_formed());
  EXPECT_TRUE(TagValueRange().well_formed());
  EXPECT_TRUE(TagValueRange(sp(test::hexbytes({0x01, 0x07}))).well_formed());  // tag with an empty value
  EXPECT_EQ(TagValueRange(sp(app)).find(Tag::UserRefIdx)->u8(), 5);
  EXPECT_FALSE(TagValueRange(sp(app)).find(24).has_value());
}

TEST(Ouch50TagValue, WriterLimits) {
  std::array<std::byte, 300> buf{};
  TagValueWriter w(buf);
  std::array<std::byte, 254> big{};
  w.put_raw(std::uint8_t{99}, big);
  EXPECT_FALSE(w.overflow());
  EXPECT_EQ(w.size(), 256u);
  EXPECT_EQ(std::to_integer<int>(buf[0]), 255);
  std::array<std::byte, 255> too_big{};
  w.put_raw(std::uint8_t{99}, too_big);
  EXPECT_TRUE(w.overflow());
  EXPECT_EQ(w.size(), 256u);
  std::array<std::byte, 2> tiny{};
  TagValueWriter t(tiny);
  t.put_u8(Tag::UserRefIdx, 1);
  EXPECT_TRUE(t.overflow());
  EXPECT_EQ(t.size(), 0u);
  TagValueWriter ok(buf);
  ok.put_i32(Tag::PegOffset, -2).put_u16(Tag::GroupID, 0xBEEF).put_u64(Tag::SecondaryOrdRefNum, 1);
  EXPECT_EQ(test::to_hex(ok.bytes()),
            test::to_hex(test::hexbytes({0x05, 0x07, 0xFF, 0xFF, 0xFF, 0xFE, 0x03, 0x18, 0xBE, 0xEF, 0x09, 0x01, 0, 0, 0,
                                         0, 0, 0, 0, 1})));
}

// ---------------------------------------------------------------------------- dispatch and peeks

TEST(Ouch50Decode, VisitDispatchesTypedViews) {
  const Bytes msg = enter_with(test::hexbytes({0x02, 0x1C, 0x05}));
  auto v = InboundDecoder::decode(sp(msg));
  ASSERT_TRUE(v.has_value());
  int calls = 0;
  v->visit([&](const auto& typed) {
    using V = std::decay_t<decltype(typed)>;
    if constexpr (std::is_same_v<V, in::EnterOrderView>) {
      EXPECT_EQ(typed.quantity(), 100u);
      ++calls;
    } else {
      ADD_FAILURE() << "wrong view";
    }
  });
  EXPECT_EQ(calls, 1);
  std::vector<std::string> names;
  for_each_field(v->as<in::EnterOrderView>(), [&](const char* name, auto) { names.emplace_back(name); });
  const std::vector<std::string> expected = {"UserRefNum", "Side",     "Quantity",
                                             "Symbol",     "Price",    "TimeInForce",
                                             "Display",    "Capacity", "InterMarketSweepEligibility",
                                             "CrossType",  "ClOrdID"};
  EXPECT_EQ(names, expected);
  EXPECT_FALSE(visit_inbound('Z', sp(msg), [](const auto&) {}));
}

TEST(Ouch50Decode, PeekHelpersOnShortInput) {
  EXPECT_EQ(peek_new_user_ref_num({}), std::nullopt);
  EXPECT_EQ(peek_new_user_ref_num(sp(B().ch('O').be16(1))), std::nullopt);
  EXPECT_EQ(peek_new_user_ref_num(sp(B().ch('O').be32(42))), 42u);  // parses although incomplete
  EXPECT_EQ(peek_new_user_ref_num(sp(B().ch('U').be32(1).be32(9))), 9u);
  EXPECT_EQ(peek_new_user_ref_num(sp(B().ch('U').be32(1).be16(9))), std::nullopt);
  EXPECT_EQ(peek_new_user_ref_num(sp(B().ch('M').be32(1))), std::nullopt);
  EXPECT_EQ(peek_user_ref_idx(sp(B().ch('Q'))), 0);
  EXPECT_EQ(peek_user_ref_idx(sp(B().ch('Q').be16(3).hex({0x02, 0x1C, 0x09}))), 9);
  EXPECT_EQ(peek_user_ref_idx(sp(B().ch('Q').be16(4).hex({0x02, 0x1C, 0x09}))), 0);  // framing fails
}

TEST(Ouch50Decode, ValidateInboundReturnsRejectReason) {
  Bytes b = enter_with({});
  b[5] = static_cast<std::byte>('Q');
  const auto r = validate_inbound(sp(b));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error(), RejectReason::InvalidSide);
}

}  // namespace
}  // namespace lle::ouch50

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#include "common/prng.h"
#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

TEST(Itch50Table, LengthTableHasExactly23Types) {
  std::size_t defined = 0;
  for (unsigned t = 0; t < 256; ++t) {
    if (kMsgLen[t] == 0) {
      EXPECT_TRUE(message_name(static_cast<char>(t)).empty());
      continue;
    }
    ++defined;
    EXPECT_FALSE(message_name(static_cast<char>(t)).empty());
    EXPECT_GE(kMsgLen[t], kMinMsgLen);
    EXPECT_LE(kMsgLen[t], kMaxMsgLen);
  }
  EXPECT_EQ(defined, 23u);
  EXPECT_EQ(std::string(kMessageTypes, kNumMessageTypes), "SRHYLVWKJhAFECXDUPQBINO");
  EXPECT_EQ(message_name('A'), "AddOrder");
  EXPECT_EQ(message_name('h'), "OperationalHalt");
}

TEST(Itch50Table, LocateZeroRule) {
  for (char t : kMessageTypes) EXPECT_EQ(locate_must_be_zero(t), t == 'S' || t == 'V' || t == 'W' || t == 'K') << t;
}

// Random bytes with a valid type byte must survive view -> struct -> encode
// unchanged: this proves the fields tile each message and that every accessor
// and its store are inverse, for every type.
TEST(Itch50Codec, RandomBytesRoundTripEveryType) {
  Prng rng(0x17C450);
  std::array<std::byte, kMaxMsgLen> in{}, out{};
  for (char t : kMessageTypes) {
    const std::size_t len = kMsgLen[static_cast<unsigned char>(t)];
    for (int iter = 0; iter < 2000; ++iter) {
      for (std::size_t i = 0; i < len; ++i) in[i] = static_cast<std::byte>(rng.next_u64());
      in[0] = static_cast<std::byte>(t);
      out.fill(std::byte{0});
      bool called = false;
      ASSERT_EQ(visit(std::span<const std::byte>(in.data(), len),
                      [&](auto v) {
                        called = true;
                        ASSERT_EQ(decltype(v)::kType, t);
                        ASSERT_EQ(encode(out, v.to_struct()), len);
                      }),
                DecodeStatus::Ok);
      ASSERT_TRUE(called);
      ASSERT_EQ(std::memcmp(in.data(), out.data(), len), 0) << "type " << t << " iteration " << iter;
    }
  }
}

TEST(Itch50Codec, TolerantEnumsKeepRawByte) {
  SystemEvent m{.stock_locate = 0, .tracking_number = 0, .timestamp = 1, .event_code = static_cast<EventCode>('Z')};
  std::array<std::byte, 16> buf{};
  ASSERT_EQ(encode(buf, m), 12u);
  const SystemEventView v{buf.data()};
  EXPECT_EQ(static_cast<char>(v.event_code()), 'Z');
  EXPECT_FALSE(is_valid(v.event_code()));
  EXPECT_TRUE(is_valid(EventCode::EndOfMessages));
  EXPECT_EQ(to_string(EventCode::EndOfMessages), "EndOfMessages");
  EXPECT_EQ(to_string(static_cast<EventCode>('Z')), "?");
  // Newest published values are in-set.
  EXPECT_TRUE(is_valid(MarketCategory::NyseTexas));
  EXPECT_TRUE(is_valid(IpoFlag::NonIpoNewListing));
  EXPECT_TRUE(is_valid(CrossType::IntradayLegacy));
  EXPECT_FALSE(is_valid(static_cast<CrossType>('A')));       // 'A' is NOII-only
  EXPECT_TRUE(is_valid(NoiiCrossType::ExtendedTradingClose));
  EXPECT_TRUE(is_valid(Side::Buy));
  EXPECT_FALSE(is_valid(static_cast<Side>('X')));
}

TEST(Itch50Codec, ExtremeValuesRoundTrip) {
  // 48-bit timestamp max, u32 Price(4) max, u64 Price(8) max (negative as int64).
  AddOrder a{.stock_locate = 0xFFFF,
             .tracking_number = 0xFFFF,
             .timestamp = (std::uint64_t{1} << 48) - 1,
             .order_ref = ~std::uint64_t{0},
             .side = Side::Sell,
             .shares = 0xFFFF'FFFF,
             .stock = Symbol8("ZZZZZZZZ"),
             .price = PxE4{0xFFFF'FFFF}};
  std::array<std::byte, 64> buf{};
  ASSERT_EQ(encode(buf, a), AddOrder::kLen);
  EXPECT_TRUE(AddOrderView{buf.data()}.to_struct() == a);

  MwcbDeclineLevel v{.stock_locate = 0, .tracking_number = 0, .timestamp = 0, .level1 = -1, .level2 = 0, .level3 = INT64_MAX};
  ASSERT_EQ(encode(buf, v), MwcbDeclineLevel::kLen);
  for (std::size_t i = 11; i < 19; ++i) EXPECT_EQ(buf[i], std::byte{0xFF});
  EXPECT_TRUE(MwcbDeclineLevelView{buf.data()}.to_struct() == v);
}

TEST(Itch50Codec, VisitErrors) {
  const std::vector<std::byte> empty;
  EXPECT_EQ(visit(empty, [](auto) { FAIL(); }), DecodeStatus::Empty);
  std::vector<std::byte> unknown(20, std::byte{'G'});  // 'G' was the ITCH 4.0 RPII type
  EXPECT_EQ(visit(unknown, [](auto) { FAIL(); }), DecodeStatus::UnknownType);
  EXPECT_FALSE(visit_unchecked(unknown.data(), [](auto) { FAIL(); }));
  std::vector<std::byte> longer(37, std::byte{0});
  longer[0] = std::byte{'A'};
  EXPECT_EQ(visit(longer, [](auto) { FAIL(); }), DecodeStatus::BadLength);
  EXPECT_EQ(decode(longer).error(), DecodeStatus::BadLength);
  EXPECT_EQ(decode(unknown).error(), DecodeStatus::UnknownType);
  EXPECT_EQ(decode(empty).error(), DecodeStatus::Empty);
  EXPECT_EQ(to_string(DecodeStatus::BadLength), "bad_length");
}

TEST(Itch50Codec, MessageViewAccess) {
  OrderDelete d{.stock_locate = 7, .tracking_number = 1, .timestamp = 99, .order_ref = 12345};
  std::array<std::byte, OrderDelete::kLen> buf{};
  ASSERT_EQ(encode(buf, d), OrderDelete::kLen);
  const auto mv = decode(buf);
  ASSERT_TRUE(mv.has_value());
  EXPECT_TRUE(mv->is<OrderDeleteView>());
  EXPECT_FALSE(mv->is<AddOrderView>());
  EXPECT_EQ(mv->header().stock_locate(), 7);
  EXPECT_EQ(mv->header().timestamp(), 99u);
  EXPECT_EQ(mv->as<OrderDeleteView>().order_ref(), 12345u);
  EXPECT_EQ(mv->bytes().size(), OrderDelete::kLen);
  OrderRef seen = 0;
  mv->visit([&](auto v) {
    if constexpr (std::is_same_v<decltype(v), OrderDeleteView>) seen = v.order_ref();
  });
  EXPECT_EQ(seen, 12345u);
}

TEST(Itch50Codec, ViewsAreOnePointer) {
  static_assert(sizeof(AddOrderView) == sizeof(void*));
  static_assert(std::is_trivially_copyable_v<NoiiView>);
  static_assert(std::is_aggregate_v<AddOrder>);
  SUCCEED();
}

}  // namespace
}  // namespace lle::itch50

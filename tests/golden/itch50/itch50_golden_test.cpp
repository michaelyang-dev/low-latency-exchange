// Golden vectors for all 23 TotalView-ITCH 5.0 message types (03-protocols §9).
// Each expected byte string is hand-assembled from the spec tables (R1a Q3):
// fields are separated by spaces in table order, starting with the common
// header "type locate tracking timestamp". Encode must equal the bytes exactly;
// decode must equal the field values.
#include <gtest/gtest.h>

#include <array>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

std::vector<std::byte> hex_bytes(std::string_view hex) {
  std::vector<std::byte> out;
  int hi = -1;
  for (char c : hex) {
    if (c == ' ' || c == '|') continue;
    const int v = std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : std::tolower(static_cast<unsigned char>(c)) - 'a' + 10;
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<std::byte>(hi * 16 + v));
      hi = -1;
    }
  }
  EXPECT_EQ(hi, -1) << "odd number of hex digits";
  return out;
}

std::string to_hex(const std::byte* p, std::size_t n) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < n; ++i) {
    s += kDigits[static_cast<unsigned>(p[i]) >> 4];
    s += kDigits[static_cast<unsigned>(p[i]) & 15];
  }
  return s;
}

template <class M>
void expect_golden(const M& m, std::string_view hex) {
  SCOPED_TRACE(std::string(message_name(M::kType)));
  const std::vector<std::byte> want = hex_bytes(hex);
  ASSERT_EQ(want.size(), M::kLen) << "golden vector length";
  ASSERT_EQ(kMsgLen[static_cast<unsigned char>(M::kType)], M::kLen);
  ASSERT_EQ(static_cast<char>(want[0]), M::kType);

  // Encode == expected bytes, with no write past kLen.
  std::array<std::byte, 64> buf;
  buf.fill(std::byte{0xEE});
  ASSERT_EQ(encode(buf, m), M::kLen);
  EXPECT_EQ(to_hex(buf.data(), M::kLen), to_hex(want.data(), want.size()));
  EXPECT_EQ(buf[M::kLen], std::byte{0xEE});
  EXPECT_EQ(encode(std::span<std::byte>(buf).first(M::kLen - 1), m), 0u) << "short buffer must be refused";

  // Decode == expected fields.
  const typename M::View v{want.data()};
  EXPECT_EQ(v.message_type(), M::kType);
  EXPECT_EQ(v.stock_locate(), m.stock_locate);
  EXPECT_EQ(v.tracking_number(), m.tracking_number);
  EXPECT_EQ(v.timestamp(), m.timestamp);
  EXPECT_TRUE(v.to_struct() == m);

  // Dispatch selects the right view; decode() validates type and length.
  bool hit = false;
  EXPECT_EQ(visit(want, [&](auto view) { hit = std::is_same_v<decltype(view), typename M::View>; }), DecodeStatus::Ok);
  EXPECT_TRUE(hit);
  const auto d = decode(want);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->type(), M::kType);
  EXPECT_TRUE(d->template as<typename M::View>().to_struct() == m);
  EXPECT_EQ(visit(std::span<const std::byte>(want).first(M::kLen - 1), [](auto) {}), DecodeStatus::BadLength);
}

TEST(Itch50Golden, S_SystemEvent) {
  const SystemEvent m{.stock_locate = 0, .tracking_number = 2, .timestamp = 0x0A0A60AADB93, .event_code = EventCode::StartOfMessages};
  expect_golden(m, "53 0000 0002 0a0a60aadb93 4f");
  EXPECT_EQ(m.timestamp, 11'039'687'760'787ull);  // 03:03:59.687760787
}

TEST(Itch50Golden, R_StockDirectory) {
  const StockDirectory m{.stock_locate = 14,
                         .tracking_number = 0,
                         .timestamp = 0x0A4A4CEE5599,
                         .stock = Symbol8("AAPL"),
                         .market_category = MarketCategory::NasdaqGlobalSelect,
                         .financial_status = FinancialStatus::Normal,
                         .round_lot_size = 100,
                         .round_lots_only = YesNo::No,
                         .issue_classification = IssueClassification::CommonStock,
                         .issue_sub_type = Alpha<2>("Z"),
                         .authenticity = Authenticity::LiveProduction,
                         .short_sale_threshold = YesNoBlank::No,
                         .ipo_flag = IpoFlag::NonIpoNewListing,
                         .luld_tier = LuldTier::Tier1,
                         .etp_flag = YesNoBlank::No,
                         .etp_leverage_factor = 2,
                         .inverse_indicator = YesNo::No};
  //            type loc  trk  timestamp    stock            mc fs lot      rlo ic sub  au ss ipo tier etp lev      inv
  expect_golden(m, "52 000e 0000 0a4a4cee5599 4141504c20202020 51 4e 00000064 4e 43 5a20 50 4e 5a 31 4e 00000002 4e");
}

TEST(Itch50Golden, H_StockTradingAction) {
  const StockTradingAction m{.stock_locate = 14,
                             .tracking_number = 3,
                             .timestamp = 0x0A4A4D1CED64,
                             .stock = Symbol8("AAPL"),
                             .trading_state = TradingState::Trading,
                             .reserved = ' ',
                             .reason = Alpha<4>("T3")};
  expect_golden(m, "48 000e 0003 0a4a4d1ced64 4141504c20202020 54 20 54332020");
}

TEST(Itch50Golden, Y_RegShoRestriction) {
  const RegShoRestriction m{.stock_locate = 14,
                            .tracking_number = 0,
                            .timestamp = 0x0A4A4D1E398C,
                            .stock = Symbol8("AAPL"),
                            .reg_sho_action = RegShoAction::RestrictionIntradayDrop};
  expect_golden(m, "59 000e 0000 0a4a4d1e398c 4141504c20202020 31");
}

TEST(Itch50Golden, L_MarketParticipantPosition) {
  const MarketParticipantPosition m{.stock_locate = 0x1695,
                                    .tracking_number = 0,
                                    .timestamp = 0x0A4CD6E5AA32,
                                    .mpid = Mpid4("LEER"),
                                    .stock = Symbol8("ONCE"),
                                    .primary_market_maker = YesNo::Yes,
                                    .market_maker_mode = MarketMakerMode::Passive,
                                    .participant_state = ParticipantState::Excused};
  expect_golden(m, "4c 1695 0000 0a4cd6e5aa32 4c454552 4f4e434520202020 59 50 45");
}

TEST(Itch50Golden, V_MwcbDeclineLevel) {
  // Price(8): 2455.20000000 / 2296.80000000 / 2112.00000000 (the 2019-01-30 levels).
  const MwcbDeclineLevel m{.stock_locate = 0,
                           .tracking_number = 0,
                           .timestamp = 0x16EC56782178,
                           .level1 = 245'520'000'000,
                           .level2 = 229'680'000'000,
                           .level3 = 211'200'000'000};
  expect_golden(m, "56 0000 0000 16ec56782178 000000392a21e400 0000003579feac00 000000312c804000");
}

TEST(Itch50Golden, W_MwcbStatus) {
  const MwcbStatus m{.stock_locate = 0, .tracking_number = 1, .timestamp = 0x16EC56782179, .breached_level = BreachedLevel::Level2};
  expect_golden(m, "57 0000 0001 16ec56782179 32");
}

TEST(Itch50Golden, K_IpoQuotingPeriodUpdate) {
  // IPO Price is binary Price(4) ($10.0000), not the stale ASCII format (erratum).
  const IpoQuotingPeriodUpdate m{.stock_locate = 0,
                                 .tracking_number = 0,
                                 .timestamp = 0x2153A0F1B2C3,
                                 .stock = Symbol8("DSACU"),
                                 .release_time = 36'600,  // 10:10:00, seconds since midnight
                                 .release_qualifier = IpoReleaseQualifier::Anticipated,
                                 .ipo_price = 100'000};
  expect_golden(m, "4b 0000 0000 2153a0f1b2c3 4453414355202020 00008ef8 41 000186a0");
}

TEST(Itch50Golden, J_LuldAuctionCollar) {
  const LuldAuctionCollar m{.stock_locate = 0x1230,
                            .tracking_number = 0,
                            .timestamp = 0x1FF0688D8200,
                            .stock = Symbol8("LBTYB"),
                            .reference_price = 430'400,
                            .upper_price = 473'400,
                            .lower_price = 387'400,
                            .extension = 1};
  expect_golden(m, "4a 1230 0000 1ff0688d8200 4c42545942202020 00069140 00073938 0005e948 00000001");
}

TEST(Itch50Golden, h_OperationalHalt) {
  const OperationalHalt m{.stock_locate = 0x0101,
                          .tracking_number = 7,
                          .timestamp = 0x123456789ABC,
                          .stock = Symbol8("QQQ"),
                          .market_code = MarketCode::NasdaqTexas,
                          .action = OperationalHaltAction::Halted};
  expect_golden(m, "68 0101 0007 123456789abc 5151512020202020 42 48");
}

TEST(Itch50Golden, A_AddOrder) {
  const AddOrder m{.stock_locate = 14,
                   .tracking_number = 1,
                   .timestamp = 0x0D18C2EB224B,
                   .order_ref = 0x0102030405060708,
                   .side = Side::Buy,
                   .shares = 100'000,
                   .stock = Symbol8("AAPL"),
                   .price = 1'999'999'900};  // $199,999.9900 stub price
  expect_golden(m, "41 000e 0001 0d18c2eb224b 0102030405060708 42 000186a0 4141504c20202020 7735939c");
}

TEST(Itch50Golden, F_AddOrderMpid) {
  const AddOrderMpid m{.stock_locate = 0x2203,
                       .tracking_number = 0,
                       .timestamp = 0x0D18C449143A,
                       .order_ref = 6004,
                       .side = Side::Sell,
                       .shares = 100,
                       .stock = Symbol8("ZVZZT"),
                       .price = 150'000,
                       .attribution = Mpid4("LEHM")};
  expect_golden(m, "46 2203 0000 0d18c449143a 0000000000001774 53 00000064 5a565a5a54202020 000249f0 4c45484d");
}

TEST(Itch50Golden, E_OrderExecuted) {
  const OrderExecuted m{.stock_locate = 0x217d,
                        .tracking_number = 2,
                        .timestamp = 0x0D18C9B2926C,
                        .order_ref = 224,
                        .executed_shares = 81,
                        .match_number = 17'421};
  expect_golden(m, "45 217d 0002 0d18c9b2926c 00000000000000e0 00000051 000000000000440d");
}

TEST(Itch50Golden, C_OrderExecutedWithPrice) {
  const OrderExecutedWithPrice m{.stock_locate = 0x1a85,
                                 .tracking_number = 1,
                                 .timestamp = 0x1C8C63DD59FD,
                                 .order_ref = 5'443'991,
                                 .executed_shares = 100,
                                 .match_number = 47'591,
                                 .printable = YesNo::No,
                                 .execution_price = 710'500};
  expect_golden(m, "43 1a85 0001 1c8c63dd59fd 0000000000531197 00000064 000000000000b9e7 4e 000ad764");
}

TEST(Itch50Golden, X_OrderCancel) {
  const OrderCancel m{.stock_locate = 0x146c, .tracking_number = 0, .timestamp = 0x0D18C6A4CE94, .order_ref = 23'411, .cancelled_shares = 500};
  expect_golden(m, "58 146c 0000 0d18c6a4ce94 0000000000005b73 000001f4");
}

TEST(Itch50Golden, D_OrderDelete) {
  const OrderDelete m{.stock_locate = 0x207e, .tracking_number = 0, .timestamp = 0x0D18C399A2D9, .order_ref = 952};
  expect_golden(m, "44 207e 0000 0d18c399a2d9 00000000000003b8");
}

TEST(Itch50Golden, U_OrderReplace) {
  const OrderReplace m{.stock_locate = 0x17c0,
                       .tracking_number = 0,
                       .timestamp = 0x0D18C4E93EB8,
                       .original_order_ref = 659,
                       .new_order_ref = 14'563,
                       .shares = 1600,
                       .price = 377'400};
  expect_golden(m, "55 17c0 0000 0d18c4e93eb8 0000000000000293 00000000000038e3 00000640 0005c238");
}

TEST(Itch50Golden, P_Trade) {
  const Trade m{.stock_locate = 0x1f07,
                .tracking_number = 2,
                .timestamp = 0x0D18CECDD8A3,
                .order_ref = 0,
                .side = Side::Buy,
                .shares = 341,
                .stock = Symbol8("UGAZ"),
                .price = 391'600,
                .match_number = 17'425};
  expect_golden(m, "50 1f07 0002 0d18cecdd8a3 0000000000000000 42 00000155 5547415a20202020 0005f9b0 0000000000004411");
}

TEST(Itch50Golden, Q_CrossTrade) {
  // AAPL 2019-01-30 closing cross: 2,340,937 shares at $165.25.
  const CrossTrade m{.stock_locate = 14,
                     .tracking_number = 1,
                     .timestamp = 0x1F1ACEE28EC2,
                     .shares = 2'340'937,
                     .stock = Symbol8("AAPL"),
                     .cross_price = 1'652'500,
                     .match_number = 0xABCDEF,
                     .cross_type = CrossType::Closing};
  expect_golden(m, "51 000e 0001 1f1acee28ec2 000000000023b849 4141504c20202020 00193714 0000000000abcdef 43");
}

TEST(Itch50Golden, B_BrokenTrade) {
  const BrokenTrade m{.stock_locate = 0x0a04, .tracking_number = 0, .timestamp = 0x2F88DEF176E5, .match_number = 4'756'379};
  expect_golden(m, "42 0a04 0000 2f88def176e5 000000000048939b");
}

TEST(Itch50Golden, I_Noii) {
  const Noii m{.stock_locate = 0x0a89,
               .tracking_number = 0,
               .timestamp = 0x1848CFA0E066,
               .paired_shares = 5000,
               .imbalance_shares = 1000,
               .imbalance_direction = ImbalanceDirection::Buy,
               .stock = Symbol8("EYEN"),
               .far_price = 100'000,
               .near_price = 100'001,
               .current_reference_price = 100'002,
               .cross_type = NoiiCrossType::ExtendedTradingClose,
               .price_variation_indicator = PriceVariation::Pct1To2};
  expect_golden(m,
                "49 0a89 0000 1848cfa0e066 0000000000001388 00000000000003e8 42 4559454e20202020 000186a0 000186a1 "
                "000186a2 41 31");
}

TEST(Itch50Golden, N_RetailInterest) {
  const RetailInterest m{.stock_locate = 0x33,
                         .tracking_number = 0,
                         .timestamp = 0x2A0B0C0D0E0F,
                         .stock = Symbol8("SPY"),
                         .interest_flag = InterestFlag::BothSides};
  expect_golden(m, "4e 0033 0000 2a0b0c0d0e0f 5350592020202020 41");
}

TEST(Itch50Golden, O_DlcrPriceDiscovery) {
  const DlcrPriceDiscovery m{.stock_locate = 0x0abc,
                             .tracking_number = 5,
                             .timestamp = 0x2B0000000001,
                             .stock = Symbol8("NEWCO"),
                             .open_eligibility_status = YesNo::Yes,
                             .min_allowable_price = 200'000,
                             .max_allowable_price = 400'000,
                             .near_execution_price = 300'000,
                             .near_execution_time = 3600,
                             .lower_price_range_collar = 280'000,
                             .upper_price_range_collar = 320'000};
  expect_golden(m,
                "4f 0abc 0005 2b0000000001 4e4557434f202020 59 00030d40 00061a80 000493e0 0000000000000e10 000445c0 "
                "0004e200");
}

}  // namespace
}  // namespace lle::itch50

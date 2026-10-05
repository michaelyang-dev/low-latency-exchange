#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "proto/itch50/validator.h"

namespace lle::itch50 {
namespace {

template <class M>
std::vector<std::byte> bytes_of(const M& m) {
  std::vector<std::byte> b(M::kLen);
  EXPECT_EQ(encode(b, m), M::kLen);
  return b;
}

SystemEvent sys(std::uint64_t ts, EventCode c) {
  return SystemEvent{.stock_locate = 0, .tracking_number = 0, .timestamp = ts, .event_code = c};
}

AddOrder add(std::uint64_t ts, Locate loc = 1) {
  return AddOrder{.stock_locate = loc,
                  .tracking_number = 0,
                  .timestamp = ts,
                  .order_ref = 1,
                  .side = Side::Buy,
                  .shares = 100,
                  .stock = Symbol8("AAPL"),
                  .price = 1'000'000};
}

StockDirectory dir(std::uint64_t ts) {
  return StockDirectory{.stock_locate = 1,
                        .tracking_number = 0,
                        .timestamp = ts,
                        .stock = Symbol8("AAPL"),
                        .market_category = MarketCategory::NasdaqGlobalSelect,
                        .financial_status = FinancialStatus::Normal,
                        .round_lot_size = 100,
                        .round_lots_only = YesNo::No,
                        .issue_classification = IssueClassification::CommonStock,
                        .issue_sub_type = Alpha<2>("Z"),
                        .authenticity = Authenticity::LiveProduction,
                        .short_sale_threshold = YesNoBlank::No,
                        .ipo_flag = IpoFlag::NotNewIpo,
                        .luld_tier = LuldTier::Tier1,
                        .etp_flag = YesNoBlank::No,
                        .etp_leverage_factor = 0,
                        .inverse_indicator = YesNo::No};
}

TEST(Validator, CleanStreamHasNoViolations) {
  Validator v;
  EXPECT_EQ(v.check(bytes_of(sys(1, EventCode::StartOfMessages))), 0u);
  EXPECT_EQ(v.check(bytes_of(dir(2))), 0u);
  StockTradingAction h{.stock_locate = 1, .tracking_number = 0, .timestamp = 3, .stock = Symbol8("AAPL"),
                       .trading_state = TradingState::Paused, .reserved = ' ', .reason = Alpha<4>("LUDP")};
  EXPECT_EQ(v.check(bytes_of(h)), 0u);
  EXPECT_EQ(v.check(bytes_of(add(3))), 0u);
  MwcbDeclineLevel lv{.stock_locate = 0, .tracking_number = 0, .timestamp = 4, .level1 = 1, .level2 = 2, .level3 = 3};
  EXPECT_EQ(v.check(bytes_of(lv)), 0u);
  EXPECT_EQ(v.messages(), 5u);
  EXPECT_EQ(v.violations(), 0u);
  EXPECT_TRUE(v.examples().empty());
}

TEST(Validator, FramingRules) {
  Validator v;
  EXPECT_EQ(v.check({}), 1u);
  std::vector<std::byte> unknown(10, std::byte{'G'});
  EXPECT_EQ(v.check(unknown), 1u);
  auto a = bytes_of(add(1));
  a.push_back(std::byte{0});
  EXPECT_EQ(v.check(a), 1u);
  EXPECT_EQ(v.count(Validator::Rule::ZeroLength), 1u);
  EXPECT_EQ(v.count(Validator::Rule::UnknownType), 1u);
  EXPECT_EQ(v.count(Validator::Rule::BadLength), 1u);
  EXPECT_EQ(v.count(Validator::Rule::BadLength, 'A'), 1u);
  ASSERT_EQ(v.examples().size(), 3u);
  EXPECT_EQ(v.examples()[2].index, 3u);
  EXPECT_EQ(v.examples()[2].value, 37u);
}

TEST(Validator, EnumAndCodeSets) {
  Validator v;
  auto s = sys(1, static_cast<EventCode>('X'));
  EXPECT_EQ(v.check(bytes_of(s)), 1u);
  auto d = dir(2);
  d.market_category = static_cast<MarketCategory>('?');
  d.ipo_flag = static_cast<IpoFlag>('Q');
  d.issue_sub_type = Alpha<2>("QQ");
  EXPECT_EQ(v.check(bytes_of(d)), 3u);
  StockTradingAction h{.stock_locate = 1, .tracking_number = 0, .timestamp = 3, .stock = Symbol8("AAPL"),
                       .trading_state = TradingState::Halted, .reserved = ' ', .reason = Alpha<4>("ZZZZ")};
  EXPECT_EQ(v.check(bytes_of(h)), 1u);
  auto a = add(4);
  a.side = static_cast<Side>('b');
  EXPECT_EQ(v.check(bytes_of(a)), 1u);
  EXPECT_EQ(v.count(Validator::Rule::EnumOutOfSet), 4u);
  EXPECT_EQ(v.count(Validator::Rule::CodeOutOfSet), 2u);
  EXPECT_EQ(v.field_count(FieldId::SystemEvent_event_code), 1u);
  EXPECT_EQ(v.field_count(FieldId::StockDirectory_market_category), 1u);
  EXPECT_EQ(v.field_count(FieldId::StockDirectory_ipo_flag), 1u);
  EXPECT_EQ(v.field_count(FieldId::StockDirectory_issue_sub_type), 1u);
  EXPECT_EQ(v.field_count(FieldId::StockTradingAction_reason), 1u);
  EXPECT_EQ(v.field_count(FieldId::AddOrder_side), 1u);
  EXPECT_EQ(field_name(FieldId::AddOrder_side), "AddOrder.side");
  EXPECT_EQ(v.examples()[0].value, static_cast<unsigned char>('X'));
  EXPECT_TRUE(is_valid_issue_sub_type(Alpha<2>("EM")));
  EXPECT_TRUE(is_valid_trading_action_reason(Alpha<4>()));
  EXPECT_TRUE(is_valid_trading_action_reason(Alpha<4>("IPOQ")));
}

TEST(Validator, LocateAndTimestampRules) {
  Validator v;
  SystemEvent s = sys(10, EventCode::StartOfSystemHours);
  s.stock_locate = 5;
  EXPECT_EQ(v.check(bytes_of(s)), 1u);
  EXPECT_EQ(v.check(bytes_of(add(20, 0))), 1u);
  IpoQuotingPeriodUpdate k{.stock_locate = 0, .tracking_number = 0, .timestamp = 30, .stock = Symbol8("X"),
                           .release_time = 0, .release_qualifier = IpoReleaseQualifier::CanceledPostponed, .ipo_price = 0};
  EXPECT_EQ(v.check(bytes_of(k)), 0u);  // K: locate "always 0"
  EXPECT_EQ(v.check(bytes_of(add(29))), 1u);                 // decrease
  EXPECT_EQ(v.check(bytes_of(add(kMaxTimestamp))), 1u);      // 24:00:00
  EXPECT_EQ(v.count(Validator::Rule::LocateNotZero), 1u);
  EXPECT_EQ(v.count(Validator::Rule::LocateZero), 1u);
  EXPECT_EQ(v.count(Validator::Rule::TimestampDecrease), 1u);
  EXPECT_EQ(v.count(Validator::Rule::TimestampOverDay), 1u);
  EXPECT_EQ(Validator::rule_name(Validator::Rule::LocateZero), "locate_zero");
}

TEST(Validator, NonStrictChecksFramingOnly) {
  Validator v(false);
  EXPECT_EQ(v.check(bytes_of(add(20, 0))), 0u);
  EXPECT_EQ(v.check(bytes_of(sys(1, static_cast<EventCode>('X')))), 0u);
  EXPECT_EQ(v.check({}), 1u);
  EXPECT_FALSE(v.strict());
}

TEST(Validator, ExamplesAreBounded) {
  Validator v;
  for (int i = 0; i < 200; ++i) v.check({});
  EXPECT_EQ(v.violations(), 200u);
  EXPECT_EQ(v.examples().size(), Validator::kMaxExamples);
}

}  // namespace
}  // namespace lle::itch50

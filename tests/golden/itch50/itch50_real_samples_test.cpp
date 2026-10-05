// Real-byte samples, one per type seen in NASDAQ's 2019-01-30 file
// (docs/plan/research/data/01302019.samples.txt). Each line carries the record
// index, type, length and the raw bytes. The expected field values below were
// decoded by hand from those bytes (and cross-checked against the R1a notes).
//
// The samples are bytes of NASDAQ's file, which is not redistributed: the file lives
// with the research notes and is not part of the repository, so the suite skips when
// it is absent (a fresh clone, CI). The hand-assembled golden vectors in
// itch50_golden_test.cpp cover every type without it.
#include <gtest/gtest.h>

#include <cctype>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <vector>

#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

struct Sample {
  std::uint64_t index = 0;
  char type = 0;
  std::size_t len = 0;
  std::vector<std::byte> bytes;
};

const std::string kSamplesPath = std::string(LLE_SOURCE_DIR) + "/docs/plan/research/data/01302019.samples.txt";

std::map<char, Sample> load_samples() {
  std::map<char, Sample> out;
  std::ifstream in(kSamplesPath);
  if (!in.good()) return out;
  const std::regex re(R"(#(\d+) type (.) len (\d+) : (.*))");
  std::string line;
  while (std::getline(in, line)) {
    std::smatch m;
    if (!std::regex_match(line, m, re)) continue;
    Sample s;
    s.index = std::stoull(m[1].str());
    s.type = m[2].str()[0];
    s.len = std::stoul(m[3].str());
    std::string hex;
    for (char c : m[4].str())
      if (std::isxdigit(static_cast<unsigned char>(c))) hex += c;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
      s.bytes.push_back(static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    out[s.type] = std::move(s);
  }
  return out;
}

class RealSamples : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { samples_ = new std::map<char, Sample>(load_samples()); }
  void SetUp() override {
    if (samples_->empty()) GTEST_SKIP() << "NASDAQ sample bytes not present (" << kSamplesPath << "); not redistributed";
  }
  static void TearDownTestSuite() {
    delete samples_;
    samples_ = nullptr;
  }
  template <class V>
  static V view() {
    const Sample& s = samples_->at(V::kType);
    EXPECT_EQ(s.bytes.size(), V::kLen);
    return V{s.bytes.data()};
  }
  static std::map<char, Sample>* samples_;
};
std::map<char, Sample>* RealSamples::samples_ = nullptr;

TEST_F(RealSamples, EverySampleDecodesAndRoundTrips) {
  ASSERT_EQ(samples_->size(), 18u);  // S R H Y L A D F U X E P V I C Q J B
  for (const auto& [type, s] : *samples_) {
    SCOPED_TRACE(std::string(1, type));
    ASSERT_EQ(s.bytes.size(), s.len);
    ASSERT_EQ(kMsgLen[static_cast<unsigned char>(type)], s.len);
    std::array<std::byte, kMaxMsgLen> out{};
    bool done = false;
    ASSERT_EQ(visit(s.bytes,
                    [&](auto v) {
                      EXPECT_EQ(encode(out, v.to_struct()), s.len);
                      EXPECT_EQ(std::memcmp(out.data(), s.bytes.data(), s.len), 0);
                      done = true;
                    }),
              DecodeStatus::Ok);
    EXPECT_TRUE(done);
  }
}

TEST_F(RealSamples, S) {
  const auto v = view<SystemEventView>();
  EXPECT_EQ(v.stock_locate(), 0);
  EXPECT_EQ(v.timestamp(), 11'039'687'760'787ull);  // 03:03:59.687760787
  EXPECT_EQ(v.event_code(), EventCode::StartOfMessages);
}

TEST_F(RealSamples, R) {
  const auto v = view<StockDirectoryView>();
  EXPECT_EQ(v.stock_locate(), 1);
  EXPECT_EQ(v.timestamp(), 11'314'234'545'561ull);
  EXPECT_EQ(v.stock().view(), "A");
  EXPECT_EQ(v.market_category(), MarketCategory::Nyse);
  EXPECT_EQ(v.financial_status(), FinancialStatus::NotAvailable);
  EXPECT_EQ(v.round_lot_size(), 100u);
  EXPECT_EQ(v.round_lots_only(), YesNo::No);
  EXPECT_EQ(v.issue_classification(), IssueClassification::CommonStock);
  EXPECT_EQ(v.issue_sub_type().raw(), "Z ");
  EXPECT_EQ(v.authenticity(), Authenticity::LiveProduction);
  EXPECT_EQ(v.short_sale_threshold(), YesNoBlank::No);
  EXPECT_EQ(v.ipo_flag(), IpoFlag::NotAvailable);
  EXPECT_EQ(v.luld_tier(), LuldTier::Tier1);
  EXPECT_EQ(v.etp_flag(), YesNoBlank::No);
  EXPECT_EQ(v.etp_leverage_factor(), 0u);
  EXPECT_EQ(v.inverse_indicator(), YesNo::No);
}

TEST_F(RealSamples, H) {
  const auto v = view<StockTradingActionView>();
  EXPECT_EQ(v.stock_locate(), 1);
  EXPECT_EQ(v.stock().view(), "A");
  EXPECT_EQ(v.trading_state(), TradingState::Trading);
  EXPECT_EQ(v.reserved(), ' ');
  EXPECT_TRUE(v.reason().blank());
}

TEST_F(RealSamples, Y) {
  const auto v = view<RegShoRestrictionView>();
  EXPECT_EQ(v.timestamp(), 11'314'237'684'108ull);
  EXPECT_EQ(v.stock().view(), "A");
  EXPECT_EQ(v.reg_sho_action(), RegShoAction::NoPriceTest);
}

TEST_F(RealSamples, L) {
  const auto v = view<MarketParticipantPositionView>();
  EXPECT_EQ(v.stock_locate(), 5781);
  EXPECT_EQ(v.mpid().view(), "LEER");
  EXPECT_EQ(v.stock().view(), "ONCE");
  EXPECT_EQ(v.primary_market_maker(), YesNo::Yes);
  EXPECT_EQ(v.market_maker_mode(), MarketMakerMode::Normal);
  EXPECT_EQ(v.participant_state(), ParticipantState::Active);
}

TEST_F(RealSamples, A) {
  const auto v = view<AddOrderView>();
  EXPECT_EQ(v.stock_locate(), 484);
  EXPECT_EQ(v.timestamp(), 14'400'000'565'835ull);  // 04:00:00.000565835
  EXPECT_EQ(v.order_ref(), 9005u);
  EXPECT_EQ(v.side(), Side::Sell);
  EXPECT_EQ(v.shares(), 600u);
  EXPECT_EQ(v.stock().view(), "ARGX");
  EXPECT_EQ(v.price(), 1'072'600);  // $107.2600
}

TEST_F(RealSamples, D) {
  const auto v = view<OrderDeleteView>();
  EXPECT_EQ(v.stock_locate(), 8318);
  EXPECT_EQ(v.order_ref(), 952u);
}

TEST_F(RealSamples, F) {
  const auto v = view<AddOrderMpidView>();
  EXPECT_EQ(v.stock_locate(), 8707);
  EXPECT_EQ(v.order_ref(), 6004u);
  EXPECT_EQ(v.side(), Side::Sell);
  EXPECT_EQ(v.shares(), 100u);
  EXPECT_EQ(v.stock().view(), "ZVZZT");
  EXPECT_EQ(v.price(), 150'000);
  EXPECT_EQ(v.attribution().view(), "LEHM");
}

TEST_F(RealSamples, U) {
  // R1a Q3: original reference 659, new reference 14,563, 1,600 shares, $37.74.
  const auto v = view<OrderReplaceView>();
  EXPECT_EQ(v.stock_locate(), 6080);
  EXPECT_EQ(v.original_order_ref(), 659u);
  EXPECT_EQ(v.new_order_ref(), 14'563u);
  EXPECT_EQ(v.shares(), 1600u);
  EXPECT_EQ(v.price(), 377'400);
}

TEST_F(RealSamples, X) {
  const auto v = view<OrderCancelView>();
  EXPECT_EQ(v.order_ref(), 23'411u);
  EXPECT_EQ(v.cancelled_shares(), 500u);
}

TEST_F(RealSamples, E) {
  const auto v = view<OrderExecutedView>();
  EXPECT_EQ(v.stock_locate(), 8573);
  EXPECT_EQ(v.tracking_number(), 2);
  EXPECT_EQ(v.order_ref(), 224u);
  EXPECT_EQ(v.executed_shares(), 81u);
  EXPECT_EQ(v.match_number(), 17'421u);
}

TEST_F(RealSamples, P) {
  const auto v = view<TradeView>();
  EXPECT_EQ(v.order_ref(), 0u);  // always 0 since 2010-12-06
  EXPECT_EQ(v.side(), Side::Buy);  // always B since 2014-07-14
  EXPECT_EQ(v.shares(), 1u);
  EXPECT_EQ(v.stock().view(), "UGAZ");
  EXPECT_EQ(v.price(), 391'600);
  EXPECT_EQ(v.match_number(), 17'425u);
}

TEST_F(RealSamples, V) {
  // 2455.20 / 2296.80 / 2112.00 in Price(8).
  const auto v = view<MwcbDeclineLevelView>();
  EXPECT_EQ(v.stock_locate(), 0);
  EXPECT_EQ(v.timestamp(), 25'204'318'806'392ull);  // 07:00:04.318806392
  EXPECT_EQ(v.level1(), 245'520'000'000);
  EXPECT_EQ(v.level2(), 229'680'000'000);
  EXPECT_EQ(v.level3(), 211'200'000'000);
}

TEST_F(RealSamples, I) {
  const auto v = view<NoiiView>();
  EXPECT_EQ(v.stock_locate(), 2697);
  EXPECT_EQ(v.paired_shares(), 0u);
  EXPECT_EQ(v.imbalance_shares(), 0u);
  EXPECT_EQ(v.imbalance_direction(), ImbalanceDirection::InsufficientOrders);
  EXPECT_EQ(v.stock().view(), "EYEN");
  EXPECT_EQ(v.far_price(), 0);
  EXPECT_EQ(v.near_price(), 0);
  EXPECT_EQ(v.current_reference_price(), 0);
  EXPECT_EQ(v.cross_type(), NoiiCrossType::HaltOrIpo);
  EXPECT_EQ(v.price_variation_indicator(), PriceVariation::CannotCalculate);
}

TEST_F(RealSamples, C) {
  const auto v = view<OrderExecutedWithPriceView>();
  EXPECT_EQ(v.order_ref(), 5'443'991u);
  EXPECT_EQ(v.executed_shares(), 100u);
  EXPECT_EQ(v.match_number(), 47'591u);
  EXPECT_EQ(v.printable(), YesNo::No);
  EXPECT_EQ(v.execution_price(), 710'500);
}

TEST_F(RealSamples, Q) {
  // Zero-share opening cross (normal: 11,996 of 17,430 Q messages in this file).
  const auto v = view<CrossTradeView>();
  EXPECT_EQ(v.timestamp(), 34'200'000'564'930ull);  // 09:30:00.000564930
  EXPECT_EQ(v.shares(), 0u);
  EXPECT_EQ(v.stock().view(), "FRI");
  EXPECT_EQ(v.cross_price(), 0);
  EXPECT_EQ(v.match_number(), 74'991u);
  EXPECT_EQ(v.cross_type(), CrossType::Opening);
}

TEST_F(RealSamples, J) {
  const auto v = view<LuldAuctionCollarView>();
  EXPECT_EQ(v.stock_locate(), 4656);
  EXPECT_EQ(v.stock().view(), "LBTYB");
  EXPECT_EQ(v.reference_price(), 231'000);
  EXPECT_EQ(v.upper_price(), 242'600);
  EXPECT_EQ(v.lower_price(), 189'000);
  EXPECT_EQ(v.extension(), 0u);
}

TEST_F(RealSamples, B) {
  const auto v = view<BrokenTradeView>();
  EXPECT_EQ(v.stock_locate(), 2564);
  EXPECT_EQ(v.match_number(), 4'756'379u);
}

}  // namespace
}  // namespace lle::itch50

#include "proto/itch50/census.h"

#include <algorithm>
#include <cstdlib>
#include <utility>
#include <vector>

#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

enum CharField : std::uint8_t {
  kSEvent,
  kRMarketCategory,
  kRFinancialStatus,
  kRRoundLotsOnly,
  kRIssueClassification,
  kRAuthenticity,
  kRShortSaleThreshold,
  kRIpoFlag,
  kRLuldTier,
  kREtpFlag,
  kRInverse,
  kHTradingState,
  kHReserved,
  kYRegShoAction,
  kLPrimaryMm,
  kLMmMode,
  kLMpState,
  kWBreachedLevel,
  kKQualifier,
  khMarketCode,
  khAction,
  kNInterestFlag,
  kOOpenEligibility,
  kQCrossType,
  kIImbalanceDirection,
  kICrossType,
  kIPriceVariation,
  kNumCharFields
};

// Labels as printed by the research analyzer.
constexpr const char* kCharFieldLabels[kNumCharFields] = {
    "S.event",          "R.market_category",  "R.financial_status",   "R.round_lots_only", "R.issue_classification",
    "R.authenticity",   "R.short_sale_threshold", "R.ipo_flag",       "R.luld_tier",       "R.etp_flag",
    "R.inverse",        "H.trading_state",    "H.reserved",           "Y.reg_sho_action",  "L.primary_mm",
    "L.mm_mode",        "L.mp_state",         "W.breached_level",     "K.qualifier",       "h.market_code",
    "h.action",         "N.interest_flag",    "O.open_eligibility",   "Q.cross_type",      "I.imbalance_direction",
    "I.cross_type",     "I.price_variation",
};

std::string chr_label(unsigned char c) {
  if (c == ' ') return "<space>";
  if (c < 32 || c > 126) {
    char b[8];
    std::snprintf(b, sizeof b, "0x%02x", c);
    return b;
  }
  return std::string(1, static_cast<char>(c));
}

std::string hms(std::uint64_t ns) {
  char b[64];
  const std::uint64_t s = ns / 1'000'000'000ull;
  std::snprintf(b, sizeof b, "%02llu:%02llu:%02llu.%09llu", static_cast<unsigned long long>(s / 3600),
                static_cast<unsigned long long>(s / 60 % 60), static_cast<unsigned long long>(s % 60),
                static_cast<unsigned long long>(ns % 1'000'000'000ull));
  return b;
}

template <std::size_t N>
std::uint64_t pack_alpha(const Alpha<N>& a) noexcept {
  std::uint64_t v = 0;
  for (char c : a.c) v = (v << 8) | static_cast<unsigned char>(c);
  return v;
}

template <std::size_t N>
std::string unpack_alpha(std::uint64_t v) {
  std::string s(N, ' ');
  for (std::size_t i = N; i-- > 0;) {
    s[i] = static_cast<char>(v & 0xFF);
    v >>= 8;
  }
  return s;
}

unsigned char uc(auto e) noexcept { return static_cast<unsigned char>(static_cast<char>(e)); }

int expected_len(unsigned t) noexcept { return kMsgLen[t] != 0 ? int{kMsgLen[t]} : -1; }

}  // namespace

struct Census::EnumHistograms {
  std::array<std::array<std::uint64_t, 256>, kNumCharFields> chars{};
  std::map<std::uint32_t, std::uint64_t> round_lot, etp_leverage;
  std::map<std::uint64_t, std::uint64_t> issue_subtype, h_reason, f_attribution;  // packed big-endian
  std::map<std::string, std::uint64_t> v_levels;
  std::uint64_t j_count = 0;

  void bump(CharField f, unsigned char c) noexcept { ++chars[f][c]; }

  void operator()(const SystemEventView& v) noexcept { bump(kSEvent, uc(v.event_code())); }
  void operator()(const StockDirectoryView& v) {
    bump(kRMarketCategory, uc(v.market_category()));
    bump(kRFinancialStatus, uc(v.financial_status()));
    ++round_lot[v.round_lot_size()];
    bump(kRRoundLotsOnly, uc(v.round_lots_only()));
    bump(kRIssueClassification, uc(v.issue_classification()));
    ++issue_subtype[pack_alpha(v.issue_sub_type())];
    bump(kRAuthenticity, uc(v.authenticity()));
    bump(kRShortSaleThreshold, uc(v.short_sale_threshold()));
    bump(kRIpoFlag, uc(v.ipo_flag()));
    bump(kRLuldTier, uc(v.luld_tier()));
    bump(kREtpFlag, uc(v.etp_flag()));
    ++etp_leverage[v.etp_leverage_factor()];
    bump(kRInverse, uc(v.inverse_indicator()));
  }
  void operator()(const StockTradingActionView& v) {
    bump(kHTradingState, uc(v.trading_state()));
    bump(kHReserved, static_cast<unsigned char>(v.reserved()));
    ++h_reason[pack_alpha(v.reason())];
  }
  void operator()(const RegShoRestrictionView& v) noexcept { bump(kYRegShoAction, uc(v.reg_sho_action())); }
  void operator()(const MarketParticipantPositionView& v) noexcept {
    bump(kLPrimaryMm, uc(v.primary_market_maker()));
    bump(kLMmMode, uc(v.market_maker_mode()));
    bump(kLMpState, uc(v.participant_state()));
  }
  void operator()(const MwcbDeclineLevelView& v) {
    char b[128];
    std::snprintf(b, sizeof b, "%llu/%llu/%llu", static_cast<unsigned long long>(v.level1()),
                  static_cast<unsigned long long>(v.level2()), static_cast<unsigned long long>(v.level3()));
    ++v_levels[b];
  }
  void operator()(const MwcbStatusView& v) noexcept { bump(kWBreachedLevel, uc(v.breached_level())); }
  void operator()(const IpoQuotingPeriodUpdateView& v) noexcept { bump(kKQualifier, uc(v.release_qualifier())); }
  void operator()(const LuldAuctionCollarView&) noexcept { ++j_count; }
  void operator()(const OperationalHaltView& v) noexcept {
    bump(khMarketCode, uc(v.market_code()));
    bump(khAction, uc(v.action()));
  }
  void operator()(const AddOrderMpidView& v) { ++f_attribution[pack_alpha(v.attribution())]; }
  void operator()(const CrossTradeView& v) noexcept { bump(kQCrossType, uc(v.cross_type())); }
  void operator()(const NoiiView& v) noexcept {
    bump(kIImbalanceDirection, uc(v.imbalance_direction()));
    bump(kICrossType, uc(v.cross_type()));
    bump(kIPriceVariation, uc(v.price_variation_indicator()));
  }
  void operator()(const RetailInterestView& v) noexcept { bump(kNInterestFlag, uc(v.interest_flag())); }
  void operator()(const DlcrPriceDiscoveryView& v) noexcept { bump(kOOpenEligibility, uc(v.open_eligibility_status())); }
  template <class V>
  void operator()(const V&) noexcept {}

  // label -> value -> count, for every field that saw at least one message.
  std::map<std::string, std::map<std::string, std::uint64_t>> collect() const {
    std::map<std::string, std::map<std::string, std::uint64_t>> out;
    for (std::size_t f = 0; f < kNumCharFields; ++f) {
      for (unsigned c = 0; c < 256; ++c) {
        if (chars[f][c] != 0) out[kCharFieldLabels[f]][chr_label(static_cast<unsigned char>(c))] += chars[f][c];
      }
    }
    for (const auto& [k, n] : round_lot) out["R.round_lot_size"][std::to_string(k)] += n;
    for (const auto& [k, n] : etp_leverage) out["R.etp_leverage"][std::to_string(k)] += n;
    for (const auto& [k, n] : issue_subtype) out["R.issue_subtype"][unpack_alpha<2>(k)] += n;
    for (const auto& [k, n] : h_reason) out["H.reason"][unpack_alpha<4>(k)] += n;
    for (const auto& [k, n] : f_attribution) out["F.attribution_top"][unpack_alpha<4>(k)] += n;
    for (const auto& [k, n] : v_levels) out["V.levels_raw"][k] += n;
    if (j_count != 0) out["J.count"]["1"] = j_count;
    return out;
  }
};

Census::Census() : enums_(std::make_unique<EnumHistograms>()) {
  // calloc: large zeroed allocations come from fresh pages, committed on first touch.
  per_ms_ = static_cast<std::uint32_t*>(std::calloc(kMsPerDay + 1, sizeof(std::uint32_t)));
  LLE_ASSERT(per_ms_ != nullptr, "Census: cannot allocate per-millisecond buckets");
}

Census::~Census() { std::free(per_ms_); }

void Census::add(std::span<const std::byte> m) noexcept {
  ++nmsg_;
  nbytes_ += 2 + m.size();
  if (m.empty()) {
    ++zero_len_;
    return;
  }
  const auto t = static_cast<unsigned char>(m[0]);
  ++cnt_[t];
  const std::size_t want = kMsgLen[t];
  if (want == 0) {
    ++unknown_;
    return;
  }
  if (want != m.size()) {
    ++lenmis_[t];
    ++bad_len_;
    return;
  }
  const MessageHeaderView h{m.data()};
  const Locate loc = h.stock_locate();
  const std::uint64_t ts = h.timestamp();
  if (loc == 0) ++loc0_[t];
  first_ts_ = std::min(first_ts_, ts);
  last_ts_ = std::max(last_ts_, ts);
  if (ts < prev_ts_) {
    ++ts_decreases_;
    max_ts_decrease_ = std::max(max_ts_decrease_, prev_ts_ - ts);
  }
  prev_ts_ = ts;
  const std::uint64_t ms = ts / 1'000'000ull;
  if (ms <= kMsPerDay) {
    ++per_ms_[ms];
  } else {
    ++ts_over_day_;
  }
  if (t == 'S' && num_sys_events_ < kMaxSysEvents) {
    sys_events_[num_sys_events_++] = SysEvent{static_cast<char>(SystemEventView{m.data()}.event_code()), ts};
  }
  (void)visit_unchecked(m.data(), *enums_);
}

std::uint32_t Census::max_in_1ms() const noexcept {
  std::uint32_t mx = 0;
  for (std::uint64_t i = 0; i < kMsPerDay; ++i) mx = std::max(mx, per_ms_[i]);
  return mx;
}

std::uint64_t Census::max_in_1s() const noexcept {
  std::uint64_t mx = 0;
  for (std::uint64_t s = 0; s < 86'400; ++s) {
    std::uint64_t sum = 0;
    for (std::uint64_t j = 0; j < 1000; ++j) sum += per_ms_[s * 1000 + j];
    mx = std::max(mx, sum);
  }
  return mx;
}

std::map<std::string, std::uint64_t> Census::enum_values(const std::string& label) const {
  auto all = enums_->collect();
  auto it = all.find(label);
  return it == all.end() ? std::map<std::string, std::uint64_t>{} : it->second;
}

void Census::print_report(std::FILE* out) const {
  using ull = unsigned long long;
  const auto pct = [this](std::uint64_t n) {
    return nmsg_ != 0 ? 100.0 * static_cast<double>(n) / static_cast<double>(nmsg_) : 0.0;
  };
  std::fprintf(out, "messages %llu  bytes(incl 2B prefix) %llu  avg_msg_len %.2f\n", static_cast<ull>(nmsg_),
               static_cast<ull>(nbytes_),
               nmsg_ != 0 ? static_cast<double>(nbytes_ - 2 * nmsg_) / static_cast<double>(nmsg_) : 0.0);
  std::fprintf(out, "zero_len %llu unknown_type %llu bad_len %llu\n", static_cast<ull>(zero_len_),
               static_cast<ull>(unknown_), static_cast<ull>(bad_len_));
  std::fprintf(out, "\nPER-TYPE COUNTS (type count pct expected_len len_mismatch locate0)\n");
  for (unsigned t = 0; t < 256; ++t) {
    if (cnt_[t] == 0) continue;
    std::fprintf(out, "  %c %12llu %7.3f%% len=%d mism=%llu loc0=%llu\n", static_cast<char>(t),
                 static_cast<ull>(cnt_[t]), pct(cnt_[t]), expected_len(t), static_cast<ull>(lenmis_[t]),
                 static_cast<ull>(loc0_[t]));
  }
  std::fprintf(out, "\nTIMESTAMPS first %s last %s decreases %llu max_decrease_ns %llu over_day %llu\n",
               hms(first_ts_).c_str(), hms(last_ts_).c_str(), static_cast<ull>(ts_decreases_),
               static_cast<ull>(max_ts_decrease_), static_cast<ull>(ts_over_day_));
  std::fprintf(out, "SYSTEM EVENTS:");
  for (std::size_t i = 0; i < num_sys_events_; ++i)
    std::fprintf(out, " %c@%s", sys_events_[i].code, hms(sys_events_[i].ts).c_str());
  std::fprintf(out, "\n");

  // Burst maxima over aligned 1 ms, 100 ms and 1 s buckets (first maximum wins).
  std::uint32_t max1ms = 0;
  std::uint64_t max1ms_at = 0, max1s = 0, max1s_at = 0, max100ms = 0;
  for (std::uint64_t i = 0; i < kMsPerDay; ++i) {
    if (per_ms_[i] > max1ms) {
      max1ms = per_ms_[i];
      max1ms_at = i;
    }
  }
  for (std::uint64_t s = 0; s < 86'400; ++s) {
    std::uint64_t sum = 0;
    for (std::uint64_t j = 0; j < 1000; ++j) sum += per_ms_[s * 1000 + j];
    if (sum > max1s) {
      max1s = sum;
      max1s_at = s;
    }
  }
  for (std::uint64_t s = 0; s < 864'000; ++s) {
    std::uint64_t sum = 0;
    for (std::uint64_t j = 0; j < 100; ++j) sum += per_ms_[s * 100 + j];
    max100ms = std::max(max100ms, sum);
  }
  std::fprintf(out,
               "BURSTS max_msgs_in_1ms %u at %s ; max_in_100ms %llu ; max_in_1s %llu at second %llu "
               "(%02llu:%02llu:%02llu)\n",
               max1ms, hms(max1ms_at * 1'000'000ull).c_str(), static_cast<ull>(max100ms), static_cast<ull>(max1s),
               static_cast<ull>(max1s_at), static_cast<ull>(max1s_at / 3600), static_cast<ull>(max1s_at / 60 % 60),
               static_cast<ull>(max1s_at % 60));
  std::fprintf(out, "HOURLY:");
  for (std::uint64_t h = 0; h < 24; ++h) {
    std::uint64_t sum = 0;
    for (std::uint64_t i = h * 3'600'000ull; i < (h + 1) * 3'600'000ull; ++i) sum += per_ms_[i];
    if (sum != 0) std::fprintf(out, " %02llu:%llu", static_cast<ull>(h), static_cast<ull>(sum));
  }
  std::fprintf(out, "\n");
  std::uint64_t rth = 0;
  for (std::uint64_t i = 34'200'000ull; i < 57'600'000ull; ++i) rth += per_ms_[i];
  std::fprintf(out, "REGULAR_HOURS(09:30-16:00) msgs %llu (%.2f%%), mean %.0f msgs/s\n", static_cast<ull>(rth), pct(rth),
               static_cast<double>(rth) / 23400.0);

  std::fprintf(out, "\nENUMERATIONS OBSERVED\n");
  for (const auto& [label, values] : enums_->collect()) {
    std::vector<std::pair<std::uint64_t, std::string>> v;
    v.reserve(values.size());
    for (const auto& [val, n] : values) v.emplace_back(n, val);
    std::sort(v.rbegin(), v.rend());  // count descending, then value descending
    std::fprintf(out, "  %s (%zu distinct):", label.c_str(), v.size());
    const std::size_t lim =
        (label == "F.attribution_top" || label == "R.round_lot_size" || label == "V.levels_raw") ? 8 : 60;
    for (std::size_t i = 0; i < v.size() && i < lim; ++i)
      std::fprintf(out, " '%s'=%llu", v[i].second.c_str(), static_cast<ull>(v[i].first));
    std::fprintf(out, "\n");
  }
}

void Census::print_coverage(std::FILE* out) const {
  std::fprintf(out, "COVERAGE (types seen in this stream = real bytes; others rely on spec vectors only)\n");
  std::string seen, unseen;
  for (char t : kMessageTypes) {
    std::string& dst = cnt_[static_cast<unsigned char>(t)] != 0 ? seen : unseen;
    if (!dst.empty()) dst += ' ';
    dst += t;
  }
  std::fprintf(out, "  real: %s\n  spec-only: %s\n", seen.empty() ? "-" : seen.c_str(),
               unseen.empty() ? "-" : unseen.c_str());
}

}  // namespace lle::itch50

#include "proto/itch50/validator.h"

#include <algorithm>

namespace lle::itch50 {
namespace {

constexpr std::string_view kFieldNames[] = {
#define ITCH_MSG(T, Name, L)
#define ITCH_FIELD(Name, f, off, len, K, E) #Name "." #f,
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
};
static_assert(std::size(kFieldNames) == static_cast<std::size_t>(FieldId::kCount));

// Appendix E: Issue Sub-Type (58 codes, 2 bytes, space padded).
constexpr std::string_view kIssueSubTypes[] = {
    "A ", "AI", "B ", "C ", "CB", "CF", "CL", "CM", "CO", "CT", "CU", "CW", "D ", "E ", "EG",
    "EI", "EM", "EN", "EU", "F ", "FI", "FL", "G ", "I ", "IR", "IW", "IX", "J ", "L ", "LL",
    "M ", "MF", "ML", "MT", "N ", "O ", "P ", "PP", "PU", "Q ", "R ", "RC", "RF", "RT", "RU",
    "S ", "SC", "SI", "T ", "TC", "TU", "U ", "V ", "W ", "WC", "X ", "Y ", "Z ",
};
static_assert(std::size(kIssueSubTypes) == 58);

// Appendix C: Trading Action Reason codes (halt/pause and resumption), plus blank.
constexpr std::string_view kTradingActionReasons[] = {
    "T1  ", "T2  ", "T5  ", "T6  ", "T8  ", "T12 ", "H4  ", "H9  ", "H10 ", "H11 ", "O1  ", "LUDP",
    "LUDS", "MWC1", "MWC2", "MWC3", "MWC0", "IPO1", "M1  ", "M2  ", "    ", "T3  ", "T7  ", "R4  ",
    "R9  ", "C3  ", "C4  ", "C9  ", "C11 ", "MWCQ", "R1  ", "R2  ", "IPOQ", "IPOE",
};

template <Kind K, class V>
inline void check_field(Validator& v, char type, FieldId id, V value) noexcept {
  if constexpr (K == Kind::Enum) {
    if (!is_valid(value)) [[unlikely]]
      v.report(Validator::Rule::EnumOutOfSet, type, id,
               static_cast<unsigned char>(static_cast<char>(value)));
  }
}

}  // namespace

std::string_view field_name(FieldId id) noexcept {
  const auto i = static_cast<std::size_t>(id);
  return i < std::size(kFieldNames) ? kFieldNames[i] : std::string_view{"?"};
}

bool is_valid_issue_sub_type(const Alpha<2>& code) noexcept {
  return std::find(std::begin(kIssueSubTypes), std::end(kIssueSubTypes), code.raw()) != std::end(kIssueSubTypes);
}

bool is_valid_trading_action_reason(const Alpha<4>& code) noexcept {
  return std::find(std::begin(kTradingActionReasons), std::end(kTradingActionReasons), code.raw()) !=
         std::end(kTradingActionReasons);
}

std::string_view Validator::rule_name(Rule r) noexcept {
  switch (r) {
    case Rule::ZeroLength:
      return "zero_length";
    case Rule::UnknownType:
      return "unknown_type";
    case Rule::BadLength:
      return "bad_length";
    case Rule::EnumOutOfSet:
      return "enum_out_of_set";
    case Rule::CodeOutOfSet:
      return "code_out_of_set";
    case Rule::LocateNotZero:
      return "locate_not_zero";
    case Rule::LocateZero:
      return "locate_zero";
    case Rule::TimestampDecrease:
      return "timestamp_decrease";
    case Rule::TimestampOverDay:
      return "timestamp_over_day";
    case Rule::kCount:
      break;
  }
  return "?";
}

void Validator::report(Rule r, char type, FieldId f, std::uint64_t value) noexcept {
  ++violations_;
  ++in_msg_;
  const auto ri = static_cast<std::size_t>(r);
  ++by_rule_[ri];
  ++by_rule_type_[ri][static_cast<unsigned char>(type)];
  if (f != FieldId::kCount) ++by_field_[static_cast<std::size_t>(f)];
  if (num_examples_ < kMaxExamples) examples_[num_examples_++] = Violation{r, messages_, type, f, value};
}

std::uint32_t Validator::check(std::span<const std::byte> msg) noexcept {
  ++messages_;
  in_msg_ = 0;
  if (msg.empty()) {
    report(Rule::ZeroLength, 0, FieldId::kCount, 0);
    return in_msg_;
  }
  const char type = static_cast<char>(msg[0]);
  const std::size_t want = kMsgLen[static_cast<unsigned char>(type)];
  if (want == 0) {
    report(Rule::UnknownType, type, FieldId::kCount, static_cast<unsigned char>(type));
    return in_msg_;
  }
  if (msg.size() != want) {
    report(Rule::BadLength, type, FieldId::kCount, msg.size());
    return in_msg_;
  }
  if (!strict_) return in_msg_;

  const MessageHeaderView h{msg.data()};
  const std::uint64_t ts = h.timestamp();
  if (ts < prev_ts_) report(Rule::TimestampDecrease, type, FieldId::kCount, ts);
  if (ts >= kMaxTimestamp) report(Rule::TimestampOverDay, type, FieldId::kCount, ts);
  prev_ts_ = ts;

  const Locate loc = h.stock_locate();
  if (locate_must_be_zero(type)) {
    if (loc != 0) report(Rule::LocateNotZero, type, FieldId::kCount, loc);
  } else if (loc == 0) {
    report(Rule::LocateZero, type, FieldId::kCount, 0);
  }

  const std::byte* p = msg.data();
  switch (type) {
#define ITCH_MSG(T, Name, L) \
  case T: {                  \
    const Name##View v{p};
#define ITCH_FIELD(Name, f, off, len, K, E) check_field<Kind::K>(*this, type, FieldId::Name##_##f, v.f());
#define ITCH_END(Name) \
  break;               \
  }
#include "proto/itch50/itch50_layouts.def"
    default:
      break;
  }

  if (type == 'R') {
    const StockDirectoryView v{p};
    if (!is_valid_issue_sub_type(v.issue_sub_type()))
      report(Rule::CodeOutOfSet, type, FieldId::StockDirectory_issue_sub_type,
             (std::uint64_t{static_cast<unsigned char>(v.issue_sub_type().c[0])} << 8) |
                 static_cast<unsigned char>(v.issue_sub_type().c[1]));
  } else if (type == 'H') {
    const StockTradingActionView v{p};
    if (!is_valid_trading_action_reason(v.reason())) {
      std::uint64_t packed = 0;
      for (char c : v.reason().c) packed = (packed << 8) | static_cast<unsigned char>(c);
      report(Rule::CodeOutOfSet, type, FieldId::StockTradingAction_reason, packed);
    }
  }
  return in_msg_;
}

}  // namespace lle::itch50

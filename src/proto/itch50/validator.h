#pragma once
// ITCH 5.0 stream validator behind `itch_validate --strict` (03-protocols §3).
// Every message the exchange emits must pass it. Violations are counted, never
// fatal, so one run reports everything wrong with a stream.
//
// Rules:
//   framing   zero-length message, undefined type, length != kMsgLen[type];
//   strict    1-byte enum outside the spec's value set (tolerant decoding keeps
//             the raw byte; this is where out-of-set values surface);
//             Issue Sub-Type (App. E) and Trading Action Reason (App. C) codes;
//             locate 0 exactly for S, V, W, K; timestamp non-decreasing and
//             below 24 h.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "proto/itch50/itch50.h"

namespace lle::itch50 {

// One id per table row (header fields excluded), e.g. FieldId::StockDirectory_ipo_flag.
enum class FieldId : std::uint16_t {
#define ITCH_MSG(T, Name, L)
#define ITCH_FIELD(Name, f, off, len, K, E) Name##_##f,
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
  kCount
};

// "StockDirectory.ipo_flag"
[[nodiscard]] std::string_view field_name(FieldId id) noexcept;

// True iff the 2-byte code is in Appendix E (Issue Sub-Type), space padded.
[[nodiscard]] bool is_valid_issue_sub_type(const Alpha<2>& code) noexcept;
// True iff the 4-byte code is in Appendix C (Trading Action Reason) or blank.
[[nodiscard]] bool is_valid_trading_action_reason(const Alpha<4>& code) noexcept;

class Validator {
 public:
  enum class Rule : std::uint8_t {
    ZeroLength,
    UnknownType,
    BadLength,
    EnumOutOfSet,
    CodeOutOfSet,
    LocateNotZero,  // S/V/W/K with a non-zero locate
    LocateZero,     // any other type with locate 0
    TimestampDecrease,
    TimestampOverDay,
    kCount
  };
  static constexpr std::size_t kNumRules = static_cast<std::size_t>(Rule::kCount);
  static constexpr std::size_t kMaxExamples = 64;

  struct Violation {
    Rule rule = Rule::ZeroLength;
    std::uint64_t index = 0;  // 1-based message index within this validator
    char type = 0;
    FieldId field = FieldId::kCount;  // EnumOutOfSet / CodeOutOfSet only
    std::uint64_t value = 0;          // offending byte, length, locate or timestamp
  };

  explicit Validator(bool strict = true) noexcept : strict_(strict) {}

  // Checks one message (the bytes after a BinaryFILE/MoldUDP64 length prefix).
  // Returns the number of violations found in it.
  std::uint32_t check(std::span<const std::byte> msg) noexcept;

  [[nodiscard]] std::uint64_t messages() const noexcept { return messages_; }
  [[nodiscard]] std::uint64_t violations() const noexcept { return violations_; }
  [[nodiscard]] std::uint64_t count(Rule r) const noexcept { return by_rule_[static_cast<std::size_t>(r)]; }
  [[nodiscard]] std::uint64_t count(Rule r, char type) const noexcept {
    return by_rule_type_[static_cast<std::size_t>(r)][static_cast<unsigned char>(type)];
  }
  [[nodiscard]] std::uint64_t field_count(FieldId f) const noexcept { return by_field_[static_cast<std::size_t>(f)]; }
  [[nodiscard]] std::span<const Violation> examples() const noexcept { return {examples_.data(), num_examples_}; }
  [[nodiscard]] bool strict() const noexcept { return strict_; }

  static std::string_view rule_name(Rule r) noexcept;

  // Used by the generated per-field checks.
  void report(Rule r, char type, FieldId f, std::uint64_t value) noexcept;

 private:
  bool strict_;
  std::uint64_t messages_ = 0;
  std::uint64_t violations_ = 0;
  std::uint64_t prev_ts_ = 0;
  std::uint32_t in_msg_ = 0;
  std::array<std::uint64_t, kNumRules> by_rule_{};
  std::array<std::array<std::uint64_t, 256>, kNumRules> by_rule_type_{};
  std::array<std::uint64_t, static_cast<std::size_t>(FieldId::kCount)> by_field_{};
  std::array<Violation, kMaxExamples> examples_{};
  std::size_t num_examples_ = 0;
};

}  // namespace lle::itch50

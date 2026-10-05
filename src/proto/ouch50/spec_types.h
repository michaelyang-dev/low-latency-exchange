#pragma once
// Descriptor vocabulary for the generated OUCH 5.0 tables (ouch50_layout.gen.h).
// The generator (tools/specgen/specgen.py) turns spec/ouch50_fields.csv into
// constexpr instances of these types; the codec walks them for validation.
#include <cstddef>
#include <cstdint>

namespace lle::ouch50 {

enum class Direction : std::uint8_t { Inbound, Outbound };

// How the Appendage Length field behaves on a message type (OUCH 5.0 s2, s3).
enum class AppendageRule : std::uint8_t {
  None,                      // no Appendage Length (System Event)
  Required,                  // "Req": always present, 0 when there are no tags
  Optional,                  // "Opt": inbound X/M/Q, the client may omit it
  OptionalUnlessUserRefIdx,  // "Opt*": outbound, absent unless the order carries a non-zero UserRefIdx
};

enum class FieldType : std::uint8_t { Type, U8, U16, U32, U64, Price, SPrice4, Timestamp, Alpha, Char, AppLen };

// Value-domain check applied by the strict validators.
enum class CheckKind : std::uint8_t {
  None,
  Enum,           // byte (or u16 code) must be a listed enumerator
  LimitOrMarket,  // 1..1,999,999,900, or a market sentinel (2,000,000,000 / 0x7FFFFFFF)
  ZeroOrLimit,    // 0 (= not set) or 1..1,999,999,900
  Range,          // lo <= value <= hi
};

// 256-bit membership set for single-byte enumerations.
struct ByteSet {
  std::uint64_t w[4];
  [[nodiscard]] constexpr bool contains(std::uint8_t b) const noexcept { return ((w[b >> 6] >> (b & 63u)) & 1u) != 0; }
};

struct FieldDesc {
  const char* name;
  std::uint8_t offset;
  std::uint8_t len;
  FieldType type;
  CheckKind check;
  std::uint16_t reject;        // RejectReason code reported when the check fails
  const ByteSet* chars;        // CheckKind::Enum on a Char field
  const std::uint16_t* codes;  // CheckKind::Enum on a U16 field (sorted)
  std::uint8_t code_count;
  std::uint64_t lo;  // CheckKind::Range
  std::uint64_t hi;
};

struct TagDesc {
  const char* name;  // nullptr: tag number not assigned
  std::uint8_t tag;
  std::uint8_t value_len;  // bytes after [len][tag]; 0 = unknown tag
  FieldType type;
  CheckKind check;
  std::uint16_t reject;
  const ByteSet* chars;
  std::uint64_t lo;
  std::uint64_t hi;
};

struct MsgDesc {
  const char* name;
  char type;
  Direction direction;
  AppendageRule rule;
  std::uint8_t fixed_len;  // bytes up to the appendage when Appendage Length is present
  std::uint8_t base_len;   // bytes before Appendage Length (== fixed_len for AppendageRule::None)
  std::uint32_t allowed_tags;  // bit n set = tag n allowed
  const FieldDesc* fields;
  std::uint8_t field_count;
};

struct FieldPos {
  std::size_t off;
  std::size_t len;
};

}  // namespace lle::ouch50

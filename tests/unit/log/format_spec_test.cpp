// Compile-time format parsing and argument-kind mapping (format_spec.h).
#include "log/format_spec.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace lle::nlog {
namespace {

enum class SideU8 : std::uint8_t { kBuy = 'B' };
enum class Signed16 : std::int16_t { kNeg = -5 };
enum Plain { kPlainA = 1 };  // unscoped: underlying type is implementation-chosen int-like
struct NotLoggable {};

// ---- kind mapping (all compile-time) ----------------------------------------------
static_assert(kind_of<std::uint8_t>() == ArgKind::kU8);
static_assert(kind_of<std::uint16_t>() == ArgKind::kU16);
static_assert(kind_of<std::uint32_t>() == ArgKind::kU32);
static_assert(kind_of<std::uint64_t>() == ArgKind::kU64);
static_assert(kind_of<unsigned long>() == ArgKind::kU64);
static_assert(kind_of<std::int8_t>() == ArgKind::kI8);
static_assert(kind_of<std::int16_t>() == ArgKind::kI16);
static_assert(kind_of<std::int32_t>() == ArgKind::kI32);
static_assert(kind_of<std::int64_t>() == ArgKind::kI64);
static_assert(kind_of<long long>() == ArgKind::kI64);
static_assert(kind_of<bool>() == ArgKind::kBool);
static_assert(kind_of<char>() == ArgKind::kChar);
static_assert(kind_of<const char&>() == ArgKind::kChar);
static_assert(kind_of<double>() == ArgKind::kF64);
static_assert(kind_of<float>() == ArgKind::kF64);
static_assert(kind_of<SideU8>() == ArgKind::kU8);
static_assert(kind_of<Signed16>() == ArgKind::kI16);
static_assert(is_signed_kind(kind_of<Plain>()) || is_unsigned_kind(kind_of<Plain>()));
static_assert(kind_of<std::string_view>() == ArgKind::kStr);
static_assert(kind_of<const char*>() == ArgKind::kStr);
static_assert(kind_of<char*>() == ArgKind::kStr);
static_assert(kind_of<char[6]>() == ArgKind::kStr);
static_assert(kind_of<const char[6]>() == ArgKind::kStr);
static_assert(kind_of<std::string>() == ArgKind::kStr);
static_assert(kind_of<const std::string&>() == ArgKind::kStr);
// Not loggable.
static_assert(kind_of<int*>() == ArgKind::kNone);
static_assert(kind_of<const void*>() == ArgKind::kNone);
static_assert(kind_of<NotLoggable>() == ArgKind::kNone);
static_assert(kind_of<wchar_t>() == ArgKind::kNone);
static_assert(kind_of<char8_t>() == ArgKind::kNone);
static_assert(kind_of<char32_t>() == ArgKind::kNone);
static_assert(kind_of<long double>() == ArgKind::kNone);

// ---- parser -----------------------------------------------------------------------
static_assert(parse_format("").count == 0);
static_assert(parse_format("no fields").count == 0);
static_assert(parse_format("order {} accepted px {} qty {} side {}").count == 4);
static_assert(parse_format("{{literal}} {}").count == 1);
static_assert(parse_format("{{}}").count == 0);
static_assert(parse_format("{:x} {:>8.3f} {:c} {}").type[0] == 'x');
static_assert(parse_format("{:x} {:>8.3f} {:c} {}").type[1] == 'f');
static_assert(parse_format("{:x} {:>8.3f} {:c} {}").type[2] == 'c');
static_assert(parse_format("{:x} {:>8.3f} {:c} {}").type[3] == '\0');
static_assert(parse_format("{:x<5}").type[0] == '\0');  // fill 'x', no presentation type
static_assert(parse_format("{:#010x}").type[0] == 'x');
static_assert(parse_format("{").error == FormatError::kUnterminatedField);
static_assert(parse_format("abc {:x").error == FormatError::kUnterminatedField);
static_assert(parse_format("}").error == FormatError::kUnmatchedClose);
static_assert(parse_format("{0}").error == FormatError::kPositionalField);
static_assert(parse_format("{name}").error == FormatError::kPositionalField);
static_assert(parse_format("{:{}}").error == FormatError::kNestedField);
static_assert(parse_format("{} {} {} {} {} {} {} {} {}").count == 9);  // counted even past kMaxArgs

// ---- presentation compatibility ---------------------------------------------------
static_assert(presentation_ok('\0', ArgKind::kU64));
static_assert(presentation_ok('x', ArgKind::kI32));
static_assert(presentation_ok('c', ArgKind::kU8));
static_assert(!presentation_ok('f', ArgKind::kU32));
static_assert(presentation_ok('f', ArgKind::kF64));
static_assert(!presentation_ok('d', ArgKind::kF64));
static_assert(presentation_ok('s', ArgKind::kStr));
static_assert(!presentation_ok('x', ArgKind::kStr));
static_assert(presentation_ok('s', ArgKind::kBool));
static_assert(!presentation_ok('c', ArgKind::kBool));
static_assert(presentation_ok('c', ArgKind::kChar));
static_assert(!presentation_ok('\0', ArgKind::kNone));

// ---- FormatCheck: the kinds recorded for a site --------------------------------
struct TagShape {
  static consteval const char* lle_nlog_fmt() { return "order {} accepted px {} qty {} side {}"; }
};
using ShapeCheck = detail::FormatCheck<TagShape, detail::TypeList<std::uint64_t, std::int64_t, std::uint32_t, SideU8>>;
static_assert(ShapeCheck::kOk);
static_assert(ShapeCheck::kKinds[0] == ArgKind::kU64);
static_assert(ShapeCheck::kKinds[1] == ArgKind::kI64);
static_assert(ShapeCheck::kKinds[2] == ArgKind::kU32);
static_assert(ShapeCheck::kKinds[3] == ArgKind::kU8);
static_assert(ShapeCheck::kKinds[4] == ArgKind::kNone);

struct TagSpecs {
  static consteval const char* lle_nlog_fmt() { return "{:#x} {:>10.3f} {:c} {:s} {:<6}"; }
};
static_assert(
    detail::FormatCheck<TagSpecs, detail::TypeList<std::uint32_t, double, char, bool, std::string_view>>::kOk);

TEST(FormatSpec, RuntimeParseMatchesCompileTime) {
  // parse_format is constexpr, not consteval: the decoder's grammar is the same.
  const std::string f = "a {} b {:x} c {{}}";
  const ParsedFormat p = parse_format(f);
  EXPECT_EQ(p.count, 2u);
  EXPECT_EQ(p.type[1], 'x');
  EXPECT_EQ(p.error, FormatError::kNone);
}

TEST(FormatSpec, KindNamesAndSizes) {
  EXPECT_EQ(kind_name(ArgKind::kU64), "u64");
  EXPECT_EQ(kind_name(ArgKind::kStr), "str");
  EXPECT_EQ(raw_size(ArgKind::kI16), 2u);
  EXPECT_EQ(raw_size(ArgKind::kF64), 8u);
  EXPECT_EQ(raw_size(ArgKind::kStr), 0u);
  for (std::uint8_t k = 1; k <= kArgKindLast; ++k) EXPECT_TRUE(is_valid_kind(k));
  EXPECT_FALSE(is_valid_kind(0));
  EXPECT_FALSE(is_valid_kind(kArgKindLast + 1));
}

}  // namespace
}  // namespace lle::nlog

#pragma once
// Compile-time format handling for nlog (11-logging-observability §1, R6 D3.5).
//
// A log call's format string uses std::format-style replacement fields: `{}` or
// `{:spec}`, with `{{`/`}}` for literal braces. Positional/named fields and
// nested (dynamic width/precision) fields are rejected because the decoder formats
// each field on its own. A consteval parser counts the fields and extracts each
// presentation type; FormatCheck turns argument types into an ArgKind array and
// fails the build (static_assert) on:
//   - a field/argument count mismatch,
//   - an argument type that cannot be logged (pointers, classes, wide chars, ...),
//   - a presentation type that does not fit the argument kind (`{:f}` on a string),
//   - any spec std::format itself rejects for the decoded type (checked with
//     std::format_string, so the offline decoder can never hit a format error on a
//     file written by this build).
// NanoLog makes the same point: format errors "may silently corrupt the log file".
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <type_traits>

namespace lle::nlog {

// Argument kinds as recorded in the site dictionary. Values are part of the file
// format (docs/design/nlog-format.md): never renumber.
enum class ArgKind : std::uint8_t {
  kNone = 0,
  kU8 = 1,
  kU16 = 2,
  kU32 = 3,
  kU64 = 4,
  kI8 = 5,
  kI16 = 6,
  kI32 = 7,
  kI64 = 8,
  kBool = 9,
  kChar = 10,
  kF64 = 11,
  kStr = 12,
};
inline constexpr std::uint8_t kArgKindLast = 12;
inline constexpr std::size_t kMaxArgs = 8;
inline constexpr std::size_t kMaxStringBytes = 64;  // longer strings are truncated (flagged)

using ArgKinds = std::array<ArgKind, kMaxArgs>;

[[nodiscard]] constexpr bool is_valid_kind(std::uint8_t k) noexcept { return k >= 1 && k <= kArgKindLast; }

[[nodiscard]] constexpr std::string_view kind_name(ArgKind k) noexcept {
  switch (k) {
    case ArgKind::kU8: return "u8";
    case ArgKind::kU16: return "u16";
    case ArgKind::kU32: return "u32";
    case ArgKind::kU64: return "u64";
    case ArgKind::kI8: return "i8";
    case ArgKind::kI16: return "i16";
    case ArgKind::kI32: return "i32";
    case ArgKind::kI64: return "i64";
    case ArgKind::kBool: return "bool";
    case ArgKind::kChar: return "char";
    case ArgKind::kF64: return "f64";
    case ArgKind::kStr: return "str";
    case ArgKind::kNone: break;
  }
  return "none";
}

// Bytes a fixed-size kind occupies in a raw ring record (0 for kStr/kNone).
[[nodiscard]] constexpr std::size_t raw_size(ArgKind k) noexcept {
  switch (k) {
    case ArgKind::kU8:
    case ArgKind::kI8:
    case ArgKind::kBool:
    case ArgKind::kChar: return 1;
    case ArgKind::kU16:
    case ArgKind::kI16: return 2;
    case ArgKind::kU32:
    case ArgKind::kI32: return 4;
    case ArgKind::kU64:
    case ArgKind::kI64:
    case ArgKind::kF64: return 8;
    case ArgKind::kStr:
    case ArgKind::kNone: break;
  }
  return 0;
}

[[nodiscard]] constexpr bool is_unsigned_kind(ArgKind k) noexcept {
  return k == ArgKind::kU8 || k == ArgKind::kU16 || k == ArgKind::kU32 || k == ArgKind::kU64;
}
[[nodiscard]] constexpr bool is_signed_kind(ArgKind k) noexcept {
  return k == ArgKind::kI8 || k == ArgKind::kI16 || k == ArgKind::kI32 || k == ArgKind::kI64;
}

namespace detail {

template <class T>
inline constexpr bool kIsStringLike =
    std::is_same_v<T, const char*> || std::is_same_v<T, char*> || std::is_same_v<T, std::string_view> ||
    std::is_same_v<T, std::string> ||
    (std::is_array_v<T> && std::is_same_v<std::remove_cv_t<std::remove_extent_t<T>>, char>);

template <class T>
inline constexpr bool kIsCharType = std::is_same_v<T, wchar_t> || std::is_same_v<T, char8_t> ||
                                    std::is_same_v<T, char16_t> || std::is_same_v<T, char32_t>;

}  // namespace detail

// The kind an argument of type T is logged as; kNone means "cannot be logged".
template <class T>
[[nodiscard]] consteval ArgKind kind_of() noexcept {
  using U = std::remove_cvref_t<T>;
  if constexpr (detail::kIsStringLike<U>) {
    return ArgKind::kStr;
  } else if constexpr (std::is_enum_v<U>) {
    return kind_of<std::underlying_type_t<U>>();  // enums log their underlying integer
  } else if constexpr (std::is_same_v<U, bool>) {
    return ArgKind::kBool;
  } else if constexpr (std::is_same_v<U, char>) {
    return ArgKind::kChar;
  } else if constexpr (detail::kIsCharType<U>) {
    return ArgKind::kNone;
  } else if constexpr (std::is_integral_v<U> && std::is_signed_v<U>) {
    if constexpr (sizeof(U) == 1) return ArgKind::kI8;
    else if constexpr (sizeof(U) == 2) return ArgKind::kI16;
    else if constexpr (sizeof(U) == 4) return ArgKind::kI32;
    else if constexpr (sizeof(U) == 8) return ArgKind::kI64;
    else return ArgKind::kNone;
  } else if constexpr (std::is_integral_v<U>) {
    if constexpr (sizeof(U) == 1) return ArgKind::kU8;
    else if constexpr (sizeof(U) == 2) return ArgKind::kU16;
    else if constexpr (sizeof(U) == 4) return ArgKind::kU32;
    else if constexpr (sizeof(U) == 8) return ArgKind::kU64;
    else return ArgKind::kNone;
  } else if constexpr (std::is_same_v<U, double> || std::is_same_v<U, float>) {
    return ArgKind::kF64;  // float is widened
  } else {
    return ArgKind::kNone;
  }
}

// The C++ type the decoder hands to std::format for each kind.
template <ArgKind K>
struct DecodedType {
  struct Unsupported {};
  using type = Unsupported;
};
template <> struct DecodedType<ArgKind::kU8> { using type = std::uint8_t; };
template <> struct DecodedType<ArgKind::kU16> { using type = std::uint16_t; };
template <> struct DecodedType<ArgKind::kU32> { using type = std::uint32_t; };
template <> struct DecodedType<ArgKind::kU64> { using type = std::uint64_t; };
template <> struct DecodedType<ArgKind::kI8> { using type = std::int8_t; };
template <> struct DecodedType<ArgKind::kI16> { using type = std::int16_t; };
template <> struct DecodedType<ArgKind::kI32> { using type = std::int32_t; };
template <> struct DecodedType<ArgKind::kI64> { using type = std::int64_t; };
template <> struct DecodedType<ArgKind::kBool> { using type = bool; };
template <> struct DecodedType<ArgKind::kChar> { using type = char; };
template <> struct DecodedType<ArgKind::kF64> { using type = double; };
template <> struct DecodedType<ArgKind::kStr> { using type = std::string_view; };
template <ArgKind K>
using decoded_t = typename DecodedType<K>::type;

enum class FormatError : std::uint8_t {
  kNone,
  kUnterminatedField,  // `{` without a closing `}`
  kUnmatchedClose,     // lone `}`
  kPositionalField,    // `{0}` / `{name}`
  kNestedField,        // `{:{}}` dynamic width/precision
};

struct ParsedFormat {
  std::size_t count = 0;              // number of replacement fields
  std::array<char, kMaxArgs> type{};  // presentation type per field ('\0' = none)
  FormatError error = FormatError::kNone;
};

[[nodiscard]] constexpr bool is_presentation_type(char c) noexcept {
  return std::string_view{"aAbBcdeEfFgGosxX?"}.find(c) != std::string_view::npos;
}

// Parses `{}` replacement fields. Runs at compile time for every log site; the
// decoder runs the same grammar at run time (format_text.cpp).
[[nodiscard]] constexpr ParsedFormat parse_format(std::string_view f) noexcept {
  ParsedFormat r;
  for (std::size_t i = 0; i < f.size(); ++i) {
    const char c = f[i];
    if (c == '}') {
      if (i + 1 < f.size() && f[i + 1] == '}') {
        ++i;
        continue;
      }
      r.error = FormatError::kUnmatchedClose;
      return r;
    }
    if (c != '{') continue;
    if (i + 1 < f.size() && f[i + 1] == '{') {
      ++i;
      continue;
    }
    std::size_t j = i + 1;
    if (j < f.size() && f[j] != ':' && f[j] != '}') {
      r.error = FormatError::kPositionalField;
      return r;
    }
    std::size_t spec_begin = j;
    std::size_t spec_end = j;
    if (j < f.size() && f[j] == ':') {
      ++j;
      spec_begin = j;
      while (j < f.size() && f[j] != '}') {
        if (f[j] == '{') {
          r.error = FormatError::kNestedField;
          return r;
        }
        ++j;
      }
      spec_end = j;
    }
    if (j >= f.size()) {
      r.error = FormatError::kUnterminatedField;
      return r;
    }
    char type = '\0';
    if (spec_end > spec_begin && is_presentation_type(f[spec_end - 1])) type = f[spec_end - 1];
    if (r.count < kMaxArgs) r.type[r.count] = type;
    ++r.count;
    i = j;
  }
  return r;
}

// Whether presentation type `t` is valid for kind `k` (std::format rules).
[[nodiscard]] constexpr bool presentation_ok(char t, ArgKind k) noexcept {
  if (t == '\0') return k != ArgKind::kNone;
  auto in = [t](std::string_view set) { return set.find(t) != std::string_view::npos; };
  switch (k) {
    case ArgKind::kU8:
    case ArgKind::kU16:
    case ArgKind::kU32:
    case ArgKind::kU64:
    case ArgKind::kI8:
    case ArgKind::kI16:
    case ArgKind::kI32:
    case ArgKind::kI64: return in("bBcdoxX");
    case ArgKind::kBool: return in("sbBdoxX");
    case ArgKind::kChar: return in("cbBdoxX?");
    case ArgKind::kF64: return in("aAeEfFgG");
    case ArgKind::kStr: return in("s?");
    case ArgKind::kNone: break;
  }
  return false;
}

namespace detail {

template <class... A>
struct TypeList {};

// Unevaluated helper: decltype(type_list(args...)) names the argument types.
template <class... A>
TypeList<std::remove_cvref_t<A>...> type_list(A&&...);

template <class... A>
consteval ArgKinds make_kinds() noexcept {
  ArgKinds k{};
  std::size_t i = 0;
  ((i < kMaxArgs ? (k[i++] = kind_of<A>()) : ArgKind::kNone), ...);
  return k;
}

consteval int first_unsupported(const ArgKinds& k, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n && i < kMaxArgs; ++i)
    if (k[i] == ArgKind::kNone) return static_cast<int>(i);
  return -1;
}

consteval int first_bad_presentation(const ParsedFormat& p, const ArgKinds& k, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n && i < kMaxArgs; ++i)
    if (!presentation_ok(p.type[i], k[i])) return static_cast<int>(i);
  return -1;
}

// Full std::format validation of the spec against the decoded types; only run once
// our own checks pass so the diagnostics stay readable. (Evaluated inside a
// consteval function: Apple clang 16 crashes on some invalid format_string
// constructions in a static data member initializer.)
template <bool kRun, class... T>
consteval bool std_format_accepts(const char* fmt) {
  if constexpr (kRun) {
    std::format_string<T...> s(fmt);
    (void)s;
  }
  return true;
}

template <class Tag, class List>
struct FormatCheck;

template <class Tag, class... A>
struct FormatCheck<Tag, TypeList<A...>> {
  static constexpr std::size_t kNargs = sizeof...(A);
  static constexpr ParsedFormat kParsed = parse_format(Tag::lle_nlog_fmt());
  static constexpr ArgKinds kKinds = make_kinds<A...>();

  static_assert(kNargs <= kMaxArgs, "nlog: at most 8 arguments per log call");
  static_assert(kParsed.error != FormatError::kUnterminatedField,
                "nlog: unterminated '{' in format string (use '{{' for a literal brace)");
  static_assert(kParsed.error != FormatError::kUnmatchedClose,
                "nlog: unmatched '}' in format string (use '}}' for a literal brace)");
  static_assert(kParsed.error != FormatError::kPositionalField,
                "nlog: positional or named replacement fields are not supported; use {} or {:spec}");
  static_assert(kParsed.error != FormatError::kNestedField,
                "nlog: nested replacement fields (dynamic width/precision) are not supported");
  static_assert(kParsed.error != FormatError::kNone || kParsed.count == kNargs,
                "nlog: number of {} placeholders does not match the number of arguments");
  static_assert(first_unsupported(kKinds, kNargs) < 0,
                "nlog: unsupported argument type (allowed: integers, enums, bool, char, float, double, "
                "std::string_view, const char*, std::string)");
  static_assert(first_unsupported(kKinds, kNargs) >= 0 || kParsed.count != kNargs ||
                    first_bad_presentation(kParsed, kKinds, kNargs) < 0,
                "nlog: format spec presentation type does not match the argument kind");

  static constexpr bool kOwnChecksOk = kNargs <= kMaxArgs && kParsed.error == FormatError::kNone &&
                                       kParsed.count == kNargs && first_unsupported(kKinds, kNargs) < 0 &&
                                       first_bad_presentation(kParsed, kKinds, kNargs) < 0;
  static_assert(std_format_accepts<kOwnChecksOk, decoded_t<kind_of<A>()>...>(Tag::lle_nlog_fmt()),
                "nlog: format spec rejected by std::format for the decoded argument types");

  static constexpr bool kOk = kOwnChecksOk;
};

}  // namespace detail
}  // namespace lle::nlog

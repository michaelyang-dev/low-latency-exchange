#pragma once
// A decoded log argument (decoder, memory sink, file encoder for tests).
#include <cstdint>
#include <string_view>

#include "log/format_spec.h"

namespace lle::nlog {

struct ArgValue {
  ArgKind kind = ArgKind::kNone;
  bool truncated = false;  // kStr only
  std::uint64_t u = 0;     // unsigned kinds, kBool (0/1), kChar (byte value)
  std::int64_t i = 0;      // signed kinds
  double d = 0.0;          // kF64
  std::string_view s;      // kStr (not owned)

  static constexpr ArgValue of_unsigned(ArgKind k, std::uint64_t v) noexcept {
    ArgValue a;
    a.kind = k;
    a.u = v;
    return a;
  }
  static constexpr ArgValue of_signed(ArgKind k, std::int64_t v) noexcept {
    ArgValue a;
    a.kind = k;
    a.i = v;
    return a;
  }
  static constexpr ArgValue of_double(double v) noexcept {
    ArgValue a;
    a.kind = ArgKind::kF64;
    a.d = v;
    return a;
  }
  static constexpr ArgValue of_string(std::string_view v, bool truncated = false) noexcept {
    ArgValue a;
    a.kind = ArgKind::kStr;
    a.s = v;
    a.truncated = truncated;
    return a;
  }
};

}  // namespace lle::nlog

#include "log/format_text.h"

#include <cmath>
#include <format>
#include <iterator>

namespace lle::nlog {
namespace {

// Specs come from the (untrusted) file dictionary: refuse widths/precisions that
// would make std::format allocate absurd amounts.
constexpr std::uint64_t kMaxSpecNumber = 512;

bool spec_is_reasonable(std::string_view spec) noexcept {
  std::uint64_t v = 0;
  bool in_number = false;
  for (const char c : spec) {
    if (c >= '0' && c <= '9') {
      v = in_number ? v * 10 + static_cast<std::uint64_t>(c - '0') : static_cast<std::uint64_t>(c - '0');
      in_number = true;
      if (v > kMaxSpecNumber) return false;
    } else {
      in_number = false;
    }
  }
  return true;
}

template <class T>
bool format_value(std::string& out, std::string_view f, T v) {
  try {
    out += std::vformat(f, std::make_format_args(v));
    return true;
  } catch (const std::format_error&) {
    return false;
  }
}

void escape_controls_into(std::string& out, std::string_view s) {
  for (const char c : s) {
    const auto u = static_cast<unsigned char>(c);
    if (u >= 0x20 && u != 0x7F) {
      out += c;
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\t') {
      out += "\\t";
    } else if (c == '\r') {
      out += "\\r";
    } else {
      out += std::format("\\x{:02x}", u);
    }
  }
}

bool format_one(std::string& out, std::string_view spec, const ArgValue& a, bool escape) {
  if (!spec_is_reasonable(spec)) return false;
  std::string f;
  f.reserve(spec.size() + 3);
  f += "{:";
  f += spec;
  f += '}';
  switch (a.kind) {
    case ArgKind::kU8: return format_value(out, f, static_cast<std::uint8_t>(a.u));
    case ArgKind::kU16: return format_value(out, f, static_cast<std::uint16_t>(a.u));
    case ArgKind::kU32: return format_value(out, f, static_cast<std::uint32_t>(a.u));
    case ArgKind::kU64: return format_value(out, f, a.u);
    case ArgKind::kI8: return format_value(out, f, static_cast<std::int8_t>(a.i));
    case ArgKind::kI16: return format_value(out, f, static_cast<std::int16_t>(a.i));
    case ArgKind::kI32: return format_value(out, f, static_cast<std::int32_t>(a.i));
    case ArgKind::kI64: return format_value(out, f, a.i);
    case ArgKind::kBool: return format_value(out, f, a.u != 0);
    case ArgKind::kChar: return format_value(out, f, static_cast<char>(static_cast<unsigned char>(a.u)));
    case ArgKind::kF64: return format_value(out, f, a.d);
    case ArgKind::kStr: {
      std::string v;
      if (escape) {
        escape_controls_into(v, a.s);
      } else {
        v.assign(a.s);
      }
      if (a.truncated) v += "...";
      return format_value(out, f, std::string_view{v});
    }
    case ArgKind::kNone: break;
  }
  return false;
}

// Length of the valid UTF-8 sequence starting at s[i] (>= 0x80), or 0.
std::size_t utf8_len(std::string_view s, std::size_t i) noexcept {
  const auto b0 = static_cast<unsigned char>(s[i]);
  auto cont = [&](std::size_t k, unsigned char lo, unsigned char hi) {
    if (i + k >= s.size()) return false;
    const auto b = static_cast<unsigned char>(s[i + k]);
    return b >= lo && b <= hi;
  };
  if (b0 >= 0xC2 && b0 <= 0xDF) return cont(1, 0x80, 0xBF) ? 2 : 0;
  if (b0 >= 0xE0 && b0 <= 0xEF) {
    const unsigned char lo = b0 == 0xE0 ? 0xA0 : 0x80;
    const unsigned char hi = b0 == 0xED ? 0x9F : 0xBF;
    return cont(1, lo, hi) && cont(2, 0x80, 0xBF) ? 3 : 0;
  }
  if (b0 >= 0xF0 && b0 <= 0xF4) {
    const unsigned char lo = b0 == 0xF0 ? 0x90 : 0x80;
    const unsigned char hi = b0 == 0xF4 ? 0x8F : 0xBF;
    return cont(1, lo, hi) && cont(2, 0x80, 0xBF) && cont(3, 0x80, 0xBF) ? 4 : 0;
  }
  return 0;
}

constexpr std::int64_t floor_div(std::int64_t a, std::int64_t b) noexcept {
  const std::int64_t q = a / b;
  return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

}  // namespace

void format_message(std::string& out, std::string_view fmt, std::span<const ArgValue> args, bool escape_controls) {
  std::size_t next_arg = 0;
  for (std::size_t i = 0; i < fmt.size(); ++i) {
    const char c = fmt[i];
    if (c == '{') {
      if (i + 1 < fmt.size() && fmt[i + 1] == '{') {
        out += '{';
        ++i;
        continue;
      }
      const std::size_t close = fmt.find('}', i + 1);
      if (close == std::string_view::npos) {
        out.append(fmt.substr(i));
        return;
      }
      const std::string_view field = fmt.substr(i + 1, close - i - 1);
      const bool well_formed = (field.empty() || field.front() == ':') && field.find('{') == std::string_view::npos;
      const std::string_view spec = field.empty() ? field : field.substr(1);
      if (!well_formed || next_arg >= args.size() || !format_one(out, spec, args[next_arg], escape_controls)) {
        out += "{?}";
      }
      ++next_arg;
      i = close;
    } else if (c == '}') {
      if (i + 1 < fmt.size() && fmt[i + 1] == '}') ++i;
      out += '}';
    } else {
      out += c;
    }
  }
}

void append_json_escaped(std::string& out, std::string_view s) {
  for (std::size_t i = 0; i < s.size();) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
          if (c < 0x20 || c == 0x7F) {
            out += std::format("\\u{:04x}", static_cast<unsigned>(c));
          } else {
            out += static_cast<char>(c);
          }
      }
      ++i;
      continue;
    }
    const std::size_t n = utf8_len(s, i);
    if (n == 0) {
      out += "\\ufffd";
      ++i;
    } else {
      out.append(s.substr(i, n));
      i += n;
    }
  }
}

void append_json_arg(std::string& out, const ArgValue& a) {
  switch (a.kind) {
    case ArgKind::kU8:
    case ArgKind::kU16:
    case ArgKind::kU32:
    case ArgKind::kU64: out += std::format("{}", a.u); return;
    case ArgKind::kI8:
    case ArgKind::kI16:
    case ArgKind::kI32:
    case ArgKind::kI64: out += std::format("{}", a.i); return;
    case ArgKind::kBool: out += a.u != 0 ? "true" : "false"; return;
    case ArgKind::kChar: {
      const char ch = static_cast<char>(static_cast<unsigned char>(a.u));
      out += '"';
      append_json_escaped(out, std::string_view{&ch, 1});
      out += '"';
      return;
    }
    case ArgKind::kF64:
      if (std::isnan(a.d)) {
        out += "\"nan\"";
      } else if (std::isinf(a.d)) {
        out += a.d > 0 ? "\"inf\"" : "\"-inf\"";
      } else {
        out += std::format("{}", a.d);
      }
      return;
    case ArgKind::kStr:
      out += '"';
      append_json_escaped(out, a.s);
      out += '"';
      return;
    case ArgKind::kNone: break;
  }
  out += "null";
}

void append_utc_time(std::string& out, std::int64_t unix_ns) {
  // Civil-from-days (H. Hinnant), proleptic Gregorian calendar.
  constexpr std::int64_t kNsPerDay = 86'400'000'000'000;
  const std::int64_t days = floor_div(unix_ns, kNsPerDay);
  std::int64_t ns_of_day = unix_ns % kNsPerDay;  // no days * kNsPerDay: overflows near INT64_MIN
  if (ns_of_day < 0) ns_of_day += kNsPerDay;
  const std::int64_t z = days + 719'468;
  const std::int64_t era = floor_div(z, 146'097);
  const std::int64_t doe = z - era * 146'097;
  const std::int64_t yoe = (doe - doe / 1460 + doe / 36'524 - doe / 146'096) / 365;
  const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const std::int64_t mp = (5 * doy + 2) / 153;
  const std::int64_t d = doy - (153 * mp + 2) / 5 + 1;
  const std::int64_t m = mp < 10 ? mp + 3 : mp - 9;
  const std::int64_t y = yoe + era * 400 + (m <= 2 ? 1 : 0);
  const std::int64_t secs = ns_of_day / 1'000'000'000;
  out += std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z", y, m, d, secs / 3600, (secs / 60) % 60, secs % 60,
                     ns_of_day % 1'000'000'000);
}

std::string_view basename_of(std::string_view path) noexcept {
  const std::size_t slash = path.find_last_of('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

}  // namespace lle::nlog

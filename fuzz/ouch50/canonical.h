#pragma once
// Canonical verdict text for OUCH messages, shared by the differential
// generator and the fuzz harnesses. Must match tools/spec/ouch50_ref_decoder.py
// character for character:
//   failure: E,<Error>,<offset>,<reject decimal>,<tag>
//   success: K,<type>,<appendage length or ->,<field>,...|<tag>:<value>,...
// Fields are rendered through the generated typed views (so the accessors are
// what gets compared); tags through the registry types.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <type_traits>

#include "proto/ouch50/ouch50.h"

namespace lle::ouch50::canon {

inline void append_hex(std::string& out, std::span<const std::byte> b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  for (std::byte x : b) {
    const auto u = std::to_integer<unsigned>(x);
    out.push_back(kDigits[u >> 4]);
    out.push_back(kDigits[u & 15u]);
  }
}

template <class T>
struct IsAlpha : std::false_type {};
template <std::size_t N>
struct IsAlpha<Alpha<N>> : std::true_type {};

template <class T>
void append_value(std::string& out, const T& v) {
  if constexpr (IsAlpha<T>::value) {
    append_hex(out, std::as_bytes(std::span(v.c)));
  } else if constexpr (std::is_enum_v<T>) {
    using U = std::underlying_type_t<T>;
    if constexpr (std::is_same_v<U, char>) {
      const std::byte b[1] = {static_cast<std::byte>(static_cast<U>(v))};
      append_hex(out, b);
    } else {
      out += std::to_string(static_cast<std::uint64_t>(static_cast<U>(v)));
    }
  } else {
    out += std::to_string(v);
  }
}

inline std::string failure(const Failure& f) {
  std::string s = "E,";
  s += to_string(f.error);
  s += ',';
  s += std::to_string(f.offset);
  s += ',';
  s += std::to_string(static_cast<unsigned>(f.reason));
  s += ',';
  s += std::to_string(f.tag);
  return s;
}

inline void append_tags(std::string& s, TagValueRange tags) {
  bool first = true;
  for (const TagValue& tv : tags) {
    if (!first) s += ',';
    first = false;
    s += std::to_string(tv.tag);
    s += ':';
    const TagDesc* d = find_tag(tv.tag);
    if (d == nullptr || d->value_len != tv.value.size()) {
      s += 'x';
      append_hex(s, tv.value);
      continue;
    }
    switch (d->type) {
      case FieldType::U8: s += std::to_string(tv.u8()); break;
      case FieldType::U16: s += std::to_string(tv.u16()); break;
      case FieldType::U32: s += std::to_string(tv.u32()); break;
      case FieldType::U64:
      case FieldType::Price: s += std::to_string(tv.u64()); break;
      case FieldType::SPrice4: s += std::to_string(tv.i32()); break;
      default: append_hex(s, tv.value); break;
    }
  }
}

template <Direction D>
std::string success(const FramedView<D>& v) {
  std::string s = "K,";
  s += v.type();
  s += ',';
  s += v.has_appendage_length() ? std::to_string(v.appendage_length()) : std::string("-");
  v.visit([&](const auto& typed) {
    for_each_field(typed, [&](const char*, const auto& value) {
      s += ',';
      append_value(s, value);
    });
  });
  s += '|';
  append_tags(s, v.tags());
  return s;
}

template <class R>
std::string result(const R& r) {
  return r ? success(*r) : failure(r.error());
}

inline std::string inbound_verdict(std::span<const std::byte> b) { return result(validate_inbound_detailed(b)); }

inline std::string outbound_verdict(std::span<const std::byte> b) {
  return "T=" + result(OutboundDecoder::decode(b)) + ";S=" + result(validate_outbound(b));
}

}  // namespace lle::ouch50::canon

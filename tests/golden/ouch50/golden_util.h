#pragma once
// Helpers for hand-assembling OUCH bytes in tests. Values and widths come from
// the spec tables as written in each test, never from the generated layout.
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "proto/ouch50/ouch50.h"

namespace lle::ouch50::test {

using Bytes = std::vector<std::byte>;

struct B {
  Bytes v;
  B& u8(unsigned x) {
    v.push_back(static_cast<std::byte>(x & 0xFFu));
    return *this;
  }
  B& ch(char c) { return u8(static_cast<unsigned char>(c)); }
  B& be16(std::uint16_t x) { return u8(x >> 8).u8(x); }
  B& be32(std::uint32_t x) { return u8(x >> 24).u8(x >> 16).u8(x >> 8).u8(x); }
  B& be64(std::uint64_t x) {
    return be32(static_cast<std::uint32_t>(x >> 32)).be32(static_cast<std::uint32_t>(x));
  }
  // Alpha: left-justified, right-padded with spaces to width n.
  B& alpha(std::string_view s, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) ch(i < s.size() ? s[i] : ' ');
    return *this;
  }
  B& hex(std::initializer_list<unsigned> xs) {
    for (unsigned x : xs) u8(x);
    return *this;
  }
  B& append(const Bytes& b) {
    v.insert(v.end(), b.begin(), b.end());
    return *this;
  }
  operator Bytes() const { return v; }  // NOLINT(google-explicit-constructor)
};

inline Bytes hexbytes(std::initializer_list<unsigned> xs) { return B().hex(xs); }

inline std::string to_hex(std::span<const std::byte> b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  for (std::byte x : b) {
    const auto u = std::to_integer<unsigned>(x);
    s.push_back(kDigits[u >> 4]);
    s.push_back(kDigits[u & 15]);
    s.push_back(' ');
  }
  return s;
}

// Encodes `m` with tags supplied by `fill(TagValueWriter&)`.
template <class Msg, class Fill>
Bytes encode_with(const Msg& m, Fill&& fill) {
  std::array<std::byte, 512> buf{};
  MessageWriter<Msg> w(buf, m);
  if constexpr (Msg::kRule != AppendageRule::None) fill(w.tags());
  const std::size_t n = w.finish();
  return Bytes(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
}

template <class Msg>
Bytes encode_plain(const Msg& m) {
  std::array<std::byte, 512> buf{};
  const std::size_t n = encode(std::span<std::byte>(buf), m);
  return Bytes(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
}

}  // namespace lle::ouch50::test

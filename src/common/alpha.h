#pragma once
// Fixed-width "Alpha" fields: left-justified, right-padded with spaces
// (ITCH, OUCH, SoupBinTCP, MoldUDP64 conventions).
#include <algorithm>
#include <array>
#include <compare>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>

namespace lle {

template <std::size_t N>
struct Alpha {
  std::array<char, N> c{};

  constexpr Alpha() noexcept { c.fill(' '); }
  constexpr explicit Alpha(std::string_view s) noexcept {
    c.fill(' ');
    const std::size_t n = std::min(N, s.size());
    for (std::size_t i = 0; i < n; ++i) c[i] = s[i];
  }

  static Alpha from_wire(const void* p) noexcept {
    Alpha a;
    std::memcpy(a.c.data(), p, N);
    return a;
  }
  void to_wire(void* p) const noexcept { std::memcpy(p, c.data(), N); }

  // Value with trailing spaces removed.
  [[nodiscard]] constexpr std::string_view view() const noexcept {
    std::size_t n = N;
    while (n > 0 && c[n - 1] == ' ') --n;
    return {c.data(), n};
  }
  [[nodiscard]] constexpr std::string_view raw() const noexcept { return {c.data(), N}; }
  [[nodiscard]] constexpr bool blank() const noexcept { return view().empty(); }

  friend constexpr bool operator==(const Alpha&, const Alpha&) = default;
  friend constexpr auto operator<=>(const Alpha&, const Alpha&) = default;
};

using Symbol8 = Alpha<8>;  // ITCH/OUCH stock symbol
using Mpid4 = Alpha<4>;    // market participant id / firm

// ASCII decimal fields left- or right-padded with spaces (SoupBinTCP sequence numbers).
// Accepts left or right padding (03-protocols §5). Returns false on non-digit
// content, on an all-blank field and on overflow of uint64_t; callers that give
// blank a meaning (e.g. "current session") check blank() first.
inline bool parse_padded_decimal(std::string_view s, std::uint64_t& out) noexcept {
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == ' ') ++b;
  while (e > b && s[e - 1] == ' ') --e;
  if (b == e) return false;
  std::uint64_t v = 0;
  for (std::size_t i = b; i < e; ++i) {
    const char ch = s[i];
    if (ch < '0' || ch > '9') return false;
    const auto d = static_cast<std::uint64_t>(ch - '0');
    if (v > (UINT64_MAX - d) / 10) return false;
    v = v * 10 + d;
  }
  out = v;
  return true;
}

// Writes `v` right-justified (left-padded with spaces) into a field of width N.
template <std::size_t N>
inline void format_padded_decimal(char (&dst)[N], std::uint64_t v) noexcept {
  std::memset(dst, ' ', N);
  std::size_t i = N;
  do {
    dst[--i] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0 && i > 0);
}

inline void format_padded_decimal(char* dst, std::size_t n, std::uint64_t v) noexcept {
  std::memset(dst, ' ', n);
  std::size_t i = n;
  do {
    dst[--i] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0 && i > 0);
}

}  // namespace lle

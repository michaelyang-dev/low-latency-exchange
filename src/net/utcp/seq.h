#pragma once
// TCP sequence-number arithmetic modulo 2^32 (RFC 9293 §3.4).
#include <cstdint>

namespace lle::net::utcp {

[[nodiscard]] constexpr bool seq_lt(std::uint32_t a, std::uint32_t b) noexcept {
  return static_cast<std::int32_t>(a - b) < 0;
}
[[nodiscard]] constexpr bool seq_le(std::uint32_t a, std::uint32_t b) noexcept {
  return static_cast<std::int32_t>(a - b) <= 0;
}
[[nodiscard]] constexpr bool seq_gt(std::uint32_t a, std::uint32_t b) noexcept { return seq_lt(b, a); }
[[nodiscard]] constexpr bool seq_ge(std::uint32_t a, std::uint32_t b) noexcept { return seq_le(b, a); }
[[nodiscard]] constexpr std::uint32_t seq_max(std::uint32_t a, std::uint32_t b) noexcept {
  return seq_lt(a, b) ? b : a;
}
// start <= x < start + len (mod 2^32).
[[nodiscard]] constexpr bool seq_in_window(std::uint32_t x, std::uint32_t start, std::uint32_t len) noexcept {
  return x - start < len;
}

}  // namespace lle::net::utcp

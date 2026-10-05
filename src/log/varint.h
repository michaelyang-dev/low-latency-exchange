#pragma once
// LEB128 varints and zigzag mapping for the compacted nlog file format
// (docs/design/nlog-format.md §4). Readers are bounds-checked: input is untrusted.
#include <cstddef>
#include <cstdint>

namespace lle::nlog {

inline constexpr std::size_t kMaxVarintBytes = 10;

[[nodiscard]] constexpr std::uint64_t zigzag_encode(std::int64_t v) noexcept {
  return (static_cast<std::uint64_t>(v) << 1) ^ static_cast<std::uint64_t>(v >> 63);
}
[[nodiscard]] constexpr std::int64_t zigzag_decode(std::uint64_t v) noexcept {
  return static_cast<std::int64_t>(v >> 1) ^ -static_cast<std::int64_t>(v & 1);
}

// Writes `v` at `p` (at least kMaxVarintBytes available); returns bytes written.
inline std::size_t put_varint(std::byte* p, std::uint64_t v) noexcept {
  std::size_t n = 0;
  while (v >= 0x80) {
    p[n++] = static_cast<std::byte>((v & 0x7F) | 0x80);
    v >>= 7;
  }
  p[n++] = static_cast<std::byte>(v);
  return n;
}

// Reads a varint from [p, end). Returns false on truncation or an over-long
// encoding (more than 10 bytes, or bits beyond 64).
[[nodiscard]] inline bool get_varint(const std::byte*& p, const std::byte* end, std::uint64_t& out) noexcept {
  std::uint64_t v = 0;
  for (unsigned shift = 0; shift < 70; shift += 7) {
    if (p == end) return false;
    const auto b = static_cast<std::uint8_t>(*p++);
    const std::uint64_t bits = b & 0x7Fu;
    if (shift == 63 && bits > 1) return false;
    v |= bits << shift;
    if ((b & 0x80u) == 0) {
      out = v;
      return true;
    }
  }
  return false;
}

}  // namespace lle::nlog

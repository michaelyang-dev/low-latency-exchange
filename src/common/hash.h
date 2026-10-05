#pragma once
// Non-cryptographic hashing for digests, state hashes and trace hashes.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <type_traits>

namespace lle {

// Incremental FNV-1a 64 over bytes. Stable across platforms (used in trace hashes).
class Fnv1a64 {
 public:
  static constexpr std::uint64_t kOffset = 0xcbf29ce484222325ull;
  static constexpr std::uint64_t kPrime = 0x100000001b3ull;

  constexpr Fnv1a64() noexcept = default;
  constexpr explicit Fnv1a64(std::uint64_t seed) noexcept : h_(seed) {}

  constexpr void bytes(const void* p, std::size_t n) noexcept {
    const auto* b = static_cast<const unsigned char*>(p);
    for (std::size_t i = 0; i < n; ++i) {
      h_ ^= b[i];
      h_ *= kPrime;
    }
  }
  void bytes(std::span<const std::byte> s) noexcept { bytes(s.data(), s.size()); }
  void str(std::string_view s) noexcept { bytes(s.data(), s.size()); }

  // Mix an integer in a byte-order-independent way (little-endian byte sequence).
  template <class T>
    requires std::is_integral_v<T> || std::is_enum_v<T>
  constexpr void u(T v) noexcept {
    auto x = static_cast<std::uint64_t>(v);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
      h_ ^= (x & 0xFFu);
      h_ *= kPrime;
      x >>= 8;
    }
  }

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return h_; }

 private:
  std::uint64_t h_ = kOffset;
};

// SplitMix64 finalizer: good avalanche for integer keys.
[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t z) noexcept {
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

// Order-sensitive digest combine.
[[nodiscard]] constexpr std::uint64_t combine(std::uint64_t h, std::uint64_t v) noexcept {
  return mix64(h ^ (v + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2)));
}

}  // namespace lle

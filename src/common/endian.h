#pragma once
// Unaligned big-/little-endian loads and stores. All protocol fields on the
// wire are big-endian (ITCH, OUCH, SoupBinTCP, MoldUDP64); the journal is
// little-endian (01-architecture §6).
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace lle {

template <class T>
[[nodiscard]] inline T load_raw(const void* p) noexcept {
  T v;
  std::memcpy(&v, p, sizeof(T));
  return v;
}

template <class T>
inline void store_raw(void* p, T v) noexcept {
  std::memcpy(p, &v, sizeof(T));
}

template <class T>
[[nodiscard]] constexpr T to_big(T v) noexcept {
  if constexpr (std::endian::native == std::endian::little && sizeof(T) > 1) {
    return std::byteswap(v);
  } else {
    return v;
  }
}

template <class T>
[[nodiscard]] constexpr T to_little(T v) noexcept {
  if constexpr (std::endian::native == std::endian::big && sizeof(T) > 1) {
    return std::byteswap(v);
  } else {
    return v;
  }
}

[[nodiscard]] inline std::uint16_t load_be16(const void* p) noexcept { return to_big(load_raw<std::uint16_t>(p)); }
[[nodiscard]] inline std::uint32_t load_be32(const void* p) noexcept { return to_big(load_raw<std::uint32_t>(p)); }
[[nodiscard]] inline std::uint64_t load_be64(const void* p) noexcept { return to_big(load_raw<std::uint64_t>(p)); }
[[nodiscard]] inline std::int32_t load_be32s(const void* p) noexcept { return static_cast<std::int32_t>(load_be32(p)); }

// ITCH 6-byte timestamp (nanoseconds since midnight).
[[nodiscard]] inline std::uint64_t load_be48(const void* p) noexcept {
  const auto* b = static_cast<const unsigned char*>(p);
  return (std::uint64_t{load_be16(b)} << 32) | std::uint64_t{load_be32(b + 2)};
}

inline void store_be16(void* p, std::uint16_t v) noexcept { store_raw(p, to_big(v)); }
inline void store_be32(void* p, std::uint32_t v) noexcept { store_raw(p, to_big(v)); }
inline void store_be64(void* p, std::uint64_t v) noexcept { store_raw(p, to_big(v)); }
inline void store_be32s(void* p, std::int32_t v) noexcept { store_be32(p, static_cast<std::uint32_t>(v)); }

inline void store_be48(void* p, std::uint64_t v) noexcept {
  auto* b = static_cast<unsigned char*>(p);
  store_be16(b, static_cast<std::uint16_t>(v >> 32));
  store_be32(b + 2, static_cast<std::uint32_t>(v));
}

[[nodiscard]] inline std::uint16_t load_le16(const void* p) noexcept { return to_little(load_raw<std::uint16_t>(p)); }
[[nodiscard]] inline std::uint32_t load_le32(const void* p) noexcept { return to_little(load_raw<std::uint32_t>(p)); }
[[nodiscard]] inline std::uint64_t load_le64(const void* p) noexcept { return to_little(load_raw<std::uint64_t>(p)); }
inline void store_le16(void* p, std::uint16_t v) noexcept { store_raw(p, to_little(v)); }
inline void store_le32(void* p, std::uint32_t v) noexcept { store_raw(p, to_little(v)); }
inline void store_le64(void* p, std::uint64_t v) noexcept { store_raw(p, to_little(v)); }

}  // namespace lle

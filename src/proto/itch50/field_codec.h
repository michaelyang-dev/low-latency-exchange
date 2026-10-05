#pragma once
// Field kinds of the ITCH 5.0 layout table (itch50_layouts.def) and their
// fixed-offset load/store. A (Kind, length) pair without a specialization is a
// compile error, which catches table rows whose length disagrees with the kind.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "common/alpha.h"
#include "common/assert.h"
#include "common/endian.h"
#include "common/types.h"

namespace lle::itch50 {

// Price(8): 8 implied decimals (MWCB decline levels only). Kept as a signed
// 64-bit integer like PxE4; the wire value is an unsigned u64 and round-trips
// bit-exactly through the two's-complement conversion.
using PxE8 = std::int64_t;

enum class Kind : std::uint8_t { U16, U32, U48, U64, Px4, Px8, Alpha, Enum, Char };

template <Kind K, std::size_t N, class E>
struct FieldCodec;  // undefined: unsupported (Kind, length) combination

template <>
struct FieldCodec<Kind::U16, 2, void> {
  using value_type = std::uint16_t;
  static value_type load(const std::byte* p) noexcept { return load_be16(p); }
  static void store(std::byte* p, value_type v) noexcept { store_be16(p, v); }
};

template <>
struct FieldCodec<Kind::U32, 4, void> {
  using value_type = std::uint32_t;
  static value_type load(const std::byte* p) noexcept { return load_be32(p); }
  static void store(std::byte* p, value_type v) noexcept { store_be32(p, v); }
};

// 48-bit timestamp: nanoseconds since midnight (US Eastern, R1a Q2).
template <>
struct FieldCodec<Kind::U48, 6, void> {
  using value_type = std::uint64_t;
  static value_type load(const std::byte* p) noexcept { return load_be48(p); }
  static void store(std::byte* p, value_type v) noexcept {
    LLE_DASSERT(v < (std::uint64_t{1} << 48), "48-bit field overflow");
    store_be48(p, v);
  }
};

template <>
struct FieldCodec<Kind::U64, 8, void> {
  using value_type = std::uint64_t;
  static value_type load(const std::byte* p) noexcept { return load_be64(p); }
  static void store(std::byte* p, value_type v) noexcept { store_be64(p, v); }
};

// Price(4): unsigned 32-bit on the wire, 4 implied decimals.
template <>
struct FieldCodec<Kind::Px4, 4, void> {
  using value_type = PxE4;
  static value_type load(const std::byte* p) noexcept { return static_cast<PxE4>(load_be32(p)); }
  static void store(std::byte* p, value_type v) noexcept {
    LLE_DASSERT(v >= 0 && v <= PxE4{0xFFFF'FFFF}, "Price(4) out of u32 range");
    store_be32(p, static_cast<std::uint32_t>(v));
  }
};

template <>
struct FieldCodec<Kind::Px8, 8, void> {
  using value_type = PxE8;
  static value_type load(const std::byte* p) noexcept { return static_cast<PxE8>(load_be64(p)); }
  static void store(std::byte* p, value_type v) noexcept { store_be64(p, static_cast<std::uint64_t>(v)); }
};

template <std::size_t N>
struct FieldCodec<Kind::Alpha, N, void> {
  using value_type = Alpha<N>;
  static value_type load(const std::byte* p) noexcept { return value_type::from_wire(p); }
  static void store(std::byte* p, const value_type& v) noexcept { v.to_wire(p); }
};

// Tolerant 1-byte code: any byte value is representable (underlying type char).
template <class E>
struct FieldCodec<Kind::Enum, 1, E> {
  using value_type = E;
  static value_type load(const std::byte* p) noexcept { return static_cast<E>(static_cast<char>(*p)); }
  static void store(std::byte* p, value_type v) noexcept {
    *p = static_cast<std::byte>(static_cast<unsigned char>(static_cast<char>(v)));
  }
};

template <>
struct FieldCodec<Kind::Char, 1, void> {
  using value_type = char;
  static value_type load(const std::byte* p) noexcept { return static_cast<char>(*p); }
  static void store(std::byte* p, value_type v) noexcept { *p = static_cast<std::byte>(static_cast<unsigned char>(v)); }
};

// Offset/length of one table row, used by the tiling static_asserts.
struct FieldSpan {
  std::size_t offset;
  std::size_t len;
};

// True iff `spans` cover [begin, end) contiguously, in order, with no gap or overlap.
template <std::size_t M>
constexpr bool tiles(const FieldSpan (&spans)[M], std::size_t begin, std::size_t end) noexcept {
  std::size_t at = begin;
  for (const FieldSpan& s : spans) {
    if (s.offset != at || s.len == 0) return false;
    at += s.len;
  }
  return at == end;
}

}  // namespace lle::itch50

#pragma once
// Raw nlog record as written by the hot path into a thread's SpscByteRing
// (11-logging-observability §1). This is an in-process format between the
// producer and the backend; the compacted file format is docs/design/nlog-format.md.
//
//   offset 0  u32 site_idx   site ID (site.h)
//          4  u16 len        record bytes including this header (unpadded)
//          6  u16 flags      kFlag* below
//          8  u64 tsc        RDTSC/CNTVCT at the call, or the caller's event time
//         16  args...        packed, little-endian, in site kind order:
//                            fixed kinds: raw bytes (raw_size(kind));
//                            kStr: u8 (n | kStrTruncatedBit) then n bytes (n <= 64)
// The ring places each record on an 8-byte boundary.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

#include "common/endian.h"
#include "log/format_spec.h"

namespace lle::nlog {

static_assert(std::endian::native == std::endian::little, "nlog raw records assume a little-endian host");

inline constexpr std::uint32_t kRecordHeaderBytes = 16;
inline constexpr std::uint16_t kFlagTruncated = 1u << 0;  // at least one string argument was cut
inline constexpr std::uint16_t kFlagEventTs = 1u << 1;    // tsc is caller-supplied (NLOG_EV)
inline constexpr std::uint8_t kStrTruncatedBit = 0x80;
inline constexpr std::uint32_t kMaxRecordBytes =
    kRecordHeaderBytes + static_cast<std::uint32_t>(kMaxArgs * (1 + kMaxStringBytes));

struct RawHeader {
  std::uint32_t site_idx;
  std::uint16_t len;
  std::uint16_t flags;
  std::uint64_t tsc;
};

[[nodiscard]] inline RawHeader read_raw_header(const std::byte* p) noexcept {
  return RawHeader{load_le32(p), load_le16(p + 4), load_le16(p + 6), load_le64(p + 8)};
}

namespace detail {

// A string argument after bounding: at most kMaxStringBytes copied.
struct StrArg {
  const char* p;
  std::uint32_t n;
  bool truncated;
};

[[nodiscard]] [[gnu::always_inline]] inline StrArg bound_cstr(const char* s) noexcept {
  if (s == nullptr) return StrArg{"", 0, false};
  std::uint32_t n = 0;
  while (n < kMaxStringBytes && s[n] != '\0') ++n;
  return StrArg{s, n, n == kMaxStringBytes && s[n] != '\0'};
}

// char arrays (literals, fixed buffers): never read past the array.
template <std::size_t N>
[[nodiscard]] [[gnu::always_inline]] inline StrArg bound_array(const char (&a)[N]) noexcept {
  constexpr std::uint32_t kCap = N < kMaxStringBytes ? static_cast<std::uint32_t>(N) : kMaxStringBytes;
  std::uint32_t n = 0;
  while (n < kCap && a[n] != '\0') ++n;
  bool cut = false;
  if constexpr (N > kMaxStringBytes) cut = n == kMaxStringBytes && a[n] != '\0';
  return StrArg{a, n, cut};
}

[[nodiscard]] [[gnu::always_inline]] inline StrArg bound_sv(std::string_view s) noexcept {
  const bool cut = s.size() > kMaxStringBytes;
  return StrArg{s.data(), static_cast<std::uint32_t>(cut ? kMaxStringBytes : s.size()), cut};
}

// Maps an argument to the value the record stores: enums -> underlying integer,
// float -> double, every string flavour -> StrArg, everything else unchanged.
template <class A>
[[nodiscard]] [[gnu::always_inline]] inline auto normalize(const A& a) noexcept {
  using T = std::remove_cvref_t<A>;
  if constexpr (std::is_enum_v<T>) {
    return static_cast<std::underlying_type_t<T>>(a);
  } else if constexpr (std::is_same_v<T, std::string_view>) {
    return bound_sv(a);
  } else if constexpr (std::is_same_v<T, std::string>) {
    return bound_sv(std::string_view{a});
  } else if constexpr (std::is_array_v<T>) {
    return bound_array(a);
  } else if constexpr (std::is_pointer_v<T>) {
    return bound_cstr(a);
  } else if constexpr (std::is_same_v<T, float>) {
    return static_cast<double>(a);
  } else {
    return a;
  }
}

template <class V>
[[nodiscard]] [[gnu::always_inline]] constexpr std::uint32_t arg_bytes(const V& v) noexcept {
  if constexpr (std::is_same_v<V, StrArg>) {
    return 1 + v.n;
  } else {
    return static_cast<std::uint32_t>(sizeof(V));
  }
}

template <class V>
[[nodiscard]] [[gnu::always_inline]] constexpr std::uint16_t arg_flags(const V& v) noexcept {
  if constexpr (std::is_same_v<V, StrArg>) {
    return v.truncated ? kFlagTruncated : std::uint16_t{0};
  } else {
    return 0;
  }
}

template <class V>
[[gnu::always_inline]] inline void put_arg(std::byte*& q, const V& v) noexcept {
  if constexpr (std::is_same_v<V, StrArg>) {
    *q++ = static_cast<std::byte>(v.n | (v.truncated ? kStrTruncatedBit : 0u));
    // An empty std::string_view may have a null data(): memcpy(dst, nullptr, 0)
    // is undefined (UBSan with glibc flags it).
    if (v.n != 0) std::memcpy(q, v.p, v.n);
    q += v.n;
  } else {
    static_assert(std::is_trivially_copyable_v<V>);
    std::memcpy(q, &v, sizeof(V));
    q += sizeof(V);
  }
}

}  // namespace detail
}  // namespace lle::nlog

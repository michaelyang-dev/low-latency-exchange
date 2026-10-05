#pragma once
// Canonical state encoding (05-matching-engine §8, E-06).
//
// The engine walks its canonical state as a fixed sequence of little-endian
// integers. The same walk feeds three visitors:
//   StateHasher   FNV-1a 64 over the bytes  -> Engine::state_hash()
//   ByteWriter    the bytes themselves      -> Engine::snapshot() payload
//   ByteReader    reads them back           -> Engine::restore()
// so state_hash() == FNV-1a(snapshot payload), and an independent
// implementation (fuzz/engine RefEngine) can reproduce both from the field
// list in README.md. The snapshot *file* container (headers, CRC, segments)
// belongs to src/snapshot; this is only the engine's payload.
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/hash.h"

namespace lle::engine {

class StateHasher {
 public:
  void u8(std::uint8_t v) noexcept { h_.u(v); }
  void u16(std::uint16_t v) noexcept { h_.u(v); }
  void u32(std::uint32_t v) noexcept { h_.u(v); }
  void u64(std::uint64_t v) noexcept { h_.u(v); }
  [[nodiscard]] std::uint64_t value() const noexcept { return h_.value(); }

 private:
  Fnv1a64 h_;
};

class ByteWriter {
 public:
  explicit ByteWriter(std::vector<std::byte>& out) noexcept : out_(out) {}
  void u8(std::uint8_t v) { out_.push_back(static_cast<std::byte>(v)); }
  void u16(std::uint16_t v) { put(v); }
  void u32(std::uint32_t v) { put(v); }
  void u64(std::uint64_t v) { put(v); }

 private:
  template <class T>
  void put(T v) {
    const std::size_t at = out_.size();
    if (out_.capacity() - at < sizeof(T)) out_.reserve(out_.capacity() < 4096 ? 4096 : 2 * out_.capacity());
    out_.resize(at + sizeof(T));
    std::byte* p = out_.data() + at;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
      p[i] = static_cast<std::byte>(v & 0xFFu);
      v = static_cast<T>(v >> 8);
    }
  }
  std::vector<std::byte>& out_;
};

// Bounds-checked reader: a short read sets fail() and yields zeros.
class ByteReader {
 public:
  explicit ByteReader(std::span<const std::byte> in) noexcept : in_(in) {}
  std::uint8_t u8() noexcept { return static_cast<std::uint8_t>(get(1)); }
  std::uint16_t u16() noexcept { return static_cast<std::uint16_t>(get(2)); }
  std::uint32_t u32() noexcept { return static_cast<std::uint32_t>(get(4)); }
  std::uint64_t u64() noexcept { return get(8); }
  [[nodiscard]] bool fail() const noexcept { return fail_; }
  [[nodiscard]] bool done() const noexcept { return pos_ == in_.size(); }
  [[nodiscard]] std::size_t remaining() const noexcept { return in_.size() - pos_; }

 private:
  std::uint64_t get(std::size_t n) noexcept {
    if (fail_ || in_.size() - pos_ < n) {
      fail_ = true;
      return 0;
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < n; ++i) v |= std::to_integer<std::uint64_t>(in_[pos_ + i]) << (8 * i);
    pos_ += n;
    return v;
  }
  std::span<const std::byte> in_;
  std::size_t pos_ = 0;
  bool fail_ = false;
};

// Alpha fields travel as their raw bytes packed little-endian into an integer.
template <std::size_t N>
[[nodiscard]] constexpr std::uint64_t pack_alpha(const Alpha<N>& a) noexcept {
  static_assert(N <= 8);
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < N; ++i) v |= std::uint64_t{static_cast<unsigned char>(a.c[i])} << (8 * i);
  return v;
}
template <std::size_t N>
[[nodiscard]] constexpr Alpha<N> unpack_alpha(std::uint64_t v) noexcept {
  static_assert(N <= 8);
  Alpha<N> a;
  for (std::size_t i = 0; i < N; ++i) a.c[i] = static_cast<char>((v >> (8 * i)) & 0xFFu);
  return a;
}

}  // namespace lle::engine

#pragma once
// OUCH 5.0 TagValue appendage (s1.2, Appendix A): a concatenation of elements
// [len u8][tag u8][value], where len counts the tag byte plus the value.
// Zero-copy reader and an in-place writer; neither allocates.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

#include "common/alpha.h"
#include "common/endian.h"

namespace lle::ouch50 {

enum class Tag : std::uint8_t;  // defined in ouch50_layout.gen.h

// One element. `value` points into the caller's buffer.
struct TagValue {
  std::uint8_t tag = 0;
  std::span<const std::byte> value;
  std::size_t offset = 0;  // element start, relative to the appendage

  // Typed reads; the caller has checked value.size() (the strict validator does).
  [[nodiscard]] std::uint8_t u8() const noexcept { return std::to_integer<std::uint8_t>(value[0]); }
  [[nodiscard]] std::uint16_t u16() const noexcept { return load_be16(value.data()); }
  [[nodiscard]] std::uint32_t u32() const noexcept { return load_be32(value.data()); }
  [[nodiscard]] std::uint64_t u64() const noexcept { return load_be64(value.data()); }
  [[nodiscard]] std::int32_t i32() const noexcept { return load_be32s(value.data()); }
  [[nodiscard]] char ch() const noexcept { return std::to_integer<char>(value[0]); }
  template <std::size_t N>
  [[nodiscard]] Alpha<N> alpha() const noexcept {
    return Alpha<N>::from_wire(value.data());
  }
};

// Forward iterator over elements. Iteration ends at the end of the appendage or
// at the first malformed element (len 0, or an element overrunning the end);
// malformed() distinguishes the two.
class TagValueIterator {
 public:
  using value_type = TagValue;
  using difference_type = std::ptrdiff_t;

  TagValueIterator() noexcept = default;
  explicit TagValueIterator(std::span<const std::byte> app) noexcept : app_(app) { load(); }

  const TagValue& operator*() const noexcept { return cur_; }
  const TagValue* operator->() const noexcept { return &cur_; }
  TagValueIterator& operator++() noexcept {
    pos_ = next_;
    load();
    return *this;
  }
  TagValueIterator operator++(int) noexcept {
    auto t = *this;
    ++*this;
    return t;
  }
  friend bool operator==(const TagValueIterator& it, std::default_sentinel_t) noexcept { return it.done_; }

  [[nodiscard]] bool malformed() const noexcept { return malformed_; }
  // Offset of the current (or offending) element within the appendage.
  [[nodiscard]] std::size_t position() const noexcept { return pos_; }

 private:
  void load() noexcept {
    if (pos_ >= app_.size()) {
      done_ = true;
      return;
    }
    const std::size_t len = std::to_integer<std::size_t>(app_[pos_]);
    if (len == 0 || len > app_.size() - pos_ - 1) {
      done_ = true;
      malformed_ = true;
      return;
    }
    cur_.tag = std::to_integer<std::uint8_t>(app_[pos_ + 1]);
    cur_.value = app_.subspan(pos_ + 2, len - 1);
    cur_.offset = pos_;
    next_ = pos_ + 1 + len;
  }

  std::span<const std::byte> app_;
  std::size_t pos_ = 0;
  std::size_t next_ = 0;
  TagValue cur_;
  bool done_ = false;
  bool malformed_ = false;
};

// Range adaptor: `for (const TagValue& tv : TagValueRange(app))`.
class TagValueRange {
 public:
  TagValueRange() noexcept = default;
  explicit TagValueRange(std::span<const std::byte> app) noexcept : app_(app) {}

  [[nodiscard]] TagValueIterator begin() const noexcept { return TagValueIterator(app_); }
  [[nodiscard]] std::default_sentinel_t end() const noexcept { return {}; }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return app_; }
  [[nodiscard]] bool empty() const noexcept { return app_.empty(); }

  // True when every element is well formed.
  [[nodiscard]] bool well_formed() const noexcept {
    TagValueIterator it(app_);
    while (it != std::default_sentinel) ++it;
    return !it.malformed();
  }

  // First element carrying `tag` (well-formed prefix only).
  [[nodiscard]] std::optional<TagValue> find(std::uint8_t tag) const noexcept {
    for (TagValueIterator it(app_); it != std::default_sentinel; ++it)
      if (it->tag == tag) return *it;
    return std::nullopt;
  }
  [[nodiscard]] std::optional<TagValue> find(Tag tag) const noexcept { return find(std::to_underlying(tag)); }

 private:
  std::span<const std::byte> app_;
};

// Appends elements into a caller-provided buffer. On overflow it stops writing
// and overflow() turns true; size() never exceeds the buffer.
class TagValueWriter {
 public:
  TagValueWriter() noexcept = default;
  explicit TagValueWriter(std::span<std::byte> out) noexcept : out_(out) {}

  TagValueWriter& put_raw(std::uint8_t tag, std::span<const std::byte> value) noexcept {
    // The element length byte counts tag + value, so a value is at most 254 bytes.
    if (value.size() > 254 || out_.size() - n_ < value.size() + 2) {
      overflow_ = true;
      return *this;
    }
    out_[n_] = static_cast<std::byte>(value.size() + 1);
    out_[n_ + 1] = static_cast<std::byte>(tag);
    if (!value.empty()) std::memcpy(out_.data() + n_ + 2, value.data(), value.size());
    n_ += value.size() + 2;
    return *this;
  }
  TagValueWriter& put_u8(std::uint8_t tag, std::uint8_t v) noexcept {
    const std::byte b[1] = {static_cast<std::byte>(v)};
    return put_raw(tag, b);
  }
  TagValueWriter& put_char(std::uint8_t tag, char v) noexcept { return put_u8(tag, static_cast<std::uint8_t>(v)); }
  TagValueWriter& put_u16(std::uint8_t tag, std::uint16_t v) noexcept {
    std::byte b[2];
    store_be16(b, v);
    return put_raw(tag, b);
  }
  TagValueWriter& put_u32(std::uint8_t tag, std::uint32_t v) noexcept {
    std::byte b[4];
    store_be32(b, v);
    return put_raw(tag, b);
  }
  TagValueWriter& put_i32(std::uint8_t tag, std::int32_t v) noexcept {
    std::byte b[4];
    store_be32s(b, v);
    return put_raw(tag, b);
  }
  TagValueWriter& put_u64(std::uint8_t tag, std::uint64_t v) noexcept {
    std::byte b[8];
    store_be64(b, v);
    return put_raw(tag, b);
  }
  template <std::size_t N>
  TagValueWriter& put_alpha(std::uint8_t tag, const Alpha<N>& v) noexcept {
    std::byte b[N];
    v.to_wire(b);
    return put_raw(tag, b);
  }

  // Tag-enum overloads.
  TagValueWriter& put_raw(Tag t, std::span<const std::byte> v) noexcept { return put_raw(std::to_underlying(t), v); }
  TagValueWriter& put_u8(Tag t, std::uint8_t v) noexcept { return put_u8(std::to_underlying(t), v); }
  TagValueWriter& put_char(Tag t, char v) noexcept { return put_char(std::to_underlying(t), v); }
  TagValueWriter& put_u16(Tag t, std::uint16_t v) noexcept { return put_u16(std::to_underlying(t), v); }
  TagValueWriter& put_u32(Tag t, std::uint32_t v) noexcept { return put_u32(std::to_underlying(t), v); }
  TagValueWriter& put_i32(Tag t, std::int32_t v) noexcept { return put_i32(std::to_underlying(t), v); }
  TagValueWriter& put_u64(Tag t, std::uint64_t v) noexcept { return put_u64(std::to_underlying(t), v); }
  template <std::size_t N>
  TagValueWriter& put_alpha(Tag t, const Alpha<N>& v) noexcept {
    return put_alpha(std::to_underlying(t), v);
  }
  template <class E>
    requires std::is_enum_v<E> && std::is_same_v<std::underlying_type_t<E>, char>
  TagValueWriter& put_enum(Tag t, E v) noexcept {
    return put_char(std::to_underlying(t), std::to_underlying(v));
  }

  [[nodiscard]] std::size_t size() const noexcept { return n_; }
  [[nodiscard]] bool overflow() const noexcept { return overflow_; }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return out_.first(n_); }

 private:
  std::span<std::byte> out_;
  std::size_t n_ = 0;
  bool overflow_ = false;
};

}  // namespace lle::ouch50

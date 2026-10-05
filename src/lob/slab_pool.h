#pragma once
// Slab pool with 32-bit handles (04-order-book §3, X08).
//
// Elements live in fixed-size slabs (about 2 MiB each, so an arena-backed
// slab is exactly one huge page) and never move, so both handles and pointers
// stay valid until the element is freed. Allocation pops a LIFO free list
// (recently freed slots are cache-hot) or bumps into the reserved slabs; a new
// slab is mapped only when the reserve is exhausted, so a pool reserved at
// startup for its peak population never allocates in the steady state.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "lob/arena.h"
#include "lob/types.h"

namespace lle::lob {

namespace detail {
template <class T>
constexpr std::size_t slot_bytes() noexcept {
  constexpr std::size_t s = sizeof(T) < sizeof(Handle32) ? sizeof(Handle32) : sizeof(T);
  constexpr std::size_t a = alignof(T) < alignof(Handle32) ? alignof(Handle32) : alignof(T);
  return (s + a - 1) / a * a;
}
template <class T>
constexpr std::uint32_t default_slab_bits() noexcept {
  constexpr std::size_t target = kHugePageBytes / slot_bytes<T>();
  constexpr std::uint32_t bits = static_cast<std::uint32_t>(std::bit_width(std::bit_floor(target)) - 1);
  return bits < 6 ? 6 : (bits > 20 ? 20 : bits);
}
}  // namespace detail

template <class T, class Backing = HeapBacking, std::uint32_t kSlabBits = detail::default_slab_bits<T>()>
class SlabPool {
 public:
  using Handle = Handle32;
  using value_type = T;
  static constexpr Handle kNil = kNil32;
  static constexpr std::uint32_t kSlabSize = 1u << kSlabBits;
  static constexpr std::uint32_t kSlabMask = kSlabSize - 1;
  static constexpr std::size_t kSlotBytes = detail::slot_bytes<T>();
  static constexpr std::size_t kSlabBytes = kSlotBytes * kSlabSize;
  static constexpr std::size_t kAlign = alignof(T) < 64 ? 64 : alignof(T);
  static constexpr std::size_t kMaxSlabs = (std::size_t{1} << 32) / kSlabSize;

  SlabPool() = default;
  explicit SlabPool(std::size_t reserve_n, bool prefault = false) { reserve(reserve_n, prefault); }
  SlabPool(const SlabPool&) = delete;
  SlabPool& operator=(const SlabPool&) = delete;
  ~SlabPool() {
    // Non-trivial elements must be freed by their owner first: the pool does
    // not track which slots are live.
    LLE_ASSERT(std::is_trivially_destructible_v<T> || live_ == 0, "SlabPool destroyed with live elements");
    for (std::byte* s : slabs_) Backing::deallocate(s, kSlabBytes, kAlign);
  }

  // Ensures capacity for n elements without further slab allocation.
  // prefault writes every byte of new slabs (startup only).
  void reserve(std::size_t n, bool prefault = false) {
    while (capacity() < n) add_slab(prefault);
  }

  template <class... A>
  [[nodiscard]] Handle alloc(A&&... args) {
    Handle h;
    if (free_ != kNil) {
      h = free_;
      std::memcpy(&free_, slot(h), sizeof(Handle));
    } else {
      if (bump_ == capacity()) [[unlikely]]
        add_slab(false);
      h = static_cast<Handle>(bump_++);
    }
    ::new (static_cast<void*>(slot(h))) T(std::forward<A>(args)...);
    ++live_;
    return h;
  }

  void free(Handle h) noexcept {
    LLE_DASSERT(h < bump_, "free of a handle never allocated");
    ptr(h)->~T();
    std::memcpy(slot(h), &free_, sizeof(Handle));
    free_ = h;
    --live_;
  }

  [[nodiscard]] T* ptr(Handle h) noexcept { return std::launder(static_cast<T*>(static_cast<void*>(slot(h)))); }
  [[nodiscard]] const T* ptr(Handle h) const noexcept {
    return std::launder(static_cast<const T*>(static_cast<const void*>(slot(h))));
  }
  [[nodiscard]] T& operator[](Handle h) noexcept { return *ptr(h); }
  [[nodiscard]] const T& operator[](Handle h) const noexcept { return *ptr(h); }

  [[nodiscard]] std::size_t live() const noexcept { return live_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return slabs_.size() * std::size_t{kSlabSize}; }
  // Slabs mapped after construction-time reserve(); a steady-state
  // regression check compares this before and after a phase.
  [[nodiscard]] std::size_t slab_count() const noexcept { return slabs_.size(); }
  // Highest handle ever handed out + 1.
  [[nodiscard]] std::size_t high_water() const noexcept { return bump_; }

  void prefetch(Handle h) const noexcept { __builtin_prefetch(slot(h)); }

 private:
  [[nodiscard]] std::byte* slot(Handle h) const noexcept {
    return slabs_[h >> kSlabBits] + std::size_t{h & kSlabMask} * kSlotBytes;
  }

  void add_slab(bool prefault) {
    LLE_ASSERT(slabs_.size() + 1 < kMaxSlabs, "SlabPool handle space exhausted");
    auto* s = static_cast<std::byte*>(Backing::allocate(kSlabBytes, kAlign));
    if (prefault) std::memset(s, 0, kSlabBytes);
    slabs_.push_back(s);
  }

  std::vector<std::byte*> slabs_;
  std::size_t bump_ = 0;
  std::size_t live_ = 0;
  Handle free_ = kNil;
};

}  // namespace lle::lob

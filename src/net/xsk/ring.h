#pragma once
// AF_XDP rings over the raw UAPI (07 §2.3; R3a §1.1). Each ring is single-producer /
// single-consumer shared with the kernel: the producer publishes entries with a release
// store of its index, the consumer reads the other side's index with an acquire load
// (the pseudo-code in Documentation/networking/af_xdp.rst). Indices are free-running
// 32-bit counters; the ring size is a power of two.
#include <linux/if_xdp.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace lle::net::xsk {

// Pointers into one mmap'ed ring region (set up by XskSocket / Umem).
struct RingMap {
  std::uint32_t* producer = nullptr;
  std::uint32_t* consumer = nullptr;
  std::uint32_t* flags = nullptr;
  void* desc = nullptr;
  std::uint32_t size = 0;
  void* mmap_base = nullptr;
  std::size_t mmap_len = 0;
};

namespace detail {
// The ring indices live in memory shared with the kernel. The __atomic builtins (GCC and
// clang) give the same acquire/relaxed/release semantics as std::atomic_ref, and also
// work on const pointers, which atomic_ref<const T> (C++26) does not yet in libc++.
inline std::uint32_t load_acquire(const std::uint32_t* p) noexcept { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
inline std::uint32_t load_relaxed(const std::uint32_t* p) noexcept { return __atomic_load_n(p, __ATOMIC_RELAXED); }
inline void store_release(std::uint32_t* p, std::uint32_t v) noexcept { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
}  // namespace detail

// We produce, the kernel consumes (FILL: u64 addresses; TX: xdp_desc).
template <class T>
class ProducerRing {
 public:
  ProducerRing() = default;
  explicit ProducerRing(const RingMap& m) noexcept
      : m_(m), ring_(static_cast<T*>(m.desc)), mask_(m.size - 1),
        cached_prod_(detail::load_relaxed(m.producer)), cached_cons_(detail::load_relaxed(m.consumer) + m.size) {}

  // Free slots, refreshing the cached consumer index only when needed.
  std::uint32_t free(std::uint32_t want) noexcept {
    std::uint32_t n = cached_cons_ - cached_prod_;
    if (n >= want) return n;
    cached_cons_ = detail::load_acquire(m_.consumer) + m_.size;
    return cached_cons_ - cached_prod_;
  }
  // Reserves up to `want` slots starting at *idx; returns the count reserved.
  std::uint32_t reserve(std::uint32_t want, std::uint32_t* idx) noexcept {
    const std::uint32_t n = free(want);
    const std::uint32_t got = n < want ? n : want;
    *idx = cached_prod_;
    cached_prod_ += got;
    return got;
  }
  T& at(std::uint32_t idx) noexcept { return ring_[idx & mask_]; }
  // Publishes everything reserved so far.
  void submit() noexcept { detail::store_release(m_.producer, cached_prod_); }
  // Returns `n` reserved but unused slots (before submit()).
  void cancel(std::uint32_t n) noexcept { cached_prod_ -= n; }
  [[nodiscard]] bool needs_wakeup() const noexcept {
    return (detail::load_relaxed(m_.flags) & XDP_RING_NEED_WAKEUP) != 0;
  }
  // Entries published but not yet consumed by the kernel.
  std::uint32_t pending() noexcept { return m_.size - free(m_.size); }
  [[nodiscard]] std::uint32_t size() const noexcept { return m_.size; }
  [[nodiscard]] bool valid() const noexcept { return ring_ != nullptr; }

 private:
  RingMap m_{};
  T* ring_ = nullptr;
  std::uint32_t mask_ = 0;
  std::uint32_t cached_prod_ = 0;
  std::uint32_t cached_cons_ = 0;
};

// The kernel produces, we consume (RX: xdp_desc; COMPLETION: u64 addresses).
template <class T>
class ConsumerRing {
 public:
  ConsumerRing() = default;
  explicit ConsumerRing(const RingMap& m) noexcept
      : m_(m), ring_(static_cast<T*>(m.desc)), mask_(m.size - 1),
        cached_prod_(detail::load_relaxed(m.producer)), cached_cons_(detail::load_relaxed(m.consumer)) {}

  // Entries available (up to `want`) starting at *idx.
  std::uint32_t peek(std::uint32_t want, std::uint32_t* idx) noexcept {
    std::uint32_t n = cached_prod_ - cached_cons_;
    if (n == 0) {
      cached_prod_ = detail::load_acquire(m_.producer);
      n = cached_prod_ - cached_cons_;
    }
    if (n > want) n = want;
    *idx = cached_cons_;
    return n;
  }
  const T& at(std::uint32_t idx) const noexcept { return ring_[idx & mask_]; }
  // Hands `n` consumed entries back to the kernel.
  void release(std::uint32_t n) noexcept {
    cached_cons_ += n;
    detail::store_release(m_.consumer, cached_cons_);
  }
  [[nodiscard]] std::uint32_t size() const noexcept { return m_.size; }
  [[nodiscard]] bool valid() const noexcept { return ring_ != nullptr; }

 private:
  RingMap m_{};
  const T* ring_ = nullptr;
  std::uint32_t mask_ = 0;
  std::uint32_t cached_prod_ = 0;
  std::uint32_t cached_cons_ = 0;
};

using FillRing = ProducerRing<std::uint64_t>;
using TxRing = ProducerRing<xdp_desc>;
using RxRing = ConsumerRing<xdp_desc>;
using CompRing = ConsumerRing<std::uint64_t>;

}  // namespace lle::net::xsk

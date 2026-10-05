#pragma once
// SpscRing: bounded single-producer/single-consumer ring (08-concurrency-runtime §3,
// research R6 §D1). A Lamport ring with cached opposite indices (MCRingBuffer /
// rigtorp SPSCQueue style): each side refreshes its copy of the other side's index
// only when the cached value says full (producer) or empty (consumer), so in steady
// state each side touches only its own lines plus the slot.
//
// Include allowlist (08 §7): this header is compiled directly by GenMC, so it may
// include only <atomic>, <cstddef>, <cstdint>, <type_traits> and common/cache.h.
// No standalone fences: TSan does not model them (08 §3).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "common/cache.h"

namespace lle::conc {

// Progress: wait-free on both sides (every call finishes in a bounded number of steps;
// it fails fast when the ring is full or empty). Waiting belongs to the caller
// (concurrent/wait.h).
//
// Positions are monotonic 64-bit counters: the ring is empty when w == r and full when
// w - r == Cap, so all Cap slots are usable (no spare slot) and wraparound needs 2^64
// operations.
template <class T, std::size_t Cap>
class SpscRing {
  static_assert(Cap >= 1 && (Cap & (Cap - 1)) == 0, "Cap must be a power of two");
  static_assert(std::is_trivially_copyable_v<T>, "slots are copied with plain assignment");
  static_assert(std::is_default_constructible_v<T>, "storage is an inline T[Cap]");

 public:
  using value_type = T;

  // Slots are initialized by a loop rather than a value-initializer: GenMC cannot model
  // the memset a `buf_[Cap]{}` lowers to, and leaving them uninitialized trips GCC's
  // -Wmaybe-uninitialized at -O3. The loop stays plain stores at -O0 (GenMC); an
  // optimizer may turn it into memset.
  SpscRing() noexcept {
    for (std::size_t i = 0; i < Cap; ++i) buf_[i] = T{};
  }
  SpscRing(const SpscRing&) = delete;
  SpscRing& operator=(const SpscRing&) = delete;

  static constexpr std::size_t capacity() noexcept { return Cap; }

  // ---- producer ----------------------------------------------------------------

  bool try_push(const T& v) noexcept {
    T* slot = try_claim();
    if (slot == nullptr) return false;
    *slot = v;
    commit();
    return true;
  }

  // Constructs T{args...} in the next slot. T is trivially copyable, so the slot
  // already holds a T and is assigned (no <new> / placement new: include allowlist).
  template <class... Args>
  bool try_emplace(Args&&... args) noexcept {
    T* slot = try_claim();
    if (slot == nullptr) return false;
    *slot = T{static_cast<Args&&>(args)...};
    commit();
    return true;
  }

  // Zero-copy write: returns the next free slot (nullptr when full) without publishing
  // it. Fill it in place, then call commit(). Calling try_claim() again before
  // commit() returns the same slot.
  T* try_claim() noexcept {
    const std::uint64_t w = w_.load(std::memory_order_relaxed);  // single writer
    if (w - rcache_ == Cap) {
      // Acquire pairs with the consumer's release of r_: its reads of the slot we are
      // about to overwrite happen-before our writes (no write-after-read race).
      rcache_ = r_.load(std::memory_order_acquire);
      if (w - rcache_ == Cap) return nullptr;
    }
    return &buf_[w & kMask];
  }

  // Publishes the slot returned by the last try_claim().
  void commit() noexcept {
    const std::uint64_t w = w_.load(std::memory_order_relaxed);
    // Release publishes the slot contents to the consumer's acquire load of w_.
    w_.store(w + 1, std::memory_order_release);
  }

  // ---- consumer ----------------------------------------------------------------

  bool try_pop(T& out) noexcept {
    const T* slot = front();
    if (slot == nullptr) return false;
    out = *slot;
    pop();
    return true;
  }

  // Zero-copy read: the oldest unread slot, or nullptr when empty. The slot stays
  // valid until pop().
  const T* front() noexcept {
    const std::uint64_t r = r_.load(std::memory_order_relaxed);  // single writer
    if (r == wcache_) {
      // Acquire pairs with the producer's release of w_: slot contents are visible.
      wcache_ = w_.load(std::memory_order_acquire);
      if (r == wcache_) return nullptr;
    }
    return &buf_[r & kMask];
  }

  // Frees the slot returned by front(). Precondition: front() returned non-null.
  void pop() noexcept {
    const std::uint64_t r = r_.load(std::memory_order_relaxed);
    r_.store(r + 1, std::memory_order_release);
  }

  // Calls f(const T&) for up to `max` available items and publishes r_ once for the
  // whole batch (one release store, one line transfer). Returns the count consumed.
  template <class F>
  std::size_t drain(F&& f, std::size_t max) {
    const std::uint64_t r = r_.load(std::memory_order_relaxed);
    std::uint64_t avail = wcache_ - r;
    if (avail == 0) {
      wcache_ = w_.load(std::memory_order_acquire);
      avail = wcache_ - r;
      if (avail == 0) return 0;
    }
    const std::uint64_t n = avail < max ? avail : static_cast<std::uint64_t>(max);
    for (std::uint64_t i = 0; i < n; ++i) f(static_cast<const T&>(buf_[(r + i) & kMask]));
    r_.store(r + n, std::memory_order_release);
    return static_cast<std::size_t>(n);
  }

  // ---- either side (approximate under concurrency) -----------------------------

  std::size_t size_approx() const noexcept {
    // Load r first: r never exceeds the w written before it, and the acquire makes
    // the later w load observe at least that value, so the difference is in [0, Cap].
    const std::uint64_t r = r_.load(std::memory_order_acquire);
    const std::uint64_t w = w_.load(std::memory_order_acquire);
    const std::uint64_t d = w - r;
    return static_cast<std::size_t>(d > Cap ? Cap : d);
  }
  bool empty_approx() const noexcept { return size_approx() == 0; }

 private:
  static constexpr std::uint64_t kMask = Cap - 1;

  // Four lines (08 §3): producer-owned, producer's cache, consumer-owned, consumer's
  // cache. The slot array starts on its own line.
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> w_{0};
  alignas(kFalseSharingBytes) std::uint64_t rcache_ = 0;  // producer-only
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> r_{0};
  alignas(kFalseSharingBytes) std::uint64_t wcache_ = 0;  // consumer-only
  alignas(kFalseSharingBytes) T buf_[Cap];  // initialized in the constructor
};

}  // namespace lle::conc

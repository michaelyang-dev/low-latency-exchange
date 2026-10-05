#pragma once
// VyukovMpscRing<T, Cap>: Dmitry Vyukov's bounded MPMC ring (per-cell sequence
// numbers), used with a single consumer. BASELINE AND NEGATIVE EXAMPLE ONLY — never
// on a production path (08-concurrency-runtime §6, research R6 §D2).
//
// It is *blocking in practice*: a producer that is suspended after winning the CAS on
// enqueue_pos_ but before storing the cell's sequence leaves a hole at its cell, and
// the consumer cannot get past it, even though later producers have completed (Vyukov:
// "not lockfree in the official meaning"). try_pop then reports "empty" while
// completed items sit behind the hole, which is not linearizable. The GenMC harness
// verify/genmc/mpsc_stalled_producer.cpp and the stalled-producer unit test show it.
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only.
// Test hook: LLE_TEST_STOP_AFTER_CLAIM(value), as in mpsc_scq.h, is evaluated right
// after the producer wins its cell (the CAS on enqueue_pos_).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "common/cache.h"

namespace lle::conc {

template <class T, std::size_t Cap>
class VyukovMpscRing {
  static_assert(Cap >= 2 && (Cap & (Cap - 1)) == 0, "Cap must be a power of two >= 2 (cell sequence encoding)");
  static_assert(std::is_trivially_copyable_v<T>);
  static_assert(std::is_default_constructible_v<T>);

 public:
  using value_type = T;

  VyukovMpscRing() noexcept {
    for (std::uint64_t i = 0; i < Cap; ++i) {
      cells_[i].seq.store(i, std::memory_order_relaxed);
      cells_[i].value = T{};  // loop, not memset (GenMC; see SpscRing)
    }
  }
  VyukovMpscRing(const VyukovMpscRing&) = delete;
  VyukovMpscRing& operator=(const VyukovMpscRing&) = delete;

  static constexpr std::size_t capacity() noexcept { return Cap; }

  bool try_push(const T& v) noexcept {
    std::uint64_t pos = enqueue_pos_.load(std::memory_order_relaxed);
    Cell* cell = nullptr;
    for (;;) {
      cell = &cells_[pos & kMask];
      const std::uint64_t seq = cell->seq.load(std::memory_order_acquire);
      const auto dif = static_cast<std::int64_t>(seq - pos);
      if (dif == 0) {
        if (enqueue_pos_.compare_exchange_strong(pos, pos + 1, std::memory_order_relaxed)) break;
      } else if (dif < 0) {
        return false;  // full
      } else {
        pos = enqueue_pos_.load(std::memory_order_relaxed);
      }
    }
#ifdef LLE_TEST_STOP_AFTER_CLAIM
    if (LLE_TEST_STOP_AFTER_CLAIM(v)) return true;  // abandoned: the cell stays a hole
#endif
    cell->value = v;
    cell->seq.store(pos + 1, std::memory_order_release);
    return true;
  }

  // Single consumer.
  bool try_pop(T& out) noexcept {
    const std::uint64_t pos = deq_pos_.load(std::memory_order_relaxed);
    Cell& cell = cells_[pos & kMask];
    const std::uint64_t seq = cell.seq.load(std::memory_order_acquire);
    if (static_cast<std::int64_t>(seq - (pos + 1)) < 0) return false;  // empty, or a stalled claim
    out = cell.value;
    cell.seq.store(pos + Cap, std::memory_order_release);
    deq_pos_.store(pos + 1, std::memory_order_relaxed);
    return true;
  }

 private:
  static constexpr std::uint64_t kMask = Cap - 1;
  struct alignas(kFalseSharingBytes) Cell {
    std::atomic<std::uint64_t> seq{0};
    T value;  // initialized in the constructor
  };

  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> enqueue_pos_{0};
  // Consumer-private. A relaxed atomic (a plain load/store on x86-64 and arm64) rather
  // than a plain integer only so GenMC's liveness check can tell that the stuck consumer
  // re-reads the latest value (verify/genmc/mpsc_stalled_producer.cpp).
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> deq_pos_{0};
  Cell cells_[Cap];
};

}  // namespace lle::conc

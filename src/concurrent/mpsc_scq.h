#pragma once
// MpscScqRing<T, Cap>: bounded lock-free multi-producer/single-consumer queue built on
// SCQ (R. Nikolaev, "A Scalable, Portable, and Memory-Efficient Lock-Free FIFO Queue",
// DISC 2019, arXiv:1908.04511). Clean-room implementation from the paper's pseudo-code
// (Figure 4: data array + two index queues; Figure 8: SCQ). This is the gateway ->
// sequencer queue (08-concurrency-runtime §5).
//
// Why SCQ: Vyukov-style rings (concurrent/mpsc_vyukov.h), the Disruptor MP sequencer
// and rigtorp's MPMC block the consumer while a producer is suspended between claiming
// and publishing a slot. In SCQ a dequeuer that reaches a slot before its enqueuer
// invalidates it (cycle bump / IsSafe clear) so the late enqueuer's CAS fails and it
// retries elsewhere; nobody waits for anybody. Single-width FAA/CAS/OR only.
//
// Memory orders: seq_cst everywhere (08 §5: relax only with GenMC evidence; see
// verify/genmc/ORDERINGS.md). On x86-64 and arm64 every RMW here costs the same at
// seq_cst as at acq_rel, and the only plain seq_cst store is the Threshold reset.
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only.
// Test hook: if LLE_TEST_STOP_AFTER_CLAIM(value) is defined before inclusion, it is
// evaluated right after a producer claims an aq slot (the Tail FAA, before the entry
// CAS). It may block (a preempted producer) and returns true to abandon the push
// forever (a producer that never runs again). Never defined in production builds.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "common/cache.h"

namespace lle::conc {
namespace detail {

constexpr unsigned log2_pow2(std::uint64_t v) noexcept {
  unsigned r = 0;
  while ((std::uint64_t{1} << r) < v) ++r;
  return r;
}

// One SCQ index ring holding up to N indices in [0, N) over 2N entries (the paper's
// "doubled capacity" that bounds the Threshold at 3N-1). Each entry is one 64-bit word
//   [ cycle : 63-k | IsSafe : 1 | index : k ]      with 2N = 2^k,
// and index == 2N-1 is the empty marker (the paper's bottom). Head and Tail are
// monotonic positions; position p maps to entry Cache_Remap(p mod 2N) in cycle p / 2N.
// kSingleDequeuer: the plan's single-consumer specialization (08 §5, ADR-031). Valid
// only when exactly one thread ever calls dequeue(): Head then has a single writer, and
// an occupied entry (index != bottom) is written only by that dequeuer, because
// enqueuers CAS empty entries only. So the Head FAA becomes a load plus a release
// store, and the consume fetch_or becomes a release store of the value just loaded.
template <std::size_t N, bool kSingleDequeuer = false>
class ScqIndexRing {
 public:
  static constexpr std::uint64_t kEntries = 2 * static_cast<std::uint64_t>(N);
  static constexpr unsigned kOrder = log2_pow2(kEntries);
  static constexpr std::uint64_t kIndexMask = kEntries - 1;
  static constexpr std::uint64_t kBottom = kEntries - 1;  // all index bits set
  static constexpr std::uint64_t kSafeBit = std::uint64_t{1} << kOrder;
  static constexpr unsigned kCycleShift = kOrder + 1;
  static constexpr std::int64_t kThreshold = 3 * static_cast<std::int64_t>(N) - 1;
  static constexpr std::uint64_t kEmpty = ~std::uint64_t{0};

  // Empty ring (paper, Figure 8 lines 1-4, shifted one cycle so no entry starts
  // "newer" than a position): Head = Tail = 2N, every entry {cycle 0, safe, bottom}.
  void init_empty() noexcept {
    head_.store(kEntries, std::memory_order_relaxed);
    tail_.store(kEntries, std::memory_order_relaxed);
    threshold_.store(-1, std::memory_order_relaxed);
    for (std::uint64_t i = 0; i < kEntries; ++i) entries_[i].store(make(0, true, kBottom), std::memory_order_relaxed);
  }

  // Full ring holding 0..N-1: Head = 2N (cycle 1), Tail = 3N; positions 2N..3N-1 hold
  // {cycle 1, safe, i}, the remaining entries {cycle 0, safe, bottom} so enqueues at
  // positions 3N..4N-1 (cycle 1) find an older, empty entry.
  void init_full() noexcept {
    head_.store(kEntries, std::memory_order_relaxed);
    tail_.store(kEntries + N, std::memory_order_relaxed);
    threshold_.store(kThreshold, std::memory_order_relaxed);
    for (std::uint64_t i = 0; i < kEntries; ++i) {
      const std::uint64_t v = i < N ? make(1, true, i) : make(0, true, kBottom);
      entries_[remap(i)].store(v, std::memory_order_relaxed);
    }
  }

  // Figure 8, enqueue (lines 11-22). Never fails: the data-array discipline keeps at
  // most N indices in a ring. `on_claim()` is the test hook (returns true to abandon).
  template <class OnClaim>
  bool enqueue(std::uint64_t index, OnClaim&& on_claim) noexcept {
    for (;;) {
      const std::uint64_t t = tail_.fetch_add(1, std::memory_order_seq_cst);  // line 13
      if (on_claim()) return false;
      const std::uint64_t tcycle = cycle_of(t);
      std::atomic<std::uint64_t>& slot = entries_[remap(t)];  // line 14
      std::uint64_t ent = slot.load(std::memory_order_seq_cst);  // line 15
      for (;;) {
        // Line 16: the entry is from an older cycle, empty, and either safe or every
        // dequeuer that could have marked it unsafe is still behind us (Head <= T).
        if (cycle_lt(entry_cycle(ent), tcycle) && (ent & kIndexMask) == kBottom &&
            ((ent & kSafeBit) != 0 || head_.load(std::memory_order_seq_cst) <= t)) {
          // Lines 17-19; a failed CAS reloads `ent` (goto 15).
          if (!slot.compare_exchange_strong(ent, make(tcycle, true, index), std::memory_order_seq_cst)) continue;
          // Lines 20-21: re-arm the dequeuers' livelock budget. An exchange rather than
          // the paper's plain store: identical under SC (x86 emits xchg for a seq_cst
          // store anyway), but concurrent enqueuers' resets become totally ordered RMWs
          // instead of racing stores, which lets GenMC use symmetry reduction
          // (verify/genmc/ORDERINGS.md, "Deviations").
          if (threshold_.load(std::memory_order_seq_cst) != kThreshold) {
            threshold_.exchange(kThreshold, std::memory_order_seq_cst);
          }
          return true;
        }
        break;  // slot unusable (stale T or occupied): take a new Tail position
      }
    }
  }

  // Positions taken by enqueuers minus positions taken by dequeuers: about the indices
  // held. Monitoring only (ring occupancy in a metrics segment), never control flow: an
  // enqueue that skips an unusable entry, or a dequeue that races ahead of Tail, moves
  // it transiently. Relaxed reads; not part of the algorithm.
  [[nodiscard]] std::uint64_t size_approx() const noexcept {
    const std::uint64_t h = head_.load(std::memory_order_relaxed);
    const std::uint64_t t = tail_.load(std::memory_order_relaxed);
    return t > h ? t - h : 0;
  }

  // Figure 8, dequeue (lines 23-45). Returns the index, or kEmpty.
  std::uint64_t dequeue() noexcept {
    if (threshold_.load(std::memory_order_seq_cst) < 0) return kEmpty;  // lines 24-25
    // Empty fast path (NOT in the paper; verify/genmc/ORDERINGS.md, "Deviations"). Every
    // enqueue re-arms Threshold to 3n-1, so without this a poller on an empty ring makes
    // up to 3n-1 full attempts (FAA Head, CAS entry, catch-up CAS on Tail) per message,
    // each contending with the next enqueue. Tail only grows and every completed enqueue
    // used a position below Tail; Head is read first, so at the instant Tail is read,
    // Tail <= Head and every completed enqueue's position is already owned by a dequeuer
    // that has passed it: returning empty there is linearizable (the argument of lines
    // 39-40, without taking a position).
    {
      const std::uint64_t h = head_.load(std::memory_order_seq_cst);
      if (tail_.load(std::memory_order_seq_cst) <= h) return kEmpty;
    }
    for (;;) {
      std::uint64_t h;  // line 27
      if constexpr (kSingleDequeuer) {
        h = head_.load(std::memory_order_relaxed);  // own variable
        head_.store(h + 1, std::memory_order_release);
      } else {
        h = head_.fetch_add(1, std::memory_order_seq_cst);
      }
      const std::uint64_t hcycle = cycle_of(h);
      std::atomic<std::uint64_t>& slot = entries_[remap(h)];  // line 28
      std::uint64_t ent = slot.load(std::memory_order_seq_cst);  // line 29
      for (;;) {
        const std::uint64_t ecycle = entry_cycle(ent);
        if (cycle_eq(ecycle, hcycle)) {
          // Lines 30-32: our entry; its cycle cannot change under us. Consume by
          // setting the index bits to bottom, keeping cycle and IsSafe.
          if constexpr (kSingleDequeuer) {
            slot.store(ent | kBottom, std::memory_order_release);  // no other writer now
          } else {
            slot.fetch_or(kBottom, std::memory_order_seq_cst);
          }
          return ent & kIndexMask;
        }
        // Lines 33-35: either mark an occupied older entry unsafe, or move an empty
        // older entry to our cycle so its (late) enqueuer fails.
        const std::uint64_t idx = ent & kIndexMask;
        const std::uint64_t desired = idx == kBottom ? make(hcycle, (ent & kSafeBit) != 0, kBottom) : (ent & ~kSafeBit);
        if (cycle_lt(ecycle, hcycle)) {  // line 36
          if (!slot.compare_exchange_strong(ent, desired, std::memory_order_seq_cst)) continue;  // goto 29
        }
        break;
      }
      const std::uint64_t t = tail_.load(std::memory_order_seq_cst);  // line 39
      if (t <= h + 1) {  // lines 40-43: empty
        catchup(t, h + 1);
        threshold_.fetch_sub(1, std::memory_order_seq_cst);
        return kEmpty;
      }
      if (threshold_.fetch_sub(1, std::memory_order_seq_cst) <= 0) return kEmpty;  // lines 44-45
    }
  }

 private:
  // Figure 8 lines 5-10: pull Tail up to Head after dequeuers overtook it.
  void catchup(std::uint64_t tail, std::uint64_t head) noexcept {
    while (!tail_.compare_exchange_strong(tail, head, std::memory_order_seq_cst)) {
      head = head_.load(std::memory_order_seq_cst);
      tail = tail_.load(std::memory_order_seq_cst);
      if (tail >= head) break;
    }
  }

  static constexpr std::uint64_t cycle_of(std::uint64_t pos) noexcept { return pos >> kOrder; }
  static constexpr std::uint64_t entry_cycle(std::uint64_t e) noexcept { return e >> kCycleShift; }
  static constexpr std::uint64_t make(std::uint64_t cycle, bool safe, std::uint64_t index) noexcept {
    return (cycle << kCycleShift) | (safe ? kSafeBit : 0) | index;
  }
  // Cycles are compared modulo the entry's cycle-field width with signed arithmetic
  // (paper §5.2), so wraparound is harmless.
  static constexpr bool cycle_lt(std::uint64_t a, std::uint64_t b) noexcept {
    return static_cast<std::int64_t>((a - b) << kCycleShift) < 0;
  }
  static constexpr bool cycle_eq(std::uint64_t a, std::uint64_t b) noexcept { return ((a ^ b) << kCycleShift) == 0; }

  // Cache_Remap: consecutive positions land on different lines (a transpose of the
  // entries viewed as [lines][entries-per-line]); identity when one line holds all.
  static constexpr unsigned kLineOrder = log2_pow2(kFalseSharingBytes / sizeof(std::uint64_t));
  static constexpr std::uint64_t remap(std::uint64_t pos) noexcept {
    const std::uint64_t i = pos & kIndexMask;
    if constexpr (kOrder <= kLineOrder) {
      return i;
    } else {
      constexpr unsigned kLinesOrder = kOrder - kLineOrder;
      return ((i & ((std::uint64_t{1} << kLinesOrder) - 1)) << kLineOrder) | (i >> kLinesOrder);
    }
  }

  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> head_{0};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> tail_{0};
  alignas(kFalseSharingBytes) std::atomic<std::int64_t> threshold_{-1};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> entries_[kEntries];
};

struct NoClaimHook {
  constexpr bool operator()() const noexcept { return false; }
};

}  // namespace detail

// Producers: any number of threads may call try_push concurrently. For the paper's
// livelock-freedom bound, Cap should be >= the number of producers (at most Cap
// concurrent dequeuers on the free-index ring); with more producers try_push can
// report "full" spuriously, but never loses or duplicates an item.
// Consumer: exactly one thread calls try_pop.
// kSingleConsumerAq selects the single-consumer specialization for the allocated-index
// ring (ADR-031); the free-index ring is dequeued by every producer and stays general.
template <class T, std::size_t Cap, bool kSingleConsumerAq = false>
class MpscScqRing {
  static_assert(Cap >= 1 && (Cap & (Cap - 1)) == 0, "Cap must be a power of two");
  static_assert(Cap <= (std::size_t{1} << 30), "index field width");
  static_assert(std::is_trivially_copyable_v<T>, "slots are copied with plain assignment");
  static_assert(std::is_default_constructible_v<T>, "storage is an inline array");

 public:
  using value_type = T;

  MpscScqRing() noexcept {
    aq_.init_empty();
    fq_.init_full();
    for (std::size_t i = 0; i < Cap; ++i) slots_[i].value = T{};  // loop, not memset (GenMC; see SpscRing)
  }
  MpscScqRing(const MpscScqRing&) = delete;
  MpscScqRing& operator=(const MpscScqRing&) = delete;

  static constexpr std::size_t capacity() noexcept { return Cap; }

  // Messages queued, approximately (ScqIndexRing::size_approx, at most Cap). Any thread;
  // monitoring only, never control flow.
  [[nodiscard]] std::size_t size_approx() const noexcept {
    const std::uint64_t n = aq_.size_approx();
    return static_cast<std::size_t>(n < Cap ? n : Cap);
  }

  // Figure 4, enqueue_ptr: take a free index, fill its slot, publish the index.
  // Returns false when the queue is full. Lock-free.
  bool try_push(const T& v) noexcept {
    const std::uint64_t idx = fq_.dequeue();
    if (idx == Ring::kEmpty) return false;
    slots_[idx].value = v;
#ifdef LLE_TEST_STOP_AFTER_CLAIM
    auto hook = [&v]() noexcept -> bool { return LLE_TEST_STOP_AFTER_CLAIM(v); };
#else
    detail::NoClaimHook hook;
#endif
    aq_.enqueue(idx, hook);  // an abandoned (test-hook) push still consumed its slot
    return true;
  }

  // Figure 4, dequeue_ptr: take a published index, copy its slot, free the index.
  // Single consumer only. Returns false when empty. Lock-free.
  bool try_pop(T& out) noexcept {
    const std::uint64_t idx = aq_.dequeue();
    if (idx == Ring::kEmpty) return false;
    out = slots_[idx].value;
    fq_.enqueue(idx, detail::NoClaimHook{});
    return true;
  }

 private:
  using Ring = detail::ScqIndexRing<Cap>;
  using ARing = detail::ScqIndexRing<Cap, kSingleConsumerAq>;
  // Slots are line-padded: consecutive pushes by different producers get adjacent
  // indices, and must not false-share.
  struct alignas(kFalseSharingBytes) Slot {
    T value;
  };

  ARing aq_;  // allocated indices: producers enqueue, the consumer dequeues
  Ring fq_;  // free indices: the consumer enqueues, producers dequeue
  Slot slots_[Cap];  // initialized in the constructor
};

}  // namespace lle::conc

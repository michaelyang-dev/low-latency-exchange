#pragma once
// Thread-ring registry shared by the producers (register_thread) and the single
// consumer (the file backend or the in-memory sink). Internal to src/log.
//
// Producers publish their ThreadBuffer into a fixed slot array (registration is
// cold and takes a mutex); the consumer scans the slots without locks. Exactly
// one consumer may run at a time (acquire_consumer). A thread that unregisters
// sets `closed`; the consumer drains the rest of its ring, reports it ended and
// frees it.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

#include "common/cache.h"
#include "concurrent/spsc_byte_ring.h"
#include "log/nlog.h"

namespace lle::nlog::detail {

inline constexpr std::size_t kMaxThreads = 256;
inline constexpr std::size_t kThreadNameBytes = 32;

struct ThreadBuffer {
  conc::SpscByteRing ring;
  std::byte* storage = nullptr;
  std::size_t storage_bytes = 0;
  std::uint32_t thread_id = 0;
  FullPolicy policy = FullPolicy::kDrop;
  char name[kThreadNameBytes] = {};

  // Written by the producer only (single writer: load + store, relaxed).
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> drops{0};
  std::atomic<bool> closed{false};  // release by the producer after its last commit

  // Consumer-private.
  alignas(kFalseSharingBytes) std::uint64_t drops_reported = 0;
  bool announced = false;
};

struct Registry {
  std::array<std::atomic<ThreadBuffer*>, kMaxThreads> slots{};
  std::atomic<std::uint32_t> high_water{0};  // slots [0, high_water) may be in use
  std::atomic<std::uint32_t> next_thread_id{1};
  std::atomic<std::uint64_t> unregistered_drops{0};
  std::atomic<bool> consumer_active{false};
  std::mutex mu;  // registration only
};

extern constinit Registry g_registry;

// Claims the consumer role; false if another consumer is running. Resets the
// consumer-private state of every live buffer so a new consumer re-announces them.
[[nodiscard]] bool acquire_consumer() noexcept;
void release_consumer() noexcept;

// Frees a closed, fully drained buffer (consumer only).
void retire(std::uint32_t slot, ThreadBuffer* b) noexcept;

// Consumer poll over every registered ring. Handler provides:
//   void on_thread(const ThreadBuffer&);                         first sight of a thread
//   void on_record(const ThreadBuffer&, const std::byte*, std::uint32_t len);
//   void on_drops(const ThreadBuffer&, std::uint64_t total);     drop counter changed
//   void on_thread_end(const ThreadBuffer&);                     closed and drained
// Visits slots in index order (deterministic for a single-threaded simulator).
// Returns the number of records consumed.
template <class Handler>
std::size_t poll_rings(Handler& h, std::size_t batch) {
  std::size_t total = 0;
  const std::uint32_t hw = g_registry.high_water.load(std::memory_order_acquire);
  for (std::uint32_t i = 0; i < hw; ++i) {
    ThreadBuffer* b = g_registry.slots[i].load(std::memory_order_acquire);
    if (b == nullptr) continue;
    if (!b->announced) {
      h.on_thread(*b);
      b->announced = true;
    }
    // Read `closed` before draining: if it was set, every commit happened before
    // and the drain loop below sees all of it.
    const bool closed = b->closed.load(std::memory_order_acquire);
    auto fn = [&](const std::byte* p, std::uint32_t len) { h.on_record(*b, p, len); };
    std::size_t n = b->ring.drain(fn, batch);
    total += n;
    if (closed) {
      while ((n = b->ring.drain(fn, batch)) != 0) total += n;
    }
    const std::uint64_t d = b->drops.load(std::memory_order_relaxed);
    if (d != b->drops_reported) {
      h.on_drops(*b, d);
      b->drops_reported = d;
    }
    if (closed) {
      h.on_thread_end(*b);
      retire(i, b);
    }
  }
  return total;
}

}  // namespace lle::nlog::detail

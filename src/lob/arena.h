#pragma once
// Memory backings for slab pools and indexes (04-order-book §3 "Memory", X12/X13).
//
// HeapBacking uses the default allocator. ArenaBacking maps anonymous memory
// directly: on Linux it requests 2 MiB pages (MAP_HUGETLB, falling back to
// MADV_HUGEPAGE when no hugetlbfs pages are reserved) and can pre-fault with
// MADV_POPULATE_WRITE; on macOS it is a plain anonymous mapping. Both are only
// called at startup or when a pool grows past its reserved size, never in the
// steady state of a pre-sized book.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "common/assert.h"

namespace lle::lob {

enum class HugePages : std::uint8_t {
  kOff,          // plain anonymous pages
  kTransparent,  // MADV_HUGEPAGE on a 2 MiB-aligned mapping (Linux THP)
  kHugetlb,      // MAP_HUGETLB 2 MiB pages; falls back to kTransparent
};

inline constexpr std::size_t kHugePageBytes = std::size_t{2} << 20;

// What a mapping actually received (for reports and tests).
struct ArenaInfo {
  std::size_t bytes = 0;     // mapped length (rounded)
  bool hugetlb = false;      // MAP_HUGETLB succeeded
  bool thp_advised = false;  // MADV_HUGEPAGE applied
  bool prefaulted = false;
};

// Process-wide counters; relaxed atomics, only touched when mapping.
struct ArenaCounters {
  std::size_t maps = 0;
  std::size_t hugetlb_maps = 0;
  std::size_t thp_maps = 0;
  std::size_t bytes = 0;
};

// Rounded length that arena_map() maps for a request of `bytes`.
[[nodiscard]] std::size_t arena_round(std::size_t bytes, HugePages mode) noexcept;

// Maps `bytes` of zero-filled anonymous memory, or returns nullptr. The
// returned block must be released with arena_unmap(p, bytes, mode) using the
// same `bytes` and `mode`.
[[nodiscard]] void* arena_map(std::size_t bytes, HugePages mode, bool prefault,
                              ArenaInfo* info = nullptr) noexcept;
void arena_unmap(void* p, std::size_t bytes, HugePages mode) noexcept;

[[nodiscard]] ArenaCounters arena_counters() noexcept;

// Default allocator (the B0 memory policy). Memory is not zeroed.
struct HeapBacking {
  static constexpr bool kZeroed = false;
  [[nodiscard]] static void* allocate(std::size_t bytes, std::size_t align) {
    return ::operator new(bytes, std::align_val_t{align});
  }
  static void deallocate(void* p, std::size_t bytes, std::size_t align) noexcept {
    ::operator delete(p, bytes, std::align_val_t{align});
  }
};

// Directly mapped (optionally huge-page) memory. Memory is zeroed.
template <HugePages kMode = HugePages::kTransparent, bool kPrefault = true>
struct ArenaBacking {
  static constexpr bool kZeroed = true;
  [[nodiscard]] static void* allocate(std::size_t bytes, std::size_t /*align*/) {
    void* p = arena_map(bytes, kMode, kPrefault);
    LLE_ASSERT(p != nullptr, "arena_map failed");
    return p;
  }
  static void deallocate(void* p, std::size_t bytes, std::size_t /*align*/) noexcept {
    arena_unmap(p, bytes, kMode);
  }
};

// Allocates zero-filled memory from any backing.
template <class Backing>
[[nodiscard]] void* allocate_zeroed(std::size_t bytes, std::size_t align) {
  void* p = Backing::allocate(bytes, align);
  if constexpr (!Backing::kZeroed) std::memset(p, 0, bytes);
  return p;
}

}  // namespace lle::lob

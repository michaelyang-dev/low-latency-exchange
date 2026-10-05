#include "lob/arena.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>

namespace lle::lob {
namespace {

std::atomic<std::size_t> g_maps{0};
std::atomic<std::size_t> g_hugetlb{0};
std::atomic<std::size_t> g_thp{0};
std::atomic<std::size_t> g_bytes{0};

std::size_t page_bytes() noexcept {
  const long p = ::sysconf(_SC_PAGESIZE);
  return p > 0 ? static_cast<std::size_t>(p) : std::size_t{4096};
}

std::size_t round_up(std::size_t v, std::size_t a) noexcept { return (v + a - 1) / a * a; }

void touch_pages(void* p, std::size_t bytes) noexcept {
  const std::size_t step = page_bytes();
  auto* b = static_cast<volatile unsigned char*>(p);
  for (std::size_t off = 0; off < bytes; off += step) b[off] = 0;
}

#if defined(__linux__)
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23  // Linux 5.14
#endif

// Maps `bytes` aligned to 2 MiB by over-mapping and trimming, so THP can back
// every 2 MiB extent of the block.
void* map_aligned(std::size_t bytes) noexcept {
  const std::size_t over = bytes + kHugePageBytes;
  void* raw = ::mmap(nullptr, over, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return nullptr;
  const auto base = reinterpret_cast<std::uintptr_t>(raw);
  const std::uintptr_t aligned = (base + kHugePageBytes - 1) & ~(std::uintptr_t{kHugePageBytes} - 1);
  const std::size_t head = aligned - base;
  const std::size_t tail = over - head - bytes;
  if (head != 0) ::munmap(raw, head);
  if (tail != 0) ::munmap(reinterpret_cast<void*>(aligned + bytes), tail);
  return reinterpret_cast<void*>(aligned);
}
#endif

}  // namespace

std::size_t arena_round(std::size_t bytes, HugePages mode) noexcept {
  if (bytes == 0) bytes = 1;
  if (mode == HugePages::kOff) return round_up(bytes, page_bytes());
  return round_up(bytes, kHugePageBytes);
}

void* arena_map(std::size_t bytes, HugePages mode, bool prefault, ArenaInfo* info) noexcept {
  const std::size_t len = arena_round(bytes, mode);
  ArenaInfo local;
  local.bytes = len;
  void* p = nullptr;
#if defined(__linux__)
  if (mode == HugePages::kHugetlb) {
    p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (p == MAP_FAILED) {
      p = nullptr;  // no reserved hugetlbfs pages: fall back to THP
    } else {
      local.hugetlb = true;
    }
  }
  if (p == nullptr && mode != HugePages::kOff) {
    p = map_aligned(len);
    if (p != nullptr && ::madvise(p, len, MADV_HUGEPAGE) == 0) local.thp_advised = true;
  }
  if (p == nullptr && mode == HugePages::kOff) {
    p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) p = nullptr;
  }
  if (p != nullptr && prefault) {
    // MADV_POPULATE_WRITE faults in huge pages; MAP_POPULATE would fault 4 KiB
    // pages before the THP advice applies (R5 D5.3 "Hugepages").
    if (::madvise(p, len, MADV_POPULATE_WRITE) != 0) touch_pages(p, len);
    local.prefaulted = true;
  }
#else
  // macOS: no hugetlbfs and no THP advice for anonymous memory on arm64.
  p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (p == MAP_FAILED) p = nullptr;
  if (p != nullptr && prefault) {
    touch_pages(p, len);
    local.prefaulted = true;
  }
#endif
  if (p == nullptr) return nullptr;
  g_maps.fetch_add(1, std::memory_order_relaxed);
  g_bytes.fetch_add(len, std::memory_order_relaxed);
  if (local.hugetlb) g_hugetlb.fetch_add(1, std::memory_order_relaxed);
  if (local.thp_advised) g_thp.fetch_add(1, std::memory_order_relaxed);
  if (info != nullptr) *info = local;
  return p;
}

void arena_unmap(void* p, std::size_t bytes, HugePages mode) noexcept {
  if (p == nullptr) return;
  ::munmap(p, arena_round(bytes, mode));
}

ArenaCounters arena_counters() noexcept {
  return ArenaCounters{g_maps.load(std::memory_order_relaxed), g_hugetlb.load(std::memory_order_relaxed),
                       g_thp.load(std::memory_order_relaxed), g_bytes.load(std::memory_order_relaxed)};
}

}  // namespace lle::lob

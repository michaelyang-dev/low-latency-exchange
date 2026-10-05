// Hot-path rule (11-logging-observability §1, conventions "Hot paths"): after
// register_thread(), NLOG calls never allocate, whether they succeed, drop on a
// full ring, or come from an unregistered thread. Checked with a counting global
// operator new; this TU replaces it for the whole nlog_test binary, counting only
// while a test turns counting on. (MSan builds skip *alloc_test.cpp files.)
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <string_view>
#include <thread>

#include "log/memory_sink.h"
#include "log/nlog.h"
#include "test_util.h"

namespace {

std::atomic<bool> g_counting{false};
std::atomic<std::uint64_t> g_allocations{0};

void* counted_alloc(std::size_t n, std::size_t align = 0) {
  if (g_counting.load(std::memory_order_relaxed)) g_allocations.fetch_add(1, std::memory_order_relaxed);
  void* p = nullptr;
  if (align <= alignof(std::max_align_t)) {
    p = std::malloc(n == 0 ? 1 : n);
  } else if (::posix_memalign(&p, align, n == 0 ? align : n) != 0) {
    p = nullptr;
  }
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void* counted_nothrow(std::size_t n, std::size_t align = 0) noexcept {
  try {
    return counted_alloc(n, align);
  } catch (...) {
    return nullptr;
  }
}

class CountAllocations {
 public:
  CountAllocations() {
    g_allocations.store(0);
    g_counting.store(true);
  }
  ~CountAllocations() { g_counting.store(false); }
  CountAllocations(const CountAllocations&) = delete;
  CountAllocations& operator=(const CountAllocations&) = delete;
  [[nodiscard]] std::uint64_t count() const { return g_allocations.load(); }
};

}  // namespace

// Every form is replaced, so nothing the standard library allocates (for
// example through the nothrow or aligned forms) is freed by a different
// allocator: under ASan with libstdc++ a partial set reports alloc-dealloc-mismatch.
void* operator new(std::size_t n) { return counted_alloc(n); }
void* operator new[](std::size_t n) { return counted_alloc(n); }
void* operator new(std::size_t n, std::align_val_t a) { return counted_alloc(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return counted_alloc(n, static_cast<std::size_t>(a)); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n); }
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
  return counted_nothrow(n, static_cast<std::size_t>(a));
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

namespace lle::nlog {
namespace {

enum class Side : char { kBuy = 'B' };

TEST(NlogAlloc, HotPathNeverAllocates) {
  test::drain_and_discard();
  ThreadScope scope({.ring_bytes = 1 << 16});  // registration may allocate
  ASSERT_TRUE(scope.ok());
  const std::string owned(100, 'x');
  std::uint64_t logged = 0;
  {
    CountAllocations counter;
    for (std::uint64_t i = 0; i < 5000; ++i) {  // fills the 64 KiB ring: later calls take the drop path
      NLOG_INFO("order {} accepted px {} qty {} side {}", i, static_cast<std::int64_t>(i) - 7, std::uint32_t{100},
                Side::kBuy);
      NLOG_EV(i, "ev {} {} {}", std::string_view{"view"}, owned, 1.5);
      NLOG_WARN("no args");
    }
    logged = 15000 - thread_drops();
    EXPECT_EQ(counter.count(), 0u);
  }
  EXPECT_GT(thread_drops(), 0u) << "the drop path must have been exercised too";
  EXPECT_GT(logged, 0u);
}

TEST(NlogAlloc, UnregisteredCallsNeverAllocate) {
  std::thread t([] {
    CountAllocations counter;
    for (int i = 0; i < 100; ++i) NLOG_INFO("unregistered {}", i);
    EXPECT_EQ(counter.count(), 0u);
  });
  t.join();
}

}  // namespace
}  // namespace lle::nlog

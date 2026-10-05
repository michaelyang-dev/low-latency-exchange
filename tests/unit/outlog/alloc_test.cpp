// Design rule (06 §8, conventions "Hot paths"): after open(), the append path
// (append, flush, index entries) never allocates, and neither do reader
// lookups over a consistent index. Checked with a counting global operator
// new; this TU replaces it for the whole test binary, counting only while a
// test turns counting on.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <span>
#include <string>
#include <vector>

#include "common/prng.h"
#include "outlog/reader.h"
#include "outlog/writer.h"
#include "outlog_test_util.h"

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

namespace lle::outlog {
namespace {

TEST(OutlogAlloc, AppendFlushAndReadDoNotAllocateAfterOpen) {
  test::TempDir dir;
  const std::string path = dir.file("itch.bin");

  // Messages prepared up front (allocation is fine here).
  constexpr std::size_t kMessages = 20'000;
  Prng rng(77);
  std::vector<std::size_t> lens(kMessages);
  std::vector<std::byte> pool;
  for (std::size_t i = 0; i < kMessages; ++i) {
    lens[i] = test::random_length(rng);
    const std::vector<std::byte> m = test::make_message(1, i + 1, lens[i]);
    pool.insert(pool.end(), m.begin(), m.end());
  }

  OutlogWriter w;
  ASSERT_TRUE(w.open(path, OutlogWriter::kMinBufferBytes).has_value());
  std::uint64_t writer_allocs = 0;
  bool ok = true;
  {
    const CountAllocations counter;
    std::size_t off = 0;
    for (std::size_t i = 0; i < kMessages; ++i) {
      ok = ok && w.append(std::span<const std::byte>(pool.data() + off, lens[i])).has_value();
      off += lens[i];
      if (i % 1000 == 999) ok = ok && w.flush().has_value();
    }
    ok = ok && w.flush().has_value();
    writer_allocs = counter.count();
  }
  EXPECT_TRUE(ok);
  EXPECT_EQ(writer_allocs, 0u);
  ASSERT_TRUE(w.close().has_value());

  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  ASSERT_EQ(r.count(), kMessages);
  std::vector<std::byte> scratch(kMaxMessageBytes);
  std::uint64_t reader_allocs = 0;
  std::size_t seen = 0;
  std::size_t delivered = 0;
  {
    const CountAllocations counter;
    for (SeqNo s = 1; s <= kMessages; s += 101) ok = ok && r.read(s, scratch).has_value();
    delivered = r.for_each(4000, 10'000, [&](SeqNo, std::span<const std::byte>) { ++seen; });
    ok = ok && r.offset_of(kMessages).has_value();
    reader_allocs = counter.count();
  }
  EXPECT_TRUE(ok);
  EXPECT_EQ(delivered, 10'000u);
  EXPECT_EQ(seen, 10'000u);
  EXPECT_EQ(reader_allocs, 0u);
}

}  // namespace
}  // namespace lle::outlog

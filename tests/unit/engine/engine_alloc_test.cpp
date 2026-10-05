// No allocation in Engine::apply() after startup (05-matching-engine §8):
// once the day's configuration is loaded and the pools, level vectors and
// indexes are pre-sized, applying order flow must not call operator new.
// Separate binary: it replaces the global allocation functions to count calls.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <deque>
#include <new>
#include <vector>

#include "engine/engine.h"
#include "gen.hpp"

namespace {
std::atomic<std::uint64_t> g_allocs{0};
std::atomic<bool> g_counting{false};

void* counted(std::size_t n, std::size_t align) {
  if (g_counting.load(std::memory_order_relaxed)) g_allocs.fetch_add(1, std::memory_order_relaxed);
  void* p = nullptr;
  if (align > alignof(std::max_align_t)) {
    if (::posix_memalign(&p, align, n == 0 ? align : n) != 0) p = nullptr;
  } else {
    p = std::malloc(n == 0 ? 1 : n);
  }
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void* counted_nothrow(std::size_t n, std::size_t align) noexcept {
  try {
    return counted(n, align);
  } catch (...) {
    return nullptr;
  }
}
}  // namespace

// Every form is replaced (docs/dev/conventions.md): with a partial set, memory the
// standard library allocates through an unreplaced form would be freed by this
// file's free(), which ASan with libstdc++ reports as alloc-dealloc-mismatch.
void* operator new(std::size_t n) { return counted(n, 0); }
void* operator new[](std::size_t n) { return counted(n, 0); }
void* operator new(std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n, 0); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return counted_nothrow(n, 0); }
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

namespace lle::engine {
namespace {

TEST(EngineAlloc, CounterSeesAllocations) {
  g_counting.store(true);
  const std::uint64_t before = g_allocs.load();
  auto* v = new std::vector<int>(100);
  g_counting.store(false);
  EXPECT_GE(g_allocs.load() - before, 2u);
  delete v;
}

TEST(EngineAlloc, SteadyStateApplyDoesNotAllocate) {
  EngineConfig cfg;
  cfg.book.reserve_orders = 1 << 16;
  cfg.book.reserve_levels = 1 << 12;
  cfg.book.levels_per_side = 64;
  cfg.urn_capacity = 1 << 16;
  std::uint64_t total_records = 0, counted_records = 0;
  for (std::uint64_t seed = 1; seed <= 24; ++seed) {
    // Materialize the records first: the generator allocates.
    std::deque<std::vector<std::byte>> payloads;
    std::vector<InputRecord> recs;
    gen::Generator g(seed);
    for (int i = 0; i < 20'000; ++i) {
      InputRecord r = g.next();
      payloads.emplace_back(r.payload.begin(), r.payload.end());
      r.payload = std::span<const std::byte>(payloads.back());
      recs.push_back(r);
    }
    Engine e(cfg);
    CountingSink sink;
    std::uint64_t before = 0;
    for (const InputRecord& r : recs) {
      // DayStart and Config load the day's tables (startup): not counted. An
      // Admin RiskLimit may create an account's per-symbol table or duplicate
      // filter the first time it is set (a cold path): not counted either.
      const auto t = static_cast<RecordType>(r.type);
      const auto adm = t == RecordType::Admin ? parse_admin(r.payload) : std::nullopt;
      const bool startup = t == RecordType::DayStart || t == RecordType::Config ||
                           (adm && adm->hdr.command == static_cast<std::uint16_t>(AdminCommand::RiskLimit));
      g_counting.store(!startup, std::memory_order_relaxed);
      before = g_allocs.load();
      e.apply(r, sink);
      g_counting.store(false, std::memory_order_relaxed);
      const std::uint64_t n = g_allocs.load() - before;
      EXPECT_EQ(n, 0u) << "seed " << seed << " record " << r.index << " type " << r.type;
      if (n != 0) return;
      ++total_records;
      if (!startup) ++counted_records;
    }
    EXPECT_GT(sink.ouch_msgs, 0u);
  }
  EXPECT_GT(counted_records, total_records * 9 / 10);
}

}  // namespace
}  // namespace lle::engine

// Steady-state allocation test (04-order-book §5 "no allocation"; X07/X08):
// once pools, index and per-book level reserves are sized for the peak, the
// optimized variants must not call operator new while applying a workload.
//
// This binary replaces the global allocation functions to count calls; the
// count is only examined around the measured phase.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

#include "book/digested_book.h"
#include "book/variants.h"
#include "common/prng.h"

namespace {
std::uint64_t g_allocs = 0;

void* counted(std::size_t n, std::size_t align) {
  ++g_allocs;
  void* p = nullptr;
  if (align <= alignof(std::max_align_t)) {
    p = std::malloc(n == 0 ? 1 : n);
  } else if (::posix_memalign(&p, align, n == 0 ? align : n) != 0) {
    p = nullptr;
  }
  if (p == nullptr) throw std::bad_alloc();
  return p;
}
}  // namespace

void* operator new(std::size_t n) { return counted(n, 0); }
void* operator new[](std::size_t n) { return counted(n, 0); }
void* operator new(std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new[](std::size_t n, std::align_val_t a) { return counted(n, static_cast<std::size_t>(a)); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
  try {
    return counted(n, 0);
  } catch (...) {
    return nullptr;
  }
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

namespace lle::book {
namespace {

template <class V>
std::uint64_t steady_state_allocs() {
  BookConfig cfg;
  cfg.reserve_orders = 1 << 17;
  cfg.reserve_levels = 1 << 15;
  cfg.levels_per_side = 512;
  DigestedBook<V> db(cfg);
  auto& b = db.book();
  // Plain ops, no workload bookkeeping (which itself allocates), measured.
  std::vector<OrderRef> refs;
  refs.reserve(200'000);
  Prng rng(5);
  for (Locate l = 1; l <= 64; ++l) b.stock_directory(l);
  auto px = [&](Locate l, Side s) {
    const PxE4 off = static_cast<PxE4>(rng.below(rng.chance(1, 2) ? 4 : 120)) * 100;
    return s == Side::Buy ? 100'000 + 1'000 * l - off : 100'100 + 1'000 * l + off;
  };
  // Sliding window: 40,000 live orders, refs rising by 4; each step removes
  // the oldest, adds a new one, and touches a random live one (reduce or U).
  std::uint64_t next = 92;
  std::size_t head = 0;
  auto add = [&]() {
    const auto l = static_cast<Locate>(1 + (next >> 2) % 64);
    const Side s = (next >> 3) % 2 ? Side::Buy : Side::Sell;
    b.add(next, l, s, px(l, s), 100 * static_cast<Qty>(1 + rng.below(10)));
    refs.push_back(next);
    next += 4;
  };
  auto churn = [&](std::uint64_t steps) {
    for (std::uint64_t i = 0; i < steps; ++i) {
      b.remove(refs[head]);
      refs[head] = 0;
      ++head;
      add();
      const std::size_t k = head + static_cast<std::size_t>(rng.below(refs.size() - head));
      if (refs[k] == 0) continue;
      if (rng.chance(1, 8)) {
        const auto o = b.find_order(refs[k]);
        if (o && b.replace(refs[k], next, px(o->locate, o->side), o->qty) == Status::kOk) {
          refs[k] = next;
          next += 4;
        }
      } else if (rng.chance(1, 4)) {
        b.reduce(refs[k], 1);
      }
      if (refs.size() == refs.capacity()) {  // compact outside the measured window
        refs.erase(refs.begin(), refs.begin() + static_cast<std::ptrdiff_t>(head));
        head = 0;
      }
    }
  };
  for (int i = 0; i < 40'000; ++i) add();
  churn(300'000);  // warm-up: reach every high-water mark
  refs.erase(refs.begin(), refs.begin() + static_cast<std::ptrdiff_t>(head));
  head = 0;
  const std::size_t room = refs.capacity() - refs.size();
  const std::uint64_t measured = room - 1'000;  // no vector growth or compaction inside the window
  const std::uint64_t before = g_allocs;
  churn(measured);
  return g_allocs - before;
}

TEST(SteadyState, OptimizedVariantsDoNotAllocate) {
  EXPECT_EQ(steady_state_allocs<VarOpt>(), 0u);
  EXPECT_EQ(steady_state_allocs<VarOptHuge>(), 0u);
  EXPECT_EQ(steady_state_allocs<VarVecIntrFlat>(), 0u);
  EXPECT_EQ(steady_state_allocs<VarWin>(), 0u);
}

TEST(SteadyState, NodeBasedVariantsAllocatePerOrder) {
  // B0 allocates an unordered_map node and a list node per order (by design);
  // the std::unordered_map index allocates a node per insert; std::map levels
  // allocate a node per new price level.
  EXPECT_GT(steady_state_allocs<VarB0>(), 100'000u);
  EXPECT_GT(steady_state_allocs<VarVecIntrStd>(), 100'000u);
  EXPECT_GT(steady_state_allocs<VarMapIntrFlat>(), 0u);
}

}  // namespace
}  // namespace lle::book

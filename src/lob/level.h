#pragma once
// A price level (04-order-book §3). One FIFO per queue class: the ITCH book
// uses one class (displayed); the matching engine uses two, displayed then
// non-displayed (05-matching-engine §2, Rule 4757(a)(1)).
#include <cstdint>

#include "lob/types.h"

namespace lle::lob {

template <class Queue, int kClasses = 1>
struct Level {
  static_assert(kClasses == 1 || kClasses == 2, "one or two queue classes per level");
  static constexpr int kQueueClasses = kClasses;

  PxE4 px = 0;                    // real (never negated) price
  std::uint64_t qty[static_cast<std::size_t>(kClasses)]{};  // aggregate shares per class (u64: 10K x 999,999 overflows u32)
  Queue q[static_cast<std::size_t>(kClasses)]{};            // FIFO per class, front = highest priority
  std::uint32_t count = 0;        // orders in all classes
  Handle32 self = kNil32;         // own pool handle when levels are pooled

  [[nodiscard]] std::uint64_t total_qty() const noexcept {
    std::uint64_t t = 0;
    for (int c = 0; c < kClasses; ++c) t += qty[c];
    return t;
  }
  [[nodiscard]] bool empty() const noexcept { return count == 0; }
};

}  // namespace lle::lob

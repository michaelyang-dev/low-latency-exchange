#pragma once
// Vocabulary of the shared LOB core (04-order-book §3).
#include <cstdint>
#include <type_traits>

#include "common/types.h"

namespace lle::lob {

// 32-bit handle into a slab pool. kNil32 is never a valid handle.
using Handle32 = std::uint32_t;
inline constexpr Handle32 kNil32 = 0xFFFF'FFFFu;

// The "no record" value for a store's handle type: nullptr for node-based
// stores (handle = record pointer), kNil32 for pooled stores.
template <class H>
[[nodiscard]] constexpr H nil_handle() noexcept {
  if constexpr (std::is_pointer_v<H>) {
    return nullptr;
  } else {
    return static_cast<H>(kNil32);
  }
}

// ITCH Price(4) is an unsigned 32-bit field, so a book price is in
// [0, kPxMaxBook]. Stub quotes reach $199,999.99 (R1a Q6 pitfall 8).
inline constexpr PxE4 kPxMaxBook = 0xFFFF'FFFFll;

[[nodiscard]] constexpr bool valid_book_px(PxE4 px) noexcept { return px >= 0 && px <= kPxMaxBook; }

// One side of the top of book: best price and the aggregate displayed
// quantity there. qty == 0 means the side is empty (px is then 0).
struct BboSide {
  PxE4 px = 0;
  std::uint64_t qty = 0;
  constexpr bool operator==(const BboSide&) const = default;
};

// Cached in the per-locate book header (X26). Crossed and locked values are
// legal (R1a Q6 pitfall 1): nothing here assumes bid < ask.
struct Bbo {
  BboSide bid;
  BboSide ask;
  constexpr bool operator==(const Bbo&) const = default;
};

// Goodness orders over level keys: better(a, b) is true when key a is a
// better price than key b. kSign maps a key to a "higher is better" scale.
struct Higher {
  static constexpr int kSign = 1;
  [[nodiscard]] static constexpr bool better(PxE4 a, PxE4 b) noexcept { return a > b; }
};
struct Lower {
  static constexpr int kSign = -1;
  [[nodiscard]] static constexpr bool better(PxE4 a, PxE4 b) noexcept { return a < b; }
};

// Level-allocation context for containers that keep levels inside their own
// nodes (std::map): there is nothing to allocate from.
// Stand-in pool for unpooled level containers. Accepts SlabPool's constructor
// arguments, so a book can construct either in place (a [[no_unique_address]]
// member gets no guaranteed copy elision from a factory call under GCC).
struct NoPool {
  NoPool() = default;
  constexpr NoPool(std::size_t, bool) noexcept {}
};

}  // namespace lle::lob

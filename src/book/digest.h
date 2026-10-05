#pragma once
// Correctness digests (04-order-book §5 "Correctness gate per run", §8).
//
// Both digests are defined field by field so an independent implementation
// (fuzz/lob/ref_book.hpp) can reproduce them without sharing this code:
//
// BBO-change stream. h0 = kBboDigestSeed; for every BBO change event in
// order: h = combine(h, locate), then combine with bid.px, bid.qty, ask.px,
// ask.qty (prices as two's-complement u64; an empty side is px 0, qty 0).
//
// Final books. h0 = kBooksDigestSeed; for each locate in ascending order
// whose book holds at least one order: h = combine(h, locate); then for side
// Buy then Sell: combine('B' or 'S'), combine(level count); for each level
// from best to worst: combine(px), combine(order count), combine(total
// shares); for each order in FIFO order: combine(ref), combine(shares).
// Finally h = combine(h, total live orders).
//
// combine() is lle::combine from common/hash.h.
#include <cstdint>

#include "common/hash.h"
#include "common/types.h"
#include "lob/types.h"

namespace lle::book {

inline constexpr std::uint64_t kBboDigestSeed = 0x6C6F'622D'6262'6F31ull;    // "lob-bbo1"
inline constexpr std::uint64_t kBooksDigestSeed = 0x6C6F'622D'626B'7331ull;  // "lob-bks1"

[[nodiscard]] constexpr std::uint64_t bbo_digest_step(std::uint64_t h, Locate loc, const lob::Bbo& b) noexcept {
  h = combine(h, loc);
  h = combine(h, static_cast<std::uint64_t>(b.bid.px));
  h = combine(h, b.bid.qty);
  h = combine(h, static_cast<std::uint64_t>(b.ask.px));
  h = combine(h, b.ask.qty);
  return h;
}

struct BboDigest {
  std::uint64_t value = kBboDigestSeed;
  std::uint64_t events = 0;
  constexpr void add(Locate loc, const lob::Bbo& b) noexcept {
    value = bbo_digest_step(value, loc, b);
    ++events;
  }
};

// Builder for the final-books digest; callers walk the canonical order.
class BooksDigest {
 public:
  constexpr void begin_book(Locate loc) noexcept { h_ = combine(h_, loc); }
  constexpr void begin_side(Side s, std::uint64_t levels) noexcept {
    h_ = combine(h_, static_cast<std::uint64_t>(static_cast<unsigned char>(s)));
    h_ = combine(h_, levels);
  }
  constexpr void level(PxE4 px, std::uint64_t orders, std::uint64_t shares) noexcept {
    h_ = combine(h_, static_cast<std::uint64_t>(px));
    h_ = combine(h_, orders);
    h_ = combine(h_, shares);
  }
  constexpr void order(OrderRef ref, Qty qty) noexcept {
    h_ = combine(h_, ref);
    h_ = combine(h_, qty);
  }
  [[nodiscard]] constexpr std::uint64_t finish(std::uint64_t live_orders) const noexcept {
    return combine(h_, live_orders);
  }

 private:
  std::uint64_t h_ = kBooksDigestSeed;
};

}  // namespace lle::book

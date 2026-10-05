#pragma once
// Per-locate level book: both sides plus the cached BBO (04-order-book §3).
//
// The order index and order records are not here: ITCH refs are day-unique
// across all symbols, so the book builder keeps one global index and this
// structure holds only levels. The matching engine composes the same pieces.
//
// With kNegateAsks the ask side stores -px, so both sides are the same
// container type with one comparator (X11) and side dispatch is an index.
#include <array>
#include <cstddef>
#include <string>
#include <type_traits>

#include "lob/levels.h"
#include "lob/types.h"

namespace lle::lob {

template <class LevelsPolicy, class Level, bool kNegateAsks>
class LevelBook {
 public:
  using BidSide = typename LevelsPolicy::template Side<Level, Higher>;
  using AskSide = typename LevelsPolicy::template Side<Level, std::conditional_t<kNegateAsks, Higher, Lower>>;

  LevelBook() = default;
  LevelBook(const LevelBook&) = delete;  // levels are pointed at by orders
  LevelBook& operator=(const LevelBook&) = delete;
  LevelBook(LevelBook&&) noexcept = default;
  LevelBook& operator=(LevelBook&&) noexcept = default;

  // Container key for a price on a side.
  [[nodiscard]] static constexpr PxE4 key(Side s, PxE4 px) noexcept {
    if constexpr (kNegateAsks) {
      return s == Side::Sell ? -px : px;
    } else {
      return px;
    }
  }

  template <class Pool>
  Level* find_or_insert(Side s, PxE4 px, Pool& pool, bool& created) {
    Level* lv = with_side(s, [&](auto& side) { return side.find_or_insert(key(s, px), pool, created); });
    if (created) lv->px = px;
    return lv;
  }

  [[nodiscard]] Level* find(Side s, PxE4 px) const noexcept {
    return with_side(s, [&](const auto& side) { return side.find(key(s, px)); });
  }

  // Removes an empty level.
  template <class Pool>
  void erase(Side s, Level* lv, Pool& pool) noexcept {
    with_side(s, [&](auto& side) { side.erase(key(s, lv->px), lv, pool); });
  }

  [[nodiscard]] Level* best(Side s) const noexcept {
    return with_side(s, [](const auto& side) { return side.best(); });
  }

  // Recomputes the cached top of one side from its best level (price and
  // class-0 quantity). Returns true when the cached BBO changed.
  bool refresh(Side s) noexcept {
    const Level* b = best(s);
    const BboSide n = b != nullptr ? BboSide{b->px, b->qty[0]} : BboSide{};
    BboSide& c = s == Side::Buy ? bbo_.bid : bbo_.ask;
    if (n == c) return false;
    c = n;
    return true;
  }

  [[nodiscard]] const Bbo& bbo() const noexcept { return bbo_; }

  // f(const Level&) from the best price to the worst.
  template <class F>
  void for_each_level(Side s, F&& f) const {
    with_side(s, [&](const auto& side) { side.for_each([&](PxE4, const Level& lv) { f(lv); }); });
  }

  [[nodiscard]] std::size_t levels(Side s) const noexcept {
    return with_side(s, [](const auto& side) { return side.size(); });
  }
  [[nodiscard]] bool empty() const noexcept { return levels(Side::Buy) == 0 && levels(Side::Sell) == 0; }

  void reserve(std::size_t per_side) {
    with_side(Side::Buy, [&](auto& side) { side.reserve(per_side); });
    with_side(Side::Sell, [&](auto& side) { side.reserve(per_side); });
  }

  template <class Pool>
  void clear(Pool& pool) noexcept {
    with_side(Side::Buy, [&](auto& side) { side.clear(pool); });
    with_side(Side::Sell, [&](auto& side) { side.clear(pool); });
    bbo_ = Bbo{};
  }

  // Container invariants, keys consistent with level prices, strictly
  // improving order by real price, non-empty levels, cached BBO correct.
  [[nodiscard]] bool check(std::string* err) const {
    auto fail = [&](const char* m) {
      if (err) *err = m;
      return false;
    };
    for (Side s : {Side::Buy, Side::Sell}) {
      bool ok = with_side(s, [&](const auto& side) { return side.check(err); });
      if (!ok) return false;
      bool first = true;
      PxE4 prev = 0;
      bool bad_key = false, bad_order = false, empty_level = false;
      with_side(s, [&](const auto& side) {
        side.for_each([&](PxE4 k, const Level& lv) {
          if (k != key(s, lv.px)) bad_key = true;
          if (lv.count == 0) empty_level = true;
          if (!first) {
            const bool improving = s == Side::Buy ? lv.px < prev : lv.px > prev;
            if (!improving) bad_order = true;
          }
          first = false;
          prev = lv.px;
        });
      });
      if (bad_key) return fail("level book: container key != key(level price)");
      if (bad_order) return fail("level book: levels not strictly ordered best to worst");
      if (empty_level) return fail("level book: empty level not erased");
      const Level* b = best(s);
      const BboSide want = b != nullptr ? BboSide{b->px, b->qty[0]} : BboSide{};
      const BboSide& have = s == Side::Buy ? bbo_.bid : bbo_.ask;
      if (want != have) return fail("level book: cached BBO stale");
    }
    return true;
  }

  // Direct side access (tests, diagnostics).
  [[nodiscard]] const BidSide& bids() const noexcept { return side0(); }
  [[nodiscard]] const AskSide& asks() const noexcept { return side1(); }

 private:
  template <class F>
  decltype(auto) with_side(Side s, F&& f) {
    if constexpr (kNegateAsks) {
      return f(sides_[s == Side::Sell ? 1 : 0]);
    } else {
      return s == Side::Buy ? f(bids_) : f(asks_);
    }
  }
  template <class F>
  decltype(auto) with_side(Side s, F&& f) const {
    if constexpr (kNegateAsks) {
      return f(sides_[s == Side::Sell ? 1 : 0]);
    } else {
      return s == Side::Buy ? f(bids_) : f(asks_);
    }
  }
  [[nodiscard]] const BidSide& side0() const noexcept {
    if constexpr (kNegateAsks) {
      return sides_[0];
    } else {
      return bids_;
    }
  }
  [[nodiscard]] const AskSide& side1() const noexcept {
    if constexpr (kNegateAsks) {
      return sides_[1];
    } else {
      return asks_;
    }
  }

  Bbo bbo_{};  // first member: the header line holds the cached top of book
  // Negated asks: both sides share one type and are indexed by side.
  // Otherwise bids and asks are distinct container types.
  struct Empty {};
  [[no_unique_address]] std::conditional_t<kNegateAsks, std::array<BidSide, 2>, Empty> sides_{};
  [[no_unique_address]] std::conditional_t<kNegateAsks, Empty, BidSide> bids_{};
  [[no_unique_address]] std::conditional_t<kNegateAsks, Empty, AskSide> asks_{};
};

}  // namespace lle::lob

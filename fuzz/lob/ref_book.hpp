#pragma once
// RefBook: the obviously-correct reference book for differential fuzzing of
// the ITCH book builder (04-order-book §8, R4b §5.1).
//
// Deliberately simple and slow: std::map levels (bids std::greater, asks
// std::less), a std::list queue per level, and an unordered_map from ref to
// position used only for lookup, never iterated. Events are applied BY
// REFERENCE (never matched at the queue front). It shares no code with
// src/lob or src/book: only common/types.h and lle::combine, which the digest
// definition in src/book/digest.h is written in terms of.
//
// Semantics (the same rules book::ItchBook documents):
//   add      qty == 0 -> BadQty; px outside [0, 2^32-1] -> BadPrice;
//            side not B/S -> BadSide; ref live -> DuplicateRef; else append.
//   reduce   qty == 0 -> BadQty; unknown -> UnknownRef; qty < open shares ->
//            shares decrease in place; qty == open -> removed; qty > open ->
//            removed and OverReduce.
//   remove   unknown -> UnknownRef; else removed.
//   replace  qty == 0 -> BadQty; bad px -> BadPrice; old unknown ->
//            UnknownRef; new != old and new live -> DuplicateRef; else old
//            removed and new appended at px with the old side and locate.
// Every rejected operation leaves the book unchanged.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <list>
#include <map>
#include <string>
#include <unordered_map>

#include "common/hash.h"
#include "common/types.h"

namespace lle::lobfuzz {

enum class RefResult : int {
  kOk = 0,
  kUnknownRef = 1,
  kDuplicateRef = 2,
  kBadQty = 3,
  kBadPrice = 4,
  kBadSide = 5,
  kOverReduce = 6,
};

struct RefTop {
  PxE4 bid_px = 0;
  std::uint64_t bid_qty = 0;
  PxE4 ask_px = 0;
  std::uint64_t ask_qty = 0;
  bool operator==(const RefTop&) const = default;
};

class RefBook {
 public:
  void declare(Locate) { begin_op(); }  // no observable effect on any book

  RefResult add(OrderRef ref, Locate loc, Side side, PxE4 px, Qty qty) {
    begin_op();
    if (qty == 0) return RefResult::kBadQty;
    if (px < 0 || px > kMaxPx) return RefResult::kBadPrice;
    if (side != Side::Buy && side != Side::Sell) return RefResult::kBadSide;
    if (orders_.find(ref) != orders_.end()) return RefResult::kDuplicateRef;
    const RefTop before = top(loc);
    put(ref, loc, side, px, qty);
    finish_op(loc, before);
    return RefResult::kOk;
  }

  RefResult reduce(OrderRef ref, Qty qty) {
    begin_op();
    if (qty == 0) return RefResult::kBadQty;
    auto it = orders_.find(ref);
    if (it == orders_.end()) return RefResult::kUnknownRef;
    const Locate loc = it->second.loc;
    const RefTop before = top(loc);
    RefResult result = RefResult::kOk;
    Resting& r = *it->second.pos;
    if (qty < r.qty) {
      r.qty -= qty;
      level_of(it->second).shares -= qty;
    } else {
      if (qty > r.qty) result = RefResult::kOverReduce;
      take(it);
    }
    finish_op(loc, before);
    return result;
  }

  RefResult remove(OrderRef ref) {
    begin_op();
    auto it = orders_.find(ref);
    if (it == orders_.end()) return RefResult::kUnknownRef;
    const Locate loc = it->second.loc;
    const RefTop before = top(loc);
    take(it);
    finish_op(loc, before);
    return RefResult::kOk;
  }

  RefResult replace(OrderRef old_ref, OrderRef new_ref, PxE4 px, Qty qty) {
    begin_op();
    if (qty == 0) return RefResult::kBadQty;
    if (px < 0 || px > kMaxPx) return RefResult::kBadPrice;
    auto it = orders_.find(old_ref);
    if (it == orders_.end()) return RefResult::kUnknownRef;
    if (new_ref != old_ref && orders_.find(new_ref) != orders_.end()) return RefResult::kDuplicateRef;
    const Locate loc = it->second.loc;
    const Side side = it->second.side;
    const RefTop before = top(loc);
    take(it);
    put(new_ref, loc, side, px, qty);
    finish_op(loc, before);
    return RefResult::kOk;
  }

  // --- per-operation event (valid after each call) ---------------------------
  [[nodiscard]] bool event_fired() const { return fired_; }
  [[nodiscard]] Locate event_locate() const { return ev_loc_; }
  [[nodiscard]] const RefTop& event_top() const { return ev_top_; }
  [[nodiscard]] std::uint64_t event_digest() const { return digest_; }
  [[nodiscard]] std::uint64_t event_count() const { return events_; }

  // --- state -------------------------------------------------------------------
  [[nodiscard]] RefTop top(Locate loc) const {
    RefTop t;
    auto b = books_.find(loc);
    if (b == books_.end()) return t;
    if (!b->second.bids.empty()) {
      t.bid_px = b->second.bids.begin()->first;
      t.bid_qty = b->second.bids.begin()->second.shares;
    }
    if (!b->second.asks.empty()) {
      t.ask_px = b->second.asks.begin()->first;
      t.ask_qty = b->second.asks.begin()->second.shares;
    }
    return t;
  }

  [[nodiscard]] std::size_t live() const { return orders_.size(); }

  // Final-books digest, computed from the definition in src/book/digest.h.
  [[nodiscard]] std::uint64_t books_digest() const {
    std::uint64_t h = kBooksSeed;
    for (const auto& [loc, b] : books_) {
      if (b.bids.empty() && b.asks.empty()) continue;
      h = combine(h, loc);
      h = side_digest(h, 'B', b.bids);
      h = side_digest(h, 'S', b.asks);
    }
    return combine(h, orders_.size());
  }

  // Shares totals, no empty levels, and the ref index agreeing both ways.
  [[nodiscard]] bool check(std::string* err) const {
    std::size_t n = 0;
    for (const auto& [loc, b] : books_) {
      if (!check_side(loc, Side::Buy, b.bids, n, err)) return false;
      if (!check_side(loc, Side::Sell, b.asks, n, err)) return false;
    }
    if (n != orders_.size()) {
      if (err) *err = "ref: resting orders != index size";
      return false;
    }
    return true;
  }

 private:
  static constexpr PxE4 kMaxPx = 0xFFFF'FFFFll;
  static constexpr std::uint64_t kBboSeed = 0x6C6F'622D'6262'6F31ull;    // "lob-bbo1"
  static constexpr std::uint64_t kBooksSeed = 0x6C6F'622D'626B'7331ull;  // "lob-bks1"

  struct Resting {
    OrderRef ref;
    Qty qty;
  };
  struct PriceLevel {
    std::list<Resting> queue;
    std::uint64_t shares = 0;
  };
  using Bids = std::map<PxE4, PriceLevel, std::greater<PxE4>>;
  using Asks = std::map<PxE4, PriceLevel, std::less<PxE4>>;
  struct SymbolBook {
    Bids bids;
    Asks asks;
  };
  struct Where {
    Locate loc;
    Side side;
    PxE4 px;
    std::list<Resting>::iterator pos;
  };

  void begin_op() { fired_ = false; }

  void finish_op(Locate loc, const RefTop& before) {
    const RefTop after = top(loc);
    if (after == before) return;
    fired_ = true;
    ev_loc_ = loc;
    ev_top_ = after;
    ++events_;
    digest_ = combine(digest_, loc);
    digest_ = combine(digest_, static_cast<std::uint64_t>(after.bid_px));
    digest_ = combine(digest_, after.bid_qty);
    digest_ = combine(digest_, static_cast<std::uint64_t>(after.ask_px));
    digest_ = combine(digest_, after.ask_qty);
  }

  void put(OrderRef ref, Locate loc, Side side, PxE4 px, Qty qty) {
    SymbolBook& b = books_[loc];
    PriceLevel& lvl = side == Side::Buy ? b.bids[px] : b.asks[px];
    lvl.queue.push_back(Resting{ref, qty});
    lvl.shares += qty;
    orders_[ref] = Where{loc, side, px, std::prev(lvl.queue.end())};
  }

  PriceLevel& level_of(const Where& w) {
    SymbolBook& b = books_.at(w.loc);
    return w.side == Side::Buy ? b.bids.at(w.px) : b.asks.at(w.px);
  }

  void take(std::unordered_map<OrderRef, Where>::iterator it) {
    const Where w = it->second;
    SymbolBook& b = books_.at(w.loc);
    if (w.side == Side::Buy) {
      drop(b.bids, w);
    } else {
      drop(b.asks, w);
    }
    orders_.erase(it);
  }

  template <class M>
  static void drop(M& m, const Where& w) {
    auto lvl = m.find(w.px);
    lvl->second.shares -= w.pos->qty;
    lvl->second.queue.erase(w.pos);
    if (lvl->second.queue.empty()) m.erase(lvl);
  }

  template <class M>
  static std::uint64_t side_digest(std::uint64_t h, char side, const M& m) {
    h = combine(h, static_cast<std::uint64_t>(static_cast<unsigned char>(side)));
    h = combine(h, m.size());
    for (const auto& [px, lvl] : m) {
      h = combine(h, static_cast<std::uint64_t>(px));
      h = combine(h, lvl.queue.size());
      h = combine(h, lvl.shares);
      for (const Resting& r : lvl.queue) {
        h = combine(h, r.ref);
        h = combine(h, r.qty);
      }
    }
    return h;
  }

  template <class M>
  bool check_side(Locate loc, Side side, const M& m, std::size_t& n, std::string* err) const {
    for (const auto& [px, lvl] : m) {
      if (lvl.queue.empty()) {
        if (err) *err = "ref: empty level kept";
        return false;
      }
      std::uint64_t sum = 0;
      for (auto it = lvl.queue.begin(); it != lvl.queue.end(); ++it) {
        sum += it->qty;
        ++n;
        auto w = orders_.find(it->ref);
        if (w == orders_.end() || w->second.loc != loc || w->second.side != side || w->second.px != px ||
            &*w->second.pos != &*it) {
          if (err) *err = "ref: index entry disagrees with resting order";
          return false;
        }
      }
      if (sum != lvl.shares) {
        if (err) *err = "ref: level shares != sum of orders";
        return false;
      }
    }
    return true;
  }

  std::map<Locate, SymbolBook> books_;
  std::unordered_map<OrderRef, Where> orders_;
  bool fired_ = false;
  Locate ev_loc_ = 0;
  RefTop ev_top_{};
  std::uint64_t digest_ = kBboSeed;
  std::uint64_t events_ = 0;
};

}  // namespace lle::lobfuzz

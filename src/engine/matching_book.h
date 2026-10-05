#pragma once
// Matching book (05-matching-engine §2, E-01): one lob::LevelBook per stock
// locate on the shared LOB core (04-order-book §3), with two FIFO queue
// classes per price level (displayed, then non-displayed: Rule 4757(a)(1)),
// sorted-vector levels from a slab pool, negated asks, and order records in a
// slab pool threaded through the intrusive FIFOs. Everything is pre-sized at
// reset(); in the steady state nothing allocates unless a pool or a side's
// level vector outgrows its reserve.
#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "common/assert.h"
#include "engine/order.h"
#include "lob/fifo.h"
#include "lob/level_book.h"
#include "lob/levels.h"
#include "lob/slab_pool.h"

namespace lle::engine {

struct BookConfig {
  std::size_t reserve_orders = std::size_t{1} << 16;  // order pool
  std::size_t reserve_levels = std::size_t{1} << 14;  // level pool (all books)
  std::size_t levels_per_side = 32;                   // per-book level-vector reserve
};

class MatchingBook {
 public:
  using Level = BookLevel;
  using Book = lob::LevelBook<lob::VecLevels, Level, /*kNegateAsks=*/true>;
  using LevelPool = lob::SlabPool<Level>;
  using OrderPool = lob::SlabPool<Order>;
  using Fifo = lob::IntrusiveFifo;

  explicit MatchingBook(const BookConfig& c = {}) : cfg_(c) { reset(0); }
  MatchingBook(const MatchingBook&) = delete;
  MatchingBook& operator=(const MatchingBook&) = delete;

  // Hot per-order links, apart from the cold record: the level FIFO (what
  // IntrusiveFifo reaches as `rec(h).link`) and the account live list.
  struct Links {
    lob::IntrusiveFifo::Link<Handle> link{};
    Handle acct_prev = kNil;
    Handle acct_next = kNil;
  };

  // Drops every order and level; books exist for locates 1..symbols (cold path).
  void reset(std::size_t symbols) {
    books_.clear();
    levels_ = std::make_unique<LevelPool>(cfg_.reserve_levels);
    orders_ = std::make_unique<OrderPool>(cfg_.reserve_orders);
    links_.assign(cfg_.reserve_orders, Links{});
    books_.reserve(symbols + 1);
    for (std::size_t i = 0; i <= symbols; ++i) {
      books_.emplace_back();
      if (i != 0) books_.back().reserve(cfg_.levels_per_side);
    }
  }

  [[nodiscard]] std::size_t symbols() const noexcept { return books_.empty() ? 0 : books_.size() - 1; }

  // ---- order records
  [[nodiscard]] Handle alloc() {
    const Handle h = orders_->alloc();
    if (h >= links_.size()) [[unlikely]]
      links_.resize(std::max<std::size_t>(std::size_t{h} + 1, links_.size() * 2));
    links_[h] = Links{};
    return h;
  }
  void free(Handle h) noexcept { orders_->free(h); }
  [[nodiscard]] Order& at(Handle h) noexcept { return (*orders_)[h]; }
  [[nodiscard]] const Order& at(Handle h) const noexcept { return (*orders_)[h]; }
  [[nodiscard]] std::size_t live_orders() const noexcept { return orders_->live(); }
  [[nodiscard]] std::size_t order_slabs() const noexcept { return orders_->slab_count(); }
  [[nodiscard]] std::size_t level_slabs() const noexcept { return levels_->slab_count(); }

  // ---- book operations
  // Appends the order (px, side, locate, display, leaves set) to the back of
  // its queue class at its price, creating the level if needed.
  void insert(Handle h) {
    Order& o = at(h);
    Book& b = books_[o.locate];
    bool created = false;
    Level* lv = b.find_or_insert(o.side, o.px, *levels_, created);
    Store st{&links_};
    const int c = o.cls();
    Fifo::push_back(st, lv->q[c], h);
    lv->qty[c] += o.leaves;
    ++lv->count;
    o.level = lv;
    if (lv == b.best(o.side)) b.refresh(o.side);  // the cached top changes only at the best level
  }

  // As insert(), but placed by its time priority (prio) among the orders of its
  // queue class: orders held for the opening cross join the book with the
  // timestamps they were accepted with (R2 D1.2). FIFOs stay sorted by prio.
  void insert_by_prio(Handle h) {
    Order& o = at(h);
    Book& b = books_[o.locate];
    bool created = false;
    Level* lv = b.find_or_insert(o.side, o.px, *levels_, created);
    const int c = o.cls();
    BookQueue& q = lv->q[c];
    Handle after = q.tail;
    while (after != kNil && at(after).prio > o.prio) after = links_[after].link.prev;
    Links& k = links_[h];
    k.link.prev = after;
    k.link.next = after == kNil ? q.head : links_[after].link.next;
    if (k.link.next != kNil) {
      links_[k.link.next].link.prev = h;
    } else {
      q.tail = h;
    }
    if (after != kNil) {
      links_[after].link.next = h;
    } else {
      q.head = h;
    }
    lv->qty[c] += o.leaves;
    ++lv->count;
    o.level = lv;
    if (lv == b.best(o.side)) b.refresh(o.side);
  }

  // Removes the order from its level (erasing the level when it empties). The
  // record itself stays allocated.
  void unlink(Handle h) noexcept {
    Order& o = at(h);
    Book& b = books_[o.locate];
    Level* lv = o.level;
    Store st{&links_};
    const int c = o.cls();
    Fifo::unlink(st, lv->q[c], h);
    lv->qty[c] -= o.leaves;
    --lv->count;
    o.level = nullptr;
    const bool top = lv == b.best(o.side);
    if (lv->count == 0) b.erase(o.side, lv, *levels_);
    if (top) b.refresh(o.side);
  }

  // Takes d shares out of a resting order; it keeps its place in the queue.
  void reduce(Handle h, Qty d) noexcept {
    Order& o = at(h);
    LLE_DASSERT(d <= o.leaves);
    o.leaves -= d;
    o.level->qty[o.cls()] -= d;
    if (o.level == books_[o.locate].best(o.side)) books_[o.locate].refresh(o.side);
  }

  [[nodiscard]] Level* best(Locate l, Side s) const noexcept { return books_[l].best(s); }
  // Best price with displayed shares (the BBO as quoted, NBBO := own BBO); 0 if none.
  [[nodiscard]] PxE4 displayed_best(Locate l, Side s) const noexcept {
    const std::size_t n = level_count(l, s);
    for (std::size_t k = 0; k < n; ++k) {
      const Level* lv = level_at_rank(l, s, k);
      if (lv->qty[kDisplayed] > 0) return lv->px;
    }
    return 0;
  }
  [[nodiscard]] std::size_t level_count(Locate l, Side s) const noexcept { return books_[l].levels(s); }
  // rank 0 = best price. Both sides are sorted vectors with the best at the back.
  [[nodiscard]] Level* level_at_rank(Locate l, Side s, std::size_t rank) const noexcept {
    const Book& b = books_[l];
    if (s == Side::Buy) return b.bids().level_at(b.bids().size() - 1 - rank);
    return b.asks().level_at(b.asks().size() - 1 - rank);
  }
  [[nodiscard]] Handle front(const Level& lv, int cls) const noexcept { return lv.q[cls].head; }
  [[nodiscard]] Handle next(Handle h) const noexcept { return links_[h].link.next; }
  [[nodiscard]] Links& links(Handle h) noexcept { return links_[h]; }
  [[nodiscard]] const Links& links(Handle h) const noexcept { return links_[h]; }
  [[nodiscard]] const Book& book(Locate l) const noexcept { return books_[l]; }

  // f(const Level&) best to worst.
  template <class F>
  void for_each_level(Locate l, Side s, F&& f) const {
    books_[l].for_each_level(s, f);
  }
  // f(Handle) in priority order within one queue class of a level.
  template <class F>
  void for_each_in(const Level& lv, int cls, F&& f) const {
    for (Handle h = lv.q[cls].head; h != kNil; h = next(h)) f(h);
  }

  // Level containers, FIFO links, per-class totals and counts, back-pointers;
  // `book_orders` must equal the number of orders resting in levels.
  [[nodiscard]] bool check(std::string* err, std::size_t book_orders) const {
    const ConstStore st{&links_};
    std::size_t total = 0;
    for (std::size_t l = 1; l < books_.size(); ++l) {
      const Book& b = books_[l];
      if (!b.check(err)) return false;
      for (Side s : {Side::Buy, Side::Sell}) {
        bool ok = true;
        b.for_each_level(s, [&](const Level& lv) {
          if (!ok) return;
          std::uint32_t n = 0;
          for (int c = 0; c < 2; ++c) {
            std::size_t cnt = 0;
            std::uint64_t q = 0;
            for (Handle h = lv.q[c].head; h != kNil; h = next(h)) {
              const Order& o = at(h);
              if (o.level != &lv || o.px != lv.px || o.side != s || o.locate != l || o.cls() != c || o.leaves == 0 ||
                  o.where != Where::Book) {
                ok = false;
                if (err) *err = "matching book: order fields disagree with its level";
                return;
              }
              ++cnt;
              q += o.leaves;
            }
            if (!Fifo::check(st, lv.q[c], cnt, err)) {
              ok = false;
              return;
            }
            if (q != lv.qty[c]) {
              ok = false;
              if (err) *err = "matching book: level class total != sum of leaves";
              return;
            }
            n += static_cast<std::uint32_t>(cnt);
          }
          if (n != lv.count) {
            ok = false;
            if (err) *err = "matching book: level count != orders";
            return;
          }
          total += n;
        });
        if (!ok) return false;
      }
    }
    if (total != book_orders) {
      if (err) *err = "matching book: resting orders != orders on the book";
      return false;
    }
    return true;
  }

 private:
  // What IntrusiveFifo needs from a store: `rec(h).link`.
  struct Store {
    std::vector<Links>* l;
    [[nodiscard]] Links& rec(Handle h) const noexcept { return (*l)[h]; }
  };
  struct ConstStore {
    const std::vector<Links>* l;
    [[nodiscard]] const Links& rec(Handle h) const noexcept { return (*l)[h]; }
  };

  BookConfig cfg_;
  std::unique_ptr<LevelPool> levels_;
  std::unique_ptr<OrderPool> orders_;
  std::vector<Links> links_;  // index = order handle
  std::vector<Book> books_;   // index = locate; [0] unused
};

}  // namespace lle::engine

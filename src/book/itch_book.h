#pragma once
// ITCH-semantics L3 book builder (04-order-book §1-§4; R1a Q6).
//
// Events are applied BY REFERENCE, exactly as the feed reports them:
//
//   add(ref, locate, side, px, qty)        A, F   new order at the back of its level's FIFO
//   reduce(ref, qty)                       E, C, X shares leave the order; it keeps its
//                                          priority; removed when it reaches 0
//   remove(ref)                            D
//   replace(old_ref, new_ref, px, qty)     U      old order removed; new order (same side and
//                                          locate) at the back of the FIFO at px: new priority
//   stock_directory(locate)                R      declares the locate; a duplicate R (sent
//                                          once a day with identical bytes) changes nothing
//
// Executions are never inferred from queue position (R1a Q6 pitfall 2), and
// crossed or locked books are legal (pitfall 1): nothing asserts bid < ask.
// Refs are 64-bit (pitfall 6); prices cover the full ITCH Price(4) range,
// including $199,999.99 and sub-penny stubs (pitfall 8).
//
// Inputs a real feed never sends are rejected without changing state, or
// (over-reduce) applied as a full removal, and reported by Status; the
// reference book (fuzz/lob/ref_book.hpp) implements the same rules.
//
// One global order store (refs are day-unique across symbols) and one
// lob::LevelBook per locate in a vector indexed by locate ("a low lying
// integer... serving as an array index"). Each operation that changes a
// locate's best bid or offer (price or aggregate shares) emits exactly one
// on_bbo_change(locate, bbo) to the Listener.
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "book/digest.h"
#include "book/listener.h"
#include "common/types.h"
#include "lob/arena.h"
#include "lob/level.h"
#include "lob/level_book.h"
#include "lob/slab_pool.h"
#include "lob/store.h"
#include "lob/types.h"

namespace lle::book {

enum class Status : std::uint8_t {
  kOk = 0,
  kUnknownRef,    // no live order has this ref; nothing changed
  kDuplicateRef,  // add/replace onto a live ref; nothing changed
  kBadQty,        // zero shares; nothing changed
  kBadPrice,      // price outside [0, 2^32-1]; nothing changed
  kBadSide,       // side is neither 'B' nor 'S'; nothing changed
  kOverReduce,    // reduce by more than the open shares; the order was removed
};

[[nodiscard]] constexpr const char* to_string(Status s) noexcept {
  switch (s) {
    case Status::kOk: return "ok";
    case Status::kUnknownRef: return "unknown_ref";
    case Status::kDuplicateRef: return "duplicate_ref";
    case Status::kBadQty: return "bad_qty";
    case Status::kBadPrice: return "bad_price";
    case Status::kBadSide: return "bad_side";
    case Status::kOverReduce: return "over_reduce";
  }
  return "?";
}

struct BookConfig {
  std::size_t reserve_orders = 1 << 16;       // order records and index, pre-sized
  std::size_t reserve_levels = 1 << 12;       // level pool (pooled level containers)
  std::size_t levels_per_side = 0;            // per-book level reserve at stock_directory (X27)
  std::uint64_t max_direct_ref = 1ull << 32;  // PagedIndex direct range
  bool prefault = false;                      // touch pooled memory at construction (X13)
};

// Policy bundle. See variants.h for the named combinations.
template <class LevelsT, class FifoT, class StoreT, class LevelBackingT = lob::HeapBacking, bool kNegate = false>
struct Policies {
  using Levels = LevelsT;              // lob::MapLevels | VecLevels | WindowLevels<bits>
  using Fifo = FifoT;                  // lob::ListFifo | IntrusiveFifo
  using Store = StoreT;                // lob::StdStore | PoolStore<Index, Backing>
  using LevelBacking = LevelBackingT;  // memory for pooled levels
  static constexpr bool kNegateAsks = kNegate;
};

template <class P>
struct Order;

template <class P>
struct OrderTypes {
  using Handle = typename P::Store::template handle<Order<P>>;
  using Queue = typename P::Fifo::template Queue<Handle>;
  using Link = typename P::Fifo::template Link<Handle>;
  using Level = lob::Level<Queue, 1>;  // ITCH shows displayed orders only
};

// The order record: 32 bytes with pooled handles (X09).
template <class P>
struct Order {
  OrderRef ref;
  typename OrderTypes<P>::Level* level;
  typename OrderTypes<P>::Link link;
  Qty qty;
  Locate locate;
  Side side;
};

// What an ITCH adapter needs from a book (see README.md).
template <class B>
concept ItchEventSink = requires(B b, OrderRef r, Locate l, Side s, PxE4 p, Qty q) {
  b.stock_directory(l);
  { b.add(r, l, s, p, q) } -> std::same_as<Status>;
  { b.reduce(r, q) } -> std::same_as<Status>;
  { b.remove(r) } -> std::same_as<Status>;
  { b.replace(r, r, p, q) } -> std::same_as<Status>;
};

template <class P, class Listener = NullListener>
class ItchBook {
 public:
  using Policy = P;
  using OrderT = Order<P>;
  using Handle = typename OrderTypes<P>::Handle;
  using Level = typename OrderTypes<P>::Level;
  using Fifo = typename P::Fifo;
  using Store = typename P::Store::template Impl<OrderT>;
  using LevelPool =
      std::conditional_t<P::Levels::kPooled, lob::SlabPool<Level, typename P::LevelBacking>, lob::NoPool>;
  using LBook = lob::LevelBook<typename P::Levels, Level, P::kNegateAsks>;
  static constexpr Handle kNil = Store::kNil;
  static constexpr std::size_t kMaxLocates = std::size_t{1} << 16;  // Locate is u16

  struct OrderView {
    OrderRef ref;
    Locate locate;
    Side side;
    PxE4 px;
    Qty qty;
  };

  explicit ItchBook(const BookConfig& cfg = {}, Listener listener = Listener{})
      : cfg_(cfg), store_(store_config(cfg)), level_pool_(cfg.reserve_levels, cfg.prefault), listener_(std::move(listener)) {
    // Reserved once so books never move: no reallocation when a locate is
    // declared mid-day, and LevelBook addresses stay stable.
    books_.reserve(kMaxLocates);
  }
  ItchBook(const ItchBook&) = delete;
  ItchBook& operator=(const ItchBook&) = delete;
  ~ItchBook() {
    for (LBook& b : books_) b.clear(level_pool_);
  }

  // Lookahead hint: starts loading the index slot for `ref` (lob_replay
  // --prefetch). A no-op for stores without an index to prefetch (B0).
  void prefetch(OrderRef ref) const noexcept {
    if constexpr (requires(const Store& s) { s.prefetch(ref); }) store_.prefetch(ref);
  }

  // R: declare a locate. Idempotent, so the duplicate R changes nothing.
  void stock_directory(Locate loc) {
    LBook& b = book(loc);
    if (cfg_.levels_per_side != 0) b.reserve(cfg_.levels_per_side);
  }

  // A / F. An add on an undeclared locate declares it.
  Status add(OrderRef ref, Locate loc, Side s, PxE4 px, Qty q) {
    if (q == 0) [[unlikely]]
      return Status::kBadQty;
    if (!lob::valid_book_px(px)) [[unlikely]]
      return Status::kBadPrice;
    if (s != Side::Buy && s != Side::Sell) [[unlikely]]
      return Status::kBadSide;
    const Handle h = store_.emplace(ref);
    if (h == kNil) [[unlikely]]
      return Status::kDuplicateRef;
    LBook& b = book(loc);
    link(h, ref, loc, s, px, q, b);
    publish(b, loc, s);
    return Status::kOk;
  }

  // E / C / X: by reference, priority kept; removed when no shares remain.
  Status reduce(OrderRef ref, Qty q) {
    if (q == 0) [[unlikely]]
      return Status::kBadQty;
    const Handle h = store_.find(ref);
    if (h == kNil) [[unlikely]]
      return Status::kUnknownRef;
    OrderT& o = store_.rec(h);
    const Locate loc = o.locate;
    const Side s = o.side;
    LBook& b = books_[loc];
    Status st = Status::kOk;
    if (q < o.qty) [[likely]] {
      o.qty -= q;
      o.level->qty[0] -= q;
    } else {
      if (q > o.qty) st = Status::kOverReduce;
      unlink(h, o, b);
    }
    publish(b, loc, s);
    return st;
  }

  // D.
  Status remove(OrderRef ref) {
    const Handle h = store_.find(ref);
    if (h == kNil) [[unlikely]]
      return Status::kUnknownRef;
    OrderT& o = store_.rec(h);
    const Locate loc = o.locate;
    const Side s = o.side;
    LBook& b = books_[loc];
    unlink(h, o, b);
    publish(b, loc, s);
    return Status::kOk;
  }

  // U: remove old_ref, add new_ref with the old side and locate at the back
  // of the FIFO at px. Atomic: on any rejection nothing changes.
  Status replace(OrderRef old_ref, OrderRef new_ref, PxE4 px, Qty q) {
    if (q == 0) [[unlikely]]
      return Status::kBadQty;
    if (!lob::valid_book_px(px)) [[unlikely]]
      return Status::kBadPrice;
    const Handle h = store_.find(old_ref);
    if (h == kNil) [[unlikely]]
      return Status::kUnknownRef;
    Handle nh = kNil;
    if (new_ref != old_ref) [[likely]] {
      nh = store_.emplace(new_ref);  // record handles stay valid across emplace
      if (nh == kNil) [[unlikely]]
        return Status::kDuplicateRef;
    }
    OrderT& o = store_.rec(h);
    const Locate loc = o.locate;
    const Side s = o.side;
    LBook& b = books_[loc];
    unlink(h, o, b);
    if (new_ref == old_ref) [[unlikely]]
      nh = store_.emplace(new_ref);  // cannot fail: the ref was just released
    link(nh, new_ref, loc, s, px, q, b);
    publish(b, loc, s);
    return Status::kOk;
  }

  // --- queries --------------------------------------------------------------
  [[nodiscard]] lob::Bbo bbo(Locate loc) const noexcept {
    return loc < books_.size() ? books_[loc].bbo() : lob::Bbo{};
  }
  [[nodiscard]] std::size_t live_orders() const noexcept { return store_.size(); }
  [[nodiscard]] std::size_t locates() const noexcept { return books_.size(); }
  [[nodiscard]] const LBook* level_book(Locate loc) const noexcept {
    return loc < books_.size() ? &books_[loc] : nullptr;
  }

  [[nodiscard]] std::optional<OrderView> find_order(OrderRef ref) const {
    const Handle h = store_.find(ref);
    if (h == kNil) return std::nullopt;
    const OrderT& o = store_.rec(h);
    return OrderView{o.ref, o.locate, o.side, o.level->px, o.qty};
  }

  // f(px, total shares, order count) from the best price to the worst.
  template <class F>
  void for_each_level(Locate loc, Side s, F&& f) const {
    if (loc >= books_.size()) return;
    books_[loc].for_each_level(s, [&](const Level& lv) { f(lv.px, lv.qty[0], lv.count); });
  }

  // f(px, ref, shares) in priority order: best price first, FIFO within it.
  template <class F>
  void for_each_order(Locate loc, Side s, F&& f) const {
    if (loc >= books_.size()) return;
    books_[loc].for_each_level(s, [&](const Level& lv) {
      Fifo::for_each(store_, lv.q[0], [&](Handle h) {
        const OrderT& o = store_.rec(h);
        f(lv.px, o.ref, o.qty);
      });
    });
  }

  // Final-books digest (definition in digest.h).
  [[nodiscard]] std::uint64_t books_digest() const {
    BooksDigest d;
    for (std::size_t i = 0; i < books_.size(); ++i) {
      const LBook& b = books_[i];
      if (b.empty()) continue;
      d.begin_book(static_cast<Locate>(i));
      for (Side s : {Side::Buy, Side::Sell}) {
        d.begin_side(s, b.levels(s));
        b.for_each_level(s, [&](const Level& lv) {
          d.level(lv.px, lv.count, lv.qty[0]);
          Fifo::for_each(store_, lv.q[0], [&](Handle h) {
            const OrderT& o = store_.rec(h);
            d.order(o.ref, o.qty);
          });
        });
      }
    }
    return d.finish(store_.size());
  }

  // Full structural check: store/index consistency, level containers, FIFO
  // links, level totals and counts, order back-pointers, BBO caches.
  [[nodiscard]] bool check_invariants(std::string* err = nullptr) const {
    std::string local;
    std::string& e = err != nullptr ? *err : local;
    if (!store_.check(&e)) return false;
    std::size_t orders = 0;
    std::size_t levels = 0;
    for (std::size_t i = 0; i < books_.size(); ++i) {
      const LBook& b = books_[i];
      const auto loc = static_cast<Locate>(i);
      if (b.empty()) {
        if (b.bbo() != lob::Bbo{}) {
          e = "locate " + std::to_string(i) + ": empty book with a non-empty cached BBO";
          return false;
        }
        continue;
      }
      if (!b.check(&e)) {
        e = "locate " + std::to_string(i) + ": " + e;
        return false;
      }
      for (Side s : {Side::Buy, Side::Sell}) {
        const char* bad = nullptr;
        std::string fifo_err;
        b.for_each_level(s, [&](const Level& lv) {
          if (bad != nullptr) return;
          ++levels;
          if (!Fifo::check(store_, lv.q[0], lv.count, &fifo_err)) {
            bad = fifo_err.c_str();
            return;
          }
          std::uint64_t sum = 0;
          Fifo::for_each(store_, lv.q[0], [&](Handle h) {
            const OrderT& o = store_.rec(h);
            sum += o.qty;
            ++orders;
            if (o.level != &lv) bad = "order does not point at its level";
            if (o.locate != loc) bad = "order locate != book locate";
            if (o.side != s) bad = "order side != book side";
            if (o.qty == 0) bad = "order with zero shares";
            if (store_.find(o.ref) != h) bad = "index does not map the order's ref to it";
          });
          if (bad == nullptr && sum != lv.qty[0]) bad = "level total != sum of order shares";
        });
        if (bad != nullptr) {
          e = "locate " + std::to_string(i) + (s == Side::Buy ? " bid: " : " ask: ") + bad;
          return false;
        }
      }
    }
    if (orders != store_.size()) {
      e = "orders reachable from levels (" + std::to_string(orders) + ") != store size (" +
          std::to_string(store_.size()) + ")";
      return false;
    }
    if constexpr (P::Levels::kPooled) {
      if (levels != level_pool_.live()) {
        e = "level pool live count != levels in books";
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] Listener& listener() noexcept { return listener_; }
  [[nodiscard]] const Listener& listener() const noexcept { return listener_; }
  [[nodiscard]] const Store& store() const noexcept { return store_; }
  [[nodiscard]] const LevelPool& level_pool() const noexcept { return level_pool_; }
  [[nodiscard]] const BookConfig& config() const noexcept { return cfg_; }

 private:
  static lob::StoreConfig store_config(const BookConfig& c) {
    lob::StoreConfig s;
    s.reserve_orders = c.reserve_orders;
    s.index.capacity = c.reserve_orders;
    s.index.max_direct_ref = c.max_direct_ref;
    s.prefault = c.prefault;
    return s;
  }
  LBook& book(Locate loc) {
    if (loc >= books_.size()) [[unlikely]]
      books_.resize(std::size_t{loc} + 1);  // within the reserve: never reallocates
    return books_[loc];
  }

  // Appends a fresh record to the back of its level's FIFO.
  void link(Handle h, OrderRef ref, Locate loc, Side s, PxE4 px, Qty q, LBook& b) {
    bool created = false;
    Level* lv = b.find_or_insert(s, px, level_pool_, created);
    OrderT& o = store_.rec(h);
    o.ref = ref;
    o.level = lv;
    o.qty = q;
    o.locate = loc;
    o.side = s;
    Fifo::push_back(store_, lv->q[0], h);
    lv->qty[0] += q;
    ++lv->count;
  }

  // Unlinks the order, erases its level if now empty, releases the record.
  void unlink(Handle h, OrderT& o, LBook& b) {
    Level* lv = o.level;
    Fifo::unlink(store_, lv->q[0], h);
    lv->qty[0] -= o.qty;
    if (--lv->count == 0) b.erase(o.side, lv, level_pool_);
    store_.erase(o.ref, h);
  }

  void publish(LBook& b, Locate loc, Side s) {
    if (b.refresh(s)) listener_.on_bbo_change(loc, b.bbo());
  }

  BookConfig cfg_;
  Store store_;
  [[no_unique_address]] LevelPool level_pool_;
  std::vector<LBook> books_;
  [[no_unique_address]] Listener listener_;
};

}  // namespace lle::book

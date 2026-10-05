#pragma once
// Differential comparison of one ItchBook variant against RefBook
// (04-order-book §8 "Harnesses"): per operation, the result code, whether a
// BBO-change event fired, its content, and the running stream digest; on
// demand, a full depth walk (final-books digest), live counts, and both
// books' invariant checkers.
#include <cstdint>
#include <string>

#include "book/digested_book.h"
#include "book/itch_book.h"
#include "gen.hpp"
#include "ref_book.hpp"

namespace lle::lobfuzz {

// book::Status -> the RefResult numbering (both documented in their headers).
[[nodiscard]] inline int result_code(book::Status s) noexcept {
  switch (s) {
    case book::Status::kOk: return 0;
    case book::Status::kUnknownRef: return 1;
    case book::Status::kDuplicateRef: return 2;
    case book::Status::kBadQty: return 3;
    case book::Status::kBadPrice: return 4;
    case book::Status::kBadSide: return 5;
    case book::Status::kOverReduce: return 6;
  }
  return -1;
}

template <class Book>
int apply_op(Book& b, const Op& op) {
  switch (op.kind) {
    case Op::Kind::kDeclare: b.stock_directory(op.loc); return 0;
    case Op::Kind::kAdd: return result_code(b.add(op.ref, op.loc, op.side, op.px, op.qty));
    case Op::Kind::kReduce: return result_code(b.reduce(op.ref, op.qty));
    case Op::Kind::kRemove: return result_code(b.remove(op.ref));
    case Op::Kind::kReplace: return result_code(b.replace(op.ref, op.new_ref, op.px, op.qty));
  }
  return -1;
}

inline int apply_op(RefBook& r, const Op& op) {
  switch (op.kind) {
    case Op::Kind::kDeclare: r.declare(op.loc); return 0;
    case Op::Kind::kAdd: return static_cast<int>(r.add(op.ref, op.loc, op.side, op.px, op.qty));
    case Op::Kind::kReduce: return static_cast<int>(r.reduce(op.ref, op.qty));
    case Op::Kind::kRemove: return static_cast<int>(r.remove(op.ref));
    case Op::Kind::kReplace: return static_cast<int>(r.replace(op.ref, op.new_ref, op.px, op.qty));
  }
  return -1;
}

template <class V>
class DiffPair {
 public:
  explicit DiffPair(const book::BookConfig& cfg) : book_(cfg) {}

  // Applies op to both books; false (with a reason) on any difference.
  bool step(const Op& op, std::string* why) {
    book::BboRecorder& rec = book_.recorder();
    rec.fired = false;
    const int vs = apply_op(book_.book(), op);
    const int rs = apply_op(ref_, op);
    if (vs != rs) {
      *why = "result: book=" + std::to_string(vs) + " ref=" + std::to_string(rs);
      return false;
    }
    if (rec.fired != ref_.event_fired()) {
      *why = std::string("event presence: book=") + (rec.fired ? "yes" : "no") + " ref=" +
             (ref_.event_fired() ? "yes" : "no");
      return false;
    }
    if (rec.fired) {
      const RefTop& t = ref_.event_top();
      if (rec.loc != ref_.event_locate() || rec.bbo.bid.px != t.bid_px || rec.bbo.bid.qty != t.bid_qty ||
          rec.bbo.ask.px != t.ask_px || rec.bbo.ask.qty != t.ask_qty) {
        *why = "event content: book=" + describe(rec.loc, rec.bbo.bid.px, rec.bbo.bid.qty, rec.bbo.ask.px,
                                                 rec.bbo.ask.qty) +
               " ref=" + describe(ref_.event_locate(), t.bid_px, t.bid_qty, t.ask_px, t.ask_qty);
        return false;
      }
    }
    if (rec.digest.value != ref_.event_digest()) {
      *why = "BBO stream digest";
      return false;
    }
    return true;
  }

  // Full depth walk plus both invariant checkers.
  bool full_check(std::string* why) {
    const auto& b = book_.book();
    if (b.live_orders() != ref_.live()) {
      *why = "live orders: book=" + std::to_string(b.live_orders()) + " ref=" + std::to_string(ref_.live());
      return false;
    }
    if (b.books_digest() != ref_.books_digest()) {
      *why = "final-books digest";
      return false;
    }
    if (book_.recorder().digest.events != ref_.event_count()) {
      *why = "event count";
      return false;
    }
    std::string err;
    if (!b.check_invariants(&err)) {
      *why = "book invariants: " + err;
      return false;
    }
    if (!ref_.check(&err)) {
      *why = "ref invariants: " + err;
      return false;
    }
    return true;
  }

  [[nodiscard]] auto& book() noexcept { return book_.book(); }
  [[nodiscard]] RefBook& ref() noexcept { return ref_; }
  [[nodiscard]] std::uint64_t stream_digest() const noexcept { return book_.recorder().digest.value; }

 private:
  static std::string describe(Locate l, PxE4 bp, std::uint64_t bq, PxE4 ap, std::uint64_t aq) {
    return "{loc " + std::to_string(l) + " " + std::to_string(bq) + "@" + std::to_string(bp) + " / " +
           std::to_string(aq) + "@" + std::to_string(ap) + "}";
  }

  book::DigestedBook<V> book_;
  RefBook ref_;
};

inline book::BookConfig book_config_for(const Swarm& sw) {
  book::BookConfig c;
  c.reserve_orders = sw.reserve_orders;
  c.reserve_levels = sw.reserve_orders < 64 ? 1 : 256;
  c.levels_per_side = sw.levels_per_side;
  c.max_direct_ref = sw.max_direct_ref;
  return c;
}

}  // namespace lle::lobfuzz

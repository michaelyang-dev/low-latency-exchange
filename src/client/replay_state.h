#pragma once
// The market state mold_replay keeps for its GLIMPSE-style snapshot service
// (03-protocols §8): every replayed message is applied to an ITCH book and to
// the reference data a spin carries, so a snapshot can be produced at any
// sequence. Satisfies glimpse::SnapshotStateLike:
//   S (every system event so far), R (one per locate), H, Y, h (the latest per
//   locate), then the resting orders as A messages, locate by locate, buy side
//   then sell side, levels from the worst price to the best and FIFO within a
//   level, so a client that re-adds them in spin order rebuilds the same queues;
//   G = the sequence of the last applied message + 1 (S(P)+1).
// The spin's A messages keep the order reference, side, shares, price, locate
// and symbol; the attribution of an F and the original timestamp are not book
// state and are not carried (the timestamp is the latest one applied).
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "book/itch_adapter.h"
#include "book/variants.h"
#include "common/types.h"
#include "proto/itch50/itch50.h"

namespace lle::client {

class ReplayBookState {
 public:
  explicit ReplayBookState(const book::BookConfig& cfg = {})
      : book_(cfg), refs_(std::make_unique<RefData[]>(kLocates)) {}
  ReplayBookState(const ReplayBookState&) = delete;
  ReplayBookState& operator=(const ReplayBookState&) = delete;

  // Applies message `seq` (its MoldUDP64 sequence). Sequences must be applied in order.
  void apply(SeqNo seq, std::span<const std::byte> msg) {
    applied_ = seq;
    if (msg.empty()) return;
    const auto* p = msg.data();
    const std::size_t n = msg.size();
    if (n != itch50::kMsgLen[static_cast<unsigned char>(p[0])]) {
      (void)book::apply_itch(book_, p, n);  // reported malformed, changes nothing
      return;
    }
    last_ts_ = itch50::MessageHeaderView(p).timestamp();
    const Locate loc = itch50::MessageHeaderView(p).stock_locate();
    switch (static_cast<char>(p[0])) {
      case 'S':
        if (n_events_ < events_.size()) events_[n_events_++] = itch50::SystemEventView(p).to_struct();
        return;
      case 'R':
        refs_[loc].dir = itch50::StockDirectoryView(p).to_struct();
        refs_[loc].has_dir = true;
        break;
      case 'H':
        refs_[loc].action = itch50::StockTradingActionView(p).to_struct();
        refs_[loc].has_action = true;
        return;
      case 'Y':
        refs_[loc].regsho = itch50::RegShoRestrictionView(p).to_struct();
        refs_[loc].has_regsho = true;
        return;
      case 'h':
        refs_[loc].halt = itch50::OperationalHaltView(p).to_struct();
        refs_[loc].has_halt = true;
        return;
      default:
        break;
    }
    (void)book::apply_itch(book_, p, n);
  }

  // --- glimpse::SnapshotStateLike ---------------------------------------------
  [[nodiscard]] SeqNo snapshot_next_seq() const noexcept { return applied_ + 1; }

  template <class F>
  void visit_system_events(F&& f) const {
    for (std::size_t i = 0; i < n_events_; ++i) f(events_[i]);
  }
  template <class F>
  void visit_stock_directory(F&& f) const {
    for (std::size_t l = 0; l < kLocates; ++l)
      if (refs_[l].has_dir) f(refs_[l].dir);
  }
  template <class F>
  void visit_trading_actions(F&& f) const {
    for (std::size_t l = 0; l < kLocates; ++l)
      if (refs_[l].has_action) f(refs_[l].action);
  }
  template <class F>
  void visit_reg_sho(F&& f) const {
    for (std::size_t l = 0; l < kLocates; ++l)
      if (refs_[l].has_regsho) f(refs_[l].regsho);
  }
  template <class F>
  void visit_operational_halts(F&& f) const {
    for (std::size_t l = 0; l < kLocates; ++l)
      if (refs_[l].has_halt) f(refs_[l].halt);
  }
  // Levels from the worst price to the best, FIFO within each level. The queue
  // order at each price is all a book's state depends on; worst-first lets a
  // client book that keeps its levels sorted with the best at the back (lob's
  // VecLevels) append every new level and find it at the touch: rebuilding a
  // 3.8M-order book this way is O(orders), where best-first scans and shifts
  // every deeper level for each order (several seconds on a full-day book).
  template <class F>
  void visit_orders(F&& f) const {
    itch50::AddOrder a;
    a.tracking_number = 0;
    a.timestamp = last_ts_;
    struct O {
      PxE4 px;
      OrderRef ref;
      Qty qty;
    };
    std::vector<O> side_orders;  // snapshot thread, cold path
    for (std::size_t l = 0; l < book_.locates(); ++l) {
      const auto loc = static_cast<Locate>(l);
      a.stock_locate = loc;
      a.stock = refs_[l].has_dir ? refs_[l].dir.stock : Symbol8{};
      for (Side s : {Side::Buy, Side::Sell}) {
        a.side = s;
        side_orders.clear();
        book_.for_each_order(loc, s, [&](PxE4 px, OrderRef ref, Qty qty) { side_orders.push_back(O{px, ref, qty}); });
        // Best-to-worst groups of equal price, emitted last group first.
        std::size_t end = side_orders.size();
        while (end > 0) {
          std::size_t begin = end - 1;
          while (begin > 0 && side_orders[begin - 1].px == side_orders[end - 1].px) --begin;
          for (std::size_t i = begin; i < end; ++i) {
            a.order_ref = side_orders[i].ref;
            a.shares = side_orders[i].qty;
            a.price = side_orders[i].px;
            f(a);
          }
          end = begin;
        }
      }
    }
  }

  [[nodiscard]] SeqNo applied() const noexcept { return applied_; }
  [[nodiscard]] std::uint64_t books_digest() const { return book_.books_digest(); }
  [[nodiscard]] std::size_t live_orders() const noexcept { return book_.live_orders(); }
  [[nodiscard]] const book::OptBook<>& book() const noexcept { return book_; }

 private:
  static constexpr std::size_t kLocates = std::size_t{1} << 16;
  struct RefData {
    itch50::StockDirectory dir{};
    itch50::StockTradingAction action{};
    itch50::RegShoRestriction regsho{};
    itch50::OperationalHalt halt{};
    bool has_dir = false, has_action = false, has_regsho = false, has_halt = false;
  };

  book::OptBook<> book_;
  std::unique_ptr<RefData[]> refs_;
  std::array<itch50::SystemEvent, 16> events_{};
  std::size_t n_events_ = 0;
  SeqNo applied_ = 0;
  std::uint64_t last_ts_ = 0;
};

}  // namespace lle::client

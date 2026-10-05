#pragma once
// GlimpseState: the market state a GLIMPSE-style snapshot describes (03 §8), built by
// applying the released ITCH stream in MoldUDP64 order. After applying messages 1..P it
// is the state at P, and glimpse::SnapshotServer turns it into the spin
//   S..., R..., H..., Y..., h..., A/F..., G(P + 1)
// (glimpse::SnapshotStateLike). Resting displayed orders are kept by order reference;
// references increase with entry (a replace takes a new one), so reference order is
// time priority. The spin lists them locate by locate, the buy side then the sell side,
// levels from the worst price to the best and FIFO within a level (as mold_replay's
// spins do): a client book that keeps its levels sorted with the best at the back adds
// every new level at the touch, so rebuilding is O(orders), not O(orders x levels).
//
// Placement (07 §3): the snapshot service runs on a housekeeping core and reads the
// output log, never the 8-core pipeline (glimpse_server.h). It is not on the hot path:
// orders live in an ordered map (one node per resting displayed order).
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "common/types.h"
#include "proto/itch50/itch50.h"

namespace lle::md {

class GlimpseState {
 public:
  explicit GlimpseState(std::size_t locates = 0) { reserve(locates); }

  // Applies the next released ITCH message (sequence applied() + 1).
  void apply(std::span<const std::byte> msg) {
    ++applied_;
    const auto v = itch50::decode(msg);
    if (!v) {
      ++malformed_;
      return;
    }
    const std::uint16_t loc = v->header().stock_locate();
    switch (v->type()) {
      case 'S':
        if (events_n_ < events_.size()) events_[events_n_++] = v->as<itch50::SystemEventView>().to_struct();
        break;
      case 'R': at(loc).directory = v->as<itch50::StockDirectoryView>().to_struct(); break;
      case 'H': at(loc).action = v->as<itch50::StockTradingActionView>().to_struct(); break;
      case 'Y': at(loc).regsho = v->as<itch50::RegShoRestrictionView>().to_struct(); break;
      case 'h': at(loc).halt = v->as<itch50::OperationalHaltView>().to_struct(); break;
      case 'A': {
        const itch50::AddOrder a = v->as<itch50::AddOrderView>().to_struct();
        orders_[a.order_ref] = Resting{a, false, {}};
        break;
      }
      case 'F': {
        const itch50::AddOrderMpid f = v->as<itch50::AddOrderMpidView>().to_struct();
        itch50::AddOrder a;
        a.stock_locate = f.stock_locate;
        a.tracking_number = f.tracking_number;
        a.timestamp = f.timestamp;
        a.order_ref = f.order_ref;
        a.side = f.side;
        a.shares = f.shares;
        a.stock = f.stock;
        a.price = f.price;
        orders_[f.order_ref] = Resting{a, true, f.attribution};
        break;
      }
      case 'E': {
        const auto e = v->as<itch50::OrderExecutedView>();
        reduce(e.order_ref(), e.executed_shares());
        break;
      }
      case 'C': {
        const auto c = v->as<itch50::OrderExecutedWithPriceView>();
        reduce(c.order_ref(), c.executed_shares());
        break;
      }
      case 'X': {
        const auto x = v->as<itch50::OrderCancelView>();
        reduce(x.order_ref(), x.cancelled_shares());
        break;
      }
      case 'D': orders_.erase(v->as<itch50::OrderDeleteView>().order_ref()); break;
      case 'U': {
        // The replacement keeps side, symbol and attribution (ITCH 5.0 §4.6.4).
        const auto u = v->as<itch50::OrderReplaceView>();
        const auto it = orders_.find(u.original_order_ref());
        if (it == orders_.end()) {
          ++unknown_refs_;
          break;
        }
        Resting r = it->second;
        orders_.erase(it);
        r.add.order_ref = u.new_order_ref();
        r.add.shares = u.shares();
        r.add.price = u.price();
        r.add.timestamp = u.timestamp();
        r.add.tracking_number = u.tracking_number();
        orders_[r.add.order_ref] = r;
        break;
      }
      default: break;
    }
  }

  // ---- glimpse::SnapshotStateLike ---------------------------------------------------
  [[nodiscard]] SeqNo snapshot_next_seq() const noexcept { return applied_ + 1; }
  template <class F>
  void visit_system_events(F&& f) const {
    for (std::size_t i = 0; i < events_n_; ++i) f(events_[i]);
  }
  template <class F>
  void visit_stock_directory(F&& f) const {
    for (const Symbol& s : symbols_)
      if (s.directory) f(*s.directory);
  }
  template <class F>
  void visit_trading_actions(F&& f) const {
    for (const Symbol& s : symbols_)
      if (s.action) f(*s.action);
  }
  template <class F>
  void visit_reg_sho(F&& f) const {
    for (const Symbol& s : symbols_)
      if (s.regsho) f(*s.regsho);
  }
  template <class F>
  void visit_operational_halts(F&& f) const {
    for (const Symbol& s : symbols_)
      if (s.halt) f(*s.halt);
  }
  template <class F>
  void visit_orders(F&& f) const {
    // Spin order (cold path: the snapshot thread at a login).
    std::vector<const Resting*> v;
    v.reserve(orders_.size());
    for (const auto& [ref, r] : orders_) v.push_back(&r);
    std::stable_sort(v.begin(), v.end(), [](const Resting* x, const Resting* y) {
      const itch50::AddOrder& a = x->add;
      const itch50::AddOrder& b = y->add;
      if (a.stock_locate != b.stock_locate) return a.stock_locate < b.stock_locate;
      const bool abuy = a.side == Side::Buy, bbuy = b.side == Side::Buy;
      if (abuy != bbuy) return abuy;  // the buy side first
      if (a.price != b.price) return abuy ? a.price < b.price : a.price > b.price;  // worst first
      return a.order_ref < b.order_ref;                                              // FIFO
    });
    for (const Resting* rp : v) {
      const Resting& r = *rp;
      if (!r.mpid) {
        f(r.add);
        continue;
      }
      itch50::AddOrderMpid m;
      m.stock_locate = r.add.stock_locate;
      m.tracking_number = r.add.tracking_number;
      m.timestamp = r.add.timestamp;
      m.order_ref = r.add.order_ref;
      m.side = r.add.side;
      m.shares = r.add.shares;
      m.stock = r.add.stock;
      m.price = r.add.price;
      m.attribution = r.attribution;
      f(m);
    }
  }

  [[nodiscard]] SeqNo applied() const noexcept { return applied_; }
  [[nodiscard]] std::size_t resting_orders() const noexcept { return orders_.size(); }
  [[nodiscard]] std::uint64_t malformed() const noexcept { return malformed_; }
  [[nodiscard]] std::uint64_t unknown_refs() const noexcept { return unknown_refs_; }
  // Messages a spin of the current state holds (including the final G).
  [[nodiscard]] std::size_t spin_messages() const noexcept {
    std::size_t n = events_n_ + orders_.size() + 1;
    for (const Symbol& s : symbols_) {
      n += std::size_t{s.directory.has_value()} + std::size_t{s.action.has_value()} +
           std::size_t{s.regsho.has_value()} + std::size_t{s.halt.has_value()};
    }
    return n;
  }

 private:
  struct Symbol {
    std::optional<itch50::StockDirectory> directory;
    std::optional<itch50::StockTradingAction> action;
    std::optional<itch50::RegShoRestriction> regsho;
    std::optional<itch50::OperationalHalt> halt;
  };
  struct Resting {
    itch50::AddOrder add;
    bool mpid = false;
    Alpha<4> attribution{};
  };

  void reserve(std::size_t locates) { symbols_.resize(locates + 1); }
  Symbol& at(std::uint16_t loc) {
    if (loc >= symbols_.size()) symbols_.resize(std::size_t{loc} + 1);
    return symbols_[loc];
  }
  void reduce(std::uint64_t ref, std::uint32_t shares) {
    const auto it = orders_.find(ref);
    if (it == orders_.end()) {
      if (ref != 0) ++unknown_refs_;
      return;
    }
    if (shares >= it->second.add.shares) {
      orders_.erase(it);
    } else {
      it->second.add.shares -= shares;
    }
  }

  SeqNo applied_ = 0;
  std::array<itch50::SystemEvent, 16> events_{};
  std::size_t events_n_ = 0;
  std::vector<Symbol> symbols_;  // index = locate
  std::map<std::uint64_t, Resting> orders_;
  std::uint64_t malformed_ = 0;
  std::uint64_t unknown_refs_ = 0;
};

}  // namespace lle::md

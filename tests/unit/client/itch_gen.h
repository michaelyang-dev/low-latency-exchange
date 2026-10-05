#pragma once
// A small seeded generator of semantically valid ITCH 5.0 streams for the
// client tests: system events, one R per locate, then adds (A, F), executions
// (E, C), cancels (X), deletes (D) and replaces (U) on live orders only, so a
// book applies every message without an error. Test-support code: allocates.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/alpha.h"
#include "common/prng.h"
#include "common/types.h"
#include "proto/itch50/itch50.h"

namespace lle::client::test {

struct GenOrder {
  OrderRef ref;
  Locate loc;
  Side side;
  PxE4 px;
  Qty qty;
};

class ItchGen {
 public:
  explicit ItchGen(std::uint64_t seed, unsigned symbols = 20) : rng_(seed), symbols_(symbols) {}

  // Generates `n` messages (the preamble counts towards n).
  std::vector<std::vector<std::byte>> make(std::size_t n) {
    std::vector<std::vector<std::byte>> out;
    out.reserve(n);
    itch50::SystemEvent se;
    se.event_code = static_cast<itch50::EventCode>('O');
    put(out, se);
    for (unsigned i = 1; i <= symbols_ && out.size() < n; ++i) {
      itch50::StockDirectory r;
      r.stock_locate = static_cast<Locate>(i);
      r.stock = symbol(i);
      r.round_lot_size = 100;
      r.market_category = static_cast<itch50::MarketCategory>('Q');
      put(out, r);
    }
    se.event_code = static_cast<itch50::EventCode>('Q');
    if (out.size() < n) put(out, se);
    while (out.size() < n) step(out);
    return out;
  }

  static Symbol8 symbol(unsigned i) {
    char b[8] = {'S', 'Y', 'M', static_cast<char>('A' + (i / 26) % 26), static_cast<char>('A' + i % 26), ' ', ' ', ' '};
    return Symbol8(std::string_view(b, 5));
  }

  [[nodiscard]] const std::vector<GenOrder>& live() const noexcept { return live_; }

 private:
  template <class M>
  void put(std::vector<std::vector<std::byte>>& out, M m) {
    m.timestamp = ts_ += 1 + rng_.below(1000);
    std::vector<std::byte> b(M::kLen);
    itch50::encode_unchecked(b.data(), m);
    out.push_back(std::move(b));
  }

  void step(std::vector<std::vector<std::byte>>& out) {
    const std::uint64_t r = rng_.below(100);
    if (live_.size() < 50 || r < 45) {
      GenOrder o{next_ref_++, static_cast<Locate>(1 + rng_.below(symbols_)), rng_.below(2) ? Side::Buy : Side::Sell, 0,
                 static_cast<Qty>(100 * (1 + rng_.below(10)))};
      // $99.00 and below for bids, $101.00 and above for offers, on the cent grid.
      o.px = o.side == Side::Buy ? 990'000 - static_cast<PxE4>(rng_.below(50)) * 100
                                 : 1'010'000 + static_cast<PxE4>(rng_.below(50)) * 100;
      if (rng_.below(10) == 0) {
        itch50::AddOrderMpid a;
        a.stock_locate = o.loc;
        a.order_ref = o.ref;
        a.side = o.side;
        a.shares = o.qty;
        a.stock = symbol(o.loc);
        a.price = o.px;
        a.attribution = Mpid4("GSCO");
        put(out, a);
      } else {
        itch50::AddOrder a;
        a.stock_locate = o.loc;
        a.order_ref = o.ref;
        a.side = o.side;
        a.shares = o.qty;
        a.stock = symbol(o.loc);
        a.price = o.px;
        put(out, a);
      }
      live_.push_back(o);
      return;
    }
    const std::size_t i = static_cast<std::size_t>(rng_.below(live_.size()));
    GenOrder& o = live_[i];
    if (r < 75) {
      itch50::OrderDelete d;
      d.stock_locate = o.loc;
      d.order_ref = o.ref;
      put(out, d);
      erase(i);
    } else if (r < 85) {
      itch50::OrderReplace u;
      u.stock_locate = o.loc;
      u.original_order_ref = o.ref;
      u.new_order_ref = next_ref_++;
      u.shares = static_cast<Qty>(100 * (1 + rng_.below(10)));
      u.price = o.px + (o.side == Side::Buy ? -100 : 100) * static_cast<PxE4>(rng_.below(3));
      put(out, u);
      o.ref = u.new_order_ref;
      o.qty = u.shares;
      o.px = u.price;
    } else if (r < 93) {
      const Qty q = std::min<Qty>(o.qty, static_cast<Qty>(100 * (1 + rng_.below(5))));
      itch50::OrderExecuted e;
      e.stock_locate = o.loc;
      e.order_ref = o.ref;
      e.executed_shares = q;
      e.match_number = ++match_;
      put(out, e);
      reduce(i, q);
    } else if (r < 96) {
      const Qty q = std::min<Qty>(o.qty, 100);
      itch50::OrderExecutedWithPrice c;
      c.stock_locate = o.loc;
      c.order_ref = o.ref;
      c.executed_shares = q;
      c.match_number = ++match_;
      c.printable = static_cast<itch50::YesNo>('Y');
      c.execution_price = o.px;
      put(out, c);
      reduce(i, q);
    } else {
      const Qty q = o.qty > 100 ? 100 : o.qty;
      itch50::OrderCancel x;
      x.stock_locate = o.loc;
      x.order_ref = o.ref;
      x.cancelled_shares = q;
      put(out, x);
      reduce(i, q);
    }
  }

  void reduce(std::size_t i, Qty q) {
    live_[i].qty -= q;
    if (live_[i].qty == 0) erase(i);
  }
  void erase(std::size_t i) {
    live_[i] = live_.back();
    live_.pop_back();
  }

  Prng rng_;
  unsigned symbols_;
  std::vector<GenOrder> live_;
  OrderRef next_ref_ = 1000;
  MatchNo match_ = 0;
  std::uint64_t ts_ = std::uint64_t{4} * 3600 * 1'000'000'000;
};

}  // namespace lle::client::test

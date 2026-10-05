#pragma once
// The pre-registered T18 strategy of refclient (07 §3 "Strategy (pre-registered)").
//
// When an ITCH Add Order (A or F) for the trigger symbol has a price at or
// through the configured threshold, send one IOC Enter Order:
//   - a Sell add priced at or below the sell threshold -> Buy IOC;
//   - a Buy add priced at or above the buy threshold   -> Sell IOC;
//   - limit price = the trigger's price, quantity = the configured size (or the
//     trigger's shares when the size is 0);
//   - ClOrdID = the trigger's MoldUDP64 sequence number in decimal, so the
//     order frame can be correlated with the trigger (ADR-013);
//   - UserRefNum strictly increasing (OUCH 5.0 §1.2), from the order entry.
// The trigger symbol's locate is learned from its Stock Directory (R) message,
// live or in a snapshot spin. The Enter Order is pre-built at configuration time;
// per order only UserRefNum, side, quantity, price and ClOrdID are patched.
// No allocation, no exceptions, no virtual dispatch.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/types.h"
#include "proto/itch50/itch50.h"
#include "proto/ouch50/ouch50.h"

namespace lle::client {

struct StrategyConfig {
  Symbol8 symbol{"AAPL"};
  bool on_sell = true;          // trigger on Sell adds priced at or below sell_threshold
  PxE4 sell_threshold = 0;
  bool on_buy = false;          // trigger on Buy adds priced at or above buy_threshold
  PxE4 buy_threshold = 0;
  Qty quantity = 100;           // 0 = the trigger's shares
  std::uint64_t max_orders = 0;  // 0 = no limit
};

struct StrategyStats {
  std::uint64_t adds_seen = 0;      // adds for the trigger symbol
  std::uint64_t triggers = 0;
  std::uint64_t orders = 0;
  std::uint64_t suppressed = 0;     // over max_orders
  std::uint64_t send_failed = 0;    // order entry refused (no session, pending queue full)
  SeqNo first_trigger = 0, last_trigger = 0;
};

class TriggerStrategy {
 public:
  static constexpr std::size_t kEnterLen = ouch50::in::EnterOrder::kFixedLen;  // Appendage Length 0

  explicit TriggerStrategy(const StrategyConfig& cfg) : cfg_(cfg) {
    ouch50::in::EnterOrder m;
    m.user_ref_num = 0;
    m.side = ouch50::Side::Buy;
    m.quantity = 0;
    m.symbol = cfg.symbol;
    m.price = 0;
    m.time_in_force = ouch50::TimeInForce::Ioc;
    m.display = ouch50::Display::Visible;
    m.capacity = ouch50::Capacity::Agency;
    m.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
    m.cross_type = ouch50::CrossType::Continuous;
    const std::size_t n = ouch50::encode(std::span<std::byte>(tmpl_), m);
    LLE_ASSERT(n == kEnterLen);
  }

  // Every in-order message, after the book applied it. Out provides
  //   UserRefNum next_urn();  bool send(std::span<const std::byte> ouch);
  template <class Out>
  void on_itch(SeqNo seq, std::span<const std::byte> msg, Out& out) {
    if (msg.empty()) return;
    const char t = static_cast<char>(msg[0]);
    if (t == 'A' || t == 'F') {
      if (!known_ || msg.size() < itch50::AddOrderView::kLen) return;
      const itch50::AddOrderView v(msg.data());  // A and F share the layout up to the price
      if (v.stock_locate() != locate_) return;
      ++st_.adds_seen;
      const Side s = v.side();
      const PxE4 px = v.price();
      const bool hit = (s == Side::Sell && cfg_.on_sell && px <= cfg_.sell_threshold) ||
                       (s == Side::Buy && cfg_.on_buy && px >= cfg_.buy_threshold);
      if (!hit) return;
      ++st_.triggers;
      if (st_.first_trigger == 0) st_.first_trigger = seq;
      st_.last_trigger = seq;
      if (cfg_.max_orders != 0 && st_.orders >= cfg_.max_orders) {
        ++st_.suppressed;
        return;
      }
      fire(seq, s == Side::Sell ? ouch50::Side::Buy : ouch50::Side::Sell, cfg_.quantity != 0 ? cfg_.quantity : v.shares(),
           px, out);
    } else if (t == 'R') {
      on_directory(msg);
    }
  }

  // Stock Directory from a snapshot spin (or live).
  void on_directory(std::span<const std::byte> msg) noexcept {
    if (msg.size() != itch50::StockDirectoryView::kLen || static_cast<char>(msg[0]) != 'R') return;
    const itch50::StockDirectoryView v(msg.data());
    if (v.stock() == cfg_.symbol) {
      locate_ = v.stock_locate();
      known_ = true;
    }
  }

  // Builds the order for trigger `seq` into out (kEnterLen bytes). Exposed for tests.
  void build(std::span<std::byte, kEnterLen> out, UserRefNum urn, SeqNo seq, ouch50::Side side, Qty qty,
             PxE4 px) const noexcept {
    std::memcpy(out.data(), tmpl_.data(), kEnterLen);
    store_be32(out.data() + 1, urn);
    out[5] = static_cast<std::byte>(static_cast<char>(side));
    store_be32(out.data() + 6, qty);
    store_be64(out.data() + 18, static_cast<std::uint64_t>(px));
    // ClOrdID @31/14: decimal sequence, left-justified, space-padded (Alpha).
    char digits[20];
    std::size_t k = 0;
    SeqNo v = seq;
    do {
      digits[k++] = static_cast<char>('0' + v % 10);
      v /= 10;
    } while (v != 0 && k < sizeof(digits));
    std::byte* c = out.data() + 31;
    for (std::size_t i = 0; i < 14; ++i) c[i] = std::byte{' '};
    for (std::size_t i = 0; i < k && i < 14; ++i) c[i] = static_cast<std::byte>(digits[k - 1 - i]);
  }

  [[nodiscard]] bool locate_known() const noexcept { return known_; }
  [[nodiscard]] Locate locate() const noexcept { return locate_; }
  [[nodiscard]] const StrategyStats& stats() const noexcept { return st_; }
  [[nodiscard]] const StrategyConfig& config() const noexcept { return cfg_; }

 private:
  template <class Out>
  void fire(SeqNo seq, ouch50::Side side, Qty qty, PxE4 px, Out& out) {
    std::array<std::byte, kEnterLen> buf;
    build(std::span<std::byte, kEnterLen>(buf), out.next_urn(), seq, side, qty, px);
    if (out.send(std::span<const std::byte>(buf))) {
      ++st_.orders;
    } else {
      ++st_.send_failed;
    }
  }

  StrategyConfig cfg_;
  std::array<std::byte, kEnterLen> tmpl_{};
  Locate locate_ = 0;
  bool known_ = false;
  StrategyStats st_;
};

}  // namespace lle::client

#pragma once
// Pre-trade risk gate (05-matching-engine §7, E-12). Runs inside the engine,
// on journaled inputs only: limits come from the RiskLimits Config table and
// Admin RiskLimit records (ADR-028), time is the record timestamp. Its state
// (limits, open and executed notional, kill switches, rate buckets and the
// duplicate filters) is part of the canonical engine state.
//
// Checks, in this order; the first failure names the reject code:
//   1  port rate (token bucket per session)                 0x0029
//   2  symbol rate (token bucket per session and symbol)    0x0028
//   3  permissions: pre-market 0x002D, post-market 0x002E, short sale 0x002B,
//      short exempt 0x002F, market order 0x002C, IPO market buy 0x0033
//   4  restricted symbol                                    0x0022
//   5  hard to borrow: short sale without SharesLocated     0x0027
//   6  maximum order quantity                               0x0031
//   7  quantity above a % of the symbol's ADV               0x0025
//   8  maximum order notional                               0x0030
//   9  Limit Order Protection: max(10%, $0.50) through      0x0006
//  10  fat finger: bps or absolute amount through           0x0026
//  11  market impact: priced through the far LULD band      0x0021
//  12  open notional in the symbol                          0x001F
//  13  gross exposure: open + executed + this order         0x0020
//  14  duplicate content within the window (Enter only)     0x002A
// 9-11 apply to continuous limit orders of a symbol that is not halted; their
// reference is the NBO for a buy (NBB for a sell; NBBO := own BBO), else the
// last sale (no check without either). Notional is shares x PxE4 price; a
// market order is valued at that reference, else at the prior close (0 when
// there is none). The kill switch
// (entry disabled, 0x000C) is checked by the engine with the other
// entry-disabled conditions, before validation.
//
// Memory: tables are sized by configure() and set(); the checks and the
// bookkeeping never allocate. Setting SymbolNotional, SymbolRate or
// DupWindowSec for an account the first time (also by an Admin RiskLimit, a
// cold path) creates that account's table.
#include <algorithm>
#include <array>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "common/int128.h"
#include "common/types.h"
#include "engine/canonical.h"
#include "engine/order.h"
#include "engine/records.h"
#include "engine/state.h"

namespace lle::engine {

// The market around one order (computed by the engine).
struct RiskQuote {
  PxE4 bid = 0, ask = 0;  // displayed best bid (for sells) and offer (for buys)
  PxE4 last = 0, prior = 0;
  PxE4 luld_lo = 0, luld_hi = 0;
  std::uint32_t adv = 0;
  Session session = Session::Regular;
  bool halted = false;
  bool ipo = false;  // IPO quotation or pre-launch period
};

struct RiskRequest {
  std::uint32_t account = 0;  // account table index
  std::uint32_t session = 0;  // session table index
  Locate locate = 0;
  Marking marking = Marking::Buy;
  Qty qty = 0;   // the order quantity (Replace: the new total over the chain)
  Qty open = 0;  // shares it would leave open at most (Replace: qty - done)
  PxE4 px = 0;   // limit price (0 for market orders)
  bool market = false;
  bool cross = false;  // an on-open, on-close or halt cross order
  bool located = false;
  bool replace = false;
  i128 old_open = 0;  // Replace: the original's open notional, released by the replace
  std::uint64_t content = 0;  // Enter: duplicate-filter key (dup_content)
};

// FNV-1a over the fields that make two Enter Orders the same order: symbol,
// side, quantity, price, time in force, display and cross type.
[[nodiscard]] std::uint64_t dup_content(Locate l, Marking m, Qty q, std::uint64_t price, Tif tif, Display d,
                                        CrossType c) noexcept;

class RiskGate {
 public:
  static constexpr std::size_t kDupBuckets = 32;  // one per second, > the 30 s maximum window
  static constexpr std::size_t kDupSlots = 8;     // contents per second; the oldest is overwritten
  static constexpr std::int64_t kMaxDupWindow = 30;
  static constexpr std::int64_t kMaxRate = 1'000'000;  // tokens per second
  static constexpr std::int64_t kNever = INT64_MIN;    // a bucket not yet used

  // Per-account limits; 0 is off except Lop (on unless set to 0).
  struct Limits {
    std::uint32_t perms = 0;
    std::int64_t max_qty = 0, max_notional = 0, ff_bps = 0, ff_abs = 0, lop = 1, dup_window = 0, port_rate = 0,
                 symbol_rate = 0, gross = 0, symbol_notional = 0, adv_pct = 0, kill_exposure = 0;
  };
  // A per-symbol rule of one account.
  struct SymbolRule {
    std::uint32_t account = 0;
    Locate locate = 0;
    bool restricted = false;
    bool hard_to_borrow = false;
    std::int64_t notional = -1;  // per-symbol open notional limit (-1: the account default)
  };
  struct Bucket {
    std::int64_t level = 0;  // nano-tokens
    std::int64_t last = kNever;
  };

  // Clears every limit and all state and sizes the tables: accounts, the
  // account of each session, symbols (locates 1..n).
  void configure(std::uint32_t accounts, std::span<const std::uint32_t> session_account, std::uint32_t symbols);
  void reset() { configure(0, {}, 0); }

  // One limit (RiskLimits entry or Admin RiskLimit) for a resolved account and
  // symbol (locate 0 = none); false when invalid (the caller rejects).
  bool set(std::uint32_t account, RiskKind kind, std::int64_t value, Locate locate);

  // The checks above; 0 when the order passes (and is then recorded by the
  // duplicate filter). *risk_px receives the price its notional is counted at.
  std::uint16_t check(const RiskRequest& r, const RiskQuote& q, std::int64_t now_ns, PxE4* risk_px);

  // Bookkeeping: open notional changes (+ when an order opens, - when shares
  // leave it) and executions.
  void open_delta(std::uint32_t account, Locate l, i128 delta) noexcept {
    accts_[account].open += delta;
    if (const std::uint32_t s = sym_open_slot_[account]; s != kNone) sym_open_[std::size_t{s} * stride_ + l] += delta;
  }
  void on_execution(std::uint32_t account, Qty q, PxE4 px) noexcept;
  // Rebuilding a per-symbol table (the account total already counts these orders).
  void add_symbol_open(std::uint32_t account, Locate l, i128 delta) noexcept {
    if (const std::uint32_t s = sym_open_slot_[account]; s != kNone) sym_open_[std::size_t{s} * stride_ + l] += delta;
  }

  [[nodiscard]] bool killed(std::uint32_t account) const noexcept { return accts_[account].killed; }
  void kill(std::uint32_t account) noexcept { accts_[account].killed = true; }
  void unkill(std::uint32_t account) noexcept { accts_[account].killed = false; }
  // Accounts whose executed notional crossed KillExposure since the last call, in account order.
  [[nodiscard]] bool kills_pending() const noexcept { return !pending_.empty(); }
  void take_pending(std::vector<std::uint32_t>& out);

  // Accounts whose per-symbol open notional is tracked: the engine fills a
  // new table from the account's open orders (needs_rebuild).
  [[nodiscard]] bool tracks_symbols(std::uint32_t account) const noexcept {
    return sym_open_slot_[account] != kNone;
  }
  [[nodiscard]] i128 open(std::uint32_t account) const noexcept { return accts_[account].open; }
  [[nodiscard]] i128 executed(std::uint32_t account) const noexcept { return accts_[account].executed; }
  [[nodiscard]] i128 symbol_open(std::uint32_t account, Locate l) const noexcept {
    const std::uint32_t s = sym_open_slot_[account];
    return s == kNone ? i128{0} : sym_open_[std::size_t{s} * stride_ + l];
  }
  [[nodiscard]] const Limits& limits(std::uint32_t account) const noexcept { return limits_[account]; }
  [[nodiscard]] std::uint32_t accounts() const noexcept { return static_cast<std::uint32_t>(limits_.size()); }
  // An account whose per-symbol table was just created by set(): the caller adds its open orders.
  [[nodiscard]] std::uint32_t take_rebuild() noexcept {
    const std::uint32_t a = rebuild_;
    rebuild_ = kNone;
    return a;
  }

  // Canonical state (engine walk order); restore() rebuilds from it.
  template <class V>
  void walk(V& v) const;
  bool restore(ByteReader& r);

  static constexpr std::uint32_t kNone = UINT32_MAX;

 private:
  struct AcctState {
    i128 open = 0;
    i128 executed = 0;
    bool killed = false;
    bool pending = false;
  };
  struct DupBucket {
    std::int64_t sec = -1;
    std::uint32_t n = 0;  // insertions this second (slot = n % kDupSlots)
    std::array<std::uint64_t, kDupSlots> h{};
  };
  struct DupFilter {
    std::uint32_t account = 0;
    std::int64_t last = -1;  // second of the latest insertion
    std::array<DupBucket, kDupBuckets> b{};
  };

  const SymbolRule* rule(std::uint32_t account, Locate l) const noexcept;
  SymbolRule& rule_mut(std::uint32_t account, Locate l);
  static bool take(Bucket& b, std::int64_t rate, std::int64_t now) noexcept;
  Bucket& sym_bucket(std::uint32_t session, Locate l);
  void ensure_sym_open(std::uint32_t account);
  void ensure_sym_buckets(std::uint32_t account);
  void ensure_dup(std::uint32_t account);
  bool dup_hit(const DupFilter& f, std::uint64_t key, std::int64_t sec, std::int64_t window) const noexcept;
  static void dup_insert(DupFilter& f, std::uint64_t key, std::int64_t sec) noexcept;

  std::vector<Limits> limits_;
  std::vector<AcctState> accts_;
  std::vector<std::uint32_t> session_account_;
  std::vector<SymbolRule> rules_;  // sorted by (account, locate)
  std::vector<std::uint8_t> has_rules_;
  std::vector<Bucket> port_;                     // per session
  std::vector<std::uint32_t> sym_bucket_slot_;   // per session
  std::vector<Bucket> sym_buckets_;              // slot * stride + locate
  std::vector<std::uint32_t> sym_open_slot_;     // per account
  std::vector<i128> sym_open_;                   // slot * stride + locate
  std::vector<std::uint32_t> dup_slot_;          // per account
  std::vector<DupFilter> dups_;
  std::vector<std::uint32_t> pending_;
  std::size_t stride_ = 1;  // symbols + 1
  std::uint32_t rebuild_ = kNone;
};

template <class V>
void RiskGate::walk(V& v) const {
  auto i128v = [&](i128 x) {
    const auto u = static_cast<u128>(x);
    v.u64(static_cast<std::uint64_t>(u));
    v.u64(static_cast<std::uint64_t>(u >> 64));
  };
  v.u32(static_cast<std::uint32_t>(limits_.size()));
  for (std::size_t a = 0; a < limits_.size(); ++a) {
    const Limits& l = limits_[a];
    v.u32(l.perms);
    for (std::int64_t x : {l.max_qty, l.max_notional, l.ff_bps, l.ff_abs, l.lop, l.dup_window, l.port_rate,
                           l.symbol_rate, l.gross, l.symbol_notional, l.adv_pct, l.kill_exposure})
      v.u64(static_cast<std::uint64_t>(x));
    i128v(accts_[a].open);
    i128v(accts_[a].executed);
    v.u8(accts_[a].killed ? 1 : 0);
    v.u8(sym_open_slot_[a] != kNone ? 1 : 0);
  }
  v.u32(static_cast<std::uint32_t>(rules_.size()));
  for (const SymbolRule& r : rules_) {
    v.u32(r.account);
    v.u16(r.locate);
    v.u8(r.restricted ? 1 : 0);
    v.u8(r.hard_to_borrow ? 1 : 0);
    v.u64(static_cast<std::uint64_t>(r.notional));
  }
  v.u32(static_cast<std::uint32_t>(port_.size()));
  for (const Bucket& b : port_) {
    v.u64(static_cast<std::uint64_t>(b.level));
    v.u64(static_cast<std::uint64_t>(b.last));
  }
  // Symbol buckets that have been used, by (session, locate).
  std::uint32_t used = 0;
  for (std::size_t s = 0; s < sym_bucket_slot_.size(); ++s) {
    if (sym_bucket_slot_[s] == kNone) continue;
    for (std::size_t l = 1; l < stride_; ++l)
      if (sym_buckets_[std::size_t{sym_bucket_slot_[s]} * stride_ + l].last != kNever) ++used;
  }
  v.u32(used);
  for (std::size_t s = 0; s < sym_bucket_slot_.size(); ++s) {
    if (sym_bucket_slot_[s] == kNone) continue;
    for (std::size_t l = 1; l < stride_; ++l) {
      const Bucket& b = sym_buckets_[std::size_t{sym_bucket_slot_[s]} * stride_ + l];
      if (b.last == kNever) continue;
      v.u32(static_cast<std::uint32_t>(s));
      v.u16(static_cast<std::uint16_t>(l));
      v.u64(static_cast<std::uint64_t>(b.level));
      v.u64(static_cast<std::uint64_t>(b.last));
    }
  }
  // Duplicate filters, by account: the latest insertion second, then each
  // second still in range (sec > last - kDupBuckets) with its contents, oldest first.
  std::uint32_t nf = 0;
  for (std::size_t a = 0; a < dup_slot_.size(); ++a) nf += dup_slot_[a] != kNone ? 1u : 0u;
  v.u32(nf);
  for (std::size_t a = 0; a < dup_slot_.size(); ++a) {
    if (dup_slot_[a] == kNone) continue;
    const DupFilter& f = dups_[dup_slot_[a]];
    v.u32(static_cast<std::uint32_t>(a));
    v.u64(static_cast<std::uint64_t>(f.last));
    std::array<const DupBucket*, kDupBuckets> live{};
    std::size_t n = 0;
    for (const DupBucket& b : f.b)
      if (b.n > 0 && b.sec > f.last - static_cast<std::int64_t>(kDupBuckets)) live[n++] = &b;
    std::sort(live.begin(), live.begin() + static_cast<std::ptrdiff_t>(n),
              [](const DupBucket* x, const DupBucket* y) { return x->sec < y->sec; });
    v.u32(static_cast<std::uint32_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
      const DupBucket& b = *live[i];
      const std::uint32_t k = b.n < kDupSlots ? b.n : static_cast<std::uint32_t>(kDupSlots);
      v.u64(static_cast<std::uint64_t>(b.sec));
      v.u32(k);
      for (std::uint32_t j = b.n - k; j < b.n; ++j) v.u64(b.h[j % kDupSlots]);
    }
  }
}

}  // namespace lle::engine

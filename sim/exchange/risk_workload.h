#pragma once
// Risk limits for the exchange worlds (05 §7, the engine's risk gate): draws that bind
// now and then for the worlds' clients, who enter 100 to 1,000 shares within a few ticks
// of the prior close (or 8 to 80 ticks away), hundreds to thousands of messages a second
// and in bursts. A risk day's limits table and the operator's intraday changes use them,
// so every kind is configured, changed, lifted, journaled, replicated and snapshotted.
#include <cstdint>
#include <iterator>
#include <span>

#include "common/alpha.h"
#include "engine/records.h"
#include "sim/rng.h"

namespace lle::sim::exch {

struct RiskDraw {
  engine::RiskKind kind = engine::RiskKind::MaxOrderQty;
  std::int64_t value = 0;
  Symbol8 symbol{};  // blank unless the kind is per symbol
};

// One limit for an account trading `traded`. With `lift`, one draw in five sets 0: no
// limit (permissions: everything allowed; the symbol lists: off).
inline RiskDraw draw_risk(Rng& r, std::span<const engine::SymbolEntry> traded, bool lift) {
  using K = engine::RiskKind;
  constexpr std::int64_t kTickPx = 100;  // $0.01 in PxE4
  const engine::SymbolEntry& s = traded[static_cast<std::size_t>(r.below(traded.size()))];
  const std::int64_t lot = s.prior_close * 100;  // notional of 100 shares (PxE4 x shares)
  auto n = [&r](std::uint64_t lo, std::uint64_t span) { return static_cast<std::int64_t>(lo + r.below(span)); };
  RiskDraw d;
  switch (r.below(16)) {
    case 0: {  // one or two permissions withdrawn
      constexpr std::uint32_t kPerms[] = {engine::kNoPreMarket,   engine::kNoPostMarket,  engine::kNoShortSell,
                                          engine::kNoShortExempt, engine::kNoMarketOrders, engine::kNoIpoMarketBuy,
                                          engine::kNoThroughBand};
      std::uint32_t v = kPerms[r.below(std::size(kPerms))];
      if (r.below(2) == 0) v |= kPerms[r.below(std::size(kPerms))];
      d = {K::Permissions, v, {}};
      break;
    }
    case 1: d = {K::MaxOrderQty, 100 * n(3, 8), {}}; break;
    case 2: d = {K::MaxOrderNotional, lot * n(3, 8), {}}; break;
    case 3: d = {K::FatFingerBps, n(1, 10), {}}; break;  // through the far side, in bps of it
    case 4: d = {K::FatFingerAbs, kTickPx * n(1, 5), {}}; break;
    case 5: d = {K::Lop, 1, {}}; break;
    case 6: d = {K::DupWindowSec, n(1, 30), {}}; break;
    case 7: d = {K::PortRate, n(100, 3000), {}}; break;  // messages a second per session
    case 8: d = {K::SymbolRate, n(50, 1500), {}}; break;
    case 9: d = {K::GrossExposure, lot * n(20, 400), {}}; break;
    case 10: d = {K::SymbolNotional, lot * n(10, 200), {}}; break;  // every symbol
    case 11: d = {K::SymbolNotional, lot * n(10, 200), s.symbol}; break;
    case 12: d = {K::AdvPct, n(1, 10), {}}; break;
    case 13: d = {K::Restricted, 1, s.symbol}; break;
    case 14: d = {K::HardToBorrow, 1, s.symbol}; break;
    default: d = {K::KillExposure, lot * n(50, 2000), {}}; break;  // latches the kill switch
  }
  if (lift && r.below(5) == 0) d.value = 0;
  return d;
}

}  // namespace lle::sim::exch

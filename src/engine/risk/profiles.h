#pragma once
// Pre-registered risk profiles (05-matching-engine §7). The T20 run loads
// kT20 on every account so that its throughput includes realistic checks:
// every price, size and exposure check is active, the duplicate filter and
// both rate buckets run on every Enter, and the per-symbol tables exist. The
// values are generous enough that the T20 mix (non-marketable orders around a
// $50 mid, 100-500 shares) is not rejected by them; the cost is the checks.
#include <cstdint>
#include <span>
#include <vector>

#include "engine/records.h"

namespace lle::engine::risk_profiles {

struct Profile {
  std::uint32_t perms;             // RiskPerm bits (prohibitions)
  std::int64_t max_qty;            // shares
  std::int64_t max_notional;       // PxE4 x shares
  std::int64_t fat_finger_bps;
  std::int64_t fat_finger_abs;     // PxE4
  std::int64_t lop;                // 1 = on
  std::int64_t dup_window_sec;
  std::int64_t port_rate;          // messages / s / session
  std::int64_t symbol_rate;        // orders / s / (session, symbol)
  std::int64_t gross;              // PxE4 x shares
  std::int64_t symbol_notional;    // PxE4 x shares
  std::int64_t adv_pct;
  std::int64_t kill_exposure;      // PxE4 x shares
};

// $10M per order, $500B gross, $1B per symbol, $500B executed before the kill switch.
// The gross and kill limits are sized for the pre-registered T20 mix at 4.2M msgs/s:
// gross exposure counts open plus executed notional, and every IOC fill counts on both
// sides of one account, so about $8.6B executes per account in 10 s and the earlier
// $5B / $100B limits would reject and latch inside one run. Every limit stays positive,
// so every check is still evaluated on every message (a limit of 0 disables a check).
inline constexpr Profile kT20{
    .perms = kNoThroughBand,
    .max_qty = 100'000,
    .max_notional = 10'000'000LL * 10'000,
    .fat_finger_bps = 1'000,
    .fat_finger_abs = 50'000,
    .lop = 1,
    .dup_window_sec = 1,
    .port_rate = 1'000'000,
    .symbol_rate = 10'000,
    .gross = 500'000'000'000LL * 10'000,
    .symbol_notional = 1'000'000'000LL * 10'000,
    .adv_pct = 50,
    .kill_exposure = 500'000'000'000LL * 10'000,
};

// The RiskLimits table entries of a profile for the given accounts.
inline std::vector<RiskEntry> entries(const Profile& p, std::span<const std::uint32_t> account_ids) {
  std::vector<RiskEntry> v;
  v.reserve(account_ids.size() * 13);
  for (const std::uint32_t a : account_ids) {
    auto add = [&](RiskKind k, std::int64_t x) {
      RiskEntry e;
      e.account_id = a;
      e.kind = k;
      e.value = x;
      v.push_back(e);
    };
    add(RiskKind::Permissions, p.perms);
    add(RiskKind::MaxOrderQty, p.max_qty);
    add(RiskKind::MaxOrderNotional, p.max_notional);
    add(RiskKind::FatFingerBps, p.fat_finger_bps);
    add(RiskKind::FatFingerAbs, p.fat_finger_abs);
    add(RiskKind::Lop, p.lop);
    add(RiskKind::DupWindowSec, p.dup_window_sec);
    add(RiskKind::PortRate, p.port_rate);
    add(RiskKind::SymbolRate, p.symbol_rate);
    add(RiskKind::GrossExposure, p.gross);
    add(RiskKind::SymbolNotional, p.symbol_notional);
    add(RiskKind::AdvPct, p.adv_pct);
    add(RiskKind::KillExposure, p.kill_exposure);
  }
  return v;
}

}  // namespace lle::engine::risk_profiles

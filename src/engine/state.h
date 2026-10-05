#pragma once
// Engine state records (05-matching-engine §5-§6): the market session, per-
// symbol trading and halt state, accounts and sessions. All of it is part of
// the canonical state (README "Canonical state").
#include <array>
#include <cstdint>

#include "common/alpha.h"
#include "common/types.h"
#include "engine/order.h"
#include "engine/records.h"

namespace lle::engine {

// The market session (05 §6), driven by StateChange and Cross timers.
enum class Session : char { Closed = 'C', PreMarket = 'P', Regular = 'R', PostMarket = 'A' };

// Milestones reached today (bit set).
enum MilestoneBit : std::uint8_t {
  kOpenFreeze = 1,
  kMooCutoff = 2,
  kLooCutoff = 4,
  kCloseFreeze = 8,
  kMocCutoff = 16,
  kLocCutoff = 32,
};

// Per-symbol halt state (SymbolStateMachine, 05 §5 "Halts, LULD, IPO").
enum class HaltPhase : std::uint8_t {
  None = 0,      // follows the market session
  Halted,        // ITCH H 'H': no matching, orders rest
  QuoteOnly,     // ITCH H 'Q': display-only resumption period, NOII, collars
  Paused,        // ITCH H 'P' LUDP: LULD pause, as QuoteOnly
  IpoQuote,      // ITCH H 'Q' IPOQ: IPO quoting period, waiting for the underwriter
  IpoPreLaunch,  // underwriter "go" received: releases when the cross qualifies
};
enum class HaltKind : std::uint8_t { None = 0, News, Luld, Mwcb, Ipo };

[[nodiscard]] constexpr bool display_only(HaltPhase p) noexcept {
  return p == HaltPhase::QuoteOnly || p == HaltPhase::Paused || p == HaltPhase::IpoQuote ||
         p == HaltPhase::IpoPreLaunch;
}

struct SymbolInfo {
  // configuration (Symbols table)
  Symbol8 symbol{};
  std::uint32_t round_lot = 100;
  std::uint32_t tick = 100;
  PxE4 prior_close = 0;
  char market_category = ' ';
  char luld_tier = ' ';
  std::uint8_t flags = 0;
  std::uint32_t adv = 0;
  // trading state
  bool opened = false;  // opening cross done (or skipped)
  bool closed = false;  // closing cross done (or skipped)
  char regsho = '0';    // '0' none, '1' triggered today, '2' carried, ' ' unknown
  HaltPhase halt = HaltPhase::None;
  HaltKind halt_kind = HaltKind::None;
  Alpha<4> reason{};
  std::uint32_t ticks = 0;       // 1 Hz ticks into the current display-only period
  std::uint32_t period = 0;      // ticks the current period lasts
  std::uint32_t extension = 0;   // collar extensions so far
  PxE4 arp = 0;                  // auction reference price of the halt
  PxE4 collar_lo = 0, collar_hi = 0;
  PxE4 collar_step = 0;          // LULD / MWCB widening step
  PxE4 luld_lo = 0, luld_hi = 0;  // LULD price bands (0 = none)
  std::int32_t limit_ticks = -1;  // ticks in a LULD limit state, -1 = not in one
  PxE4 last_sale = 0;             // last execution today
  Nanos last_sale_ns = 0;         // its time (ns since midnight)
  PxE4 open_ref2 = 0;             // 09:28 CRP (second opening reference price)
  PxE4 close_ref1 = 0, close_ref2 = 0;  // 15:50 and 15:55 CRPs
  PxE4 ipo_price = 0, ipo_band = 0, ipo_expected = 0;
  std::uint32_t peg_pulled = 0;   // consecutive ticks with midpoint pegs pulled
  // off-book lists (MatchingBook::Links)
  Handle pend_head = kNil, pend_tail = kNil;
  std::array<Handle, 2> peg_head{kNil, kNil}, peg_tail{kNil, kNil};  // [0] buy, [1] sell
};

struct AccountInfo {
  std::uint32_t id = 0;
  std::array<Firm, AccountEntry::kMaxFirms> firms{};  // authorized firms, compacted; [0] = default
  std::uint8_t nfirms = 0;
  std::uint8_t disabled = 0;  // bit i: entry disabled for firms[i] (Disable 'D' / Enable 'E')
  bool cross_permit = false;  // Admin CrossCancelPermit (close freeze error correction)
  Handle head = kNil;         // live orders in ascending exchange reference (= entry) order
  Handle tail = kNil;
  [[nodiscard]] Firm default_firm() const noexcept { return nfirms != 0 ? firms[0] : Firm{}; }
};

struct SessionInfo {
  std::uint32_t id = 0;
  std::uint32_t account = 0;  // account table index
  std::uint8_t flags = 0;
  AiqMode default_aiq = AiqMode::Disabled;
  LateCrossPolicy late_cross = LateCrossPolicy::Reprice;
  std::uint64_t live = 0;      // bit per live instance (primary, mirrors)
  std::uint64_t ouch_out = 0;  // OUCH messages sent today (next SoupBinTCP sequence - 1)
};

// Market parameters (Schedule table parameter entries).
struct MarketParams {
  std::int64_t threshold_bps = 1'000;  // max(10%, $0.50) beyond the BBO (R2 D2.4)
  std::int64_t threshold_min = 5'000;
  std::int64_t price_test_bps = 1'000;  // UNVERIFIED defaults (R2 risks)
  std::int64_t price_test_min = 5'000;
  std::int64_t price_tests = 7;
  std::int64_t halt_period = 300;
  std::int64_t luld_pause = 300;
  std::int64_t mwcb_period = 900;
  std::int64_t limit_state = 15;
  std::int64_t extension = 300;

  // Bounds a Schedule table (and a snapshot) must respect: percentages up to
  // 1000%, minimums up to the OUCH maximum price, the test mask A|B|C, periods
  // up to a day. They keep every derived product (price x bps, seconds x 1e9)
  // far inside int64.
  static constexpr std::int64_t kMaxBps = 100'000;
  static constexpr std::int64_t kMaxPeriodSec = 86'400;
  [[nodiscard]] constexpr bool valid() const noexcept {
    const auto in = [](std::int64_t x, std::int64_t hi) { return x >= 0 && x <= hi; };
    return in(threshold_bps, kMaxBps) && in(price_test_bps, kMaxBps) && in(threshold_min, kPxMaxLimit) &&
           in(price_test_min, kPxMaxLimit) && in(price_tests, 7) && in(halt_period, kMaxPeriodSec) &&
           in(luld_pause, kMaxPeriodSec) && in(mwcb_period, kMaxPeriodSec) && in(limit_state, kMaxPeriodSec) &&
           in(extension, kMaxPeriodSec);
  }
};

}  // namespace lle::engine

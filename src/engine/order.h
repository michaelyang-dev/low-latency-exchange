#pragma once
// Order model (05-matching-engine §2).
//
// OrderSpec is what an Enter or Replace asks for, decoded from the OUCH fixed
// fields plus the appendage tags. Order is the record of a live order: pooled,
// 32-bit handles. Where it lives:
//   Book     in its price level's FIFO (queue class displayed or non-displayed);
//   Pending  off the continuous book in its symbol's pending list: cross-only
//            orders (MOO/LOO/OIO/MOC/LOC/IO, halt-cross H) and Day orders held
//            for the opening cross (early market hours);
//   Peg      in its symbol's midpoint-peg list for its side.
// The links (level FIFO or list, and the account's live list in reference =
// entry order) live apart from the record (MatchingBook::Links). A reserve
// order is two records: the displayed slice (the parent: identity, UserRefNum,
// account list) and the non-displayed reserve (the child, flag kReserveChild,
// in the non-displayed queue with the original timestamp).
#include <cstdint>

#include "common/alpha.h"
#include "common/types.h"
#include "lob/fifo.h"
#include "lob/level.h"
#include "lob/types.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine {

using Handle = lob::Handle32;
inline constexpr Handle kNil = lob::kNil32;

using Firm = Mpid4;
using ClOrdId = Alpha<14>;
using AiqGroup = Alpha<2>;
using Tif = ouch50::TimeInForce;
using Display = ouch50::Display;
using CrossType = ouch50::CrossType;
using PegType = ouch50::PriceType;
using HandleInst = ouch50::HandleInst;
using AiqMode = ouch50::AiqStrategy;
using Capacity = ouch50::Capacity;
using Marking = ouch50::Side;  // B, S, T (short), E (short exempt)

// Queue classes of a price level (Rule 4757(a)(1)): displayed first.
inline constexpr int kDisplayed = 0;
inline constexpr int kHidden = 1;

using BookQueue = lob::IntrusiveFifo::Queue<Handle>;
using BookLevel = lob::Level<BookQueue, 2>;

[[nodiscard]] constexpr Side book_side(Marking m) noexcept { return m == Marking::Buy ? Side::Buy : Side::Sell; }
[[nodiscard]] constexpr int queue_class(Display d) noexcept { return d == Display::Hidden ? kHidden : kDisplayed; }
// Displayed orders appear on ITCH: 'A' (anonymous) or 'F' (attributed).
[[nodiscard]] constexpr bool itch_visible(Display d) noexcept { return d != Display::Hidden; }

struct OrderSpec {
  Side side = Side::Buy;
  Marking marking = Marking::Buy;
  Qty qty = 0;
  PxE4 px = 0;
  bool market = false;
  Tif tif = Tif::Day;
  Display display = Display::Visible;
  CrossType cross = CrossType::Continuous;
  PegType peg = PegType::Limit;
  Qty min_qty = 0;
  Qty max_floor = 0;
  bool post_only = false;
  bool imbalance_only = false;  // HandleInst I with CrossType O or C (OIO / IO)
  bool shares_located = false;  // tag 25 = Y
  HandleInst handle_inst = HandleInst::None;
  Firm firm{};
  std::uint16_t group_id = 0;
  AiqMode aiq = AiqMode::Disabled;
  AiqGroup aiq_group{};
  Capacity capacity = Capacity::Agency;
  ouch50::IsoEligibility iso = ouch50::IsoEligibility::NotEligible;
  ClOrdId cl_ord_id{};
  std::uint32_t expire_time = 0;
  bool has_expire = false;
  PxE4 risk_px = 0;  // set by the risk gate: the price its notional is counted at
  std::uint8_t user_ref_idx = 0;
  UserRefNum urn = 0;
};

// What a request does to a resting order. Priority (the record's journal
// index) survives only a size decrease or a long/short re-marking
// (Rule 4702(a), R2 D1.1); everything else, including every Replace, gives the
// order a new exchange reference and puts it at the back of its queue.
enum class Change : std::uint8_t { Decrease, Remark, Increase, PriceChange, DisplayChange, Replace };

[[nodiscard]] constexpr bool keeps_priority(Change c) noexcept {
  return c == Change::Decrease || c == Change::Remark;
}

// Off: a reserve parent whose display is used up, between an execution and its
// refresh within the same record (never seen at a record boundary).
enum class Where : std::uint8_t { Book = 0, Pending = 1, Peg = 2, Off = 3 };

struct Order {
  // flags
  static constexpr std::uint16_t kPostOnly = 1;
  static constexpr std::uint16_t kHasExpire = 2;
  static constexpr std::uint16_t kHeld = 4;            // Day order held for the opening cross
  static constexpr std::uint16_t kImbalanceOnly = 8;   // OIO / IO
  static constexpr std::uint16_t kMarket = 16;         // market cross order (MOO / MOC / market H)
  static constexpr std::uint16_t kCancelPending = 32;  // full cancel held until after the cross
  static constexpr std::uint16_t kPendingSent = 64;    // 'P' Cancel Pending already sent
  static constexpr std::uint16_t kRejectSent = 128;    // 'I' Cancel Reject already sent
  static constexpr std::uint16_t kMidPeg = 256;        // midpoint peg (Where::Peg)
  static constexpr std::uint16_t kReserveChild = 512;  // reserve part of a reserve order
  static constexpr std::uint16_t kLocated = 1024;      // SharesLocated = Y
  static constexpr std::uint16_t kRefresh = 2048;      // reserve parent queued for a refresh (transient)

  BookLevel* level = nullptr;  // Where::Book only
  OrderRef ref = 0;            // exchange order reference (OUCH)
  OrderRef itch_ref = 0;       // ITCH reference of the displayed slice (changes on reserve refresh)
  std::uint64_t prio = 0;      // journal index that created or re-prioritized it
  PxE4 px = 0;                 // limit (pegs: the cap; market cross orders: 0)
  PxE4 risk_px = 0;            // price its open notional is counted at (risk gate)
  Qty leaves = 0;              // open shares (for a reserve parent: the displayed slice)
  Qty done = 0;                // executed + self-match decremented over the replace chain
  Qty min_qty = 0;
  Qty max_floor = 0;
  UserRefNum urn = 0;
  std::uint32_t account = 0;  // account table index
  std::uint32_t session = 0;  // session table index
  std::uint32_t expire_time = 0;
  Handle peer = kNil;  // reserve parent <-> child
  Firm firm{};
  Locate locate = 0;
  std::uint16_t group_id = 0;
  std::uint16_t flags = 0;
  AiqGroup aiq_group{};
  std::uint8_t user_ref_idx = 0;
  Where where = Where::Book;
  Side side = Side::Buy;
  Marking marking = Marking::Buy;
  Display display = Display::Visible;
  Tif tif = Tif::Day;
  Capacity capacity = Capacity::Agency;
  ouch50::IsoEligibility iso = ouch50::IsoEligibility::NotEligible;
  CrossType cross = CrossType::Continuous;
  AiqMode aiq = AiqMode::Disabled;

  [[nodiscard]] bool has(std::uint16_t f) const noexcept { return (flags & f) != 0; }
  [[nodiscard]] bool post_only() const noexcept { return has(kPostOnly); }
  [[nodiscard]] int cls() const noexcept { return queue_class(display); }
  [[nodiscard]] bool cross_only() const noexcept { return cross != CrossType::Continuous; }
};

}  // namespace lle::engine

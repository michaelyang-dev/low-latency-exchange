#pragma once
// Expected-message builders for the engine golden tests: every field is
// written out by the test; these only assemble the codec value structs.
#include <string_view>
#include <vector>

#include "engine_test_util.h"

namespace lle::engine::testing {

namespace in = ouch50::in;
namespace out = ouch50::out;
using CR = ouch50::CancelReason;
using LF = ouch50::LiquidityFlag;
using RR = ouch50::RejectReason;
using OS = ouch50::Side;
using TIF = ouch50::TimeInForce;
using DSP = ouch50::Display;

inline constexpr std::uint64_t kP100 = 1'000'000;  // $100.0000

// ---- expected OUCH messages
struct Acc {
  UserRefNum urn;
  OS side;
  Qty qty;
  const char* sym;
  std::uint64_t px;
  OrderRef ref;
  bool live = true;
  TIF tif = TIF::Day;
  DSP display = DSP::Visible;
  const char* cl = "";
  ouch50::CrossType cross = ouch50::CrossType::Continuous;
};
inline std::vector<std::byte> acc(std::uint64_t ts, const Acc& a, const ouch50::TagSet& tags = {}) {
  out::OrderAccepted m{};
  m.user_ref_num = a.urn;
  m.side = a.side;
  m.quantity = a.qty;
  m.symbol = Symbol8(a.sym);
  m.price = a.px;
  m.time_in_force = a.tif;
  m.display = a.display;
  m.order_reference_number = a.ref;
  m.capacity = ouch50::Capacity::Agency;
  m.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
  m.cross_type = a.cross;
  m.order_state = a.live ? ouch50::OrderState::Live : ouch50::OrderState::Dead;
  m.cl_ord_id = Alpha<14>(a.cl);
  return ouch_out(m, ts, tags);
}
inline std::vector<std::byte> exe(std::uint64_t ts, UserRefNum urn, Qty q, std::uint64_t px, LF f, MatchNo mn,
                           std::uint8_t idx = 0) {
  out::OrderExecuted m{};
  m.user_ref_num = urn;
  m.quantity = q;
  m.price = px;
  m.liquidity_flag = f;
  m.match_number = mn;
  return ouch_out(m, ts, idx != 0 ? tags_idx(idx) : ouch50::TagSet{});
}
inline std::vector<std::byte> can(std::uint64_t ts, UserRefNum urn, Qty q, CR why, std::uint8_t idx = 0) {
  out::OrderCanceled m{};
  m.user_ref_num = urn;
  m.quantity = q;
  m.reason = why;
  return ouch_out(m, ts, idx != 0 ? tags_idx(idx) : ouch50::TagSet{});
}
inline std::vector<std::byte> rej(std::uint64_t ts, UserRefNum urn, RR why, const char* cl = "") {
  out::Rejected m{};
  m.user_ref_num = urn;
  m.reason = why;
  m.cl_ord_id = Alpha<14>(cl);
  return ouch_out(m, ts);
}
inline std::vector<std::byte> aiqc(std::uint64_t ts, UserRefNum urn, Qty d, std::uint64_t px, LF f, char strat) {
  out::AiqCanceled m{};
  m.user_ref_num = urn;
  m.decrement_shares = d;
  m.reason = CR::SelfMatchPrevention;
  m.quantity_prevented_from_trading = d;
  m.execution_price = px;
  m.liquidity_flag = f;
  m.aiq_strategy = static_cast<ouch50::AiqStrategy>(strat);
  return ouch_out(m, ts);
}
struct Rpl {
  UserRefNum orig, urn;
  OS side;
  Qty qty;
  const char* sym;
  std::uint64_t px;
  OrderRef ref;
  bool live = true;
  TIF tif = TIF::Day;
  DSP display = DSP::Visible;
};
inline std::vector<std::byte> rpl(std::uint64_t ts, const Rpl& r) {
  out::OrderReplaced m{};
  m.orig_user_ref_num = r.orig;
  m.user_ref_num = r.urn;
  m.side = r.side;
  m.quantity = r.qty;
  m.symbol = Symbol8(r.sym);
  m.price = r.px;
  m.time_in_force = r.tif;
  m.display = r.display;
  m.order_reference_number = r.ref;
  m.capacity = ouch50::Capacity::Agency;
  m.inter_market_sweep_eligibility = ouch50::IsoEligibility::NotEligible;
  m.cross_type = ouch50::CrossType::Continuous;
  m.order_state = r.live ? ouch50::OrderState::Live : ouch50::OrderState::Dead;
  return ouch_out(m, ts);
}

// ---- expected ITCH messages
inline std::vector<std::byte> iadd(std::uint64_t ts, Locate l, OrderRef ref, Side s, Qty q, const char* sym, PxE4 px) {
  itch50::AddOrder m{};
  m.order_ref = ref;
  m.side = s;
  m.shares = q;
  m.stock = Symbol8(sym);
  m.price = px;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> iaddf(std::uint64_t ts, Locate l, OrderRef ref, Side s, Qty q, const char* sym, PxE4 px,
                             const char* mpid) {
  itch50::AddOrderMpid m{};
  m.order_ref = ref;
  m.side = s;
  m.shares = q;
  m.stock = Symbol8(sym);
  m.price = px;
  m.attribution = Mpid4(mpid);
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> iexe(std::uint64_t ts, Locate l, OrderRef ref, Qty q, MatchNo mn) {
  itch50::OrderExecuted m{};
  m.order_ref = ref;
  m.executed_shares = q;
  m.match_number = mn;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> itrade(std::uint64_t ts, Locate l, Qty q, const char* sym, PxE4 px, MatchNo mn) {
  itch50::Trade m{};
  m.order_ref = 0;
  m.side = Side::Buy;
  m.shares = q;
  m.stock = Symbol8(sym);
  m.price = px;
  m.match_number = mn;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> ixcl(std::uint64_t ts, Locate l, OrderRef ref, Qty q) {
  itch50::OrderCancel m{};
  m.order_ref = ref;
  m.cancelled_shares = q;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> idel(std::uint64_t ts, Locate l, OrderRef ref) {
  itch50::OrderDelete m{};
  m.order_ref = ref;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> irep(std::uint64_t ts, Locate l, OrderRef o, OrderRef n, Qty q, PxE4 px) {
  itch50::OrderReplace m{};
  m.original_order_ref = o;
  m.new_order_ref = n;
  m.shares = q;
  m.price = px;
  return itch_bytes(m, l, ts);
}

// OUCH 'R' Order Restated, reason 'R' (reserve refresh): the new ITCH reference and display size.
inline std::vector<std::byte> rst(std::uint64_t ts, UserRefNum urn, OrderRef itch_ref, Qty display) {
  out::OrderRestated m{};
  m.user_ref_num = urn;
  m.reason = ouch50::RestatedReason::DisplayRefresh;
  ouch50::TagSet t;
  t.set_secondary_ord_ref_num(itch_ref);
  t.set_display_quantity(display);
  return ouch_out(m, ts, t);
}

// ---- auctions, halts and market-wide events
inline std::vector<std::byte> pend(std::uint64_t ts, UserRefNum urn) {
  out::CancelPending m{};
  m.user_ref_num = urn;
  return ouch_out(m, ts);
}
inline std::vector<std::byte> crej(std::uint64_t ts, UserRefNum urn) {
  out::CancelReject m{};
  m.user_ref_num = urn;
  return ouch_out(m, ts);
}
inline std::vector<std::byte> osys(std::uint64_t ts, ouch50::EventCode e) {
  out::SystemEvent m{};
  m.event_code = e;
  return ouch_out(m, ts);
}
// ITCH 'C' Printable = N at the cross price (R2 D2.7).
inline std::vector<std::byte> ixc(std::uint64_t ts, Locate l, OrderRef ref, Qty q, MatchNo mn, PxE4 px) {
  itch50::OrderExecutedWithPrice m{};
  m.order_ref = ref;
  m.executed_shares = q;
  m.match_number = mn;
  m.printable = itch50::YesNo::No;
  m.execution_price = px;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> iq(std::uint64_t ts, Locate l, const char* sym, std::uint64_t shares, PxE4 px, MatchNo mn,
                                 char type) {
  itch50::CrossTrade m{};
  m.shares = shares;
  m.stock = Symbol8(sym);
  m.cross_price = px;
  m.match_number = mn;
  m.cross_type = static_cast<itch50::CrossType>(type);
  return itch_bytes(m, l, ts);
}
struct Noii {
  std::uint64_t paired, imbalance;
  char dir;
  PxE4 far, near, crp;
  char cross;
  char pvi;
};
inline std::vector<std::byte> inoii(std::uint64_t ts, Locate l, const char* sym, const Noii& n) {
  itch50::Noii m{};
  m.paired_shares = n.paired;
  m.imbalance_shares = n.imbalance;
  m.imbalance_direction = static_cast<itch50::ImbalanceDirection>(n.dir);
  m.stock = Symbol8(sym);
  m.far_price = n.far;
  m.near_price = n.near;
  m.current_reference_price = n.crp;
  m.cross_type = static_cast<itch50::NoiiCrossType>(n.cross);
  m.price_variation_indicator = static_cast<itch50::PriceVariation>(n.pvi);
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> ih(std::uint64_t ts, Locate l, const char* sym, char state, const char* reason) {
  itch50::StockTradingAction m{};
  m.stock = Symbol8(sym);
  m.trading_state = static_cast<itch50::TradingState>(state);
  m.reserved = ' ';
  m.reason = Alpha<4>(reason);
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> ij(std::uint64_t ts, Locate l, const char* sym, PxE4 ref, PxE4 up, PxE4 lo,
                                 std::uint32_t ext) {
  itch50::LuldAuctionCollar m{};
  m.stock = Symbol8(sym);
  m.reference_price = ref;
  m.upper_price = up;
  m.lower_price = lo;
  m.extension = ext;
  return itch_bytes(m, l, ts);
}
inline std::vector<std::byte> ik(std::uint64_t ts, const char* sym, std::uint32_t release, char qual, PxE4 px) {
  itch50::IpoQuotingPeriodUpdate m{};
  m.stock = Symbol8(sym);
  m.release_time = release;
  m.release_qualifier = static_cast<itch50::IpoReleaseQualifier>(qual);
  m.ipo_price = px;
  return itch_bytes(m, 0, ts);
}
inline std::vector<std::byte> iv(std::uint64_t ts, std::int64_t l1, std::int64_t l2, std::int64_t l3) {
  itch50::MwcbDeclineLevel m{};
  m.level1 = l1;
  m.level2 = l2;
  m.level3 = l3;
  return itch_bytes(m, 0, ts);
}
inline std::vector<std::byte> iw(std::uint64_t ts, char level) {
  itch50::MwcbStatus m{};
  m.breached_level = static_cast<itch50::BreachedLevel>(level);
  return itch_bytes(m, 0, ts);
}
inline std::vector<std::byte> isys(std::uint64_t ts, char code) {
  itch50::SystemEvent m{};
  m.event_code = static_cast<itch50::EventCode>(code);
  return itch_bytes(m, 0, ts);
}
inline std::vector<std::byte> iy(std::uint64_t ts, Locate l, const char* sym, char action) {
  itch50::RegShoRestriction m{};
  m.stock = Symbol8(sym);
  m.reg_sho_action = static_cast<itch50::RegShoAction>(action);
  return itch_bytes(m, l, ts);
}

inline ouch50::TagSet aiq_tag(char c) {
  ouch50::TagSet t;
  t.set_aiq_strategy(static_cast<ouch50::AiqStrategy>(c));
  return t;
}

inline std::vector<std::byte> unhex(std::string_view h) {
  std::vector<std::byte> b;
  auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    if (h[i] == ' ') {
      --i;
      continue;
    }
    b.push_back(static_cast<std::byte>(nib(h[i]) * 16 + nib(h[i + 1])));
  }
  return b;
}


}  // namespace lle::engine::testing

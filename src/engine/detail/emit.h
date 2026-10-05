#pragma once
// Engine emission helpers: one encoded ITCH or OUCH message per call, stamped
// with the record's wire timestamp and journal index. Included by engine.h.
#include <array>
#include <span>

namespace lle::engine {

template <class S>
void Engine::audit(Out<S>& o, AuditCode c, std::uint32_t session_id, std::uint64_t detail) {
  o.sink.audit(o.idx, AuditEvent{c, session_id, detail});
}

template <class S, class M>
void Engine::itch(Out<S>& o, M m, Locate l) {
  m.stock_locate = l;
  m.tracking_number = 0;
  m.timestamp = o.ts;
  std::array<std::byte, itch50::kMaxMsgLen> b;
  const std::size_t n = itch50::encode(std::span<std::byte>(b), m);
  ++itch_count_;
  o.sink.itch(o.idx, std::span<const std::byte>(b.data(), n));
}

template <class S>
void Engine::itch_delete(Out<S>& o, Locate l, OrderRef ref) {
  itch50::OrderDelete d{};
  d.order_ref = ref;
  itch(o, d, l);
}

// Shares leave a displayed order: 'X' for part, 'D' for all of it.
template <class S>
void Engine::itch_reduce(Out<S>& o, const Order& r, Qty d) {
  if (d == r.leaves) {
    itch_delete(o, r.locate, r.itch_ref);
    return;
  }
  itch50::OrderCancel x{};
  x.order_ref = r.itch_ref;
  x.cancelled_shares = d;
  itch(o, x, r.locate);
}

template <class S>
void Engine::itch_add(Out<S>& o, const Order& r) {
  if (r.display == Display::Visible) {
    itch50::AddOrder m{};
    m.order_ref = r.itch_ref;
    m.side = r.side;
    m.shares = r.leaves;
    m.stock = symbols_[r.locate].symbol;
    m.price = r.px;
    itch(o, m, r.locate);
  } else if (r.display == Display::Attributable) {
    itch50::AddOrderMpid m{};
    m.order_ref = r.itch_ref;
    m.side = r.side;
    m.shares = r.leaves;
    m.stock = symbols_[r.locate].symbol;
    m.price = r.px;
    m.attribution = r.firm;
    itch(o, m, r.locate);
  }
}

template <class S>
void Engine::itch_trading_action(Out<S>& o, Locate l, char state, const Alpha<4>& reason) {
  itch50::StockTradingAction m{};
  m.stock = symbols_[l].symbol;
  m.trading_state = static_cast<itch50::TradingState>(state);
  m.reserved = ' ';
  m.reason = reason;
  itch(o, m, l);
}

// OUCH message to a session (by table index); the order's non-zero
// UserRefIdx rides in tag 28 (and gives Opt* messages their appendage).
template <class S, class Msg>
void Engine::ouch(Out<S>& o, std::uint32_t s, Msg m, std::uint8_t idx) {
  m.timestamp = o.ts;
  std::array<std::byte, ouch50::kMaxOutboundOuchLen> b;
  ouch50::MessageWriter<Msg> w(std::span<std::byte>(b), m);
  if constexpr (Msg::kRule != ouch50::AppendageRule::None) {
    if (idx != 0) w.tags().put_u8(Tag::UserRefIdx, idx);
  }
  const std::size_t n = w.finish();
  ++sessions_[s].ouch_out;
  o.sink.ouch(o.idx, sessions_[s].id, std::span<const std::byte>(b.data(), n));
}

template <class S, class Msg>
void Engine::ouch_tags(Out<S>& o, std::uint32_t s, Msg m, const TagSet& tags) {
  m.timestamp = o.ts;
  std::array<std::byte, ouch50::kMaxOutboundOuchLen> b;
  ouch50::MessageWriter<Msg> w(std::span<std::byte>(b), m);
  ouch50::put_tags(w.tags(), tags);
  const std::size_t n = w.finish();
  ++sessions_[s].ouch_out;
  o.sink.ouch(o.idx, sessions_[s].id, std::span<const std::byte>(b.data(), n));
}

template <class S>
void Engine::reject(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, std::uint16_t why,
                    const ClOrdId& id) {
  ouch50::out::Rejected m{};
  m.user_ref_num = urn;
  m.reason = static_cast<RR>(why);
  m.cl_ord_id = id;
  ouch(o, s, m, idx);
}

template <class S>
void Engine::canceled(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty q, CR why) {
  ouch50::out::OrderCanceled m{};
  m.user_ref_num = urn;
  m.quantity = q;
  m.reason = why;
  ouch(o, s, m, idx);
}

template <class S>
void Engine::executed(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty q, PxE4 px, LF flag,
                      MatchNo mn) {
  ouch50::out::OrderExecuted m{};
  m.user_ref_num = urn;
  m.quantity = q;
  m.price = static_cast<std::uint64_t>(px);
  m.liquidity_flag = flag;
  m.match_number = mn;
  ouch(o, s, m, idx);
  risk_.on_execution(sessions_[s].account, q, px);
}

// A self-match decrement: 'D' AIQ Canceled (strategies with details) or 'C' reason 'Q'.
template <class S>
void Engine::smp_notice(Out<S>& o, std::uint32_t s, UserRefNum urn, std::uint8_t idx, Qty d, PxE4 px, LF flag,
                        const Taker& t) {
  if (!t.smp.details) {
    canceled(o, s, urn, idx, d, CR::SelfMatchPrevention);
    return;
  }
  ouch50::out::AiqCanceled m{};
  m.user_ref_num = urn;
  m.decrement_shares = d;
  m.reason = CR::SelfMatchPrevention;
  m.quantity_prevented_from_trading = d;
  m.execution_price = static_cast<std::uint64_t>(px);
  m.liquidity_flag = flag;
  m.aiq_strategy = t.aiq;
  ouch(o, s, m, idx);
}

}  // namespace lle::engine

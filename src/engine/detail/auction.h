#pragma once
// Crosses (05 §5, E-09), NOII (E-10) and the halt / LULD / IPO / MWCB
// controller (E-11). Included by engine.h.

namespace lle::engine {

// Opening Cross (R2 D2.3 open column): MOO/LOO/OIO, the early market-hours
// orders held since the pre-market, and the continuous book. A halted symbol
// does not cross: its on-open orders cancel with reason 'H' and its held
// orders join the book without matching. When every opening price test fails
// the cross does not happen: on-open and held orders cancel with reason 'X'.
template <class S>
void Engine::opening_cross(Out<S>& o, Locate l) {
  SymbolInfo& y = symbols_[l];
  if (y.halt != HaltPhase::None) {
    cancel_pending(o, l, CrossType::Opening, CR::HaltedAfterOpen, false);
    post_held(o, l);
    y.opened = true;
    return;
  }
  const CrossResult r = compute_cross(l, CrossKind::Open, false, false);
  if (r.valid && r.volume > 0 && !price_tests_pass(l, r.price)) {
    cancel_pending(o, l, CrossType::Opening, CR::OpenProtection, true);
    execute_cross(o, l, CrossKind::Open, CrossResult{}, false);  // the zero-share 'Q'
    y.opened = true;
    return;
  }
  execute_cross(o, l, CrossKind::Open, r, false);
  cancel_pending(o, l, CrossType::Opening, CR::ImmediateOrCancel, false);
  post_held(o, l);
  uncross(o, l);
  y.opened = true;
}

// Closing Cross (R2 D2.3 close column): MOC/LOC/IO and the continuous book.
template <class S>
void Engine::closing_cross(Out<S>& o, Locate l) {
  SymbolInfo& y = symbols_[l];
  if (y.halt != HaltPhase::None) {
    cancel_pending(o, l, CrossType::Closing, CR::HaltedAfterOpen, false);
    y.closed = true;
    return;
  }
  const CrossResult r = compute_cross(l, CrossKind::Close, false, false);
  execute_cross(o, l, CrossKind::Close, r, false);
  cancel_pending(o, l, CrossType::Closing, CR::ImmediateOrCancel, false);
  uncross(o, l);
  y.closed = true;
}

// Executions at the cross price in priority order (allocate()), paired buy to
// sell; each pair is one match number: OUCH 'E' to the buyer then the seller,
// then ITCH 'C' Printable=N for each side that is a displayed order on the
// book (R2 D2.7). Then the 'Q' bulk print: always for the open and the close
// (zero shares and price 0 when nothing crosses), only when shares cross for a
// halt or IPO cross.
template <class S>
void Engine::execute_cross(Out<S>& o, Locate l, CrossKind kind, const CrossResult& r, bool halt_ipo) {
  std::uint64_t volume = 0;
  const PxE4 p = r.price;
  if (r.valid && r.volume > 0) {
    allocate(l, kind, r);
    auto flag = [&](const Order& x) {
      if (kind == CrossKind::Open) return x.has(Order::kImbalanceOnly) ? LF::OpeningCrossImbalanceOnly : LF::OpeningCross;
      if (kind == CrossKind::Close) return x.has(Order::kImbalanceOnly) ? LF::ClosingCrossImbalanceOnly : LF::ClosingCross;
      return halt_ipo ? LF::HaltIpoCross : LF::HaltCross;
    };
    auto report_c = [&](const Order& x, Qty q, MatchNo mn) {
      if (x.where != Where::Book || x.cls() != kDisplayed) return;
      itch50::OrderExecutedWithPrice c{};
      c.order_ref = x.itch_ref;
      c.executed_shares = q;
      c.match_number = mn;
      c.printable = itch50::YesNo::No;
      c.execution_price = p;
      itch(o, c, l);
    };
    // Applies an order's whole allocation once it has been paired out.
    auto settle = [&](const Fill& f) { consume(f.h, f.qty); };
    std::size_t i = 0, j = 0;
    Qty bq = buys_.empty() ? 0 : buys_[0].qty, sq = sells_.empty() ? 0 : sells_[0].qty;
    while (i < buys_.size() && j < sells_.size()) {
      const Qty q = std::min(bq, sq);
      const MatchNo mn = next_match_++;
      const Order& b = book_.at(buys_[i].h);
      const Order& s = book_.at(sells_[j].h);
      executed(o, b.session, b.urn, b.user_ref_idx, q, p, flag(b), mn);
      executed(o, s.session, s.urn, s.user_ref_idx, q, p, flag(s), mn);
      report_c(b, q, mn);
      report_c(s, q, mn);
      volume += q;
      bq -= q;
      sq -= q;
      if (bq == 0) {
        settle(buys_[i]);
        if (++i < buys_.size()) bq = buys_[i].qty;
      }
      if (sq == 0) {
        settle(sells_[j]);
        if (++j < sells_.size()) sq = sells_[j].qty;
      }
    }
  }
  if (kind == CrossKind::Halt && volume == 0) return;
  itch50::CrossTrade q{};
  q.shares = volume;
  q.stock = symbols_[l].symbol;
  q.cross_price = volume > 0 ? p : 0;
  q.match_number = next_match_++;
  q.cross_type = static_cast<itch50::CrossType>(static_cast<char>(kind));
  itch(o, q, l);
  if (volume > 0) after_execution(o, l, p);
  if (!refresh_.empty()) run_refreshes(o);
}

// Cancels the symbol's pending cross orders of one type (and, with `held`,
// the held early market-hours orders), in entry order. An order whose cancel
// was held during the freeze ('P' sent) cancels with reason 'U'.
template <class S>
void Engine::cancel_pending(Out<S>& o, Locate l, CrossType which, CR why, bool held) {
  SymbolInfo& y = symbols_[l];
  for (Handle h = y.pend_head; h != kNil;) {
    const Handle nx = book_.next(h);
    const Order& r = book_.at(h);
    if (r.cross == which || (held && r.has(Order::kHeld)))
      cancel_whole(o, h, r.has(Order::kCancelPending) ? CR::UserRequested : why);
    h = nx;
  }
}

// After the opening cross, held early market-hours orders join the book with
// the time priority they were accepted with, and appear on ITCH ('A'/'F') at
// the cross timestamp (R2 D1.2). Post-only applies as on entry.
template <class S>
void Engine::post_held(Out<S>& o, Locate l) {
  SymbolInfo& y = symbols_[l];
  for (Handle h = y.pend_head; h != kNil;) {
    const Handle nx = book_.next(h);
    Order& r = book_.at(h);
    if (!r.has(Order::kHeld)) {
      h = nx;
      continue;
    }
    if (r.has(Order::kCancelPending)) {
      cancel_whole(o, h, CR::UserRequested);
      h = nx;
      continue;
    }
    if (r.post_only() && y.halt == HaltPhase::None) {
      const PostOnlyResult po = post_only_check(l, r.side, r.px, sessions_[r.session]);
      if (po.kind == PostOnlyResult::Cancel) {
        cancel_whole(o, h, po.reason);
        h = nx;
        continue;
      }
      if (po.kind == PostOnlyResult::Slid) r.px = po.px;
    }
    list_unlink(y.pend_head, y.pend_tail, h);
    r.where = Where::Book;
    r.flags = static_cast<std::uint16_t>(r.flags & ~Order::kHeld);
    book_.insert_by_prio(h);
    itch_add(o, r);
    h = nx;
  }
}

// One ITCH 'I' (R2 D2.6). EOII: Far = Near = 0 and PVI blank. Halt NOII:
// Far = Near = CRP = the halt cross price, or 0 with a market order imbalance.
template <class S>
void Engine::emit_noii(Out<S>& o, Locate l, CrossKind k, bool eoii) {
  NoiiValues v;
  if (k == CrossKind::Halt) {
    const CrossResult r = compute_cross(l, CrossKind::Halt, false, false);
    if (r.valid && !interest_.empty()) {  // no interest at all: 'O' and zeros
      v.paired = r.volume;
      v.imbalance = r.imbalance;
      v.direction = r.side;
      // The prices are omitted while market orders would stay unexecuted (R2 D2.3).
      if (!r.market_unexecuted) v.far = v.near = v.crp = r.price;
    }
  } else {
    v = noii_values(l, k, eoii);
  }
  itch50::Noii m{};
  m.paired_shares = v.paired;
  m.imbalance_shares = v.imbalance;
  m.imbalance_direction = static_cast<itch50::ImbalanceDirection>(v.direction);
  m.stock = symbols_[l].symbol;
  m.far_price = v.far;
  m.near_price = v.near;
  m.current_reference_price = v.crp;
  m.cross_type = static_cast<itch50::NoiiCrossType>(static_cast<char>(k));
  m.price_variation_indicator = static_cast<itch50::PriceVariation>(eoii ? ' ' : price_variation(v.near, v.crp));
  itch(o, m, l);
}

// A halt state change with its ITCH 'H'; midpoint pegs cancel when a halt is
// declared (R2 D1.1).
template <class S>
void Engine::enter_halt(Out<S>& o, Locate l, HaltPhase phase, HaltKind kind, const Alpha<4>& reason) {
  SymbolInfo& y = symbols_[l];
  y.halt = phase;
  y.halt_kind = kind;
  y.reason = reason;
  y.ticks = 0;
  y.period = 0;
  y.extension = 0;
  y.arp = y.collar_lo = y.collar_hi = y.collar_step = 0;
  y.limit_ticks = -1;
  const char state = phase == HaltPhase::Halted ? 'H' : (phase == HaltPhase::Paused ? 'P' : 'Q');
  itch_trading_action(o, l, state, reason);
  cancel_pegs(o, l, CR::HaltedAfterOpen);
}

// A display-only period (news resumption, LULD pause, MWCB reopening): ITCH
// 'H' Q (P for LULD), the collars, and ITCH 'J' for news and LULD (R2 D2.7).
// It lasts LuldPauseSec for a LULD pause and HaltPeriodSec otherwise.
template <class S>
void Engine::start_display_period(Out<S>& o, Locate l, HaltKind kind, PxE4 arp) {
  SymbolInfo& y = symbols_[l];
  const Alpha<4> reason = kind == HaltKind::Luld ? Alpha<4>("LUDP") : y.reason;
  enter_halt(o, l, kind == HaltKind::Luld ? HaltPhase::Paused : HaltPhase::QuoteOnly, kind, reason);
  y.period = static_cast<std::uint32_t>(kind == HaltKind::Luld ? params_.luld_pause : params_.halt_period);
  set_collars(l, kind, arp);
  if ((kind == HaltKind::News || kind == HaltKind::Luld) && y.collar_hi > 0) emit_collars(o, l);
}

template <class S>
void Engine::emit_collars(Out<S>& o, Locate l) {
  const SymbolInfo& y = symbols_[l];
  itch50::LuldAuctionCollar j{};
  j.stock = y.symbol;
  j.reference_price = y.arp;
  j.upper_price = y.collar_hi;
  j.lower_price = y.collar_lo;
  j.extension = y.extension;
  itch(o, j, l);
}

// Per symbol, per 1 Hz tick.
template <class S>
void Engine::symbol_tick(Out<S>& o, Locate l) {
  SymbolInfo& y = symbols_[l];
  if (y.halt == HaltPhase::Halted && y.halt_kind == HaltKind::Mwcb && mwcb_breached_ < 3) {
    // The Level 1/2 halt ends after MwcbPeriodSec; ARP = last sale, else prior close.
    if (++y.ticks >= y.period) {
      y.reason = Alpha<4>("MWCQ");
      start_display_period(o, l, HaltKind::Mwcb, y.last_sale > 0 ? y.last_sale : y.prior_close);
    }
    return;
  }
  if (display_only(y.halt)) {
    ++y.ticks;
    emit_noii(o, l, CrossKind::Halt, false);
    if (y.halt == HaltPhase::IpoQuote) return;
    const CrossResult r = compute_cross(l, CrossKind::Halt, false, false);
    if (y.halt == HaltPhase::IpoPreLaunch) {
      // Release needs every market order to execute and the price within the
      // underwriter's band of the Expected Price (R2 D2.4).
      const PxE4 d = r.price > y.ipo_expected ? r.price - y.ipo_expected : y.ipo_expected - r.price;
      if (!r.valid || (!r.market_unexecuted && d <= y.ipo_band)) resume(o, l, r);
      return;
    }
    const bool inside = y.collar_hi == 0 || (r.price >= y.collar_lo && r.price <= y.collar_hi);
    const bool ok = !r.valid || (!r.market_unexecuted && inside);
    if (y.ticks >= y.period) {
      if (ok) {
        resume(o, l, r);
        return;
      }
      ++y.extension;
      widen_collars(l, r.side);
      y.ticks = 0;
      y.period = static_cast<std::uint32_t>(params_.extension);
      if (y.halt_kind == HaltKind::News || y.halt_kind == HaltKind::Luld) emit_collars(o, l);
    } else if (y.extension >= 2 && ok && r.imbalance == 0) {
      resume(o, l, r);  // from the third period: release at the first NOII with no imbalance
    }
    return;
  }
  if (y.halt == HaltPhase::None && session_ == Session::Regular && y.luld_hi > 0) {
    // LULD limit state (NBO at the lower band or NBB at the upper band, NBBO :=
    // own BBO); a Trading Pause when it lasts LimitStateSec (R2 D3.1).
    const PxE4 ask = book_.displayed_best(l, Side::Sell);
    const PxE4 bid = book_.displayed_best(l, Side::Buy);
    char side = 0;
    if (ask > 0 && ask <= y.luld_lo) {
      side = 'S';
    } else if (bid > 0 && bid >= y.luld_hi) {
      side = 'B';
    }
    if (side == 0) {
      y.limit_ticks = -1;
    } else if (++y.limit_ticks >= params_.limit_state) {
      start_display_period(o, l, HaltKind::Luld, side == 'S' ? y.luld_lo : y.luld_hi);
    }
  }
}

// Resumption: the halt cross at `r` (executions and a 'Q' when shares cross),
// ITCH 'H' T at the same timestamp, unexecuted halt-cross orders cancel
// (reason 'I'), and any lock or cross left is uncrossed.
template <class S>
void Engine::resume(Out<S>& o, Locate l, const CrossResult& r) {
  SymbolInfo& y = symbols_[l];
  execute_cross(o, l, CrossKind::Halt, r, y.halt_kind == HaltKind::Ipo);
  itch_trading_action(o, l, 'T', Alpha<4>{});
  y.halt = HaltPhase::None;
  y.halt_kind = HaltKind::None;
  y.reason = Alpha<4>{};
  y.ticks = y.period = y.extension = 0;
  y.arp = y.collar_lo = y.collar_hi = y.collar_step = 0;
  y.ipo_band = y.ipo_expected = 0;
  cancel_pending(o, l, CrossType::HaltIpo, CR::ImmediateOrCancel, false);
  uncross(o, l);
}

}  // namespace lle::engine

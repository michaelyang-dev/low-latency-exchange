#pragma once
// Continuous matching (05 §4 steps 4-5), placement of accepted orders, the
// uncross sweep, reserve refreshes, midpoint pegs and order removal with its
// reporting. Included by engine.h.

namespace lle::engine {

// After the 'A' (or 'U'): where the order goes (Engine::Route, from the gate).
template <class S>
void Engine::place(Out<S>& o, const OrderSpec& sp, Route route, Taker& t, OrderRef ref, PxE4 px, PostOnlyResult po) {
  if (t.rem == 0) return;
  switch (route) {
    case Route::Cross:
    case Route::Held: {
      const Handle h = new_order(sp, t, ref, px, o.idx);
      Order& r = book_.at(h);
      r.where = Where::Pending;
      if (route == Route::Held) r.flags = static_cast<std::uint16_t>(r.flags | Order::kHeld);
      SymbolInfo& y = symbols_[t.locate];
      list_append(y.pend_head, y.pend_tail, h);
      return;
    }
    case Route::RestOnly: (void)rest_on_book(o, sp, t, ref, px); return;
    case Route::Peg:
    case Route::Match: break;
  }
  if (po.kind == PostOnlyResult::Cancel) return;  // 'A'/'U' with Order State Dead says it all
  const Stop st = match(o, t);
  finish(o, t, sp, ref, px, st);
  if (!refresh_.empty()) run_refreshes(o);
}

// The opposite interest a taker would meet, in execution order, without
// changing anything: the book levels by price (displayed, then non-displayed,
// FIFO), with the midpoint pegs that accept mid placed before the first level
// priced worse than mid (book orders first at an equal price). Stops at the
// limit and the LULD bands. f(handle) returns false to stop. The midpoint is
// the one at the start of the walk (it does not move while a taker executes).
template <class F>
void Engine::scan(const Taker& t, F&& f) const {
  const Side opp = opposite(t.side);
  const std::size_t sd = opp == Side::Buy ? 0 : 1;
  const SymbolInfo& y = symbols_[t.locate];
  bool active = false;
  const PxE4 mid = y.peg_head[sd] != kNil ? midpoint(t.locate, active) : 0;  // no pegs: no midpoint needed
  bool pegs = active && crosses(t.side, mid, t.limit) && in_band(t, mid);
  auto visit_pegs = [&]() -> bool {
    for (Handle h = y.peg_head[sd]; h != kNil; h = book_.next(h))
      if (peg_eligible(book_.at(h), mid) && !f(h)) return false;
    return true;
  };
  const std::size_t n = book_.level_count(t.locate, opp);
  for (std::size_t k = 0; k < n; ++k) {
    const BookLevel* lv = book_.level_at_rank(t.locate, opp, k);
    if (pegs && worse(t.side, lv->px, mid)) {
      pegs = false;
      if (!visit_pegs()) return;
    }
    if (!crosses(t.side, lv->px, t.limit) || !in_band(t, lv->px)) break;
    for (int c = 0; c < 2; ++c)
      for (Handle h = lv->q[c].head; h != kNil; h = book_.next(h))
        if (!f(h)) return;
  }
  if (pegs) (void)visit_pegs();
}

// Step 4: the aggressor walks the opposite side best-first, displayed then
// non-displayed FIFO within a level, executing at the resting price, within
// the LULD bands when they are set; midpoint pegs execute at mid where scan()
// places them. A peg taker needs an active midpoint; a MinQty taker needs
// MinQty shares of available contra interest (aggregate), else nothing executes.
template <class S>
Engine::Stop Engine::match(Out<S>& o, Taker& t) {
  const Side opp = opposite(t.side);
  const std::size_t psd = opp == Side::Buy ? 0 : 1;
  bool active = false;
  const PxE4 mid = t.peg || symbols_[t.locate].peg_head[psd] != kNil ? midpoint(t.locate, active) : 0;
  if (t.peg && !active) return Stop::Exhausted;
  if (t.min_qty > 0 && available(t) < t.min_qty) return Stop::Exhausted;
  const bool pegs_ok = active && symbols_[t.locate].peg_head[psd] != kNil && crosses(t.side, mid, t.limit) &&
                       in_band(t, mid);
  while (t.rem > 0) {
    Handle ph = kNil;
    if (pegs_ok) {
      for (Handle h = symbols_[t.locate].peg_head[psd]; h != kNil; h = book_.next(h)) {
        if (peg_eligible(book_.at(h), mid)) {
          ph = h;
          break;
        }
      }
    }
    BookLevel* lv = book_.best(t.locate, opp);
    const bool level_ok = lv != nullptr && crosses(t.side, lv->px, t.limit) && in_band(t, lv->px);
    if (ph != kNil && (!level_ok || worse(t.side, lv->px, mid))) {
      if (self_match(t, book_.at(ph))) {
        if (smp_event(o, t, ph, LF::MidpointAdded, mid)) return Stop::SmpNewest;
        continue;
      }
      fill(o, t, ph, std::min(t.rem, book_.at(ph).leaves), mid, LF::MidpointAdded);
      continue;
    }
    if (lv == nullptr) return Stop::Exhausted;
    if (!level_ok) return Stop::Limit;
    const int cls = lv->q[kDisplayed].head != kNil ? kDisplayed : kHidden;
    const Handle h = lv->q[cls].head;
    const LF rflag = resting_flag(book_.at(h));
    if (self_match(t, book_.at(h))) {
      if (smp_event(o, t, h, rflag, lv->px)) return Stop::SmpNewest;
      continue;
    }
    const Qty f = std::min(t.rem, book_.at(h).leaves);
    fill(o, t, h, f, lv->px, rflag);
  }
  return Stop::Filled;
}

// One continuous execution of the aggressor `t` against resting order h at px.
template <class S>
void Engine::fill(Out<S>& o, Taker& t, Handle h, Qty f, PxE4 px, LF rflag) {
  const Order& r = book_.at(h);
  const MatchNo mn = next_match_++;
  executed(o, r.session, r.urn, r.user_ref_idx, f, px, rflag, mn);
  executed(o, t.session, t.urn, t.idx, f, px, t.peg ? LF::MidpointRemoved : LF::Removed, mn);
  if (r.where == Where::Book && r.cls() == kDisplayed) {
    itch50::OrderExecuted e{};
    e.order_ref = r.itch_ref;
    e.executed_shares = f;
    e.match_number = mn;
    itch(o, e, t.locate);
  } else {
    itch50::Trade tr{};  // non-displayed fills: ref 0, side 'B' (R2 D1.2)
    tr.order_ref = 0;
    tr.side = Side::Buy;
    tr.shares = f;
    tr.stock = symbols_[t.locate].symbol;
    tr.price = px;
    tr.match_number = mn;
    itch(o, tr, t.locate);
  }
  t.rem -= f;
  t.done += f;
  consume(h, f);
  after_execution(o, t.locate, px);
}

// A self-match against resting order h at price px (Rule 4757(a)(4)); true
// when the aggressor was cancelled (cancel newest) and the walk must stop.
template <class S>
bool Engine::smp_event(Out<S>& o, Taker& t, Handle h, LF rflag, PxE4 px) {
  const Order& r = book_.at(h);
  if (t.smp.action == SmpAction::CancelNewest) {
    if (!t.dead) canceled(o, t.session, t.urn, t.idx, t.rem, CR::SelfMatchPrevention);
    t.rem = 0;
    return true;
  }
  if (t.smp.action == SmpAction::CancelOldest) {
    cancel_whole(o, h, CR::SelfMatchPrevention);
    return false;
  }
  const Qty d = std::min(t.rem, r.leaves);
  smp_notice(o, r.session, r.urn, r.user_ref_idx, d, px, rflag, t);
  if (!t.dead) smp_notice(o, t.session, t.urn, t.idx, d, px, t.peg ? LF::MidpointRemoved : LF::Removed, t);
  if (r.where == Where::Book && r.cls() == kDisplayed) itch_reduce(o, r, d);
  t.rem -= d;
  t.done += d;
  consume(h, d);
  return false;
}

// Step 5: IOC and market remainders cancel ('I', or 'K' when a market order
// stopped at its collar); a peg rests in its symbol's peg list; anything else
// rests at the back of its queue.
template <class S>
void Engine::finish(Out<S>& o, Taker& t, const OrderSpec& sp, OrderRef ref, PxE4 px, Stop st) {
  if (t.rem == 0) return;
  if (sp.tif == Tif::Ioc || sp.market) {
    const CR why = sp.market && st == Stop::Limit ? CR::MarketCollars : CR::ImmediateOrCancel;
    if (!t.dead) canceled(o, t.session, t.urn, t.idx, t.rem, why);
    return;
  }
  if (sp.peg == PegType::MidpointPeg) {
    const Handle h = new_order(sp, t, ref, sp.px, o.idx);
    Order& r = book_.at(h);
    r.where = Where::Peg;
    SymbolInfo& y = symbols_[t.locate];
    const std::size_t sd = r.side == Side::Buy ? 0 : 1;
    list_append(y.peg_head[sd], y.peg_tail[sd], h);
    return;
  }
  (void)rest_on_book(o, sp, t, ref, px);
}

// A resting order on the book with its ITCH 'A'/'F'. A reserve order (MaxFloor)
// shows its display size; the rest is a second record in the non-displayed
// queue at the same price with the order's own time priority.
template <class S>
Handle Engine::rest_on_book(Out<S>& o, const OrderSpec& sp, const Taker& t, OrderRef ref, PxE4 px) {
  const Handle h = new_order(sp, t, ref, px, o.idx);
  if (sp.max_floor != 0) {
    const Qty lot = symbols_[t.locate].round_lot;
    const Qty disp = sp.max_floor / lot * lot;
    if (book_.at(h).leaves > disp) {
      const Qty reserve = book_.at(h).leaves - disp;
      book_.at(h).leaves = disp;  // the open notional already counts both parts
      const Handle c = book_.alloc();
      Order& k = book_.at(c);
      k = book_.at(h);
      k.flags = static_cast<std::uint16_t>(k.flags | Order::kReserveChild);
      k.display = Display::Hidden;
      k.leaves = reserve;
      k.done = 0;      // executions count on the parent
      k.itch_ref = 0;  // never on ITCH
      k.peer = h;
      book_.at(h).peer = c;
      book_.insert(c);
    }
  }
  book_.insert(h);
  itch_add(o, book_.at(h));
  return h;
}

// q shares of resting record h executed or self-match decremented. The
// order-level `done` lives on the parent of a reserve order. A reserve parent
// whose displayed slice falls below a round lot is queued for a refresh; one
// with no display left leaves its queue until then (Where::Off).
inline void Engine::consume(Handle h, Qty q) {
  Order& r = book_.at(h);
  if (r.has(Order::kReserveChild)) {
    book_.at(r.peer).done += q;
    if (q == r.leaves) {
      remove_order(h);
    } else {
      take_leaves(h, q);
    }
    return;
  }
  r.done += q;
  if (r.peer == kNil) {
    if (q == r.leaves) {
      if (r.has(Order::kRefresh)) std::erase(refresh_, h);
      remove_order(h);
    } else {
      take_leaves(h, q);
    }
    return;
  }
  if (q == r.leaves) {
    risk_.open_delta(r.account, r.locate, -i128{q} * r.risk_px);
    book_.unlink(h);
    r.leaves = 0;
    r.where = Where::Off;
  } else {
    take_leaves(h, q);
  }
  if (r.leaves < symbols_[r.locate].round_lot && !r.has(Order::kRefresh)) {
    r.flags = static_cast<std::uint16_t>(r.flags | Order::kRefresh);
    refresh_.push_back(h);
  }
}

// Reserve refresh (Rule 4703(h); R2 D1.1/D1.3): after the taker (or cross, or
// uncross sweep) that drew a displayed slice below a round lot, the display is
// topped up to its size from the reserve with a new time priority (back of the
// displayed queue) and a new ITCH reference: ITCH 'D' for an odd-lot remainder,
// then 'A'/'F', and OUCH 'R' reason 'R' with SecondaryOrdRefNum = the new ITCH
// reference and DisplayQuantity. A slice with no reserve left stays (or, when
// empty, completes the order).
template <class S>
void Engine::run_refreshes(Out<S>& o) {
  for (std::size_t i = 0; i < refresh_.size(); ++i) {
    const Handle h = refresh_[i];
    Order& r = book_.at(h);
    r.flags = static_cast<std::uint16_t>(r.flags & ~Order::kRefresh);
    const Qty lot = symbols_[r.locate].round_lot;
    if (r.peer == kNil) {
      if (r.leaves == 0) remove_order(h);
      continue;
    }
    if (r.leaves >= lot) continue;
    const Handle ch = r.peer;
    const Qty disp = r.max_floor / lot * lot;
    const Qty add = std::min<Qty>(disp - r.leaves, book_.at(ch).leaves);
    if (r.where == Where::Book) {
      if (itch_visible(r.display)) itch_delete(o, r.locate, r.itch_ref);
      book_.unlink(h);
    }
    // Shares move from the reserve record to the display: open notional unchanged.
    if (add == book_.at(ch).leaves) {
      remove_order(ch);
    } else {
      take_leaves(ch, add);
    }
    risk_.open_delta(r.account, r.locate, i128{add} * r.risk_px);
    r.leaves += add;
    r.itch_ref = next_ref_++;
    r.prio = o.idx;
    r.where = Where::Book;
    book_.insert(h);
    itch_add(o, r);
    ouch50::out::OrderRestated m{};
    m.user_ref_num = r.urn;
    m.reason = ouch50::RestatedReason::DisplayRefresh;
    TagSet tags;
    tags.set_secondary_ord_ref_num(r.itch_ref);
    tags.set_display_quantity(r.leaves);
    if (r.user_ref_idx != 0) tags.set_user_ref_idx(r.user_ref_idx);
    ouch_tags(o, r.session, m, tags);
  }
  refresh_.clear();
}

// A user decrease of d shares (not all of them): the reserve goes first, then
// the displayed slice ('X'); priority is kept (keeps_priority(Change::Decrease)).
template <class S>
void Engine::reduce_total(Out<S>& o, Handle h, Qty d) {
  Order& r = book_.at(h);
  if (r.peer != kNil) {
    const Handle ch = r.peer;
    const Qty k = std::min(d, book_.at(ch).leaves);
    if (k == book_.at(ch).leaves) {
      remove_order(ch);
    } else {
      take_leaves(ch, k);
    }
    d -= k;
  }
  if (d == 0) return;
  if (r.where == Where::Book && itch_visible(r.display)) itch_reduce(o, r, d);
  take_leaves(h, d);
}

// Takes d shares out of an order (not all of them); it keeps its priority.
template <class S>
void Engine::reduce_order(Out<S>& o, Handle h, Qty d) {
  (void)o;
  take_leaves(h, d);
}

// Full cancel of an order: 'C' to its session, ITCH 'D' if it is displayed on
// the book. A reserve record stands for its whole order.
template <class S>
void Engine::cancel_whole(Out<S>& o, Handle h, CR why) {
  if (book_.at(h).has(Order::kReserveChild)) h = book_.at(h).peer;
  const Order& r = book_.at(h);
  canceled(o, r.session, r.urn, r.user_ref_idx, total_leaves(h), why);
  if (r.where == Where::Book && itch_visible(r.display)) itch_delete(o, r.locate, r.itch_ref);
  if (r.has(Order::kRefresh)) std::erase(refresh_, h);  // queued for a refresh
  remove_order(h);
}

// Last sale; Rule 201: an execution at or below 90% of the prior close turns
// the short sale price test on for the day ('Y' '1').
template <class S>
void Engine::after_execution(Out<S>& o, Locate l, PxE4 px) {
  SymbolInfo& y = symbols_[l];
  y.last_sale = px;
  y.last_sale_ns = static_cast<Nanos>(o.ts);
  if (y.regsho == '0' && y.prior_close > 0 && px * 10 <= y.prior_close * 9) {
    y.regsho = '1';
    itch50::RegShoRestriction m{};
    m.stock = y.symbol;
    m.reg_sho_action = static_cast<itch50::RegShoAction>('1');
    itch(o, m, l);
  }
}

template <class S>
void Engine::cancel_pegs(Out<S>& o, Locate l, CR why) {
  SymbolInfo& y = symbols_[l];
  for (int sd = 0; sd < 2; ++sd) {
    for (Handle h = y.peg_head[static_cast<std::size_t>(sd)]; h != kNil;) {
      const Handle nx = book_.next(h);
      cancel_whole(o, h, why);
      h = nx;
    }
  }
  y.peg_pulled = 0;
}

// Midpoint pegs with no valid midpoint (no bid or offer, or locked/crossed)
// are pulled; if the next 1 Hz tick still finds them pulled they are cancelled
// ('Z') (R2 D1.1: cancelled if no valid price within 1 s).
template <class S>
void Engine::peg_tick(Out<S>& o, Locate l) {
  SymbolInfo& y = symbols_[l];
  if (y.peg_head[0] == kNil && y.peg_head[1] == kNil) {
    y.peg_pulled = 0;
    return;
  }
  bool active = false;
  (void)midpoint(l, active);
  if (active) {
    y.peg_pulled = 0;
  } else if (y.peg_pulled == 0) {
    y.peg_pulled = 1;
  } else {
    cancel_pegs(o, l, CR::System);
  }
}

// After a period without matching (the open, a halt) the book may be locked
// or crossed: the front orders of the best bid and offer execute against each
// other until it is not. The earlier order (by time priority) is the resting
// side and sets the price; the later one is reported like an aggressor, and
// on ITCH it prints as 'C' Printable=N at the execution price (its own
// displayed order), so each trade is printed once (by the 'E' or 'P' of the
// earlier side). Self-match prevention applies with the later order's strategy.
template <class S>
void Engine::uncross(Out<S>& o, Locate l) {
  for (;;) {
    BookLevel* bl = book_.best(l, Side::Buy);
    BookLevel* al = book_.best(l, Side::Sell);
    if (bl == nullptr || al == nullptr || bl->px < al->px) break;
    const Handle bh = bl->q[kDisplayed].head != kNil ? bl->q[kDisplayed].head : bl->q[kHidden].head;
    const Handle ah = al->q[kDisplayed].head != kNil ? al->q[kDisplayed].head : al->q[kHidden].head;
    const Order& b = book_.at(bh);
    const Order& a = book_.at(ah);
    const bool buy_first = b.prio < a.prio || (b.prio == a.prio && b.ref < a.ref);
    const Handle eh = buy_first ? bh : ah;  // earlier: the resting side
    const Handle lh = buy_first ? ah : bh;  // later: reported as the aggressor
    const Order& e = book_.at(eh);
    const Order& lt = book_.at(lh);
    const LF eflag = resting_flag(e);
    Taker t;
    t.locate = l;
    t.side = lt.side;
    t.account = lt.account;
    t.session = lt.session;
    t.urn = lt.urn;
    t.idx = lt.user_ref_idx;
    t.firm = lt.firm;
    t.aiq = lt.aiq;
    t.aiq_group = lt.aiq_group;
    t.smp = smp_of(lt.aiq);
    t.rem = lt.leaves;
    if (self_match(t, e)) {
      if (t.smp.action == SmpAction::CancelNewest) {
        cancel_whole(o, lh, CR::SelfMatchPrevention);
      } else if (t.smp.action == SmpAction::CancelOldest) {
        cancel_whole(o, eh, CR::SelfMatchPrevention);
      } else {
        const Qty d = std::min(e.leaves, lt.leaves);
        smp_notice(o, e.session, e.urn, e.user_ref_idx, d, e.px, eflag, t);
        smp_notice(o, lt.session, lt.urn, lt.user_ref_idx, d, e.px, LF::Removed, t);
        if (e.cls() == kDisplayed) itch_reduce(o, e, d);
        if (lt.cls() == kDisplayed) itch_reduce(o, lt, d);
        consume(eh, d);
        consume(lh, d);
      }
      continue;
    }
    const PxE4 px = e.px;
    const Qty q = std::min(e.leaves, lt.leaves);
    const MatchNo mn = next_match_++;
    executed(o, e.session, e.urn, e.user_ref_idx, q, px, eflag, mn);
    executed(o, lt.session, lt.urn, lt.user_ref_idx, q, px, LF::Removed, mn);
    if (e.cls() == kDisplayed) {
      itch50::OrderExecuted x{};
      x.order_ref = e.itch_ref;
      x.executed_shares = q;
      x.match_number = mn;
      itch(o, x, l);
    } else {
      itch50::Trade x{};
      x.order_ref = 0;
      x.side = Side::Buy;
      x.shares = q;
      x.stock = symbols_[l].symbol;
      x.price = px;
      x.match_number = mn;
      itch(o, x, l);
    }
    if (lt.cls() == kDisplayed) {
      itch50::OrderExecutedWithPrice c{};
      c.order_ref = lt.itch_ref;
      c.executed_shares = q;
      c.match_number = mn;
      c.printable = itch50::YesNo::No;
      c.execution_price = px;
      itch(o, c, l);
    }
    consume(eh, q);
    consume(lh, q);
    after_execution(o, l, px);
  }
  if (!refresh_.empty()) run_refreshes(o);
}

}  // namespace lle::engine

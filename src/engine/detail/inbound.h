#pragma once
// OUCH inbound handling (05 §4 steps 1-2, 6-8): the UserRefNum filter,
// validation, Enter, Replace, Cancel, Modify, Mass Cancel, Disable/Enable,
// Account Query and cancel-on-disconnect. Included by engine.h.

namespace lle::engine {

template <class S>
void Engine::on_ouch(Out<S>& o, std::span<const std::byte> p, bool malformed) {
  const auto in = parse_ouch_inbound(p);
  if (!in) {
    audit(o, AuditCode::MalformedPayload, 0, 0);
    return;
  }
  const Handle sh = sess_index_->find(in->hdr.session_id);
  if (sh == kNil) {
    audit(o, AuditCode::UnknownSession, in->hdr.session_id, 0);
    return;
  }
  const std::uint32_t s = sh;
  const std::uint32_t a = sessions_[s].account;
  if (accounts_[a].id != in->hdr.account) {
    audit(o, AuditCode::AccountMismatch, in->hdr.session_id, in->hdr.account);
    return;
  }
  started_ = true;
  const std::span<const std::byte> msg = in->msg;
  const char type = msg.empty() ? '\0' : std::to_integer<char>(msg[0]);
  switch (type) {
    case 'O':
    case 'U':
    case 'C':
    case 'D':
    case 'E': on_consuming(o, s, a, type, msg, malformed); break;
    case 'X':
    case 'M':
    case 'Q': on_referencing(o, s, a, type, msg, malformed); break;
    default: audit(o, AuditCode::InvalidNoReject, sessions_[s].id, static_cast<std::uint64_t>(type)); break;
  }
}

// Step 1: messages that consume a new UserRefNum are filtered (a value at or
// below the last consumed one for (account, UserRefIdx) is a benign resend);
// step 2: a validation failure emits 'J' and consumes it (Replace excepted).
// A record the gateway flagged as truncated (kFlagMalformedInput) never validates.
template <class S>
void Engine::on_consuming(Out<S>& o, std::uint32_t s, std::uint32_t a, char type, std::span<const std::byte> msg,
                          bool malformed) {
  const auto urn = ouch50::peek_new_user_ref_num(msg);
  if (!urn) {
    audit(o, AuditCode::NoUserRefNum, sessions_[s].id, static_cast<std::uint64_t>(type));
    return;
  }
  const std::expected<ouch50::InboundView, RR> v =
      malformed ? std::expected<ouch50::InboundView, RR>(std::unexpected(RR::Other)) : ouch50::validate_inbound(msg);
  const std::uint8_t idx = v ? ouch50::peek_user_ref_idx(v->bytes()) : ouch50::peek_user_ref_idx(msg);
  UserRefNum& last = trackers_[a][idx];
  if (*urn <= last) {
    audit(o, AuditCode::Resend, sessions_[s].id, *urn);
    return;
  }
  if (type == 'U') {
    on_replace(o, s, a, msg, v, *urn, idx);
    return;
  }
  last = *urn;
  if (!v) {
    constexpr std::size_t kClOrdOff = 31;  // Enter Order ClOrdID (s2.1)
    const ClOrdId id = type == 'O' && msg.size() >= kClOrdOff + 14 ? ClOrdId::from_wire(msg.data() + kClOrdOff) : ClOrdId{};
    reject(o, s, *urn, idx, code(v.error()), id);
    return;
  }
  switch (type) {
    case 'O': on_enter(o, s, a, v->as<ouch50::in::EnterOrderView>(), *urn, idx); break;
    case 'C': on_mass_cancel(o, s, a, v->as<ouch50::in::MassCancelView>(), *urn, idx); break;
    case 'D': on_entry_switch(o, s, a, v->as<ouch50::in::DisableOrderEntryView>(), *urn, idx, true); break;
    default: on_entry_switch(o, s, a, v->as<ouch50::in::EnableOrderEntryView>(), *urn, idx, false); break;
  }
}

// Cancel 'X', Modify 'M' and Account Query 'Q' carry no new UserRefNum: never
// filtered; a validation failure has nothing to reject with, so it is dropped.
template <class S>
void Engine::on_referencing(Out<S>& o, std::uint32_t s, std::uint32_t a, char type, std::span<const std::byte> msg,
                            bool malformed) {
  const auto v = malformed ? std::expected<ouch50::InboundView, RR>(std::unexpected(RR::Other))
                           : ouch50::validate_inbound(msg);
  if (!v) {
    audit(o, AuditCode::InvalidNoReject, sessions_[s].id, static_cast<std::uint64_t>(type));
    return;
  }
  const std::uint8_t idx = ouch50::peek_user_ref_idx(v->bytes());
  switch (type) {
    case 'X': on_cancel(o, s, a, v->as<ouch50::in::CancelOrderView>(), idx); break;
    case 'M': on_modify(o, s, a, v->as<ouch50::in::ModifyOrderView>(), idx); break;
    default: {
      ouch50::out::AccountQueryResponse m{};
      m.next_user_ref_num = trackers_[a][idx] + 1;  // wraps to 0 after 0xFFFFFFFF: nothing can follow
      ouch(o, s, m, idx);
      break;
    }
  }
}

// ---------------------------------------------------------------------------- Enter

template <class S>
void Engine::on_enter(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::EnterOrderView& v, UserRefNum urn,
                      std::uint8_t idx) {
  const SessionInfo& si = sessions_[s];
  TagSet tags;
  (void)ouch50::parse_tags(v.tags(), tags);
  OrderSpec sp;
  sp.marking = v.side();
  sp.side = book_side(sp.marking);
  sp.qty = v.quantity();
  sp.market = ouch50::classify_price(v.price()) == ouch50::PriceKind::Market;
  sp.px = sp.market ? 0 : static_cast<PxE4>(v.price());
  sp.tif = v.time_in_force();
  sp.display = v.display();
  sp.capacity = v.capacity();
  sp.iso = v.inter_market_sweep_eligibility();
  sp.cross = v.cross_type();
  sp.cl_ord_id = v.cl_ord_id();
  sp.post_only = tags.has(Tag::PostOnly) && tags.post_only == ouch50::PostOnly::PostOnly;
  sp.firm = tags.has(Tag::Firm) ? tags.firm : accounts_[a].default_firm();
  sp.group_id = tags.has(Tag::GroupID) ? tags.group_id : std::uint16_t{0};
  sp.aiq = resolve_aiq(tags.has(Tag::AIQStrategy) ? tags.aiq_strategy : AiqMode::PortDefault, si);
  sp.aiq_group = tags.has(Tag::AIQGroupID) ? tags.aiq_group_id : AiqGroup{};
  sp.expire_time = tags.has(Tag::ExpireTime) ? tags.expire_time : 0;
  sp.has_expire = tags.has(Tag::ExpireTime);
  sp.handle_inst = tags.has(Tag::HandleInst) ? tags.handle_inst : HandleInst::None;
  sp.peg = tags.has(Tag::PriceType) ? tags.price_type : PegType::Limit;
  sp.min_qty = tags.has(Tag::MinQty) ? tags.min_qty : 0;
  sp.max_floor = tags.has(Tag::MaxFloor) ? tags.max_floor : 0;
  sp.shares_located = tags.has(Tag::SharesLocated) && tags.shares_located == ouch50::SharesLocated::Yes;
  sp.user_ref_idx = idx;
  sp.urn = urn;

  const Locate l = find_symbol(v.symbol());
  Route route = Route::Match;
  std::uint16_t r = 0;
  if (l == 0) {
    r = code(RR::InvalidSymbol);
  } else if ((tags.has(Tag::Firm) && !authorized(a, sp.firm)) || disabled(a, sp.firm) || risk_.killed(a)) {
    r = code(RR::FirmNotAuthorized);
  } else {
    r = check_order(sp, tags, si, l, false, route);
  }
  if (r == 0) {
    RiskRequest rq;
    rq.account = a;
    rq.session = s;
    rq.locate = l;
    rq.marking = sp.marking;
    rq.qty = sp.qty;
    rq.open = sp.qty;
    rq.px = sp.market ? 0 : sp.px;
    rq.market = sp.market;
    rq.cross = sp.cross != CrossType::Continuous;
    rq.located = sp.shares_located;
    rq.content = dup_content(l, sp.marking, sp.qty, v.price(), sp.tif, sp.display, sp.cross);
    r = risk_.check(rq, risk_quote(l, sp.side), static_cast<std::int64_t>(o.ts), &sp.risk_px);
  }
  if (r != 0) {
    reject(o, s, urn, idx, r, sp.cl_ord_id);
    return;
  }

  const OrderRef ref = next_ref_++;
  Taker t = make_taker(sp, l, a, s);
  t.rem = sp.qty;
  PostOnlyResult po{};
  PxE4 px = sp.px;
  bool dead = false;
  if (route == Route::Match || route == Route::Peg) {
    if (sp.post_only) po = post_only_check(l, sp.side, sp.px, si);
    if (po.kind == PostOnlyResult::Slid) px = po.px;
    t.limit = sp.market ? collar_limit(l, sp.side) : (t.peg ? peg_limit(l, sp.side, px) : px);
    dead = po.kind == PostOnlyResult::Cancel || dead_on_arrival(t, sp.tif == Tif::Ioc || sp.market);
  }
  t.dead = dead;
  ouch50::out::OrderAccepted m{};
  m.user_ref_num = urn;
  m.side = sp.marking;
  m.quantity = sp.qty;
  m.symbol = v.symbol();
  m.price = sp.market ? v.price() : static_cast<std::uint64_t>(px);
  m.time_in_force = sp.tif;
  m.display = sp.display;
  m.order_reference_number = ref;
  m.capacity = sp.capacity;
  m.inter_market_sweep_eligibility = sp.iso;
  m.cross_type = sp.cross;
  m.order_state = dead ? ouch50::OrderState::Dead : ouch50::OrderState::Live;
  m.cl_ord_id = sp.cl_ord_id;
  TagSet echo = tags;
  echo.present &= ouch50::out::OrderAccepted::kAllowedTags;
  ouch_tags(o, s, m, echo);
  place(o, sp, route, t, ref, px, po);
}

// ---------------------------------------------------------------------------- Replace

// Outcomes (OUCH 5.0 §2.2, R2 D4.4): the original is not live -> ignored and
// the new UserRefNum is not consumed; invalid details -> the original is
// cancelled ('C' reason 'U'), not consumed; entry disabled -> 'J' 0x000C, a
// frozen cross order -> 'J' 0x0015 (consumed); otherwise 'U' Order Replaced.
template <class S>
void Engine::on_replace(Out<S>& o, std::uint32_t s, std::uint32_t a, std::span<const std::byte> msg,
                        const std::expected<ouch50::InboundView, RR>& v, UserRefNum nurn, std::uint8_t idx) {
  const UserRefNum ourn = load_be32(msg.data() + 1);
  const Handle oh = urn_->find(urn_key(a, idx, ourn));
  if (oh == kNil) {
    audit(o, AuditCode::UnknownOrder, sessions_[s].id, ourn);
    return;
  }
  const Order& old = book_.at(oh);
  if (frozen(old)) {
    trackers_[a][idx] = nurn;
    const ClOrdId id = v ? v->as<ouch50::in::ReplaceOrderView>().cl_ord_id() : ClOrdId{};
    reject(o, s, nurn, idx, code(RR::ReplaceNotAllowed), id);
    return;
  }
  if (!v) {
    cancel_whole(o, oh, CR::UserRequested);
    return;
  }
  const ouch50::in::ReplaceOrderView rv = v->as<ouch50::in::ReplaceOrderView>();
  if (disabled(a, old.firm) || risk_.killed(a)) {
    trackers_[a][idx] = nurn;
    reject(o, s, nurn, idx, code(RR::FirmNotAuthorized), rv.cl_ord_id());
    return;
  }
  TagSet tags;
  (void)ouch50::parse_tags(rv.tags(), tags);
  const SessionInfo& si = sessions_[s];
  // Symbol, firm, group, capacity, cross type and HandleInst are inherited;
  // optional attributes not restated in the request keep the original's values.
  OrderSpec sp;
  sp.side = old.side;
  sp.marking = tags.has(Tag::Side) ? tags.side : old.marking;
  sp.qty = rv.quantity();
  sp.market = ouch50::classify_price(rv.price()) == ouch50::PriceKind::Market;
  sp.px = sp.market ? 0 : static_cast<PxE4>(rv.price());
  sp.tif = rv.time_in_force();
  sp.display = rv.display();
  sp.capacity = old.capacity;
  sp.iso = rv.inter_market_sweep_eligibility();
  sp.cross = old.cross;
  sp.imbalance_only = old.has(Order::kImbalanceOnly);
  sp.cl_ord_id = rv.cl_ord_id();
  sp.post_only = tags.has(Tag::PostOnly) ? tags.post_only == ouch50::PostOnly::PostOnly : old.post_only();
  sp.firm = old.firm;
  sp.group_id = old.group_id;
  sp.aiq = tags.has(Tag::AIQStrategy) ? resolve_aiq(tags.aiq_strategy, si) : old.aiq;
  sp.aiq_group = tags.has(Tag::AIQGroupID) ? tags.aiq_group_id : old.aiq_group;
  sp.expire_time = tags.has(Tag::ExpireTime) ? tags.expire_time : old.expire_time;
  sp.has_expire = tags.has(Tag::ExpireTime) || old.has(Order::kHasExpire);
  sp.peg = tags.has(Tag::PriceType) ? tags.price_type : (old.has(Order::kMidPeg) ? PegType::MidpointPeg : PegType::Limit);
  sp.min_qty = tags.has(Tag::MinQty) ? tags.min_qty : old.min_qty;
  sp.max_floor = tags.has(Tag::MaxFloor) ? tags.max_floor : old.max_floor;
  sp.shares_located = tags.has(Tag::SharesLocated) ? tags.shares_located == ouch50::SharesLocated::Yes
                                                    : old.has(Order::kLocated);
  sp.user_ref_idx = idx;
  sp.urn = nurn;
  Route route = Route::Match;
  std::uint16_t r = 0;
  if (book_side(sp.marking) != old.side) r = code(RR::InvalidSide);
  if (r == 0) r = check_order(sp, tags, si, old.locate, true, route);
  if (r != 0) {
    cancel_whole(o, oh, CR::UserRequested);
    return;
  }
  trackers_[a][idx] = nurn;
  // Risk (05 §7): a failing replace is rejected ('J', UserRefNum consumed); the original stays.
  RiskRequest rq;
  rq.account = a;
  rq.session = s;
  rq.locate = old.locate;
  rq.marking = sp.marking;
  rq.qty = sp.qty;
  rq.open = sp.qty > old.done ? sp.qty - old.done : 0;
  rq.px = sp.market ? 0 : sp.px;
  rq.market = sp.market;
  rq.cross = sp.cross != CrossType::Continuous;
  rq.located = sp.shares_located;
  rq.replace = true;
  rq.old_open = i128{total_leaves(oh)} * old.risk_px;
  if (const std::uint16_t rc = risk_.check(rq, risk_quote(old.locate, sp.side), static_cast<std::int64_t>(o.ts), &sp.risk_px);
      rc != 0) {
    reject(o, s, nurn, idx, rc, rv.cl_ord_id());
    return;
  }
  do_replace(o, s, a, oh, sp, route, rv, tags);
}

// Quantity is the total liable over the replace chain (executions and
// self-match decrements included): the new order opens with Q - done.
template <class S>
void Engine::do_replace(Out<S>& o, std::uint32_t s, std::uint32_t a, Handle oh, OrderSpec sp, Route route,
                        const ouch50::in::ReplaceOrderView& rv, const TagSet& tags) {
  const Order old = book_.at(oh);
  const OrderRef nref = next_ref_++;
  const Qty leaves = sp.qty > old.done ? sp.qty - old.done : 0;
  remove_order(oh);
  const Locate l = old.locate;
  PostOnlyResult po{};
  if (leaves > 0 && route == Route::Match && sp.post_only) po = post_only_check(l, sp.side, sp.px, sessions_[s]);
  const PxE4 px = po.kind == PostOnlyResult::Slid ? po.px : sp.px;
  Taker t = make_taker(sp, l, a, s);
  t.limit = t.peg ? peg_limit(l, sp.side, px) : px;
  t.rem = leaves;
  t.done = old.done;
  bool dead = leaves == 0 || po.kind == PostOnlyResult::Cancel;
  bool touches = false;
  if (!dead && (route == Route::Match || route == Route::Peg)) {
    const Dry d = dry_run(t);
    dead = d == Dry::Gone || (d == Dry::Left && sp.tif == Tif::Ioc);
    // Any resting order the walk would meet means an interaction (an execution
    // or a self-match event), even when no execution follows.
    scan(t, [&](Handle) {
      touches = true;
      return false;
    });
  }
  t.dead = dead;
  // ITCH 'U' only when the new order rests untouched on the book with the same
  // attribution; otherwise the original is deleted first ('D') so the feed
  // never shows an aggressor, and a resting remainder is a fresh 'A'/'F'.
  const bool on_book_route = route == Route::Match || route == Route::RestOnly;
  const bool u_path = !dead && !touches && on_book_route && old.where == Where::Book && itch_visible(old.display) &&
                      sp.display == old.display && sp.max_floor == 0 && old.peer == kNil && old.max_floor == 0;

  ouch50::out::OrderReplaced m{};
  m.orig_user_ref_num = old.urn;
  m.user_ref_num = sp.urn;
  m.side = sp.marking;
  m.quantity = leaves;
  m.symbol = symbols_[l].symbol;
  m.price = sp.market ? rv.price() : static_cast<std::uint64_t>(px);
  m.time_in_force = sp.tif;
  m.display = sp.display;
  m.order_reference_number = nref;
  m.capacity = sp.capacity;
  m.inter_market_sweep_eligibility = sp.iso;
  m.cross_type = sp.cross;
  m.order_state = dead ? ouch50::OrderState::Dead : ouch50::OrderState::Live;
  m.cl_ord_id = rv.cl_ord_id();
  TagSet echo = tags;
  echo.present &= ouch50::out::OrderReplaced::kAllowedTags;
  ouch_tags(o, s, m, echo);

  if (u_path) {
    itch50::OrderReplace u{};
    u.original_order_ref = old.itch_ref;
    u.new_order_ref = nref;
    u.shares = leaves;
    u.price = px;
    itch(o, u, l);
    const Handle h = new_order(sp, t, nref, px, o.idx);
    book_.insert(h);
    return;
  }
  if (old.where == Where::Book && itch_visible(old.display)) itch_delete(o, l, old.itch_ref);
  place(o, sp, route, t, nref, px, po);
}

// ---------------------------------------------------------------------------- Cancel / Modify

// A frozen cross order (05 §4 step 3): a full cancel gets 'P' Cancel Pending
// and happens after the cross; a partial cancel or a modify gets 'I' Cancel
// Reject. Each at most once per order (OUCH 5.0 §3.9-3.10).
template <class S>
bool Engine::frozen_change(Out<S>& o, Handle h, bool full_cancel) {
  Order& r = book_.at(h);
  if (!frozen(r)) return false;
  if (full_cancel) {
    r.flags = static_cast<std::uint16_t>(r.flags | Order::kCancelPending);
    if (!r.has(Order::kPendingSent)) {
      r.flags = static_cast<std::uint16_t>(r.flags | Order::kPendingSent);
      ouch50::out::CancelPending m{};
      m.user_ref_num = r.urn;
      ouch(o, r.session, m, r.user_ref_idx);
    }
  } else if (!r.has(Order::kRejectSent)) {
    r.flags = static_cast<std::uint16_t>(r.flags | Order::kRejectSent);
    ouch50::out::CancelReject m{};
    m.user_ref_num = r.urn;
    ouch(o, r.session, m, r.user_ref_idx);
  }
  return true;
}

// Quantity is the new intended order size (OUCH 2.0+): at most that many
// shares may execute in total, prior executions included. Superfluous
// cancels change nothing and are ignored (R2 D4.4).
template <class S>
void Engine::on_cancel(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::CancelOrderView& v,
                       std::uint8_t idx) {
  const Handle h = urn_->find(urn_key(a, idx, v.user_ref_num()));
  if (h == kNil) {
    audit(o, AuditCode::UnknownOrder, sessions_[s].id, v.user_ref_num());
    return;
  }
  const Order& r = book_.at(h);
  const Qty open = total_leaves(h);
  const Qty want = v.quantity();
  const Qty nl = want > r.done ? want - r.done : 0;
  if (nl >= open) {
    audit(o, AuditCode::Superfluous, sessions_[s].id, v.user_ref_num());
    return;
  }
  if (frozen_change(o, h, nl == 0)) return;
  const Qty d = open - nl;
  canceled(o, r.session, r.urn, r.user_ref_idx, d, CR::UserRequested);
  if (nl == 0) {
    if (r.where == Where::Book && itch_visible(r.display)) itch_delete(o, r.locate, r.itch_ref);
    remove_order(h);
  } else {
    reduce_total(o, h, d);  // keeps_priority(Change::Decrease)
  }
}

// Modify keeps priority (keeps_priority: a decrease or a long/short
// re-marking). Side may change only among S, T and E; an increase is
// ignored. A request that changes nothing is ignored.
template <class S>
void Engine::on_modify(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::ModifyOrderView& v,
                       std::uint8_t idx) {
  const Handle h = urn_->find(urn_key(a, idx, v.user_ref_num()));
  if (h == kNil) {
    audit(o, AuditCode::UnknownOrder, sessions_[s].id, v.user_ref_num());
    return;
  }
  Order& r = book_.at(h);
  const Marking nm = v.side();
  const bool remark = nm != r.marking;
  if (remark && (nm == Marking::Buy || r.marking == Marking::Buy)) {
    audit(o, AuditCode::InvalidModify, sessions_[s].id, v.user_ref_num());
    return;
  }
  const Qty open = total_leaves(h);
  const Qty want = v.quantity();
  const Qty nl = want > r.done ? want - r.done : 0;
  const bool dec = nl < open;
  if (!remark && !dec) {
    audit(o, AuditCode::Superfluous, sessions_[s].id, v.user_ref_num());
    return;
  }
  if (frozen_change(o, h, false)) return;
  static_assert(keeps_priority(Change::Decrease) && keeps_priority(Change::Remark));
  r.marking = nm;
  if (r.peer != kNil) book_.at(r.peer).marking = nm;
  TagSet tags;
  (void)ouch50::parse_tags(v.tags(), tags);
  tags.present &= ouch50::out::OrderModified::kAllowedTags;
  if (r.user_ref_idx != 0) {
    tags.set_user_ref_idx(r.user_ref_idx);
  } else {
    tags.clear(Tag::UserRefIdx);
  }
  ouch50::out::OrderModified m{};
  m.user_ref_num = r.urn;
  m.side = nm;
  m.quantity = dec ? nl : open;
  ouch_tags(o, r.session, m, tags);
  if (!dec) return;
  if (nl == 0) {
    if (r.where == Where::Book && itch_visible(r.display)) itch_delete(o, r.locate, r.itch_ref);
    remove_order(h);
  } else {
    reduce_total(o, h, open - nl);
  }
}

// ---------------------------------------------------------------------------- session-level operations

// Step 7: 'X' first, then 'C' reason 'U' per matching order in entry order.
// Frozen cross orders are spared (05 §4 step 3).
template <class S>
void Engine::on_mass_cancel(Out<S>& o, std::uint32_t s, std::uint32_t a, const ouch50::in::MassCancelView& v,
                            UserRefNum urn, std::uint8_t idx) {
  const Firm firm = v.firm().blank() ? accounts_[a].default_firm() : v.firm();
  if (!authorized(a, firm)) {
    reject(o, s, urn, idx, code(RR::FirmNotAuthorized), ClOrdId{});
    return;
  }
  Locate l = 0;
  if (!v.symbol().blank()) {
    l = find_symbol(v.symbol());
    if (l == 0) {
      reject(o, s, urn, idx, code(RR::InvalidSymbol), ClOrdId{});
      return;
    }
  }
  TagSet tags;
  (void)ouch50::parse_tags(v.tags(), tags);
  ouch50::out::MassCancelResponse m{};
  m.user_ref_num = urn;
  m.firm = v.firm();
  m.symbol = v.symbol();
  TagSet echo = tags;
  echo.present &= ouch50::out::MassCancelResponse::kAllowedTags;
  ouch_tags(o, s, m, echo);
  const bool by_group = tags.has(Tag::GroupID);
  const bool by_side = tags.has(Tag::Side);
  const bool by_idx = tags.has(Tag::UserRefIdx) && tags.user_ref_idx != 0;
  const Side side = by_side ? book_side(tags.side) : Side::Buy;
  for (Handle h = accounts_[a].head; h != kNil;) {
    const Order& r = book_.at(h);
    const Handle nx = book_.links(h).acct_next;
    if (r.firm == firm && (l == 0 || r.locate == l) && (!by_side || r.side == side) &&
        (!by_group || r.group_id == tags.group_id) && (!by_idx || r.user_ref_idx == tags.user_ref_idx) && !frozen(r))
      cancel_whole(o, h, CR::UserRequested);
    h = nx;
  }
}

// Disable 'D' / Enable 'E' order entry for (account, Firm); blank Firm means
// the account's default firm. While disabled, Enter and Replace get 'J'
// 0x000C; Cancel, Modify and Mass Cancel still work.
template <class S, class View>
void Engine::on_entry_switch(Out<S>& o, std::uint32_t s, std::uint32_t a, const View& v, UserRefNum urn,
                             std::uint8_t idx, bool disable) {
  const Firm firm = v.firm().blank() ? accounts_[a].default_firm() : v.firm();
  AccountInfo& ai = accounts_[a];
  int k = -1;
  for (int i = 0; i < ai.nfirms; ++i)
    if (ai.firms[static_cast<std::size_t>(i)] == firm) k = i;
  if (k < 0) {
    reject(o, s, urn, idx, code(RR::FirmNotAuthorized), ClOrdId{});
    return;
  }
  const auto bit = static_cast<std::uint8_t>(1u << k);
  ai.disabled = disable ? static_cast<std::uint8_t>(ai.disabled | bit) : static_cast<std::uint8_t>(ai.disabled & ~bit);
  TagSet tags;
  (void)ouch50::parse_tags(v.tags(), tags);
  if (disable) {
    ouch50::out::DisableOrderEntryResponse m{};
    m.user_ref_num = urn;
    m.firm = v.firm();
    tags.present &= ouch50::out::DisableOrderEntryResponse::kAllowedTags;
    ouch_tags(o, s, m, tags);
  } else {
    ouch50::out::EnableOrderEntryResponse m{};
    m.user_ref_num = urn;
    m.firm = v.firm();
    tags.present &= ouch50::out::EnableOrderEntryResponse::kAllowedTags;
    ouch_tags(o, s, m, tags);
  }
}

// Step 8: cancel-on-disconnect, in entry order, reason 'Z' (System).
// KeepCrossOrders spares cross orders; frozen ones are spared regardless.
template <class S>
void Engine::cancel_session_orders(Out<S>& o, std::uint32_t s) {
  const SessionInfo& si = sessions_[s];
  const bool keep_cross = (si.flags & SessionEntry::kKeepCrossOrders) != 0;
  for (Handle h = accounts_[si.account].head; h != kNil;) {
    const Order& r = book_.at(h);
    const Handle nx = book_.links(h).acct_next;
    if (r.session == s && !(keep_cross && r.cross_only()) && !frozen(r)) cancel_whole(o, h, CR::System);
    h = nx;
  }
}

}  // namespace lle::engine

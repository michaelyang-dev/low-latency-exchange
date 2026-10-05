#pragma once
// Record handlers other than OUCH: day start, configuration, session events,
// timers (system events, milestones, NOII ticks, crosses, expiry sweeps, the
// 1 Hz clock) and admin commands. Included by engine.h.

namespace lle::engine {

template <class S>
void Engine::on_day_start(Out<S>& o, std::span<const std::byte> p) {
  const auto d = parse_day_start(p);
  if (!d) {
    audit(o, AuditCode::MalformedPayload, 0, 0);
    return;
  }
  reset_day();
  midnight_ = d->local_midnight_ns;
  date_ = d->date;
}

// Config chunks are reassembled in order; a table applies when its last chunk
// arrives, and only before the first OuchInbound (ADR-028: later changes are
// Admin records).
template <class S>
void Engine::on_config(Out<S>& o, std::span<const std::byte> p) {
  const auto c = parse_config_chunk(p);
  if (started_ || !c) {
    cfg_next_ = 0;
    cfg_buf_.clear();
    audit(o, AuditCode::ConfigRejected, 0, c ? static_cast<std::uint64_t>(c->table) : 0);
    return;
  }
  if (c->index == 0) {
    cfg_table_ = c->table;
    cfg_total_ = c->table_bytes;
    cfg_next_ = 0;
    cfg_buf_.clear();
  }
  if (c->table != cfg_table_ || c->index != cfg_next_ || c->table_bytes != cfg_total_ ||
      cfg_buf_.size() + c->bytes.size() > cfg_total_) {
    cfg_next_ = 0;
    cfg_buf_.clear();
    audit(o, AuditCode::ConfigRejected, 0, static_cast<std::uint64_t>(c->table));
    return;
  }
  cfg_buf_.insert(cfg_buf_.end(), c->bytes.begin(), c->bytes.end());
  ++cfg_next_;
  if (cfg_next_ < c->count) return;
  const ConfigTable t = cfg_table_;
  const bool ok = cfg_buf_.size() == cfg_total_ && load_table(t, cfg_buf_);
  cfg_next_ = 0;
  cfg_buf_.clear();
  if (!ok) {
    audit(o, AuditCode::ConfigRejected, 0, static_cast<std::uint64_t>(t));
    return;
  }
  if (t == ConfigTable::Symbols) emit_directory(o);
}

// ITCH 'R' Stock Directory per symbol in locate order, then the Reg SHO 'Y'
// spin for symbols whose state is known.
template <class S>
void Engine::emit_directory(Out<S>& o) {
  for (Locate l = 1; l < symbols_.size(); ++l) {
    const SymbolInfo& y = symbols_[l];
    itch50::StockDirectory m{};
    m.stock = y.symbol;
    m.market_category = static_cast<itch50::MarketCategory>(y.market_category);
    m.financial_status = itch50::FinancialStatus::Normal;
    m.round_lot_size = y.round_lot;
    m.round_lots_only = itch50::YesNo::No;
    m.issue_classification = itch50::IssueClassification::CommonStock;
    m.issue_sub_type = Alpha<2>("Z");
    m.authenticity = (y.flags & SymbolEntry::kFlagTest) != 0 ? itch50::Authenticity::Test
                                                              : itch50::Authenticity::LiveProduction;
    m.short_sale_threshold = itch50::YesNoBlank::No;
    m.ipo_flag = itch50::IpoFlag::NotNewIpo;
    m.luld_tier = static_cast<itch50::LuldTier>(y.luld_tier);
    m.etp_flag = (y.flags & SymbolEntry::kFlagEtp) != 0 ? itch50::YesNoBlank::Yes : itch50::YesNoBlank::No;
    m.etp_leverage_factor = 0;
    m.inverse_indicator = itch50::YesNo::No;
    itch(o, m, l);
  }
  for (Locate l = 1; l < symbols_.size(); ++l) {
    if (symbols_[l].regsho != '0' && symbols_[l].regsho != '2') continue;
    itch50::RegShoRestriction y{};
    y.stock = symbols_[l].symbol;
    y.reg_sho_action = static_cast<itch50::RegShoAction>(symbols_[l].regsho);
    itch(o, y, l);
  }
}

template <class S>
void Engine::on_session_event(Out<S>& o, std::span<const std::byte> p) {
  const auto e = parse_session_event(p);
  if (!e) {
    audit(o, AuditCode::MalformedPayload, 0, 0);
    return;
  }
  const Handle s = sess_index_->find(e->session_id);
  if (s == kNil) {
    audit(o, AuditCode::UnknownSession, e->session_id, 0);
    return;
  }
  SessionInfo& si = sessions_[s];
  const std::uint64_t bit = std::uint64_t{1} << (e->instance & 63u);
  switch (e->event) {
    case SessionEventKind::Login:
    case SessionEventKind::MirrorAttach: si.live |= bit; break;
    case SessionEventKind::Logout: si.live &= ~bit; break;
    case SessionEventKind::Disconnect:
    case SessionEventKind::InstanceDown: {
      const bool had = (si.live & bit) != 0;
      si.live &= ~bit;
      // 05 §4 step 8: the last live instance (primary and mirrors) is gone.
      if (had && si.live == 0 && (si.flags & SessionEntry::kCancelOnDisconnect) != 0) cancel_session_orders(o, s);
      break;
    }
    default: audit(o, AuditCode::UnhandledRecord, e->session_id, static_cast<std::uint64_t>(e->event)); break;
  }
}

// A Timer record means what its Schedule entry says (records.h).
template <class S>
void Engine::on_timer(Out<S>& o, std::span<const std::byte> p) {
  const auto t = parse_timer(p);
  if (!t) {
    audit(o, AuditCode::MalformedPayload, 0, 0);
    return;
  }
  const ScheduleEntry* e = find_timer(t->timer_id);
  if (e == nullptr || e->kind != t->kind) {
    audit(o, AuditCode::UnhandledRecord, 0, t->timer_id);
    return;
  }
  switch (e->kind) {
    case TimerKind::SystemEvent: {
      const auto ec = static_cast<itch50::EventCode>(e->arg);
      if (e->arg > 0x7F || !itch50::is_valid(ec)) {
        audit(o, AuditCode::UnhandledRecord, 0, e->arg);
        return;
      }
      itch50::SystemEvent m{};
      m.event_code = ec;
      itch(o, m, 0);
      if (ec == itch50::EventCode::StartOfMessages || ec == itch50::EventCode::EndOfMessages) {
        ouch50::out::SystemEvent se{};
        se.event_code = ec == itch50::EventCode::StartOfMessages ? ouch50::EventCode::StartOfDay
                                                                  : ouch50::EventCode::EndOfDay;
        for (std::uint32_t s = 0; s < sessions_.size(); ++s) ouch(o, s, se, 0);
      }
      break;
    }
    case TimerKind::StateChange: state_change(o, static_cast<Milestone>(e->arg)); break;
    case TimerKind::Eoii:
    case TimerKind::Noii:
      if (e->arg == 'O' || e->arg == 'C') {
        noii_tick(o, static_cast<CrossKind>(e->arg), e->kind == TimerKind::Eoii);
      } else if (e->arg == 'H' && e->kind == TimerKind::Noii) {
        clock_tick(o, t->scheduled_ns);
      } else {
        audit(o, AuditCode::UnhandledRecord, 0, e->arg);
      }
      break;
    case TimerKind::Cross:
      if (e->arg == 'O' || e->arg == 'C') {
        run_crosses(o, static_cast<CrossKind>(e->arg));
      } else {
        audit(o, AuditCode::UnhandledRecord, 0, e->arg);
      }
      break;
    case TimerKind::ExpirySweep: expiry_sweep(o, static_cast<char>(e->arg)); break;
    case TimerKind::DayEnd: break;
    default: audit(o, AuditCode::UnhandledRecord, 0, static_cast<std::uint64_t>(e->kind)); break;
  }
}

template <class S>
void Engine::state_change(Out<S>& o, Milestone m) {
  auto record_crp = [&](CrossKind k, PxE4 SymbolInfo::*field) {
    for (Locate l = 1; l < symbols_.size(); ++l) {
      SymbolInfo& y = symbols_[l];
      if (y.halt != HaltPhase::None || (k == CrossKind::Open ? y.opened : y.closed)) continue;
      const CrossResult r = compute_cross(l, k, false, true);
      // A reference off the tick grid rounds by the imbalance (R2 D2.1): up for a buy
      // imbalance, down for a sell imbalance, to nearest otherwise.
      y.*field = r.valid && r.price > 0 ? round_tick(l, r.price, r.side == 'B' ? 'U' : (r.side == 'S' ? 'D' : 'N')) : 0;
    }
  };
  switch (m) {
    case Milestone::PreMarket: session_ = Session::PreMarket; break;
    case Milestone::OpenFreeze: milestones_ |= kOpenFreeze; break;
    case Milestone::MooCutoff:
      milestones_ |= kMooCutoff;
      record_crp(CrossKind::Open, &SymbolInfo::open_ref2);
      break;
    case Milestone::LooCutoff: milestones_ |= kLooCutoff; break;
    case Milestone::CloseFreeze:
      milestones_ |= kCloseFreeze;
      record_crp(CrossKind::Close, &SymbolInfo::close_ref1);
      break;
    case Milestone::MocCutoff:
      milestones_ |= kMocCutoff;
      record_crp(CrossKind::Close, &SymbolInfo::close_ref2);
      break;
    case Milestone::LocCutoff:
      milestones_ |= kLocCutoff;
      for (AccountInfo& a : accounts_) a.cross_permit = false;
      break;
    case Milestone::SystemClose: session_ = Session::Closed; break;
    default: audit(o, AuditCode::UnhandledRecord, 0, static_cast<std::uint64_t>(m)); break;
  }
}

// The opening (closing) cross runs for every symbol on one record, in locate
// order (05 §5 "Cross execution"; NASDAQ staggers them over about 1 s).
template <class S>
void Engine::run_crosses(Out<S>& o, CrossKind k) {
  for (Locate l = 1; l < symbols_.size(); ++l) {
    if (k == CrossKind::Open && !symbols_[l].opened) opening_cross(o, l);
    if (k == CrossKind::Close && !symbols_[l].closed) closing_cross(o, l);
  }
  session_ = k == CrossKind::Open ? Session::Regular : Session::PostMarket;
}

// 'D' after the close: Day orders expire; 'X' at the end of system hours:
// everything left expires. Cancel reason 'E' (Closed), accounts in table
// order, each in entry order.
template <class S>
void Engine::expiry_sweep(Out<S>& o, char kind) {
  if (kind != 'D' && kind != 'X') {
    audit(o, AuditCode::UnhandledRecord, 0, static_cast<std::uint64_t>(kind));
    return;
  }
  for (AccountInfo& a : accounts_) {
    for (Handle h = a.head; h != kNil;) {
      const Handle nx = book_.links(h).acct_next;
      if (kind == 'X' || book_.at(h).tif == Tif::Day) cancel_whole(o, h, CR::Closed);
      h = nx;
    }
  }
}

template <class S>
void Engine::noii_tick(Out<S>& o, CrossKind k, bool eoii) {
  const bool open = k == CrossKind::Open;
  if (open ? session_ != Session::PreMarket : session_ != Session::Regular) return;
  for (Locate l = 1; l < symbols_.size(); ++l) {
    const SymbolInfo& y = symbols_[l];
    if (y.halt != HaltPhase::None || (open ? y.opened : y.closed)) continue;
    emit_noii(o, l, k, eoii);
  }
}

// The 1 Hz clock (Noii 'H' timers): display-only periods, LULD limit states,
// midpoint-peg pulls, GTT expiry.
template <class S>
void Engine::clock_tick(Out<S>& o, Nanos scheduled) {
  for (Locate l = 1; l < symbols_.size(); ++l) symbol_tick(o, l);
  for (Locate l = 1; l < symbols_.size(); ++l) peg_tick(o, l);
  const std::uint32_t now_s =  // seconds since midnight, overflow-free as in wire_ts
      scheduled > midnight_
          ? static_cast<std::uint32_t>((static_cast<std::uint64_t>(scheduled) - static_cast<std::uint64_t>(midnight_)) /
                                       static_cast<std::uint64_t>(kNsPerSec))
          : 0;
  // GTT expiry (ExpireTime is seconds since midnight): accounts in table order, entry order.
  for (AccountInfo& a : accounts_) {
    for (Handle h = a.head; h != kNil;) {
      const Handle nx = book_.links(h).acct_next;
      const Order& r = book_.at(h);
      if (r.tif == Tif::Gtt && r.has(Order::kHasExpire) && r.expire_time <= now_s && !frozen(r))
        cancel_whole(o, h, CR::Timeout);
      h = nx;
    }
  }
}

template <class S>
void Engine::on_admin(Out<S>& o, std::span<const std::byte> p) {
  const auto rec = parse_admin(p);
  const auto args = rec ? parse_admin_args(rec->args, rec->hdr.tlv_version) : std::nullopt;
  if (!rec || !args) {
    audit(o, AuditCode::MalformedPayload, 0, rec ? rec->hdr.command : 0);
    return;
  }
  const AdminArgs& a = *args;
  const auto cmd = static_cast<AdminCommand>(rec->hdr.command);
  const Locate l = a.has(AdminTag::Symbol) ? find_symbol(a.symbol) : Locate{0};
  auto bad = [&] { audit(o, AuditCode::UnhandledRecord, 0, rec->hdr.command); };
  switch (cmd) {
    case AdminCommand::Halt:
      if (l == 0) return bad();
      enter_halt(o, l, HaltPhase::Halted, HaltKind::News, a.has(AdminTag::Reason) ? a.reason : Alpha<4>("T1"));
      break;
    case AdminCommand::QuoteOnly: {
      if (l == 0 || (a.has(AdminTag::Price) && a.price > 0xFFFF'FFFFll)) return bad();
      SymbolInfo& y = symbols_[l];
      y.reason = a.has(AdminTag::Reason) ? a.reason : Alpha<4>("T3");
      const PxE4 arp = a.has(AdminTag::Price) && a.price > 0 ? a.price : (y.last_sale > 0 ? y.last_sale : y.prior_close);
      start_display_period(o, l, HaltKind::News, arp);
      break;
    }
    case AdminCommand::Resume: {
      if (l == 0 || symbols_[l].halt == HaltPhase::None) return bad();
      const CrossResult r = compute_cross(l, CrossKind::Halt, false, false);
      resume(o, l, r);
      break;
    }
    case AdminCommand::IpoSchedule: {
      if (l == 0 || !a.has(AdminTag::Price) || a.price <= 0 || a.price > 0xFFFF'FFFFll) return bad();
      const char q = a.has(AdminTag::Qualifier) ? static_cast<char>(a.qualifier) : 'A';
      if (q != 'A' && q != 'C') return bad();
      SymbolInfo& y = symbols_[l];
      y.ipo_price = q == 'A' ? a.price : 0;
      itch50::IpoQuotingPeriodUpdate k{};
      k.stock = y.symbol;
      k.release_time = a.time;
      k.release_qualifier = static_cast<itch50::IpoReleaseQualifier>(q);
      k.ipo_price = a.price;
      itch(o, k, 0);
      break;
    }
    case AdminCommand::IpoQuote:
      if (l == 0) return bad();
      enter_halt(o, l, HaltPhase::IpoQuote, HaltKind::Ipo, Alpha<4>("IPOQ"));
      break;
    case AdminCommand::IpoRelease: {
      if (l == 0 || symbols_[l].halt != HaltPhase::IpoQuote || (a.has(AdminTag::Band) && a.band > 0xFFFF'FFFFll))
        return bad();
      SymbolInfo& y = symbols_[l];
      const CrossResult r = compute_cross(l, CrossKind::Halt, false, false);
      y.ipo_band = a.has(AdminTag::Band) && a.band > 0 ? a.band : 0;
      y.ipo_expected = r.valid ? r.price : y.ipo_price;
      y.halt = HaltPhase::IpoPreLaunch;
      break;
    }
    case AdminCommand::LuldBands:
      if (l == 0 || a.lower <= 0 || a.upper <= a.lower || a.upper > 0xFFFF'FFFFll) return bad();
      symbols_[l].luld_lo = a.lower;
      symbols_[l].luld_hi = a.upper;
      break;
    case AdminCommand::MwcbLevels: {
      mwcb_levels_ = {a.level1, a.level2, a.level3};
      itch50::MwcbDeclineLevel v{};
      v.level1 = a.level1;
      v.level2 = a.level2;
      v.level3 = a.level3;
      itch(o, v, 0);
      break;
    }
    case AdminCommand::MwcbBreach: {
      if (a.level < 1 || a.level > 3) return bad();
      mwcb_breached_ = a.level;
      itch50::MwcbStatus w{};
      w.breached_level = static_cast<itch50::BreachedLevel>('0' + a.level);
      itch(o, w, 0);
      // Level 1/2 (Rule 4121): every trading symbol halts ('H' MWC1/MWC2) for
      // MwcbPeriodSec, then reopens through a display-only period ('Q' MWCQ) and
      // the halt cross (symbol_tick). Level 3 halts everything for the day.
      for (Locate s = 1; s < symbols_.size(); ++s) {
        SymbolInfo& y = symbols_[s];
        if (a.level == 3) {
          enter_halt(o, s, HaltPhase::Halted, HaltKind::Mwcb, Alpha<4>("MWC3"));
        } else if (y.halt == HaltPhase::None) {
          enter_halt(o, s, HaltPhase::Halted, HaltKind::Mwcb, Alpha<4>(a.level == 1 ? "MWC1" : "MWC2"));
          y.period = static_cast<std::uint32_t>(params_.mwcb_period);
        }
      }
      break;
    }
    case AdminCommand::CrossCancelPermit: {
      const Handle ai = a.has(AdminTag::Account) ? acct_index_->find(a.account) : kNil;
      if (ai == kNil || (milestones_ & kLocCutoff) != 0) return bad();
      accounts_[ai].cross_permit = true;
      break;
    }
    case AdminCommand::RegSho: {
      if (l == 0 || (a.action != '0' && a.action != '1' && a.action != '2')) return bad();
      symbols_[l].regsho = static_cast<char>(a.action);
      itch50::RegShoRestriction y{};
      y.stock = symbols_[l].symbol;
      y.reg_sho_action = static_cast<itch50::RegShoAction>(a.action);
      itch(o, y, l);
      break;
    }
    case AdminCommand::KillSwitch:
    case AdminCommand::KillReset: {
      const Handle ai = a.has(AdminTag::Account) ? acct_index_->find(a.account) : kNil;
      if (ai == kNil) return bad();
      if (cmd == AdminCommand::KillSwitch) {
        kill_account(o, ai);
      } else {
        risk_.unkill(ai);
      }
      break;
    }
    case AdminCommand::RiskLimit: {
      const Handle ai = a.has(AdminTag::Account) ? acct_index_->find(a.account) : kNil;
      const Locate sl = a.has(AdminTag::Symbol) ? l : Locate{0};
      if (ai == kNil || !a.has(AdminTag::Kind) || !a.has(AdminTag::Value) || (a.has(AdminTag::Symbol) && sl == 0) ||
          !risk_.set(ai, static_cast<RiskKind>(a.kind), a.value, sl))
        return bad();
      if (const std::uint32_t rb = risk_.take_rebuild(); rb != RiskGate::kNone) risk_rebuild(rb);
      break;
    }
    default: bad(); break;
  }
}

// Kill switch (05 §7; Equity 6 §3): entry disabled until KillReset and every
// order of the account cancelled, in entry order, frozen cross orders included.
template <class S>
void Engine::kill_account(Out<S>& o, std::uint32_t a) {
  risk_.kill(a);
  for (Handle h = accounts_[a].head; h != kNil;) {
    const Handle nx = book_.links(h).acct_next;
    cancel_whole(o, h, CR::Supervisory);
    h = nx;
  }
}

// Accounts whose executed notional crossed KillExposure during the record, in account order.
template <class S>
void Engine::run_kills(Out<S>& o) {
  risk_.take_pending(kills_);
  for (const std::uint32_t a : kills_)
    if (!risk_.killed(a)) kill_account(o, a);
}

}  // namespace lle::engine

// Non-emitting parts of the engine: configuration tables, the order gate,
// cross interest and allocation, collars, order bookkeeping, and the
// canonical state (hash, snapshot, restore). See engine.h.
#include "engine/engine.h"

#include <algorithm>

namespace lle::engine {

namespace {
constexpr PxE4 absdiff(PxE4 a, PxE4 b) noexcept { return a > b ? a - b : b - a; }
}  // namespace

Engine::Engine(const EngineConfig& c) : cfg_(c), book_(c.book) {
  interest_.reserve(c.scratch);
  handles_.reserve(c.scratch);
  buys_.reserve(c.scratch);
  sells_.reserve(c.scratch);
  scratch_.reserve(c.scratch);
  bcand_.reserve(c.scratch);
  scand_.reserve(c.scratch);
  calc_.reserve(c.scratch);
  refresh_.reserve(c.scratch);
  reset_day();
}

void Engine::reset_day() {
  symbols_.assign(1, SymbolInfo{});
  accounts_.clear();
  sessions_.clear();
  trackers_.clear();
  schedule_.clear();
  timers_.clear();
  sym_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{1024, 0});
  acct_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{1024, 0});
  sess_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{1024, 0});
  urn_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{cfg_.urn_capacity, 0});
  book_.reset(0);
  risk_.reset();
  params_ = MarketParams{};
  cfg_next_ = 0;
  cfg_total_ = 0;
  cfg_buf_.clear();
  midnight_ = 0;
  date_ = 0;
  started_ = false;
  session_ = initial_session_ = Session::Regular;
  milestones_ = 0;
  next_ref_ = 1;
  next_match_ = 1;
  itch_count_ = 0;
  live_ = 0;
  mwcb_levels_ = {};
  mwcb_breached_ = 0;
}

// Overflow-free for any (ts, midnight): the difference is taken in uint64 once
// ts > midnight_, where it is exact.
std::uint64_t Engine::wire_ts(Nanos ts) const noexcept {
  if (ts <= midnight_) return 0;
  const std::uint64_t t = static_cast<std::uint64_t>(ts) - static_cast<std::uint64_t>(midnight_);
  return t >= static_cast<std::uint64_t>(kNsPerDay) ? static_cast<std::uint64_t>(kNsPerDay) - 1 : t;
}

Locate Engine::find_symbol(const Symbol8& s) const noexcept {
  const Handle h = sym_index_->find(pack_alpha(s));
  return h == kNil ? Locate{0} : static_cast<Locate>(h);
}

std::vector<std::pair<std::uint32_t, std::uint64_t>> Engine::session_outputs() const {
  std::vector<std::pair<std::uint32_t, std::uint64_t>> v;
  for (const SessionInfo& s : sessions_) v.emplace_back(s.id, s.ouch_out);
  return v;
}

// ============================================================================ configuration

bool Engine::load_table(ConfigTable t, std::span<const std::byte> body) {
  switch (t) {
    case ConfigTable::Symbols: return load_symbols(body);
    case ConfigTable::Accounts: return load_accounts(body);
    case ConfigTable::Sessions: return load_sessions(body);
    case ConfigTable::RiskLimits: return load_risk(body);
    case ConfigTable::Schedule: return load_schedule(body);
    default: return false;
  }
}

// Locates are 1 + table position.
bool Engine::load_symbols(std::span<const std::byte> body) {
  const auto v = parse_table(body, SymbolEntry::kLen, SymbolEntry::kVersion);
  if (!v || v->count > 0xFFFE) return false;
  std::vector<SymbolInfo> syms(1);
  auto idx = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{v->count + 16u, 0});
  for (std::uint32_t i = 0; i < v->count; ++i) {
    const SymbolEntry e = parse_symbol_entry(v->body.data() + std::size_t{i} * SymbolEntry::kLen);
    if (e.symbol.blank() || e.tick == 0 || kPxScale % e.tick != 0 || e.round_lot == 0 || e.prior_close < 0 ||
        e.prior_close > 0xFFFF'FFFFll)
      return false;
    if (!idx->insert(pack_alpha(e.symbol), i + 1)) return false;  // duplicate symbol
    SymbolInfo y;
    y.symbol = e.symbol;
    y.round_lot = e.round_lot;
    y.tick = e.tick;
    y.prior_close = e.prior_close;
    y.market_category =
        itch50::is_valid(static_cast<itch50::MarketCategory>(e.market_category)) ? e.market_category : ' ';
    y.luld_tier = itch50::is_valid(static_cast<itch50::LuldTier>(e.luld_tier)) ? e.luld_tier : ' ';
    y.flags = e.flags;
    y.adv = e.adv;
    y.regsho = e.regsho == '0' || e.regsho == '2' ? e.regsho : ' ';
    syms.push_back(y);
  }
  symbols_ = std::move(syms);
  sym_index_ = std::move(idx);
  book_.reset(v->count);
  risk_configure();
  return true;
}

// Reloading accounts drops the session table (sessions refer to accounts).
bool Engine::load_accounts(std::span<const std::byte> body) {
  const auto v = parse_table(body, AccountEntry::kLen, AccountEntry::kVersion);
  if (!v || v->count > kMaxAccounts) return false;
  std::vector<AccountInfo> accts;
  accts.reserve(v->count);
  auto idx = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{v->count + 16u, 0});
  for (std::uint32_t i = 0; i < v->count; ++i) {
    const AccountEntry e = parse_account_entry(v->body.data() + std::size_t{i} * AccountEntry::kLen);
    if (!idx->insert(e.account_id, i)) return false;
    AccountInfo a;
    a.id = e.account_id;
    for (const Firm& f : e.firms) {
      if (f.blank()) continue;
      bool dup = false;
      for (std::uint8_t k = 0; k < a.nfirms; ++k) dup = dup || a.firms[k] == f;
      if (!dup) a.firms[a.nfirms++] = f;
    }
    accts.push_back(a);
  }
  accounts_ = std::move(accts);
  acct_index_ = std::move(idx);
  trackers_.assign(accounts_.size(), std::array<UserRefNum, 256>{});
  sessions_.clear();
  sess_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{1024, 0});
  risk_configure();
  return true;
}

bool Engine::load_sessions(std::span<const std::byte> body) {
  const auto v = parse_table(body, SessionEntry::kLen, SessionEntry::kVersion);
  if (!v) return false;
  std::vector<SessionInfo> sess;
  sess.reserve(v->count);
  auto idx = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{v->count + 16u, 0});
  for (std::uint32_t i = 0; i < v->count; ++i) {
    const SessionEntry e = parse_session_entry(v->body.data() + std::size_t{i} * SessionEntry::kLen);
    const Handle a = acct_index_->find(e.account_id);
    if (a == kNil || !idx->insert(e.session_id, i) || static_cast<std::uint8_t>(e.late_cross) > 2) return false;
    SessionInfo s;
    s.id = e.session_id;
    s.account = a;
    s.flags = e.flags;
    const auto aiq = static_cast<AiqMode>(e.default_aiq);
    s.default_aiq = aiq_supported(aiq) ? aiq : AiqMode::Disabled;
    s.late_cross = e.late_cross;
    sess.push_back(s);
  }
  sessions_ = std::move(sess);
  sess_index_ = std::move(idx);
  risk_configure();
  return true;
}

// Resolved against the loaded Symbols, Accounts and Sessions (send it after
// them; reloading any of those clears the limits). A table with an unknown
// account or symbol or an invalid value is rejected as a whole.
bool Engine::load_risk(std::span<const std::byte> body) {
  const auto v = parse_table(body, RiskEntry::kLen, RiskEntry::kVersion);
  if (!v) return false;
  RiskGate g;
  std::vector<std::uint32_t> sa;
  for (const SessionInfo& si : sessions_) sa.push_back(si.account);
  g.configure(static_cast<std::uint32_t>(accounts_.size()), sa, static_cast<std::uint32_t>(symbols_.size() - 1));
  for (std::uint32_t i = 0; i < v->count; ++i) {
    const RiskEntry e = parse_risk_entry(v->body.data() + std::size_t{i} * RiskEntry::kLen);
    const Handle a = acct_index_->find(e.account_id);
    const Locate l = e.symbol.blank() ? Locate{0} : find_symbol(e.symbol);
    if (a == kNil || (!e.symbol.blank() && l == 0) || !g.set(a, e.kind, e.value, l)) return false;
  }
  (void)g.take_rebuild();  // no orders before trading starts
  risk_ = std::move(g);
  return true;
}

void Engine::risk_configure() {
  std::vector<std::uint32_t> sa;
  sa.reserve(sessions_.size());
  for (const SessionInfo& si : sessions_) sa.push_back(si.account);
  risk_.configure(static_cast<std::uint32_t>(accounts_.size()), sa, static_cast<std::uint32_t>(symbols_.size() - 1));
  kills_.reserve(accounts_.size());
}

RiskQuote Engine::risk_quote(Locate l, Side side) const noexcept {
  const SymbolInfo& y = symbols_[l];
  RiskQuote q;
  if (side == Side::Buy) {
    q.ask = book_.displayed_best(l, Side::Sell);
  } else {
    q.bid = book_.displayed_best(l, Side::Buy);
  }
  q.last = y.last_sale;
  q.prior = y.prior_close;
  q.luld_lo = y.luld_lo;
  q.luld_hi = y.luld_hi;
  q.adv = y.adv;
  q.session = session_;
  q.halted = y.halt != HaltPhase::None;
  q.ipo = y.halt == HaltPhase::IpoQuote || y.halt == HaltPhase::IpoPreLaunch;
  return q;
}

void Engine::risk_rebuild(std::uint32_t a) {
  for (Handle h = accounts_[a].head; h != kNil; h = book_.links(h).acct_next) {
    const Order& r = book_.at(h);
    risk_.add_symbol_open(a, r.locate, i128{total_leaves(h)} * r.risk_px);
  }
}

// Timer entries must have unique ids >= 1 and a known kind; parameter entries
// (id 0) set market parameters.
bool Engine::load_schedule(std::span<const std::byte> body) {
  const auto v = parse_table(body, ScheduleEntry::kLen, ScheduleEntry::kVersion);
  if (!v) return false;
  std::vector<ScheduleEntry> all, timers;
  MarketParams p = params_;
  Session init = initial_session_;
  for (std::uint32_t i = 0; i < v->count; ++i) {
    const ScheduleEntry e = parse_schedule_entry(v->body.data() + std::size_t{i} * ScheduleEntry::kLen);
    all.push_back(e);
    if (e.timer_id != 0) {
      const auto k = static_cast<std::uint16_t>(e.kind);
      if (k < 1 || k > 7) return false;
      timers.push_back(e);
      continue;
    }
    const std::int64_t x = e.time_ns;
    switch (static_cast<Param>(e.arg)) {
      case Param::InitialSession:
        if (x != 'C' && x != 'P' && x != 'R' && x != 'A') return false;
        init = static_cast<Session>(x);
        break;
      case Param::ThresholdBps: p.threshold_bps = x; break;
      case Param::ThresholdMin: p.threshold_min = x; break;
      case Param::PriceTestBps: p.price_test_bps = x; break;
      case Param::PriceTestMin: p.price_test_min = x; break;
      case Param::PriceTests: p.price_tests = x; break;
      case Param::HaltPeriodSec: p.halt_period = x; break;
      case Param::LuldPauseSec: p.luld_pause = x; break;
      case Param::MwcbPeriodSec: p.mwcb_period = x; break;
      case Param::LimitStateSec: p.limit_state = x; break;
      case Param::ExtensionSec: p.extension = x; break;
      default: return false;
    }
    if (x < 0) return false;
  }
  std::sort(timers.begin(), timers.end(),
            [](const ScheduleEntry& a, const ScheduleEntry& b) { return a.timer_id < b.timer_id; });
  for (std::size_t i = 1; i < timers.size(); ++i)
    if (timers[i].timer_id == timers[i - 1].timer_id) return false;
  if (!p.valid()) return false;
  schedule_ = std::move(all);
  timers_ = std::move(timers);
  params_ = p;
  initial_session_ = init;
  session_ = init;
  return true;
}

const ScheduleEntry* Engine::find_timer(std::uint32_t id) const noexcept {
  const auto it = std::lower_bound(timers_.begin(), timers_.end(), id,
                                   [](const ScheduleEntry& e, std::uint32_t x) { return e.timer_id < x; });
  return it != timers_.end() && it->timer_id == id ? &*it : nullptr;
}

// ============================================================================ the gate

bool Engine::authorized(std::uint32_t a, const Firm& f) const noexcept {
  const AccountInfo& ai = accounts_[a];
  for (std::uint8_t i = 0; i < ai.nfirms; ++i)
    if (ai.firms[i] == f) return true;
  return false;
}

bool Engine::disabled(std::uint32_t a, const Firm& f) const noexcept {
  const AccountInfo& ai = accounts_[a];
  for (std::uint8_t i = 0; i < ai.nfirms; ++i)
    if (ai.firms[i] == f) return ((ai.disabled >> i) & 1u) != 0;
  return false;
}

AiqMode Engine::resolve_aiq(AiqMode m, const SessionInfo& si) noexcept {
  return m == AiqMode::PortDefault ? si.default_aiq : m;
}

// Checks in the documented order (docs/design/matching-rules.md "Reject order").
std::uint16_t Engine::check_order(OrderSpec& sp, const TagSet& tags, const SessionInfo& si, Locate l, bool replace,
                                  Route& route) const noexcept {
  route = Route::Match;
  if (sp.iso == ouch50::IsoEligibility::Eligible) return code(RR::IsoNotAllowed);
  const bool cross = sp.cross == CrossType::Opening || sp.cross == CrossType::Closing || sp.cross == CrossType::HaltIpo;
  if (sp.cross != CrossType::Continuous && !cross) return code(RR::InvalidCrossOrder);  // S R E A
  if (tags.has(Tag::HandleInst) && tags.handle_inst != HandleInst::None) {
    const HandleInst h = tags.handle_inst;
    if (h == HandleInst::ImbalanceOnly) {
      if (sp.cross != CrossType::Opening && sp.cross != CrossType::Closing) return code(RR::InvalidCrossOrder);
      sp.imbalance_only = true;
    } else {
      const bool retail = h == HandleInst::RetailOrderType1 || h == HandleInst::RetailOrderType2 ||
                          h == HandleInst::RetailPriceImprovement;
      return retail ? code(RR::RetailNotAllowed) : code(RR::InvalidCrossOrder);
    }
  }
  if (tags.has(Tag::CustomerType) && tags.customer_type == ouch50::CustomerType::RetailDesignated)
    return code(RR::RetailNotAllowed);
  if (sp.peg != PegType::Limit) {
    if (sp.peg == PegType::MidpointPeg && sp.post_only) return code(RR::InvalidMidpointPostOnlyPrice);
    if (sp.peg == PegType::Midpoint) return code(RR::PeggingNotAllowed);
    if (sp.peg != PegType::MidpointPeg) return code(RR::InvalidPegType);
    if (cross) return code(RR::PeggingNotAllowed);  // pegs never join a cross
  }
  if (tags.has(Tag::PegOffset) && tags.peg_offset != 0) return code(RR::InvalidPegType);
  if (tags.has(Tag::DiscretionPrice) || tags.has(Tag::DiscretionPriceType) || tags.has(Tag::DiscretionPegOffset) ||
      tags.has(Tag::RandomReserves))
    return code(RR::Other);
  if (tags.has(Tag::TradeNow) && tags.trade_now == ouch50::TradeNow::Yes) return code(RR::Other);
  // Reserve (MaxFloor, Rule 4703(h)): at least one round lot shown, less than
  // the quantity; a displayed, resting, continuous limit order only.
  const Qty lot = symbols_[l].round_lot;
  if (sp.max_floor != 0 && (sp.max_floor < lot || sp.max_floor >= sp.qty || sp.display == Display::Hidden ||
                            sp.tif == Tif::Ioc || sp.market || sp.min_qty != 0 || sp.peg != PegType::Limit || cross))
    return code(RR::InvalidMaxFloor);
  // Minimum quantity (Rule 4703(e)): at least one round lot, at most the
  // quantity; never rests (forced IOC) and never joins a cross.
  if (sp.min_qty != 0) {
    if (sp.min_qty < lot || sp.min_qty > sp.qty || cross || sp.post_only || sp.peg != PegType::Limit)
      return code(RR::InvalidMinQuantity);
    sp.tif = Tif::Ioc;
  }
  if (!aiq_supported(sp.aiq)) return code(RR::InvalidAiq);
  if (sp.tif == Tif::Gtt && !sp.has_expire) return code(RR::Other);
  // Rule 201 (Reg SHO 'Y' state): short sales need a known state; with the
  // price test on ('1', '2') they must be priced above the NBB (own best bid).
  if (sp.marking == Marking::SellShort) {
    const char rs = symbols_[l].regsho;
    if (rs != '0' && rs != '1' && rs != '2') return code(RR::RegShoStateNotAvailable);
    if (rs != '0') {
      const PxE4 nbb = book_.displayed_best(l, Side::Buy);
      if (sp.market || (nbb > 0 && sp.px <= nbb)) return code(RR::RiskShortSellRestricted);
    }
  }
  if (cross) return check_cross_order(sp, si, l, replace, route);
  // Midpoint peg (Rule 4703(d)): regular market hours, a limit (the cap), not halted; never displayed.
  if (sp.peg == PegType::MidpointPeg) {
    if (sp.market || session_ != Session::Regular) return code(RR::PeggingNotAllowed);
    if (!on_tick(l, sp.px)) return code(RR::InvalidPrice);
    if (symbols_[l].halt != HaltPhase::None) return code(RR::Halted);
    sp.display = Display::Hidden;
    route = Route::Peg;
    return 0;
  }
  if (sp.market) {
    if (replace || sp.tif != Tif::Ioc) return code(RR::InvalidPrice);
    if ((si.flags & SessionEntry::kMarketOrders) == 0) return code(RR::RiskMarketOrderNotAllowed);
  }
  if (sp.post_only && sp.tif == Tif::Ioc) return code(RR::Other);
  if (!sp.market && !on_tick(l, sp.px)) return code(RR::InvalidPrice);
  // The state gate (05 §4 step 3).
  if (session_ == Session::Closed) return code(RR::DestinationClosed);
  const SymbolInfo& y = symbols_[l];
  const bool immediate = sp.tif == Tif::Ioc || sp.market;
  if (y.halt != HaltPhase::None) {
    if (immediate) return code(RR::Halted);
    route = Route::RestOnly;
    return 0;
  }
  if (session_ == Session::PreMarket && sp.tif == Tif::Day) {
    if (sp.max_floor != 0) return code(RR::InvalidMaxFloor);  // reserve orders do not wait for the open
    route = Route::Held;  // early market hours: held for the opening cross
  } else if (session_ == Session::PostMarket && sp.tif == Tif::Day) {
    return code(RR::DestinationClosed);  // market hours are over
  }
  return 0;
}

// Cross orders (05 §5 timeline, R2 D2.1-D2.2).
std::uint16_t Engine::check_cross_order(OrderSpec& sp, const SessionInfo& si, Locate l, bool replace,
                                        Route& route) const noexcept {
  (void)replace;
  const SymbolInfo& y = symbols_[l];
  if (session_ == Session::Closed) return code(RR::DestinationClosed);
  if (sp.post_only) return code(RR::InvalidCrossOrder);
  if (sp.market && sp.imbalance_only) return code(RR::InvalidCrossOrder);  // IO has no market version
  if (!sp.market && !on_tick(l, sp.px)) return code(RR::InvalidPrice);
  const bool buy = sp.side == Side::Buy;
  bool late = false;
  switch (sp.cross) {
    case CrossType::Opening:
      if (session_ != Session::PreMarket || y.opened) return code(RR::InvalidCrossOrder);
      if (sp.market) {
        if ((milestones_ & kMooCutoff) != 0) return code(RR::InvalidCrossOrder);
      } else if (!sp.imbalance_only) {
        if ((milestones_ & kLooCutoff) != 0) return code(RR::InvalidCrossOrder);
        late = (milestones_ & kMooCutoff) != 0;
      }
      break;
    case CrossType::Closing:
      if ((session_ != Session::PreMarket && session_ != Session::Regular) || y.closed)
        return code(RR::InvalidCrossOrder);
      if (sp.market) {
        if ((milestones_ & kMocCutoff) != 0) return code(RR::InvalidCrossOrder);
      } else if (!sp.imbalance_only) {
        if ((milestones_ & kLocCutoff) != 0) return code(RR::InvalidCrossOrder);
        late = (milestones_ & kMocCutoff) != 0;
        if (late && y.close_ref1 == 0 && y.close_ref2 == 0) return code(RR::NoClosingReferencePrice);
      }
      break;
    default:  // HaltIpo: only while the symbol is halted
      if (y.halt == HaltPhase::None) return code(RR::InvalidCrossOrder);
      break;
  }
  if (late) {
    // Late LOO/LOC (R2 D2.1): accepted at the limit, repriced to the more
    // aggressive of the first and second reference prices, or rejected when
    // more aggressive than that, per the port's option.
    const PxE4 ref = late_reference(l, buy, sp.cross);
    if (ref > 0) {
      if (si.late_cross == LateCrossPolicy::Reprice) {
        sp.px = buy ? std::min(sp.px, ref) : std::max(sp.px, ref);
      } else if (si.late_cross == LateCrossPolicy::Reject && (buy ? sp.px > ref : sp.px < ref)) {
        return code(RR::LateLocTooAggressive);
      }
    }
  }
  route = Route::Cross;
  return 0;
}

PxE4 Engine::late_reference(Locate l, bool buy, CrossType ct) const noexcept {
  const SymbolInfo& y = symbols_[l];
  const PxE4 a = ct == CrossType::Opening ? y.prior_close : y.close_ref1;
  const PxE4 b = ct == CrossType::Opening ? y.open_ref2 : y.close_ref2;
  if (a <= 0) return b > 0 ? b : 0;
  if (b <= 0) return a;
  return buy ? std::max(a, b) : std::min(a, b);
}

// A pending cross order (or held order) inside its freeze (05 §4 step 3).
bool Engine::frozen(const Order& r) const noexcept {
  if (r.where != Where::Pending) return false;
  const SymbolInfo& y = symbols_[r.locate];
  if (r.cross == CrossType::Opening || r.has(Order::kHeld)) return (milestones_ & kOpenFreeze) != 0 && !y.opened;
  if (r.cross == CrossType::Closing)
    return (milestones_ & kCloseFreeze) != 0 && !y.closed &&
           ((milestones_ & kLocCutoff) != 0 || !accounts_[r.account].cross_permit);
  return false;
}

bool Engine::can_match(Locate l) const noexcept {
  return symbols_[l].halt == HaltPhase::None && session_ != Session::Closed;
}

PxE4 Engine::tick_of(Locate l, PxE4 px) const noexcept {
  return px >= kPxScale ? static_cast<PxE4>(symbols_[l].tick) : PxE4{1};
}
bool Engine::on_tick(Locate l, PxE4 px) const noexcept { return px % tick_of(l, px) == 0; }
PxE4 Engine::tick_below(Locate l, PxE4 p) const noexcept {
  return p > kPxScale ? p - static_cast<PxE4>(symbols_[l].tick) : p - 1;
}
PxE4 Engine::tick_above(Locate l, PxE4 p) const noexcept {
  return p >= kPxScale ? p + static_cast<PxE4>(symbols_[l].tick) : p + 1;
}

// To the symbol's price grid: 'U' up, 'D' down, 'N' nearest (half up).
PxE4 Engine::round_tick(Locate l, PxE4 p, char dir) const noexcept {
  if (p <= 0) return 0;
  const PxE4 t = tick_of(l, p);
  const PxE4 down = p / t * t;
  if (down == p) return p;
  PxE4 r = down;
  if (dir == 'U') r = down + t;
  if (dir == 'N') r = (p - down) * 2 >= t ? down + t : down;
  // A result that crossed the $1 boundary is on the finer grid either way.
  return r;
}

bool Engine::crosses(Side side, PxE4 resting, PxE4 limit) noexcept {
  return side == Side::Buy ? resting <= limit : resting >= limit;
}

PxE4 Engine::collar_limit(Locate l, Side side) const noexcept {
  const BookLevel* lv = book_.best(l, opposite(side));
  if (lv == nullptr) return 0;  // nothing to match; the limit is never consulted
  const PxE4 band = collar_band(lv->px);
  return side == Side::Buy ? lv->px + band : lv->px - band;
}

// Post-Only (tag 12; Rule 4702(b)(4)): an order that would lock or cross the
// best opposite level (displayed or not) is repriced one tick away, or
// cancelled when the port says so or no valid price remains. 'G' when the
// contra level has displayed shares, 'F' when it holds only non-displayed ones.
Engine::PostOnlyResult Engine::post_only_check(Locate l, Side side, PxE4 px, const SessionInfo& si) const noexcept {
  const BookLevel* lv = book_.best(l, opposite(side));
  if (lv == nullptr || !crosses(side, lv->px, px)) return {};
  PostOnlyResult r;
  r.reason = lv->qty[kDisplayed] > 0 ? CR::PostOnlyContra : CR::PostOnlyNms;
  const PxE4 np = side == Side::Buy ? tick_below(l, lv->px) : tick_above(l, lv->px);
  if ((si.flags & SessionEntry::kPostOnlyCancel) != 0 || np < 1 || np > kPxMaxLimit) {
    r.kind = PostOnlyResult::Cancel;
    return r;
  }
  r.kind = PostOnlyResult::Slid;
  r.px = np;
  return r;
}

Engine::Taker Engine::make_taker(const OrderSpec& sp, Locate l, std::uint32_t a, std::uint32_t s) const noexcept {
  Taker t;
  t.locate = l;
  t.side = sp.side;
  t.account = a;
  t.session = s;
  t.urn = sp.urn;
  t.idx = sp.user_ref_idx;
  t.firm = sp.firm;
  t.aiq = sp.aiq;
  t.aiq_group = sp.aiq_group;
  t.smp = smp_of(sp.aiq);
  t.min_qty = sp.min_qty;
  t.peg = sp.peg == PegType::MidpointPeg;
  const SymbolInfo& y = symbols_[l];
  if (session_ == Session::Regular && y.luld_hi > 0) {
    t.band_lo = y.luld_lo;
    t.band_hi = y.luld_hi;
  }
  return t;
}

// Self-match (Rule 4757(a)(4)): both orders carry an active AIQ strategy and
// the same AIQ Group ID, and share the firm (Firm level) or the account
// (Match-Any level) of the incoming order's strategy.
bool Engine::self_match(const Taker& t, const Order& r) noexcept {
  if (t.smp.action == SmpAction::None || r.aiq == AiqMode::Disabled || r.aiq_group != t.aiq_group) return false;
  return t.smp.firm_level ? r.firm == t.firm : r.account == t.account;
}

// Dry run of match(): Exec (some execution occurs), Left (no execution,
// shares remain to rest or cancel), Gone (self-match prevention consumes the
// order before any execution). Decides the Order State of the 'A'/'U'.
Engine::Dry Engine::dry_run(const Taker& t) const noexcept {
  if (t.peg) {
    bool active = false;
    (void)midpoint(t.locate, active);
    if (!active) return Dry::Left;
  }
  if (t.min_qty > 0 && available(t) < t.min_qty) return Dry::Left;
  Qty rem = t.rem;
  Dry d = Dry::Left;
  scan(t, [&](Handle h) {
    const Order& r = book_.at(h);
    if (!self_match(t, r)) {
      d = Dry::Exec;
      return false;
    }
    if (t.smp.action == SmpAction::CancelNewest) {
      d = Dry::Gone;
      return false;
    }
    if (t.smp.action == SmpAction::DecrementBoth) {
      if (rem <= r.leaves) {
        d = Dry::Gone;
        return false;
      }
      rem -= r.leaves;
    }
    return true;
  });
  return d;
}

Qty Engine::available(const Taker& t) const noexcept {
  std::uint64_t sum = 0;
  scan(t, [&](Handle h) {
    const Order& r = book_.at(h);
    if (!self_match(t, r)) sum += r.leaves;
    return sum < t.min_qty;
  });
  return static_cast<Qty>(std::min<std::uint64_t>(sum, t.min_qty));
}

bool Engine::dead_on_arrival(const Taker& t, bool immediate) const noexcept {
  const Dry d = dry_run(t);
  return d == Dry::Gone || (d == Dry::Left && immediate);
}

PxE4 Engine::midpoint(Locate l, bool& active) const noexcept {
  const PxE4 bid = book_.displayed_best(l, Side::Buy);
  const PxE4 ask = book_.displayed_best(l, Side::Sell);
  active = bid > 0 && ask > 0 && bid < ask;
  return active ? (bid + ask) / 2 : 0;
}

PxE4 Engine::peg_limit(Locate l, Side side, PxE4 cap) const noexcept {
  bool active = false;
  const PxE4 mid = midpoint(l, active);
  if (!active) return cap;
  return side == Side::Buy ? std::min(cap, mid) : std::max(cap, mid);
}

bool Engine::peg_eligible(const Order& r, PxE4 mid) const noexcept {
  return r.side == Side::Buy ? mid <= r.px : mid >= r.px;
}

// ============================================================================ crosses

void Engine::gather_interest(Locate l, CrossKind k, bool cross_only) {
  interest_.clear();
  handles_.clear();
  const SymbolInfo& y = symbols_[l];
  const PxE4 bid = book_.displayed_best(l, Side::Buy);
  const PxE4 ask = book_.displayed_best(l, Side::Sell);
  for (Handle h = y.pend_head; h != kNil; h = book_.next(h)) {
    const Order& r = book_.at(h);
    const bool in = (k == CrossKind::Open && (r.cross == CrossType::Opening || r.has(Order::kHeld))) ||
                    (k == CrossKind::Close && r.cross == CrossType::Closing) ||
                    (k == CrossKind::Halt && r.cross == CrossType::HaltIpo);
    if (!in || r.min_qty != 0) continue;  // MinQty orders do not take part in crosses
    CrossInterest c;
    c.qty = r.leaves;
    c.buy = r.side == Side::Buy;
    c.market = r.has(Order::kMarket);
    c.imbalance_only = r.has(Order::kImbalanceOnly);
    c.cross_order = !c.imbalance_only;
    c.px = r.px;
    // OIO/IO are priced at the Nasdaq bid (buys) or offer (sells), never beyond their limit.
    if (c.imbalance_only) c.px = c.buy ? (bid > 0 ? std::min(r.px, bid) : r.px) : (ask > 0 ? std::max(r.px, ask) : r.px);
    interest_.push_back(c);
    handles_.push_back(h);
  }
  if (cross_only) return;
  for (Side s : {Side::Buy, Side::Sell}) {
    const std::size_t n = book_.level_count(l, s);
    for (std::size_t lvk = 0; lvk < n; ++lvk) {
      const BookLevel* lv = book_.level_at_rank(l, s, lvk);
      for (int c = 0; c < 2; ++c) {
        for (Handle h = lv->q[c].head; h != kNil; h = book_.next(h)) {
          const Order& r = book_.at(h);
          if (r.min_qty != 0) continue;
          CrossInterest ci;
          ci.px = r.px;
          ci.qty = r.leaves;
          ci.buy = s == Side::Buy;
          interest_.push_back(ci);
          handles_.push_back(h);
        }
      }
    }
  }
}

CrossResult Engine::compute_cross(Locate l, CrossKind k, bool cross_only, bool crp) {
  gather_interest(l, k, cross_only);
  const SymbolInfo& y = symbols_[l];
  const PxE4 bid = book_.displayed_best(l, Side::Buy);
  const PxE4 ask = book_.displayed_best(l, Side::Sell);
  CrossParams p;
  p.kind = k;
  if (k == CrossKind::Halt) {
    p.ref = y.halt_kind == HaltKind::Ipo && y.ipo_price > 0 ? y.ipo_price : (y.last_sale > 0 ? y.last_sale : y.prior_close);
  } else if (bid > 0 && ask > 0) {
    p.ref = (bid + ask) / 2;
  } else {
    p.ref = k == CrossKind::Open ? y.prior_close : (y.last_sale > 0 ? y.last_sale : y.prior_close);
  }
  if (crp) {
    if (bid > 0 && ask > 0 && bid <= ask) {
      p.lo = bid;
      p.hi = ask;
      p.hard = true;
    }
  } else if (k != CrossKind::Halt && !cross_only) {
    threshold_window(l, k, p.ref, p);
  }
  return calc_.compute(interest_, p);
}

// Open/close threshold (R2 D2.4): max(10% of the QBBO midpoint, $0.50) beyond
// the Nasdaq bid and offer; ETPs: open max(5%, $0.50), close 3% above $50.01.
void Engine::threshold_window(Locate l, CrossKind k, PxE4 ref, CrossParams& p) const noexcept {
  (void)ref;
  const PxE4 bid = book_.displayed_best(l, Side::Buy);
  const PxE4 ask = book_.displayed_best(l, Side::Sell);
  if (bid == 0 && ask == 0) return;
  const PxE4 mid = bid > 0 && ask > 0 ? (bid + ask) / 2 : (bid > 0 ? bid : ask);
  PxE4 thr;
  if ((symbols_[l].flags & SymbolEntry::kFlagEtp) != 0) {
    thr = k == CrossKind::Close && mid > 500'100 ? mid * 3 / 100 : std::max<PxE4>(mid * 5 / 100, 5'000);
  } else {
    thr = std::max<PxE4>(mid * params_.threshold_bps / 10'000, params_.threshold_min);
  }
  PxE4 lo = (bid > 0 ? bid : ask) - thr;
  PxE4 hi = (ask > 0 ? ask : bid) + thr;
  lo = lo < 1 ? 1 : round_tick(l, lo, 'U');
  hi = round_tick(l, hi, 'D');
  if (hi < lo) hi = lo;
  p.lo = lo;
  p.hi = hi;
  p.hard = false;
}

// Opening Cross Price Tests A (prior close), B (last sale after 09:15), C (the
// Nasdaq bid or offer): the cross happens if any applicable test passes, or
// if none applies (R2 D2.3 step F).
bool Engine::price_tests_pass(Locate l, PxE4 p) const noexcept {
  const std::int64_t mask = params_.price_tests;
  if (mask == 0) return true;
  const SymbolInfo& y = symbols_[l];
  auto thr = [&](PxE4 ref) { return std::max<PxE4>(ref * params_.price_test_bps / 10'000, params_.price_test_min); };
  bool applicable = false;
  if ((mask & 1) != 0 && y.prior_close > 0) {
    applicable = true;
    if (absdiff(p, y.prior_close) <= thr(y.prior_close)) return true;
  }
  if ((mask & 2) != 0 && y.last_sale > 0 && y.last_sale_ns >= hms_ns(9, 15, 0)) {
    applicable = true;
    if (absdiff(p, y.last_sale) <= thr(y.last_sale)) return true;
  }
  if ((mask & 4) != 0) {
    const PxE4 bid = book_.displayed_best(l, Side::Buy);
    const PxE4 ask = book_.displayed_best(l, Side::Sell);
    if (bid > 0 || ask > 0) applicable = true;
    if (bid > 0 && absdiff(p, bid) <= thr(bid)) return true;
    if (ask > 0 && absdiff(p, ask) <= thr(ask)) return true;
  }
  return !applicable;
}

// Allocation at the cross price (R2 D2.5). Open/close: market cross orders by
// time; then displayed interest (LOO/LOC/OIO/IO, held orders shown on ITCH
// when posted, displayed book orders) by price then time; then non-displayed
// by price then time. Halt: price, then displayed before non-displayed, then
// time. Regular interest executes first on each side; imbalance-only orders
// fill what remains of V on the side short of shares.
void Engine::allocate(Locate l, CrossKind k, const CrossResult& res) {
  gather_interest(l, k, false);
  buys_.clear();
  sells_.clear();
  const PxE4 p = res.price;
  std::vector<Cand>& bc = bcand_;
  std::vector<Cand>& sc = scand_;
  bc.clear();
  sc.clear();
  std::uint64_t rb = 0, rs = 0;
  for (std::size_t i = 0; i < interest_.size(); ++i) {
    const CrossInterest& c = interest_[i];
    if (!(c.market || (c.buy ? c.px >= p : c.px <= p))) continue;
    const Order& r = book_.at(handles_[i]);
    const bool hidden = r.where == Where::Book ? r.cls() == kHidden : (r.has(Order::kHeld) && r.display == Display::Hidden);
    Cand x{handles_[i], c.px, c.qty, 0, 0, r.prio, r.ref, c.imbalance_only, c.market};
    if (k == CrossKind::Halt) {
      x.rank = c.market ? 0 : 1;
      x.display = hidden ? 1 : 0;
    } else {
      x.rank = c.market ? 0 : (hidden ? 2 : 1);
    }
    if (!c.imbalance_only) (c.buy ? rb : rs) += c.qty;
    (c.buy ? bc : sc).push_back(x);
  }
  auto order = [k](bool buy) {
    return [k, buy](const Cand& a, const Cand& b) {
      if (a.rank != b.rank) return a.rank < b.rank;
      if (!a.market && a.px != b.px) return buy ? a.px > b.px : a.px < b.px;
      if (k == CrossKind::Halt && a.display != b.display) return a.display < b.display;
      if (a.prio != b.prio) return a.prio < b.prio;
      return a.ref < b.ref;
    };
  };
  std::sort(bc.begin(), bc.end(), order(true));
  std::sort(sc.begin(), sc.end(), order(false));
  auto give = [&](std::vector<Cand>& v, std::uint64_t reg_total, std::vector<Fill>& out) {
    std::uint64_t reg = std::min<std::uint64_t>(reg_total, res.volume);
    std::uint64_t io = res.volume - reg;
    for (Cand& c : v) {
      std::uint64_t& pool = c.io ? io : reg;
      const std::uint64_t q = std::min<std::uint64_t>(pool, c.qty);
      pool -= q;
      if (q > 0) out.push_back(Fill{c.h, static_cast<Qty>(q)});
    }
  };
  give(bc, rb, buys_);
  give(sc, rs, sells_);
}

// Halt collars (R2 D2.4), rounded to the nearest tick.
void Engine::set_collars(Locate l, HaltKind kind, PxE4 arp) {
  SymbolInfo& y = symbols_[l];
  y.arp = arp;
  y.extension = 0;
  y.collar_lo = y.collar_hi = y.collar_step = 0;
  if (arp <= 0) return;
  switch (kind) {
    case HaltKind::News: {
      // ARP +/- max($1, 10%) above $1, max($0.50, 10%) at or below.
      const PxE4 d = arp > kPxScale ? std::max<PxE4>(kPxScale, arp / 10) : std::max<PxE4>(5'000, arp / 10);
      y.collar_lo = round_tick(l, arp - d, 'N');
      y.collar_hi = round_tick(l, arp + d, 'N');
      break;
    }
    case HaltKind::Luld: {
      // Trigger side: ARP -/+ 5% ($0.15 at or below $3); the other side is the opposite band.
      y.collar_step = arp <= 30'000 ? 1'500 : round_tick(l, arp / 20, 'N');
      if (arp == y.luld_lo) {
        y.collar_lo = arp - y.collar_step;
        y.collar_hi = y.luld_hi;
      } else {
        y.collar_hi = arp + y.collar_step;
        y.collar_lo = y.luld_lo;
      }
      break;
    }
    case HaltKind::Mwcb: {
      // +/- 10% ($0.50 at or below $5).
      y.collar_step = arp <= 50'000 ? 5'000 : round_tick(l, arp / 10, 'N');
      y.collar_lo = arp - y.collar_step;
      y.collar_hi = arp + y.collar_step;
      break;
    }
    default: return;
  }
  clamp_collars(y);
}

// Collars stay inside the ITCH Price(4) range: at most $429,496.00 (a multiple of
// every tick), the lower one at least one tick unit and not above the upper.
void Engine::clamp_collars(SymbolInfo& y) noexcept {
  constexpr PxE4 kMaxCollar = PxE4{0xFFFF'FFFF} / kPxScale * kPxScale;
  if (y.collar_hi > kMaxCollar) y.collar_hi = kMaxCollar;
  if (y.collar_lo < 1) y.collar_lo = 1;
  if (y.collar_hi > 0 && y.collar_lo > y.collar_hi) y.collar_lo = y.collar_hi;
}

// Extensions (R2 D2.4): news halts widen both collars by max($1, 10% of the
// initial ARP) at the first extension and by max($1, 20%) at each later one
// ($0.50 at or below $1); LULD and MWCB widen only the imbalance side by their
// step (both sides when there is no imbalance).
void Engine::widen_collars(Locate l, char side) {
  SymbolInfo& y = symbols_[l];
  if (y.collar_hi == 0) return;
  if (y.halt_kind == HaltKind::News) {
    const PxE4 pct = y.extension <= 1 ? y.arp / 10 : y.arp / 5;
    const PxE4 d = y.arp > kPxScale ? std::max<PxE4>(kPxScale, pct) : std::max<PxE4>(5'000, pct);
    y.collar_lo = round_tick(l, y.collar_lo - d, 'N');
    y.collar_hi = round_tick(l, y.collar_hi + d, 'N');
  } else {
    if (side != 'S') y.collar_hi += y.collar_step;
    if (side != 'B') y.collar_lo -= y.collar_step;
  }
  clamp_collars(y);
}

Engine::NoiiValues Engine::noii_values(Locate l, CrossKind k, bool eoii) {
  NoiiValues v;
  gather_interest(l, k, true);
  if (interest_.empty()) return v;  // 'O': no cross interest
  const CrossResult r = compute_cross(l, k, false, true);
  if (!r.valid) return v;
  v.paired = r.volume;
  v.imbalance = r.imbalance;
  v.direction = r.side;
  v.crp = r.price;
  if (!eoii) {
    const CrossResult near = compute_cross(l, k, false, false);
    v.near = near.valid && near.volume > 0 ? near.price : 0;
    const CrossResult far = compute_cross(l, k, true, false);
    v.far = far.valid && far.volume > 0 ? far.price : 0;
  }
  return v;
}

// ============================================================================ order bookkeeping

Handle Engine::new_order(const OrderSpec& sp, const Taker& t, OrderRef ref, PxE4 px, std::uint64_t prio) {
  const Handle h = book_.alloc();
  Order& r = book_.at(h);
  r = Order{};
  r.ref = ref;
  r.itch_ref = ref;
  r.prio = prio;
  r.px = sp.market ? 0 : px;
  r.risk_px = sp.risk_px;
  r.leaves = t.rem;
  r.done = t.done;
  r.min_qty = sp.min_qty;
  r.max_floor = sp.max_floor;
  r.urn = sp.urn;
  r.account = t.account;
  r.session = t.session;
  r.expire_time = sp.expire_time;
  r.firm = sp.firm;
  r.locate = t.locate;
  r.group_id = sp.group_id;
  std::uint16_t f = 0;
  if (sp.post_only) f |= Order::kPostOnly;
  if (sp.has_expire) f |= Order::kHasExpire;
  if (sp.imbalance_only) f |= Order::kImbalanceOnly;
  if (sp.market) f |= Order::kMarket;
  if (sp.peg == PegType::MidpointPeg) f |= Order::kMidPeg;
  if (sp.shares_located) f |= Order::kLocated;
  r.flags = f;
  r.aiq_group = sp.aiq_group;
  r.user_ref_idx = sp.user_ref_idx;
  r.side = sp.side;
  r.marking = sp.marking;
  r.display = sp.display;
  r.tif = sp.tif;
  r.capacity = sp.capacity;
  r.iso = sp.iso;
  r.cross = sp.cross;
  r.aiq = sp.aiq;
  const bool fresh = urn_->insert(urn_key(r.account, r.user_ref_idx, r.urn), h);
  LLE_ASSERT(fresh, "UserRefNum already maps to a live order");
  acct_append(h);
  risk_.open_delta(r.account, r.locate, i128{r.leaves} * r.risk_px);
  ++live_;
  return h;
}

void Engine::acct_append(Handle h) noexcept {
  AccountInfo& ai = accounts_[book_.at(h).account];
  MatchingBook::Links& k = book_.links(h);
  k.acct_prev = ai.tail;
  k.acct_next = kNil;
  if (ai.tail != kNil) {
    book_.links(ai.tail).acct_next = h;
  } else {
    ai.head = h;
  }
  ai.tail = h;
}

void Engine::acct_unlink(Handle h) noexcept {
  AccountInfo& ai = accounts_[book_.at(h).account];
  const MatchingBook::Links k = book_.links(h);
  if (k.acct_prev != kNil) {
    book_.links(k.acct_prev).acct_next = k.acct_next;
  } else {
    ai.head = k.acct_next;
  }
  if (k.acct_next != kNil) {
    book_.links(k.acct_next).acct_prev = k.acct_prev;
  } else {
    ai.tail = k.acct_prev;
  }
}

void Engine::list_append(Handle& head, Handle& tail, Handle h) noexcept {
  auto& k = book_.links(h).link;
  k.prev = tail;
  k.next = kNil;
  if (tail != kNil) {
    book_.links(tail).link.next = h;
  } else {
    head = h;
  }
  tail = h;
}

void Engine::list_unlink(Handle& head, Handle& tail, Handle h) noexcept {
  const auto k = book_.links(h).link;
  if (k.prev != kNil) {
    book_.links(k.prev).link.next = k.next;
  } else {
    head = k.next;
  }
  if (k.next != kNil) {
    book_.links(k.next).link.prev = k.prev;
  } else {
    tail = k.prev;
  }
}

void Engine::detach(Handle h) noexcept {
  Order& r = book_.at(h);
  SymbolInfo& y = symbols_[r.locate];
  switch (r.where) {
    case Where::Book: book_.unlink(h); break;
    case Where::Pending: list_unlink(y.pend_head, y.pend_tail, h); break;
    case Where::Peg: {
      const std::size_t sd = r.side == Side::Buy ? 0 : 1;
      list_unlink(y.peg_head[sd], y.peg_tail[sd], h);
      break;
    }
    case Where::Off: break;  // already out of its queue
  }
}

void Engine::remove_order(Handle h) noexcept {
  Order& r = book_.at(h);
  risk_.open_delta(r.account, r.locate, -i128{total_leaves(h)} * r.risk_px);
  if (r.has(Order::kReserveChild)) {
    // The reserve part alone: its parent stays.
    book_.at(r.peer).peer = kNil;
    detach(h);
    book_.free(h);
    return;
  }
  if (r.peer != kNil) {
    detach(r.peer);
    book_.free(r.peer);
    r.peer = kNil;
  }
  detach(h);
  (void)urn_->erase(urn_key(r.account, r.user_ref_idx, r.urn));
  acct_unlink(h);
  book_.free(h);
  --live_;
}

void Engine::take_leaves(Handle h, Qty d) noexcept {
  Order& r = book_.at(h);
  risk_.open_delta(r.account, r.locate, -i128{d} * r.risk_px);
  if (r.where == Where::Book) {
    book_.reduce(h, d);
  } else {
    r.leaves -= d;
  }
}

Qty Engine::total_leaves(Handle h) const noexcept {
  const Order& r = book_.at(h);
  return r.leaves + (r.peer != kNil && !r.has(Order::kReserveChild) ? book_.at(r.peer).leaves : 0);
}

// ============================================================================ consistency

bool Engine::check(std::string* err) const {
  auto fail = [&](const char* m) {
    if (err) *err = m;
    return false;
  };
  std::size_t book_orders = 0, listed = 0;
  for (std::uint32_t a = 0; a < accounts_.size(); ++a) {
    OrderRef prev = 0;
    Handle p = kNil;
    for (Handle h = accounts_[a].head; h != kNil; h = book_.links(h).acct_next) {
      const Order& o = book_.at(h);
      if (o.account != a || book_.links(h).acct_prev != p || o.ref <= prev || o.has(Order::kReserveChild))
        return fail("engine: account list broken or out of reference order");
      if (urn_->find(urn_key(a, o.user_ref_idx, o.urn)) != h) return fail("engine: UserRefNum index does not map to the order");
      if (o.leaves == 0) return fail("engine: live order with no shares");
      if (o.where == Where::Book) ++book_orders;
      if (o.peer != kNil) {
        const Order& c = book_.at(o.peer);
        if (!c.has(Order::kReserveChild) || c.peer != h || c.where != Where::Book) return fail("engine: reserve link broken");
        ++book_orders;
      }
      if (o.where == Where::Pending && o.cross == CrossType::Continuous && !o.has(Order::kHeld))
        return fail("engine: continuous order off the book");
      prev = o.ref;
      p = h;
      ++listed;
    }
    if (accounts_[a].tail != p) return fail("engine: account list tail mismatch");
    // Risk bookkeeping: open notional = sum of open shares x risk price.
    i128 open = 0;
    for (Handle h = accounts_[a].head; h != kNil; h = book_.links(h).acct_next)
      open += i128{total_leaves(h)} * book_.at(h).risk_px;
    if (a < risk_.accounts() && risk_.open(a) != open) return fail("engine: risk open notional mismatch");
    if (a < risk_.accounts() && risk_.tracks_symbols(a)) {
      for (Locate l = 1; l < symbols_.size(); ++l) {
        i128 so = 0;
        for (Handle h = accounts_[a].head; h != kNil; h = book_.links(h).acct_next)
          if (book_.at(h).locate == l) so += i128{total_leaves(h)} * book_.at(h).risk_px;
        if (risk_.symbol_open(a, l) != so) return fail("engine: risk per-symbol open notional mismatch");
      }
    }
  }
  if (listed != live_ || urn_->size() != live_) return fail("engine: live order count mismatch");
  for (Locate l = 1; l < symbols_.size(); ++l) {
    const SymbolInfo& y = symbols_[l];
    Handle p = kNil;
    for (Handle h = y.pend_head; h != kNil; h = book_.next(h)) {
      const Order& o = book_.at(h);
      if (o.where != Where::Pending || o.locate != l || book_.links(h).link.prev != p)
        return fail("engine: pending list broken");
      p = h;
    }
    if (y.pend_tail != p) return fail("engine: pending list tail mismatch");
  }
  return book_.check(err, book_orders);
}

// ============================================================================ canonical state

template <class V>
void Engine::walk_order(V& v, const Order& r) {
  v.u16(r.locate);
  v.u8(static_cast<std::uint8_t>(r.side));
  v.u8(static_cast<std::uint8_t>(r.where));
  v.u8(static_cast<std::uint8_t>(r.cls()));
  v.u64(r.ref);
  v.u64(r.itch_ref);
  v.u64(r.prio);
  v.u64(static_cast<std::uint64_t>(r.px));
  v.u64(static_cast<std::uint64_t>(r.risk_px));
  v.u32(r.leaves);
  v.u32(r.done);
  v.u32(r.min_qty);
  v.u32(r.max_floor);
  v.u32(r.urn);
  v.u32(r.account);
  v.u32(r.session);
  v.u32(r.expire_time);
  v.u32(static_cast<std::uint32_t>(pack_alpha(r.firm)));
  v.u16(r.group_id);
  v.u16(r.flags);
  v.u16(static_cast<std::uint16_t>(pack_alpha(r.aiq_group)));
  v.u8(r.user_ref_idx);
  v.u8(static_cast<std::uint8_t>(r.marking));
  v.u8(static_cast<std::uint8_t>(r.display));
  v.u8(static_cast<std::uint8_t>(r.tif));
  v.u8(static_cast<std::uint8_t>(r.capacity));
  v.u8(static_cast<std::uint8_t>(r.iso));
  v.u8(static_cast<std::uint8_t>(r.cross));
  v.u8(static_cast<std::uint8_t>(r.aiq));
}

template <class V>
void Engine::walk(V& v) const {
  v.u64(kMagic);
  v.u32(kVersion);
  v.u64(static_cast<std::uint64_t>(midnight_));
  v.u32(date_);
  v.u8(started_ ? 1 : 0);
  v.u8(static_cast<std::uint8_t>(session_));
  v.u8(static_cast<std::uint8_t>(initial_session_));
  v.u8(milestones_);
  v.u64(next_ref_);
  v.u64(next_match_);
  v.u64(itch_count_);
  v.u8(mwcb_breached_);
  for (std::int64_t x : mwcb_levels_) v.u64(static_cast<std::uint64_t>(x));
  for (std::int64_t x : {params_.threshold_bps, params_.threshold_min, params_.price_test_bps, params_.price_test_min,
                         params_.price_tests, params_.halt_period, params_.luld_pause, params_.mwcb_period,
                         params_.limit_state, params_.extension})
    v.u64(static_cast<std::uint64_t>(x));
  v.u32(static_cast<std::uint32_t>(schedule_.size()));
  for (const ScheduleEntry& e : schedule_) {
    v.u32(e.timer_id);
    v.u16(static_cast<std::uint16_t>(e.kind));
    v.u16(e.arg);
    v.u64(static_cast<std::uint64_t>(e.time_ns));
  }
  v.u32(static_cast<std::uint32_t>(symbols_.size() - 1));
  for (std::size_t l = 1; l < symbols_.size(); ++l) {
    const SymbolInfo& y = symbols_[l];
    v.u64(pack_alpha(y.symbol));
    v.u32(y.round_lot);
    v.u32(y.tick);
    v.u64(static_cast<std::uint64_t>(y.prior_close));
    v.u8(static_cast<std::uint8_t>(y.market_category));
    v.u8(static_cast<std::uint8_t>(y.luld_tier));
    v.u8(y.flags);
    v.u32(y.adv);
    v.u8(y.opened ? 1 : 0);
    v.u8(y.closed ? 1 : 0);
    v.u8(static_cast<std::uint8_t>(y.regsho));
    v.u8(static_cast<std::uint8_t>(y.halt));
    v.u8(static_cast<std::uint8_t>(y.halt_kind));
    v.u32(static_cast<std::uint32_t>(pack_alpha(y.reason)));
    v.u32(y.ticks);
    v.u32(y.period);
    v.u32(y.extension);
    for (PxE4 x : {y.arp, y.collar_lo, y.collar_hi, y.collar_step, y.luld_lo, y.luld_hi})
      v.u64(static_cast<std::uint64_t>(x));
    v.u32(static_cast<std::uint32_t>(y.limit_ticks));
    for (PxE4 x : {y.last_sale, static_cast<PxE4>(y.last_sale_ns), y.open_ref2, y.close_ref1, y.close_ref2, y.ipo_price,
                   y.ipo_band, y.ipo_expected})
      v.u64(static_cast<std::uint64_t>(x));
    v.u32(y.peg_pulled);
  }
  v.u32(static_cast<std::uint32_t>(accounts_.size()));
  for (std::size_t a = 0; a < accounts_.size(); ++a) {
    const AccountInfo& ai = accounts_[a];
    v.u32(ai.id);
    for (const Firm& f : ai.firms) v.u32(static_cast<std::uint32_t>(pack_alpha(f)));
    v.u8(ai.nfirms);
    v.u8(ai.disabled);
    v.u8(ai.cross_permit ? 1 : 0);
    std::uint16_t n = 0;
    for (UserRefNum x : trackers_[a]) n = static_cast<std::uint16_t>(n + (x != 0 ? 1 : 0));
    v.u16(n);
    for (std::size_t i = 0; i < 256; ++i) {
      if (trackers_[a][i] == 0) continue;
      v.u8(static_cast<std::uint8_t>(i));
      v.u32(trackers_[a][i]);
    }
  }
  v.u32(static_cast<std::uint32_t>(sessions_.size()));
  for (const SessionInfo& si : sessions_) {
    v.u32(si.id);
    v.u32(si.account);
    v.u8(si.flags);
    v.u8(static_cast<std::uint8_t>(si.default_aiq));
    v.u8(static_cast<std::uint8_t>(si.late_cross));
    v.u64(si.live);
    v.u64(si.ouch_out);
  }
  std::uint64_t records = 0;
  for (const AccountInfo& ai : accounts_)
    for (Handle h = ai.head; h != kNil; h = book_.links(h).acct_next) records += book_.at(h).peer != kNil ? 2u : 1u;
  v.u64(records);
  for (Locate l = 1; l < symbols_.size(); ++l) {
    for (Side side : {Side::Buy, Side::Sell}) {
      book_.for_each_level(l, side, [&](const BookLevel& lv) {
        for (int c = 0; c < 2; ++c) book_.for_each_in(lv, c, [&](Handle h) { walk_order(v, book_.at(h)); });
      });
    }
    const SymbolInfo& y = symbols_[l];
    for (Handle h = y.pend_head; h != kNil; h = book_.next(h)) walk_order(v, book_.at(h));
    for (std::size_t sd = 0; sd < 2; ++sd)
      for (Handle h = y.peg_head[sd]; h != kNil; h = book_.next(h)) walk_order(v, book_.at(h));
  }
  risk_.walk(v);
}

std::uint64_t Engine::state_hash() const {
  StateHasher h;
  walk(h);
  return h.value();
}

void Engine::snapshot(std::vector<std::byte>& out) const {
  ByteWriter w(out);
  walk(w);
}

bool Engine::restore(std::span<const std::byte> in) {
  if (restore_impl(in)) return true;
  reset_day();
  return false;
}

bool Engine::restore_impl(std::span<const std::byte> in) {
  ByteReader rd(in);
  if (rd.u64() != kMagic || rd.u32() != kVersion) return false;
  reset_day();
  midnight_ = static_cast<Nanos>(rd.u64());
  date_ = rd.u32();
  started_ = rd.u8() != 0;
  auto session_of = [](std::uint8_t c, Session& s) {
    if (c != 'C' && c != 'P' && c != 'R' && c != 'A') return false;
    s = static_cast<Session>(c);
    return true;
  };
  if (!session_of(rd.u8(), session_) || !session_of(rd.u8(), initial_session_)) return false;
  milestones_ = rd.u8();
  next_ref_ = rd.u64();
  next_match_ = rd.u64();
  itch_count_ = rd.u64();
  mwcb_breached_ = rd.u8();
  for (std::int64_t& x : mwcb_levels_) x = static_cast<std::int64_t>(rd.u64());
  if (mwcb_breached_ > 3) return false;
  for (std::int64_t* x : {&params_.threshold_bps, &params_.threshold_min, &params_.price_test_bps,
                          &params_.price_test_min, &params_.price_tests, &params_.halt_period, &params_.luld_pause,
                          &params_.mwcb_period, &params_.limit_state, &params_.extension})
    *x = static_cast<std::int64_t>(rd.u64());
  if (!params_.valid()) return false;
  const std::uint32_t nsched = rd.u32();
  if (rd.fail() || nsched > rd.remaining() / 16) return false;
  for (std::uint32_t i = 0; i < nsched; ++i) {
    ScheduleEntry e;
    e.timer_id = rd.u32();
    e.kind = static_cast<TimerKind>(rd.u16());
    e.arg = rd.u16();
    e.time_ns = static_cast<Nanos>(rd.u64());
    schedule_.push_back(e);
    if (e.timer_id != 0) timers_.push_back(e);
  }
  std::sort(timers_.begin(), timers_.end(),
            [](const ScheduleEntry& a, const ScheduleEntry& b) { return a.timer_id < b.timer_id; });
  for (std::size_t i = 0; i < timers_.size(); ++i) {  // as load_schedule: known kinds, unique ids
    const auto k = static_cast<std::uint16_t>(timers_[i].kind);
    if (k < 1 || k > 7 || (i > 0 && timers_[i].timer_id == timers_[i - 1].timer_id)) return false;
  }
  const std::uint32_t nsym = rd.u32();
  if (rd.fail() || nsym > 0xFFFE || nsym > rd.remaining() / 64) return false;
  sym_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{nsym + 16u, 0});
  for (std::uint32_t i = 0; i < nsym; ++i) {
    SymbolInfo y;
    y.symbol = unpack_alpha<8>(rd.u64());
    y.round_lot = rd.u32();
    y.tick = rd.u32();
    y.prior_close = static_cast<PxE4>(rd.u64());
    y.market_category = static_cast<char>(rd.u8());
    y.luld_tier = static_cast<char>(rd.u8());
    y.flags = rd.u8();
    y.adv = rd.u32();
    y.opened = rd.u8() != 0;
    y.closed = rd.u8() != 0;
    y.regsho = static_cast<char>(rd.u8());
    const std::uint8_t halt = rd.u8();
    const std::uint8_t kind = rd.u8();
    if (halt > 5 || kind > 4) return false;
    y.halt = static_cast<HaltPhase>(halt);
    y.halt_kind = static_cast<HaltKind>(kind);
    y.reason = unpack_alpha<4>(rd.u32());
    y.ticks = rd.u32();
    y.period = rd.u32();
    y.extension = rd.u32();
    for (PxE4* x : {&y.arp, &y.collar_lo, &y.collar_hi, &y.collar_step, &y.luld_lo, &y.luld_hi})
      *x = static_cast<PxE4>(rd.u64());
    y.limit_ticks = static_cast<std::int32_t>(rd.u32());
    y.last_sale = static_cast<PxE4>(rd.u64());
    y.last_sale_ns = static_cast<Nanos>(rd.u64());
    for (PxE4* x : {&y.open_ref2, &y.close_ref1, &y.close_ref2, &y.ipo_price, &y.ipo_band, &y.ipo_expected})
      *x = static_cast<PxE4>(rd.u64());
    y.peg_pulled = rd.u32();
    // The checks the Symbols table gets, plus every price in the ITCH u32 range.
    const auto px_ok = [](PxE4 x) { return x >= 0 && x <= PxE4{0xFFFF'FFFF}; };
    bool prices = true;
    for (PxE4 x : {y.prior_close, y.arp, y.collar_lo, y.collar_hi, y.collar_step, y.luld_lo, y.luld_hi, y.last_sale,
                   y.open_ref2, y.close_ref1, y.close_ref2, y.ipo_price, y.ipo_band, y.ipo_expected})
      prices = prices && px_ok(x);
    if (rd.fail() || y.symbol.blank() || y.round_lot == 0 || y.tick == 0 || kPxScale % y.tick != 0 || !prices ||
        (y.market_category != ' ' && !itch50::is_valid(static_cast<itch50::MarketCategory>(y.market_category))) ||
        (y.luld_tier != ' ' && !itch50::is_valid(static_cast<itch50::LuldTier>(y.luld_tier))) ||
        (y.regsho != ' ' && y.regsho != '0' && y.regsho != '1' && y.regsho != '2'))
      return false;
    if (!sym_index_->insert(pack_alpha(y.symbol), i + 1)) return false;
    symbols_.push_back(y);
  }
  const std::uint32_t nacct = rd.u32();
  if (rd.fail() || nacct > kMaxAccounts || nacct > rd.remaining() / 25) return false;
  acct_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{nacct + 16u, 0});
  trackers_.assign(nacct, std::array<UserRefNum, 256>{});
  for (std::uint32_t a = 0; a < nacct; ++a) {
    AccountInfo ai;
    ai.id = rd.u32();
    for (Firm& f : ai.firms) f = unpack_alpha<4>(rd.u32());
    ai.nfirms = rd.u8();
    ai.disabled = rd.u8();
    ai.cross_permit = rd.u8() != 0;
    const std::uint16_t n = rd.u16();
    if (rd.fail() || ai.nfirms > AccountEntry::kMaxFirms || n > 256) return false;
    for (std::uint16_t k = 0; k < n; ++k) {
      const std::uint8_t i = rd.u8();
      trackers_[a][i] = rd.u32();
    }
    if (rd.fail() || !acct_index_->insert(ai.id, a)) return false;
    accounts_.push_back(ai);
  }
  const std::uint32_t nsess = rd.u32();
  if (rd.fail() || nsess > rd.remaining() / 27) return false;
  sess_index_ = std::make_unique<lob::FlatIndex<>>(lob::IndexConfig{nsess + 16u, 0});
  for (std::uint32_t i = 0; i < nsess; ++i) {
    SessionInfo si;
    si.id = rd.u32();
    si.account = rd.u32();
    si.flags = rd.u8();
    si.default_aiq = static_cast<AiqMode>(rd.u8());
    const std::uint8_t lc = rd.u8();
    si.live = rd.u64();
    si.ouch_out = rd.u64();
    if (rd.fail() || si.account >= nacct || !aiq_supported(si.default_aiq) || lc > 2 || !sess_index_->insert(si.id, i))
      return false;
    si.late_cross = static_cast<LateCrossPolicy>(lc);
    sessions_.push_back(si);
  }
  const std::uint64_t norders = rd.u64();
  if (rd.fail() || norders > rd.remaining() / 88) return false;
  book_.reset(nsym);
  std::vector<std::pair<OrderRef, Handle>> parents;
  std::vector<Handle> children;
  for (std::uint64_t k = 0; k < norders; ++k) {
    Order r;
    r.locate = rd.u16();
    r.side = static_cast<Side>(rd.u8());
    const std::uint8_t where = rd.u8();
    const std::uint8_t cls = rd.u8();
    r.ref = rd.u64();
    r.itch_ref = rd.u64();
    r.prio = rd.u64();
    r.px = static_cast<PxE4>(rd.u64());
    r.risk_px = static_cast<PxE4>(rd.u64());
    r.leaves = rd.u32();
    r.done = rd.u32();
    r.min_qty = rd.u32();
    r.max_floor = rd.u32();
    r.urn = rd.u32();
    r.account = rd.u32();
    r.session = rd.u32();
    r.expire_time = rd.u32();
    r.firm = unpack_alpha<4>(rd.u32());
    r.group_id = rd.u16();
    r.flags = rd.u16();
    r.aiq_group = unpack_alpha<2>(rd.u16());
    r.user_ref_idx = rd.u8();
    r.marking = static_cast<Marking>(rd.u8());
    r.display = static_cast<Display>(rd.u8());
    r.tif = static_cast<Tif>(rd.u8());
    r.capacity = static_cast<Capacity>(rd.u8());
    r.iso = static_cast<ouch50::IsoEligibility>(rd.u8());
    r.cross = static_cast<CrossType>(rd.u8());
    r.aiq = static_cast<AiqMode>(rd.u8());
    if (rd.fail() || r.locate == 0 || r.locate > nsym || (r.side != Side::Buy && r.side != Side::Sell) || where > 2 ||
        cls != r.cls() || r.leaves == 0 || r.account >= nacct || r.session >= nsess || r.px < 0 || r.px > kPxMaxLimit ||
        r.risk_px < 0 || r.risk_px > kPxMaxLimit ||
        book_side(r.marking) != r.side || (where != 0 && r.has(Order::kReserveChild)) || r.has(Order::kRefresh) ||
        (where == 2) != r.has(Order::kMidPeg) || r.ref >= next_ref_ || r.itch_ref >= next_ref_ ||
        !ouch50::is_valid_inbound(r.marking) || !ouch50::is_valid_inbound(r.tif) ||
        !ouch50::is_valid_inbound(r.display) || !ouch50::is_valid_inbound(r.capacity) ||
        !ouch50::is_valid_inbound(r.iso) || !ouch50::is_valid_inbound(r.cross) || !aiq_supported(r.aiq) ||
        r.urn > trackers_[r.account][r.user_ref_idx])  // every live UserRefNum was consumed
      return false;
    r.where = static_cast<Where>(where);
    const Handle h = book_.alloc();
    book_.at(h) = r;
    SymbolInfo& y = symbols_[r.locate];
    switch (r.where) {
      case Where::Book: book_.insert(h); break;
      case Where::Pending: list_append(y.pend_head, y.pend_tail, h); break;
      case Where::Peg: {
        const std::size_t sd = r.side == Side::Buy ? 0 : 1;
        list_append(y.peg_head[sd], y.peg_tail[sd], h);
        break;
      }
      case Where::Off: return false;
    }
    if (r.has(Order::kReserveChild)) {
      children.push_back(h);
    } else {
      if (!urn_->insert(urn_key(r.account, r.user_ref_idx, r.urn), h)) return false;
      parents.emplace_back(r.ref, h);
    }
  }
  std::sort(parents.begin(), parents.end());
  for (std::size_t k = 0; k < parents.size(); ++k) {
    if (k > 0 && parents[k].first == parents[k - 1].first) return false;
    acct_append(parents[k].second);
  }
  live_ = parents.size();
  for (const Handle c : children) {
    const OrderRef ref = book_.at(c).ref;
    const auto it = std::lower_bound(parents.begin(), parents.end(), std::pair<OrderRef, Handle>{ref, 0});
    if (it == parents.end() || it->first != ref || book_.at(it->second).peer != kNil) return false;
    // A reserve child is its parent's copy (rest_on_book): hidden, no ITCH
    // reference, executions counted on the parent, every order field shared.
    const Order& pa = book_.at(it->second);
    const Order& ch = book_.at(c);
    if (pa.max_floor == 0 || ch.display != Display::Hidden || ch.done != 0 || ch.itch_ref != 0 ||
        ch.locate != pa.locate || ch.side != pa.side || ch.px != pa.px || ch.risk_px != pa.risk_px ||
        ch.account != pa.account || ch.session != pa.session || ch.urn != pa.urn ||
        ch.user_ref_idx != pa.user_ref_idx || ch.marking != pa.marking || ch.firm != pa.firm ||
        ch.group_id != pa.group_id || ch.aiq_group != pa.aiq_group || ch.tif != pa.tif || ch.capacity != pa.capacity ||
        ch.iso != pa.iso || ch.cross != pa.cross || ch.aiq != pa.aiq || ch.min_qty != pa.min_qty ||
        ch.max_floor != pa.max_floor || ch.expire_time != pa.expire_time)
      return false;
    book_.at(it->second).peer = c;
    book_.at(c).peer = it->second;
  }
  risk_configure();
  if (!risk_.restore(rd)) return false;
  // Per-symbol open notional is derived from the orders.
  for (std::uint32_t a = 0; a < nacct; ++a)
    if (risk_.tracks_symbols(a)) risk_rebuild(a);
  // The payload repeats derived state (risk open notional, level totals); a
  // restored engine must be self-consistent, whatever the container checked.
  return !rd.fail() && rd.done() && check(nullptr);
}

template void Engine::walk<StateHasher>(StateHasher&) const;
template void Engine::walk<ByteWriter>(ByteWriter&) const;

}  // namespace lle::engine

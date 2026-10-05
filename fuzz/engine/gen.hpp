#pragma once
// Swarm generator of engine input records (05-matching-engine §9, E-14).
//
// Each seed draws a "swarm" configuration (which operations and attributes
// are enabled, and how often) and then plays trading days: the scripted day
// (pre-market, open freeze, MOO and LOO cutoffs, EOII/NOII ticks, the opening
// cross, regular hours, the close freeze and cutoffs, the closing cross,
// expiry sweeps, post-market, system close) advanced at random points, with
// the 1 Hz clock, admin disturbances (halts, resumption periods, LULD bands,
// IPOs, MWCB, Reg SHO, permits), OUCH operations including cross orders, and
// malformed inputs. Some seeds fire timers in random order instead of the
// script, to exercise every state combination. Deterministic: everything
// comes from one lle::Prng.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <vector>

#include "common/alpha.h"
#include "common/prng.h"
#include "common/time.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "proto/ouch50/ouch50.h"

namespace lle::engine::gen {

class Generator {
 public:
  static constexpr Nanos kMidnight = Scenario::kMidnight;

  explicit Generator(std::uint64_t seed) : rng_(seed) {
    draw_swarm();
    start_day();
  }

  // The next record; its payload stays valid until the following call.
  const InputRecord& next() {
    while (pending_.empty()) produce();
    payload_ = std::move(pending_.front().payload);
    rec_.type = pending_.front().type;
    rec_.flags = pending_.front().flags;
    pending_.pop_front();
    rec_.index = next_index_++;
    ts_ += 1 + static_cast<Nanos>(rng_.below(5'000));
    rec_.ts_ns = ts_;
    rec_.payload = std::span<const std::byte>(payload_);
    rec_.epoch = 1;
    return rec_;
  }

 private:
  struct Pending {
    std::uint16_t type;
    std::vector<std::byte> payload;
    std::uint16_t flags = 0;
  };
  struct Sym {
    std::string name;
    PxE4 mid;
    PxE4 tick;
    std::uint32_t lot = 100;
  };
  struct Acct {
    std::uint32_t id;
    std::vector<std::string> firms;
  };
  struct Sess {
    std::uint32_t id;
    std::size_t acct;
  };
  struct Chan {  // (account, UserRefIdx) as the client sees it
    std::uint32_t* next = nullptr;   // shared by the account's channels: a message whose
                                     // UserRefIdx is lost to corruption cannot jump channel 0 ahead
    std::deque<UserRefNum> history;  // recently sent order UserRefNums
  };
  struct Reenable {
    std::size_t session;
    std::string firm;
  };

  // ---- swarm configuration: per-seed weights (0 disables a feature)
  struct Swarm {
    std::uint32_t w_enter, w_cancel, w_replace, w_modify, w_mass, w_switch, w_query, w_session, w_timer, w_admin,
        w_garbage, w_day, w_clock, w_advance;
    std::uint32_t p_ioc, p_market, p_hidden, p_attr, p_post_only, p_aiq, p_idx, p_firm_tag, p_bad_attr, p_bad_price,
        p_resend, p_group, p_side_tag, p_cross, p_ext_tif, p_reserve, p_minqty, p_peg;
    std::uint32_t width;  // price levels either side of the mid
    std::uint32_t max_qty;
    bool scripted;        // the day script (else timers in random order)
    bool late_open;       // the clock reaches 09:15 before the opening cross (price test B)
  } sw_{};

  std::uint32_t pct(std::uint32_t lo, std::uint32_t hi) { return static_cast<std::uint32_t>(rng_.range(lo, hi)); }
  std::uint32_t maybe(std::uint32_t w) { return rng_.chance(1, 5) ? 0 : w; }
  bool chance(std::uint32_t pct_) { return rng_.below(100) < pct_; }

  void draw_swarm() {
    sw_.w_enter = 40 + pct(0, 40);
    sw_.w_cancel = maybe(pct(5, 30));
    sw_.w_replace = maybe(pct(5, 20));
    sw_.w_modify = maybe(pct(2, 10));
    sw_.w_mass = maybe(pct(0, 3));
    sw_.w_switch = maybe(pct(0, 2));
    sw_.w_query = maybe(pct(0, 2));
    sw_.w_session = maybe(pct(0, 2));
    sw_.w_timer = maybe(pct(0, 3));
    sw_.w_admin = maybe(pct(0, 3));
    sw_.w_garbage = maybe(pct(0, 4));
    sw_.w_day = rng_.chance(1, 4) ? 1 : 0;
    sw_.w_clock = maybe(pct(1, 12));
    sw_.w_advance = pct(1, 4);
    sw_.p_ioc = maybe(pct(5, 30));
    sw_.p_market = maybe(pct(1, 10));
    sw_.p_hidden = maybe(pct(5, 40));
    sw_.p_attr = maybe(pct(0, 20));
    sw_.p_post_only = maybe(pct(0, 30));
    sw_.p_aiq = maybe(pct(0, 50));
    sw_.p_idx = maybe(pct(0, 40));
    sw_.p_firm_tag = maybe(pct(0, 40));
    sw_.p_bad_attr = maybe(pct(0, 6));
    sw_.p_bad_price = maybe(pct(0, 5));
    sw_.p_resend = maybe(pct(0, 6));
    sw_.p_group = maybe(pct(0, 30));
    sw_.p_side_tag = maybe(pct(0, 10));
    sw_.p_cross = maybe(pct(0, 30));
    sw_.p_ext_tif = maybe(pct(5, 60));
    sw_.p_reserve = maybe(pct(0, 25));
    sw_.p_minqty = maybe(pct(0, 15));
    sw_.p_peg = maybe(pct(0, 25));
    sw_.width = pct(1, 12);
    sw_.max_qty = rng_.chance(1, 2) ? pct(1, 10) * 100 : pct(1, 1000);
    sw_.scripted = rng_.chance(4, 5);
    sw_.late_open = rng_.chance(1, 3);
  }

  void push(RecordType t, std::vector<std::byte> p, std::uint16_t flags = 0) {
    pending_.push_back(Pending{static_cast<std::uint16_t>(t), std::move(p), flags});
  }
  void push_table(ConfigTable t, const std::vector<std::byte>& body) {
    for (auto& c : config_chunks(t, body)) push(RecordType::Config, std::move(c));
  }

  // ---- the day's timers: one Schedule entry per (kind, arg) the generator fires
  struct T {
    TimerKind kind;
    std::uint16_t arg;
  };
  static constexpr std::array<T, 29> kTimers = {{
      {TimerKind::SystemEvent, 'O'}, {TimerKind::SystemEvent, 'S'}, {TimerKind::SystemEvent, 'Q'},
      {TimerKind::SystemEvent, 'M'}, {TimerKind::SystemEvent, 'E'}, {TimerKind::SystemEvent, 'C'},
      {TimerKind::SystemEvent, 'Z'}, {TimerKind::StateChange, 'P'}, {TimerKind::StateChange, 'F'},
      {TimerKind::StateChange, 'M'}, {TimerKind::StateChange, 'L'}, {TimerKind::StateChange, 'f'},
      {TimerKind::StateChange, 'm'}, {TimerKind::StateChange, 'l'}, {TimerKind::StateChange, 'X'},
      {TimerKind::StateChange, 'z'}, {TimerKind::Eoii, 'O'},       {TimerKind::Eoii, 'C'},
      {TimerKind::Noii, 'O'},        {TimerKind::Noii, 'C'},       {TimerKind::Noii, 'H'},
      {TimerKind::Cross, 'O'},       {TimerKind::Cross, 'C'},      {TimerKind::Cross, 'Z'},
      {TimerKind::ExpirySweep, 'D'}, {TimerKind::ExpirySweep, 'X'}, {TimerKind::ExpirySweep, 'Z'},
      {TimerKind::DayEnd, 0},        {TimerKind::Eoii, 'H'},
  }};
  void fire(TimerKind k, std::uint16_t arg) {
    if (k == TimerKind::Noii && arg == 'H') ts_ += kNsPerSec;  // the 1 Hz clock moves the day on
    for (std::size_t i = 0; i < kTimers.size(); ++i) {
      if (kTimers[i].kind == k && kTimers[i].arg == arg) {
        push(RecordType::Timer, encode_timer(TimerRecord{static_cast<std::uint32_t>(i + 1), k, ts_ + 1}));
        return;
      }
    }
  }

  // ---- day setup
  void start_day() {
    DayStart d;
    d.date = 20261001;
    d.local_midnight_ns = kMidnight;
    push(RecordType::DayStart, encode_day_start(d));
    if (ts_ == 0) ts_ = kMidnight + hms_ns(4, 0, 0);
    syms_.clear();
    have_last_ = false;  // no resubmission across days (different symbols and sessions)
    killed_.clear();
    accts_.clear();
    sess_.clear();
    chans_.clear();
    reenable_.clear();
    stage_ = 0;
    static constexpr std::array<const char*, 6> kNames = {"AAPL", "MSFT", "PENY", "HALF", "ZZZ", "QQQ"};
    const std::size_t nsym = 1 + rng_.below(4);
    std::vector<SymbolEntry> se;
    for (std::size_t i = 0; i < nsym; ++i) {
      Sym s;
      s.name = kNames[i];
      const std::uint64_t kind = rng_.below(5);
      s.tick = kind == 0 ? 50 : (kind == 1 ? 1 : 100);
      static constexpr std::array<PxE4, 5> kMids = {5'000, 10'000, 100'000, 1'000'000, 9'990};
      s.mid = kMids[rng_.below(kMids.size())];
      if (s.mid >= kPxScale) s.mid -= s.mid % s.tick;
      SymbolEntry e;
      e.symbol = Symbol8(s.name);
      e.tick = static_cast<std::uint32_t>(s.tick);
      e.round_lot = rng_.chance(1, 10) ? 1 : 100;
      s.lot = e.round_lot;
      e.prior_close = rng_.chance(1, 5) ? 0 : s.mid + static_cast<PxE4>(rng_.range(-3, 3)) * (s.mid >= kPxScale ? s.tick : 1);
      // Sometimes far enough above the mid that trades there trigger Rule 201 (<= 90% of the prior close).
      if (rng_.chance(1, 6)) e.prior_close = s.mid + s.mid / 8;
      e.market_category = rng_.chance(1, 20) ? 'x' : 'Q';
      e.luld_tier = rng_.chance(1, 2) ? '1' : '2';
      e.flags = static_cast<std::uint8_t>((rng_.chance(1, 10) ? SymbolEntry::kFlagTest : 0) |
                                          (rng_.chance(1, 5) ? SymbolEntry::kFlagEtp : 0));
      e.regsho = "02 x"[rng_.below(4)];
      e.adv = static_cast<std::uint32_t>(rng_.chance(1, 3) ? rng_.below(5'000) : rng_.below(1'000'000));
      se.push_back(e);
      syms_.push_back(s);
    }
    if (rng_.chance(1, 25)) {  // a table with a duplicate symbol is rejected whole
      std::vector<SymbolEntry> dup = se;
      dup.push_back(se.front());
      push_table(ConfigTable::Symbols, encode_symbols(dup));
    }
    push_table(ConfigTable::Symbols, encode_symbols(se));

    static constexpr std::array<const char*, 6> kFirms = {"FA01", "FA02", "FB01", "FB02", "FC01", "SHRD"};
    const std::size_t nacct = 1 + rng_.below(3);
    std::vector<AccountEntry> ae;
    for (std::size_t i = 0; i < nacct; ++i) {
      Acct a;
      a.id = static_cast<std::uint32_t>(100 + i);
      a.firms.push_back(kFirms[2 * (i % 3)]);
      if (rng_.chance(1, 2)) a.firms.push_back(kFirms[2 * (i % 3) + 1]);
      if (rng_.chance(1, 4)) a.firms.push_back("SHRD");  // a firm shared across accounts
      AccountEntry e;
      e.account_id = a.id;
      for (std::size_t k = 0; k < a.firms.size(); ++k) e.firms[k] = Mpid4(a.firms[k]);
      ae.push_back(e);
      accts_.push_back(a);
    }
    push_table(ConfigTable::Accounts, encode_accounts(ae));
    std::vector<SessionEntry> ss;
    static constexpr std::array<char, 6> kDefAiq = {'N', 'N', 'D', 'O', '1', 'R'};
    for (std::size_t i = 0; i < nacct; ++i) {
      const std::size_t n = 1 + rng_.below(2);
      for (std::size_t k = 0; k < n; ++k) {
        SessionEntry e;
        e.session_id = static_cast<std::uint32_t>(10 * (i + 1) + k);
        e.account_id = accts_[i].id;
        e.flags = static_cast<std::uint8_t>(rng_.below(16));
        if (rng_.chance(3, 4)) e.flags |= SessionEntry::kMarketOrders;
        e.default_aiq = kDefAiq[rng_.below(kDefAiq.size())];
        e.late_cross = static_cast<LateCrossPolicy>(rng_.below(3));
        ss.push_back(e);
        sess_.push_back(Sess{e.session_id, i});
      }
    }
    push_table(ConfigTable::Sessions, encode_sessions(ss));
    // Risk limits (05 §7): sometimes a table with an invalid entry first (rejected whole).
    if (rng_.chance(1, 15)) {
      std::vector<RiskEntry> bad(1 + rng_.below(3));
      for (RiskEntry& e : bad) e = risk_entry();
      bad[rng_.below(bad.size())] = risk_entry(true);
      push_table(ConfigTable::RiskLimits, encode_risk(bad));
    }
    if (rng_.chance(1, 2)) {
      std::vector<RiskEntry> rl(rng_.below(6));
      for (RiskEntry& e : rl) e = risk_entry();
      push_table(ConfigTable::RiskLimits, encode_risk(rl));
    }
    // The schedule: parameters (short halt periods so they complete) and the timer table.
    std::vector<ScheduleEntry> sch;
    auto param = [&](Param p, std::int64_t v) {
      ScheduleEntry e;
      e.kind = static_cast<TimerKind>(0);
      e.arg = static_cast<std::uint16_t>(p);
      e.time_ns = v;
      sch.push_back(e);
    };
    static constexpr std::array<char, 6> kInit = {'P', 'P', 'R', 'R', 'C', 'A'};
    const char init = sw_.scripted ? (rng_.chance(3, 4) ? 'C' : 'P') : kInit[rng_.below(kInit.size())];
    param(Param::InitialSession, init);
    param(Param::PriceTests, static_cast<std::int64_t>(rng_.below(8)));
    param(Param::PriceTestBps, static_cast<std::int64_t>(rng_.range(10, 2'000)));
    param(Param::HaltPeriodSec, static_cast<std::int64_t>(rng_.range(1, 20)));
    param(Param::LuldPauseSec, static_cast<std::int64_t>(rng_.range(1, 20)));
    param(Param::MwcbPeriodSec, static_cast<std::int64_t>(rng_.range(1, 30)));
    param(Param::LimitStateSec, static_cast<std::int64_t>(rng_.range(1, 8)));
    param(Param::ExtensionSec, static_cast<std::int64_t>(rng_.range(1, 10)));
    if (rng_.chance(1, 3)) param(Param::ThresholdBps, static_cast<std::int64_t>(rng_.range(10, 3'000)));
    // Small minimums so that thresholds and opening price tests bind within the generated spreads.
    if (rng_.chance(1, 2)) param(Param::PriceTestMin, static_cast<std::int64_t>(rng_.range(0, 200)));
    if (rng_.chance(1, 3)) param(Param::ThresholdMin, static_cast<std::int64_t>(rng_.range(0, 500)));
    for (std::size_t i = 0; i < kTimers.size(); ++i)
      sch.push_back(ScheduleEntry{static_cast<std::uint32_t>(i + 1), kTimers[i].kind, kTimers[i].arg,
                                  hms_ns(4, 0, 0) + static_cast<Nanos>(i)});
    if (rng_.chance(1, 20)) {  // a table with a parameter beyond its bounds first (rejected whole)
      std::vector<ScheduleEntry> bad = sch;
      static constexpr std::array<std::pair<Param, std::int64_t>, 6> kBad = {{{Param::ThresholdBps, 100'001},
                                                                              {Param::PriceTestBps, 1ll << 60},
                                                                              {Param::PriceTestMin, kPxMaxLimit + 1},
                                                                              {Param::PriceTests, 8},
                                                                              {Param::HaltPeriodSec, 86'401},
                                                                              {Param::ExtensionSec, -5}}};
      const auto& [k, v] = kBad[rng_.below(kBad.size())];
      ScheduleEntry e;
      e.kind = static_cast<TimerKind>(0);
      e.arg = static_cast<std::uint16_t>(k);
      e.time_ns = v;
      bad.push_back(e);
      push_table(ConfigTable::Schedule, encode_schedule(bad));
    }
    push_table(ConfigTable::Schedule, encode_schedule(sch));
    for (const Sess& s : sess_) {
      push(RecordType::SessionEvent, encode_session_event(SessionEvent{s.id, 0, SessionEventKind::Login, 0}));
      if (rng_.chance(1, 3))
        push(RecordType::SessionEvent, encode_session_event(SessionEvent{s.id, 1, SessionEventKind::MirrorAttach, 0}));
    }
    next_urn_.assign(accts_.size(), 1);
    chans_.assign(accts_.size() * 4, Chan{});
    for (std::size_t i = 0; i < chans_.size(); ++i) chans_[i].next = &next_urn_[i / 4];
  }

  // ---- the day script: each stage is a list of timers fired when it is reached
  void advance() {
    switch (stage_++) {
      case 0: fire(TimerKind::SystemEvent, 'O'); fire(TimerKind::SystemEvent, 'S'); fire(TimerKind::StateChange, 'P'); break;
      case 1: fire(TimerKind::StateChange, 'F'); fire(TimerKind::Eoii, 'O'); break;
      case 2: fire(TimerKind::StateChange, 'M'); fire(TimerKind::Noii, 'O'); break;
      case 3:
        // Pre-open trades after 09:15 make opening price test B applicable.
        if (sw_.late_open)
          ts_ = std::max(ts_, kMidnight + hms_ns(9, 15, 0) + static_cast<Nanos>(rng_.below(600)) * kNsPerSec);
        fire(TimerKind::StateChange, 'L');
        fire(TimerKind::Noii, 'O');
        break;
      case 4: fire(TimerKind::SystemEvent, 'Q'); fire(TimerKind::Cross, 'O'); break;
      case 5: fire(TimerKind::StateChange, 'f'); fire(TimerKind::Eoii, 'C'); break;
      case 6: fire(TimerKind::StateChange, 'm'); fire(TimerKind::Noii, 'C'); break;
      case 7: fire(TimerKind::StateChange, 'l'); fire(TimerKind::Noii, 'C'); break;
      case 8: fire(TimerKind::SystemEvent, 'M'); fire(TimerKind::Cross, 'C'); fire(TimerKind::ExpirySweep, 'D'); break;
      case 9: fire(TimerKind::ExpirySweep, 'X'); fire(TimerKind::SystemEvent, 'E'); fire(TimerKind::StateChange, 'X'); break;
      case 10: fire(TimerKind::SystemEvent, 'C'); fire(TimerKind::DayEnd, 0); break;
      default: start_day(); break;
    }
  }
  // NOII / EOII ticks while the current stage has them.
  void stage_ticks() {
    if (stage_ == 2) fire(TimerKind::Eoii, 'O');
    if (stage_ == 3 || stage_ == 4) fire(TimerKind::Noii, 'O');
    if (stage_ == 6) fire(TimerKind::Eoii, 'C');
    if (stage_ == 7 || stage_ == 8) fire(TimerKind::Noii, 'C');
  }

  // ---- helpers
  static constexpr std::array<std::uint8_t, 4> kIdx = {0, 1, 7, 255};
  Chan& chan(std::size_t acct, std::size_t ci) { return chans_[acct * 4 + ci]; }
  std::size_t pick_chan() { return rng_.below(100) < sw_.p_idx ? 1 + rng_.below(3) : 0; }

  UserRefNum new_urn(Chan& c) {
    if (chance(sw_.p_resend) && *c.next > 1) return static_cast<UserRefNum>(1 + rng_.below(*c.next - 1));
    const UserRefNum u = *c.next;
    *c.next += rng_.chance(1, 20) ? static_cast<std::uint32_t>(1 + rng_.below(5)) : 1;
    return u;
  }
  UserRefNum old_urn(Chan& c) {
    if (c.history.empty() || rng_.chance(1, 20)) return static_cast<UserRefNum>(rng_.below(*c.next + 2));
    const std::size_t span = rng_.chance(7, 10) ? 6 : 24;  // mostly recent, hence mostly live, orders
    return c.history[c.history.size() - 1 - rng_.below(std::min<std::size_t>(c.history.size(), span))];
  }
  void remember(Chan& c, UserRefNum u) {
    c.history.push_back(u);
    if (c.history.size() > 64) c.history.pop_front();
  }

  std::uint64_t price(const Sym& s) {
    if (chance(sw_.p_bad_price)) {
      switch (rng_.below(4)) {
        case 0: return 0;
        case 1: return static_cast<std::uint64_t>(s.mid + 1);  // usually off tick
        case 2: return 2'000'000'001ull;
        default: return 1'999'999'900ull;
      }
    }
    const auto k = static_cast<PxE4>(rng_.range(-static_cast<std::int64_t>(sw_.width), sw_.width));
    PxE4 p = s.mid + k * (s.mid >= kPxScale ? s.tick : 1);
    if (p < 1) p = 1;
    return static_cast<std::uint64_t>(p);
  }
  Qty qty() {
    if (chance(sw_.p_bad_price)) return rng_.chance(1, 2) ? 0 : 1'000'000;
    return static_cast<Qty>(1 + rng_.below(sw_.max_qty));
  }
  ouch50::Side side() {
    const std::uint64_t r = rng_.below(20);
    if (r < 9) return ouch50::Side::Buy;
    if (r < 17) return ouch50::Side::Sell;
    return r < 19 ? ouch50::Side::SellShort : ouch50::Side::SellShortExempt;
  }
  ouch50::AiqStrategy aiq() {
    static constexpr std::array<char, 14> kGood = {'N', 'Y', 'D', 'O', 'W', '0', '1', '2', '4', '*', 'D', '1', 'W', 'O'};
    static constexpr std::array<char, 6> kBad = {'R', 'y', 'o', 'Z', 'X', '5'};
    if (chance(sw_.p_bad_attr)) return static_cast<ouch50::AiqStrategy>(kBad[rng_.below(kBad.size())]);
    return static_cast<ouch50::AiqStrategy>(kGood[rng_.below(kGood.size())]);
  }
  // An ExpireTime (seconds since midnight) a few clock ticks away.
  std::uint32_t expire_soon() {
    const std::int64_t now_s = (ts_ - kMidnight) / kNsPerSec;
    return static_cast<std::uint32_t>(std::clamp<std::int64_t>(now_s + rng_.range(-3, 40), 0, 86'399));
  }
  ouch50::TimeInForce tif() {
    if (chance(sw_.p_ioc)) return ouch50::TimeInForce::Ioc;
    if (!chance(sw_.p_ext_tif)) return ouch50::TimeInForce::Day;
    static constexpr std::array<ouch50::TimeInForce, 3> kExt = {ouch50::TimeInForce::Gtx, ouch50::TimeInForce::Gtt,
                                                               ouch50::TimeInForce::AfterHours};
    return kExt[rng_.below(3)];
  }

  // Optional attributes shared by Enter and Replace.
  void common_tags(ouch50::TagSet& t, std::size_t ci, bool replace) {
    if (ci != 0 || rng_.chance(1, 20)) t.set_user_ref_idx(kIdx[ci]);
    if (chance(sw_.p_post_only)) t.set_post_only(rng_.chance(4, 5) ? ouch50::PostOnly::PostOnly : ouch50::PostOnly::No);
    if (chance(sw_.p_aiq)) {
      t.set_aiq_strategy(aiq());
      if (rng_.chance(1, 4)) t.set_aiq_group_id(Alpha<2>(rng_.chance(1, 2) ? "G1" : "G2"));
    }
    if (rng_.chance(1, 30)) t.set_expire_time(expire_soon());
    if (rng_.chance(1, 40)) t.set_shares_located(ouch50::SharesLocated::Yes);
    if (chance(sw_.p_bad_attr)) {
      switch (rng_.below(12)) {
        case 0: t.set_min_qty(100); break;
        case 1: t.set_max_floor(100); break;
        case 2: t.set_price_type(rng_.chance(1, 2) ? ouch50::PriceType::MidpointPeg : ouch50::PriceType::MarketPeg); break;
        case 3: t.set_peg_offset(rng_.chance(1, 2) ? 0 : 100); break;
        case 4: t.set_discretion_price(1'000'000); break;
        case 5: t.set_random_reserves(10); break;
        case 6: t.set_trade_now(rng_.chance(1, 2) ? ouch50::TradeNow::Yes : ouch50::TradeNow::No); break;
        case 7: t.set_handle_inst(static_cast<ouch50::HandleInst>("IOTQBD "[rng_.below(7)])); break;
        case 8:
          if (!replace)
            t.set_customer_type(rng_.chance(1, 2) ? ouch50::CustomerType::RetailDesignated
                                                  : ouch50::CustomerType::NotRetailDesignated);
          break;
        case 9: t.set_price_type(ouch50::PriceType::Limit); break;
        case 10: t.set_locate_broker(Mpid4("LB01")); break;
        default: t.set_discretion_peg_offset(5); break;
      }
    }
  }

  void ouch(std::size_t si, std::vector<std::byte> msg, std::uint16_t flags = 0) {
    std::uint32_t sid = sess_[si].id;
    std::uint32_t acct = accts_[sess_[si].acct].id;
    if (rng_.chance(1, 400)) sid = 9999;  // unknown session
    if (rng_.chance(1, 400)) acct += 1;   // account mismatch
    push(RecordType::OuchInbound, encode_ouch_inbound(OuchInboundHeader{sid, acct, 0}, msg), flags);
  }

  // ---- operations
  void op_enter() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t a = sess_[si].acct;
    const std::size_t ci = pick_chan();
    Chan& c = chan(a, ci);
    const Sym& s = syms_[rng_.below(syms_.size())];
    EnterArgs e;
    e.urn = new_urn(c);
    e.side = side();
    e.qty = qty();
    e.symbol = rng_.chance(1, 60) ? std::string_view("NOPE") : std::string_view(s.name);
    e.price = price(s);
    e.tif = tif();
    ouch50::TagSet t;
    common_tags(t, ci, false);
    if (chance(sw_.p_cross)) {
      // Cross orders: MOO/LOO/OIO, MOC/LOC/IO, halt-cross H, market or limit.
      e.cross = static_cast<ouch50::CrossType>("OOCCH"[rng_.below(5)]);
      if (rng_.chance(1, 3)) e.price = rng_.chance(1, 2) ? 0x7FFF'FFFFull : 2'000'000'000ull;
      if (rng_.chance(1, 4)) t.set_handle_inst(ouch50::HandleInst::ImbalanceOnly);
      if (rng_.chance(9, 10)) t.clear(ouch50::Tag::PostOnly);
    } else if (chance(sw_.p_market)) {
      e.price = rng_.chance(1, 2) ? 0x7FFF'FFFFull : 2'000'000'000ull;
      if (rng_.chance(9, 10)) e.tif = ouch50::TimeInForce::Ioc;
    } else if (chance(sw_.p_peg)) {  // midpoint peg (the limit is its cap)
      t.set_price_type(ouch50::PriceType::MidpointPeg);
      t.clear(ouch50::Tag::PostOnly);
      if (e.tif != ouch50::TimeInForce::Ioc && rng_.chance(3, 4)) e.tif = ouch50::TimeInForce::Day;
    } else if (chance(sw_.p_reserve)) {  // reserve: shows MaxFloor (rounded down to round lots)
      const std::uint32_t lots = 2 + static_cast<std::uint32_t>(rng_.below(9));
      e.qty = static_cast<Qty>(s.lot * lots + (rng_.chance(1, 3) ? rng_.below(s.lot) : 0));
      std::uint32_t mf = s.lot * (1 + static_cast<std::uint32_t>(rng_.below(lots - 1)));
      if (rng_.chance(1, 4)) mf += static_cast<std::uint32_t>(rng_.below(s.lot));  // a mixed lot
      t.set_max_floor(mf);
      if (e.tif == ouch50::TimeInForce::Ioc) e.tif = ouch50::TimeInForce::Day;
      t.clear(ouch50::Tag::MinQty);
    } else if (chance(sw_.p_minqty)) {  // minimum quantity (aggregate), always IOC
      e.qty = static_cast<Qty>(s.lot * (1 + rng_.below(6)));
      t.set_min_qty(static_cast<std::uint32_t>(s.lot * (1 + rng_.below(e.qty / s.lot))));
      t.clear(ouch50::Tag::PostOnly);
    }
    e.display = chance(sw_.p_hidden) ? ouch50::Display::Hidden
                                     : (chance(sw_.p_attr) ? ouch50::Display::Attributable : ouch50::Display::Visible);
    if (chance(sw_.p_bad_attr)) e.iso = ouch50::IsoEligibility::Eligible;
    if (chance(sw_.p_bad_attr)) e.cross = static_cast<ouch50::CrossType>("NOCHSREA"[rng_.below(8)]);
    e.cl_ord_id = rng_.chance(1, 2) ? "CL" : "";
    if (e.tif == ouch50::TimeInForce::Gtt && rng_.chance(9, 10) && !t.has(ouch50::Tag::ExpireTime))
      t.set_expire_time(expire_soon());
    if (chance(sw_.p_firm_tag)) {
      const Acct& acct = accts_[a];
      t.set_firm(Mpid4(rng_.chance(9, 10) ? acct.firms[rng_.below(acct.firms.size())] : std::string("ZZZZ")));
    }
    if (chance(sw_.p_group)) t.set_group_id(static_cast<std::uint16_t>(rng_.below(3)));
    // Resubmitting the previous order's content (the duplicate filter's case).
    if (have_last_ && rng_.chance(1, 12) && last_si_ == si) {
      const UserRefNum u = e.urn;
      e = last_enter_;
      t = last_tags_;
      e.urn = u;
      if (ci != 0) t.set_user_ref_idx(kIdx[ci]);
    }
    last_enter_ = e;
    last_sym_ = std::string(e.symbol);  // owned: the symbol table is rebuilt every day
    last_enter_.symbol = last_sym_;
    last_tags_ = t;
    last_si_ = si;
    have_last_ = true;
    remember(c, e.urn);
    ouch(si, enter_msg(e, t));
  }

  void op_cancel() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t ci = pick_chan();
    Chan& c = chan(sess_[si].acct, ci);
    const Qty q = rng_.chance(1, 2) ? 0 : static_cast<Qty>(rng_.below(sw_.max_qty + 2));
    ouch50::TagSet t;
    if (ci != 0 || rng_.chance(1, 10)) t.set_user_ref_idx(kIdx[ci]);  // sometimes an explicit 0
    ouch(si, cancel_msg(old_urn(c), q, t));
  }

  void op_replace() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t a = sess_[si].acct;
    const std::size_t ci = pick_chan();
    Chan& c = chan(a, ci);
    const Sym& s = syms_[rng_.below(syms_.size())];
    ReplaceArgs r;
    r.orig = old_urn(c);
    r.urn = new_urn(c);
    r.qty = rng_.chance(1, 8) ? static_cast<Qty>(1 + rng_.below(50)) : qty();
    r.price = price(s);
    if (rng_.chance(1, 40)) r.price = 0x7FFF'FFFFull;
    r.tif = tif();
    if (r.tif == ouch50::TimeInForce::AfterHours && rng_.chance(1, 2)) r.tif = ouch50::TimeInForce::Gtx;
    r.display = chance(sw_.p_hidden) ? ouch50::Display::Hidden
                                     : (chance(sw_.p_attr) ? ouch50::Display::Attributable : ouch50::Display::Visible);
    if (chance(sw_.p_bad_attr)) r.iso = ouch50::IsoEligibility::Eligible;
    ouch50::TagSet t;
    common_tags(t, ci, true);
    if (chance(sw_.p_side_tag)) t.set_side(side());
    if (chance(sw_.p_reserve)) t.set_max_floor(s.lot * static_cast<std::uint32_t>(rng_.range(0, 3)));
    if (chance(sw_.p_peg)) t.set_price_type(rng_.chance(1, 2) ? ouch50::PriceType::MidpointPeg : ouch50::PriceType::Limit);
    if (chance(sw_.p_minqty)) t.set_min_qty(s.lot * static_cast<std::uint32_t>(rng_.range(0, 2)));
    remember(c, r.urn);
    ouch(si, replace_msg(r, t));
  }

  void op_modify() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t ci = pick_chan();
    Chan& c = chan(sess_[si].acct, ci);
    ouch50::TagSet t;
    if (ci != 0 || rng_.chance(1, 10)) t.set_user_ref_idx(kIdx[ci]);
    if (rng_.chance(1, 10)) t.set_shares_located(ouch50::SharesLocated::Yes);
    if (rng_.chance(1, 10)) t.set_locate_broker(Mpid4("LB02"));
    ouch(si, modify_msg(old_urn(c), side(), static_cast<Qty>(rng_.below(sw_.max_qty + 2)), t));
  }

  std::string firm_choice(std::size_t a) {
    const std::uint64_t r = rng_.below(10);
    if (r < 3) return "";
    if (r < 9) return accts_[a].firms[rng_.below(accts_[a].firms.size())];
    return "ZZZZ";
  }

  void op_mass() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t a = sess_[si].acct;
    const std::size_t ci = pick_chan();
    Chan& c = chan(a, ci);
    const std::uint64_t r = rng_.below(10);
    const std::string sym = r < 5 ? "" : (r < 9 ? syms_[rng_.below(syms_.size())].name : "NOPE");
    ouch50::TagSet t;
    if (ci != 0 || rng_.chance(1, 10)) t.set_user_ref_idx(kIdx[ci]);
    if (rng_.chance(1, 4)) t.set_side(side());
    if (rng_.chance(1, 4)) t.set_group_id(static_cast<std::uint16_t>(rng_.below(3)));
    ouch(si, mass_cancel_msg(new_urn(c), firm_choice(a), sym, t));
  }

  void op_switch() {
    const std::size_t si = rng_.below(sess_.size());
    const std::size_t a = sess_[si].acct;
    const std::size_t ci = pick_chan();
    Chan& c = chan(a, ci);
    ouch50::TagSet t;
    if (ci != 0 || rng_.chance(1, 10)) t.set_user_ref_idx(kIdx[ci]);
    if (rng_.chance(1, 3)) {
      const std::string f = firm_choice(a);
      ouch(si, disable_msg(new_urn(c), f, t));
      reenable_.push_back(Reenable{si, f});
    } else {
      ouch(si, enable_msg(new_urn(c), firm_choice(a), t));
    }
  }

  void op_query() {
    const std::size_t si = rng_.below(sess_.size());
    ouch50::TagSet t;
    const std::size_t ci = pick_chan();
    if (ci != 0 || rng_.chance(1, 10)) t.set_user_ref_idx(kIdx[ci]);
    ouch(si, account_query_msg(t));
  }

  void op_session() {
    const std::size_t si = rng_.below(sess_.size());
    static constexpr std::array<SessionEventKind, 7> kEv = {
        SessionEventKind::Login,      SessionEventKind::Login,        SessionEventKind::Logout,
        SessionEventKind::Disconnect, SessionEventKind::MirrorAttach, SessionEventKind::InstanceDown,
        SessionEventKind::Login};
    SessionEvent e{sess_[si].id, static_cast<std::uint16_t>(rng_.below(3)), kEv[rng_.below(kEv.size())], 0};
    if (rng_.chance(1, 50)) e.event = static_cast<SessionEventKind>(9);
    push(RecordType::SessionEvent, encode_session_event(e));
  }

  void op_timer() {
    if (sw_.scripted && rng_.chance(9, 10)) {
      stage_ticks();
      return;
    }
    const T& t = kTimers[rng_.below(kTimers.size())];
    fire(t.kind, t.arg);
    if (rng_.chance(1, 50)) push(RecordType::Timer, encode_timer(TimerRecord{999, TimerKind::Cross, ts_}));
  }

  // One risk limit, scaled to the generated orders so that most kinds bind
  // sometimes; `invalid` makes it one the gate must refuse.
  RiskEntry risk_entry(bool invalid = false) {
    RiskEntry e;
    e.account_id = accts_[rng_.below(accts_.size())].id;
    const Sym& s = syms_[rng_.below(syms_.size())];
    const std::int64_t unit = std::max<std::int64_t>(s.mid, 1) * std::max<std::int64_t>(sw_.max_qty, 1);
    const auto kind = static_cast<std::uint16_t>(1 + rng_.below(15));
    e.kind = static_cast<RiskKind>(kind);
    switch (kind) {
      case 1:
        for (std::uint32_t bit = 1; bit <= 64; bit <<= 1)
          if (rng_.chance(1, 6)) e.value |= bit;
        break;
      case 2: e.value = 1 + static_cast<std::int64_t>(rng_.below(sw_.max_qty * 2 + 1)); break;
      case 3: e.value = unit * rng_.range(1, 4) / 2 + 1; break;
      case 4: e.value = rng_.range(1, 3'000); break;
      case 5: e.value = rng_.range(1, 30) * std::max<PxE4>(s.tick, 1); break;
      case 6: e.value = static_cast<std::int64_t>(rng_.below(2)); break;
      case 7: e.value = static_cast<std::int64_t>(rng_.below(31)); break;
      case 8: e.value = std::array<std::int64_t, 5>{1, 20, 500, 20'000, 1'000'000}[rng_.below(5)]; break;
      case 9: e.value = std::array<std::int64_t, 4>{1, 20, 500, 20'000}[rng_.below(4)]; break;
      case 10: e.value = unit * rng_.range(1, 50); break;
      case 11:
        e.value = unit * rng_.range(1, 20);
        if (rng_.chance(1, 2)) e.symbol = Symbol8(s.name);
        break;
      case 12: e.value = rng_.range(0, 100); break;
      case 13:
      case 14:
        e.symbol = Symbol8(s.name);
        e.value = rng_.chance(4, 5) ? 1 : 0;
        break;
      default:  // KillExposure: mostly beyond a day's executions, sometimes within reach
        e.value = unit * (rng_.chance(1, 4) ? rng_.range(200, 20'000) : rng_.range(20'000, 2'000'000));
        break;
    }
    if (invalid) {
      switch (rng_.below(12)) {
        case 0: e.account_id = 999; break;
        case 1: e.symbol = Symbol8("NOPE"); e.kind = RiskKind::Restricted; break;
        case 2: e.value = -1; break;
        case 3: e.kind = RiskKind::Lop; e.value = 2; break;
        case 4: e.kind = RiskKind::DupWindowSec; e.value = 31; break;
        case 5: e.kind = static_cast<RiskKind>(rng_.chance(1, 2) ? 0 : 16); break;
        case 7:  // an unknown permission bit
          e.kind = RiskKind::Permissions;
          e.value = std::int64_t{128} << rng_.below(20);
          e.symbol = Symbol8();
          break;
        case 8:  // above the rate cap
          e.kind = rng_.chance(1, 2) ? RiskKind::PortRate : RiskKind::SymbolRate;
          e.value = 1'000'001;
          e.symbol = Symbol8();
          break;
        case 9:  // a per-symbol rule without its symbol
          e.kind = rng_.chance(1, 2) ? RiskKind::Restricted : RiskKind::HardToBorrow;
          e.value = 1;
          e.symbol = Symbol8();
          break;
        case 10: e.kind = RiskKind::HardToBorrow; e.value = 2; e.symbol = Symbol8(s.name); break;
        case 11: e.kind = RiskKind::GrossExposure; e.symbol = Symbol8(s.name); break;
        default: e.kind = RiskKind::MaxOrderQty; e.symbol = Symbol8(s.name); break;
      }
    }
    return e;
  }

  void op_admin() {
    if (rng_.chance(1, 3)) {  // risk: limit changes, kill switch and reset
      AdminArgsBuilder b;
      AdminCommand c = AdminCommand::RiskLimit;
      const std::uint64_t r = rng_.below(10);
      if (r < 5) {
        const RiskEntry e = risk_entry(rng_.chance(1, 10));
        if (e.kind == RiskKind::KillExposure && rng_.chance(1, 2)) return;
        b.u32(AdminTag::Account, e.account_id).u16(AdminTag::Kind, static_cast<std::uint16_t>(e.kind));
        if (rng_.chance(39, 40)) b.i64(AdminTag::Value, e.value);
        if (!e.symbol.blank()) b.symbol(e.symbol);
      } else {
        c = r < 6 ? AdminCommand::KillSwitch : AdminCommand::KillReset;
        if (rng_.chance(19, 20)) {
          std::uint32_t id = accts_[rng_.below(accts_.size())].id;
          if (c == AdminCommand::KillReset && !killed_.empty() && rng_.chance(3, 4)) {
            // Mostly reset an account the day script latched, so kills do not last all day.
            const std::size_t k = rng_.below(killed_.size());
            id = killed_[k];
            killed_.erase(killed_.begin() + static_cast<std::ptrdiff_t>(k));
          } else if (rng_.chance(1, 20)) {
            id = 999;
          }
          if (c == AdminCommand::KillSwitch && id != 999) killed_.push_back(id);
          b.u32(AdminTag::Account, id);
        }
      }
      push(RecordType::Admin, encode_admin(c, b));
      return;
    }
    const Sym& s = syms_[rng_.below(syms_.size())];
    AdminArgsBuilder b;
    if (rng_.chance(19, 20)) b.symbol(rng_.chance(39, 40) ? s.name : std::string("NOPE"));
    const auto px = [&](int spread) {
      return s.mid + static_cast<PxE4>(rng_.range(-spread, spread)) * (s.mid >= kPxScale ? s.tick : 1);
    };
    AdminCommand c = AdminCommand::Halt;
    switch (rng_.below(16)) {
      case 0:
      case 1: c = AdminCommand::Halt; if (rng_.chance(1, 2)) b.reason("T1"); break;
      case 2:
      case 3:
        c = AdminCommand::QuoteOnly;
        if (rng_.chance(1, 2)) b.reason("T3");
        if (rng_.chance(1, 2)) b.i64(AdminTag::Price, rng_.chance(1, 40) ? std::int64_t{1} << 40 : px(3));
        break;
      case 4:
      case 5: c = AdminCommand::Resume; break;
      case 6:
        c = AdminCommand::IpoSchedule;
        b.i64(AdminTag::Price, px(2)).u32(AdminTag::Time, 36'600);
        if (rng_.chance(1, 5)) b.u8(AdminTag::Qualifier, 'C');
        break;
      case 7: c = AdminCommand::IpoQuote; break;
      case 8:
        c = AdminCommand::IpoRelease;
        b.i64(AdminTag::Band, rng_.chance(1, 40) ? std::int64_t{1} << 33 : rng_.range(0, 5'000));
        break;
      case 9:
      case 10: {
        c = AdminCommand::LuldBands;
        const PxE4 m = px(2);
        const PxE4 tk = s.mid >= kPxScale ? s.tick : 1;
        const PxE4 w = rng_.chance(1, 2) ? std::max<PxE4>(m / 20, 2) : tk * rng_.range(1, sw_.width + 1);
        b.i64(AdminTag::Lower, m - w).i64(AdminTag::Upper, m + w);
        break;
      }
      case 11:
        c = AdminCommand::MwcbLevels;
        b.i64(AdminTag::Level1, 636'725'000'000).i64(AdminTag::Level2, 595'646'000'000).i64(AdminTag::Level3, 547'720'000'000);
        break;
      case 12:
        c = AdminCommand::MwcbBreach;
        b.u8(AdminTag::Level, static_cast<std::uint8_t>(rng_.chance(1, 4) ? 3 : 1 + rng_.below(2)));
        if (!rng_.chance(1, 4)) c = AdminCommand::Resume;  // breaches are rare
        break;
      case 13:
        c = AdminCommand::CrossCancelPermit;
        b.u32(AdminTag::Account, accts_[rng_.below(accts_.size())].id);
        break;
      case 14: c = AdminCommand::RegSho; b.u8(AdminTag::Action, static_cast<std::uint8_t>("0127"[rng_.below(4)])); break;
      default: c = static_cast<AdminCommand>(rng_.below(20)); break;
    }
    push(RecordType::Admin, encode_admin(c, b));
  }

  void op_garbage() {
    const std::size_t si = rng_.below(sess_.size());
    const std::uint64_t r = rng_.below(7);
    if (r == 0) {  // random bytes
      std::vector<std::byte> b(rng_.below(60));
      for (std::byte& x : b) x = static_cast<std::byte>(rng_.below(256));
      if (!b.empty() && rng_.chance(1, 2)) b[0] = static_cast<std::byte>("OUXMCDEQ"[rng_.below(8)]);
      // A consuming message carries a plausible new UserRefNum: a random one
      // would usually be huge and silence the channel for the rest of the day.
      if (!b.empty()) {
        const char t = static_cast<char>(b[0]);
        const std::size_t off = t == 'U' ? 5 : 1;
        if ((t == 'O' || t == 'U' || t == 'C' || t == 'D' || t == 'E') && b.size() >= off + 4)
          store_be32(b.data() + off, new_urn(chan(sess_[si].acct, 0)));
      }
      ouch(si, std::move(b));
      return;
    }
    if (r == 1) {  // malformed record payloads
      std::vector<std::byte> b(rng_.below(20));
      for (std::byte& x : b) x = static_cast<std::byte>(rng_.below(256));
      static constexpr std::array<RecordType, 7> kT = {RecordType::OuchInbound, RecordType::Config,
                                                       RecordType::SessionEvent, RecordType::Timer,
                                                       RecordType::Admin,       RecordType::Pad,
                                                       RecordType::SnapshotMark};
      push(kT[rng_.below(kT.size())], std::move(b));
      if (rng_.chance(1, 10)) push(static_cast<RecordType>(42), {});
      return;
    }
    // A valid message with one corruption (or the gateway's truncation flag).
    const std::size_t before = pending_.size();
    if (r == 2) {
      op_enter();
    } else if (r == 3) {
      op_replace();
    } else if (r == 4) {
      op_cancel();
    } else {
      op_mass();
    }
    if (pending_.size() == before) return;
    Pending& p = pending_.back();
    if (r == 6) {
      p.flags = 1;  // kFlagMalformedInput
      return;
    }
    if (p.payload.size() <= OuchInboundHeader::kLen + 1) return;
    std::vector<std::byte> msg(p.payload.begin() + OuchInboundHeader::kLen, p.payload.end());
    switch (rng_.below(4)) {
      // Corruptions leave the type and UserRefNum fields (bytes 0..8) alone.
      case 0:
        if (msg.size() > 9) msg[9 + rng_.below(msg.size() - 9)] = static_cast<std::byte>(rng_.below(256));
        break;
      case 1: msg.resize(1 + rng_.below(msg.size() - 1)); break;
      case 2: msg.push_back(static_cast<std::byte>(rng_.below(256))); break;
      default:
        msg.push_back(std::byte{2});
        msg.push_back(static_cast<std::byte>(rng_.chance(1, 2) ? 28 : 8));
        msg.push_back(std::byte{1});
        break;
    }
    const OuchInboundHeader h{load_le32(p.payload.data()), load_le32(p.payload.data() + 4),
                              load_le16(p.payload.data() + 8)};
    p.payload = encode_ouch_inbound(h, msg);
  }

  void produce() {
    if (sw_.w_day != 0 && rng_.chance(1, 20'000)) {
      start_day();
      return;
    }
    if (!reenable_.empty() && rng_.chance(1, 40)) {  // disabled entry does not last all day
      const Reenable e = reenable_.front();
      reenable_.pop_front();
      ouch(e.session, enable_msg(new_urn(chan(sess_[e.session].acct, 0)), e.firm));
      return;
    }
    // The closed part of the day (after the post-market close) passes 8x faster.
    if (sw_.scripted && rng_.below(1'000) < (stage_ >= 10 ? 8 * sw_.w_advance : sw_.w_advance)) {
      advance();
      return;
    }
    const std::uint32_t total = sw_.w_enter + sw_.w_cancel + sw_.w_replace + sw_.w_modify + sw_.w_mass + sw_.w_switch +
                                sw_.w_query + sw_.w_session + sw_.w_timer + sw_.w_admin + sw_.w_garbage + sw_.w_clock;
    std::uint64_t r = rng_.below(total);
    auto take = [&](std::uint32_t w) {
      if (r < w) return true;
      r -= w;
      return false;
    };
    if (take(sw_.w_enter)) return op_enter();
    if (take(sw_.w_cancel)) return op_cancel();
    if (take(sw_.w_replace)) return op_replace();
    if (take(sw_.w_modify)) return op_modify();
    if (take(sw_.w_mass)) return op_mass();
    if (take(sw_.w_switch)) return op_switch();
    if (take(sw_.w_query)) return op_query();
    if (take(sw_.w_session)) return op_session();
    if (take(sw_.w_timer)) return op_timer();
    if (take(sw_.w_admin)) return op_admin();
    if (take(sw_.w_clock)) return fire(TimerKind::Noii, 'H');
    op_garbage();
  }

  Prng rng_;
  std::deque<Pending> pending_;
  std::vector<std::byte> payload_;
  InputRecord rec_;
  std::uint64_t next_index_ = 1;
  Nanos ts_ = 0;
  EnterArgs last_enter_;
  std::string last_sym_;
  ouch50::TagSet last_tags_;
  std::size_t last_si_ = 0;
  bool have_last_ = false;
  std::size_t stage_ = 0;
  std::vector<std::uint32_t> killed_;  // accounts latched by Admin KillSwitch today
  std::vector<Sym> syms_;
  std::vector<Acct> accts_;
  std::vector<Sess> sess_;
  std::deque<Reenable> reenable_;
  std::vector<std::uint32_t> next_urn_;
  std::vector<Chan> chans_;
};

}  // namespace lle::engine::gen

#include "admin/day_runner.h"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string_view>

#include "admin/commands.h"
#include "common/endian.h"
#include "common/time.h"
#include "concurrent/mpsc_scq.h"
#include "engine/engine.h"
#include "engine/journal_adapter.h"
#include "engine/records.h"
#include "engine/scenario.h"
#include "journal/l2_ring.h"
#include "proto/itch50/validator.h"
#include "sequencer/engine_day.h"
#include "sequencer/sequencer.h"

namespace lle::admin {

namespace {

struct ManualClock {
  Nanos real = 0;
  Nanos now_mono() noexcept { return 0; }
  Nanos now_real() noexcept { return real; }
  std::uint64_t tsc() noexcept { return 0; }
};
struct DayEnv {
  using Clock = ManualClock;
  using OuchQueue = conc::MpscScqRing<seq::InboundMsg, 1024>;
  using SessionQueue = conc::MpscScqRing<seq::SessionEventMsg, 64>;
  using AdminQueue = conc::MpscScqRing<seq::AdminMsg, 64>;
  using Ring = journal::L2Ring<2>;
};

std::unexpected<std::string> fail(int line, const std::string& m) {
  return std::unexpected("line " + std::to_string(line) + ": " + m);
}

std::vector<std::string> split(const std::string& s) {
  std::vector<std::string> v;
  std::istringstream in(s);
  std::string w;
  while (in >> w) v.push_back(w);
  return v;
}

// "HH:MM:SS[.fraction]" -> ns since midnight.
std::expected<Nanos, std::string> parse_time(std::string_view s) {
  const auto hms = parse_hms(s.substr(0, std::min<std::size_t>(8, s.size())));
  if (!hms) return std::unexpected(hms.error());
  Nanos t = static_cast<Nanos>(*hms) * kNsPerSec;
  if (s.size() > 8) {
    if (s[8] != '.' || s.size() > 18) return std::unexpected("bad time fraction: " + std::string(s));
    std::string frac(s.substr(9));
    frac.resize(9, '0');
    const auto ns = parse_uint(frac);
    if (!ns) return std::unexpected(ns.error());
    t += static_cast<Nanos>(*ns);
  }
  return t;
}

// UNIX ns of local midnight for YYYYMMDD, US Eastern daylight time (UTC-4):
// the model's trading days fall in the daylight-saving season of the tests.
Nanos local_midnight(std::uint32_t date) {
  const int y0 = static_cast<int>(date / 10000), m = static_cast<int>(date / 100 % 100), d = static_cast<int>(date % 100);
  const int y = m <= 2 ? y0 - 1 : y0;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days = std::int64_t{era} * 146097 + doe - 719468;
  return (days * 86'400 + 4 * 3'600) * kNsPerSec;
}

struct Action {
  Nanos t = 0;
  enum Kind { Session, Ouch, Admin, Run } kind = Run;
  std::uint32_t session = 0;
  std::uint32_t account = 0;
  engine::SessionEventKind event = engine::SessionEventKind::Login;
  std::vector<std::byte> bytes;  // OUCH message or admin args
  std::uint16_t command = 0;
};

struct Script {
  std::uint32_t date = 20261001;
  bool early_close = false;
  std::vector<engine::SymbolEntry> symbols;
  std::vector<engine::AccountEntry> accounts;
  std::vector<engine::SessionEntry> sessions;
  std::vector<engine::RiskEntry> risk;
  std::vector<engine::ScheduleEntry> params;
  std::vector<Action> actions;
  Nanos end = 0;
};

std::expected<std::uint64_t, std::string> price_or_market(const std::string& s) {
  if (s == "MKT") return ouch50::kMarketPrice;
  const auto p = parse_decimal(s, 4);
  if (!p) return std::unexpected(p.error());
  return static_cast<std::uint64_t>(*p);
}

std::expected<Script, std::string> parse(const std::string& text) {
  Script sc;
  std::istringstream in(text);
  std::string raw;
  int ln = 0;
  Nanos last_t = 0;
  auto account_of = [&](std::uint32_t session) -> std::uint32_t {
    for (const auto& s : sc.sessions)
      if (s.session_id == session) return s.account_id;
    return 0;
  };
  while (std::getline(in, raw)) {
    ++ln;
    const std::size_t hash = raw.find('#');
    const std::vector<std::string> w = split(hash == std::string::npos ? raw : raw.substr(0, hash));
    if (w.empty()) continue;
    auto kv = [&](std::string_view key) -> std::string {
      for (std::size_t i = 1; i < w.size(); ++i)
        if (w[i].starts_with(std::string(key) + "=")) return w[i].substr(key.size() + 1);
      return {};
    };
    auto has = [&](std::string_view flag) {
      return std::find(w.begin(), w.end(), std::string(flag)) != w.end();
    };
    const std::string& head = w[0];
    if (head == "day") {
      if (w.size() < 2) return fail(ln, "day YYYYMMDD");
      const auto d = parse_uint(w[1]);
      if (!d || *d < 19700101 || *d > 29991231) return fail(ln, "bad date");
      sc.date = static_cast<std::uint32_t>(*d);
      sc.early_close = has("early-close");
    } else if (head == "symbol") {
      if (w.size() < 2 || w[1].size() > 8) return fail(ln, "symbol SYM ...");
      engine::SymbolEntry e;
      e.symbol = Symbol8(w[1]);
      if (const auto p = kv("prior"); !p.empty()) {
        const auto v = parse_decimal(p, 4);
        if (!v) return fail(ln, v.error());
        e.prior_close = *v;
      }
      if (const auto p = kv("lot"); !p.empty()) e.round_lot = static_cast<std::uint32_t>(parse_uint(p).value_or(100));
      if (const auto p = kv("tick"); !p.empty()) e.tick = static_cast<std::uint32_t>(parse_decimal(p, 4).value_or(100));
      if (const auto p = kv("tier"); !p.empty()) e.luld_tier = p[0];
      if (const auto p = kv("adv"); !p.empty()) e.adv = static_cast<std::uint32_t>(parse_uint(p).value_or(0));
      if (const auto p = kv("regsho"); !p.empty()) e.regsho = p[0];
      if (has("etp")) e.flags |= engine::SymbolEntry::kFlagEtp;
      sc.symbols.push_back(e);
    } else if (head == "account") {
      if (w.size() < 3) return fail(ln, "account ID FIRM[,FIRM...]");
      engine::AccountEntry e;
      e.account_id = static_cast<std::uint32_t>(parse_uint(w[1]).value_or(0));
      std::size_t k = 0, start = 0;
      while (start <= w[2].size() && k < engine::AccountEntry::kMaxFirms) {
        const std::size_t comma = w[2].find(',', start);
        e.firms[k++] = Mpid4(w[2].substr(start, comma == std::string::npos ? std::string::npos : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
      }
      sc.accounts.push_back(e);
    } else if (head == "session") {
      if (w.size() < 3) return fail(ln, "session ID account=ACCOUNT");
      engine::SessionEntry e;
      e.session_id = static_cast<std::uint32_t>(parse_uint(w[1]).value_or(0));
      e.account_id = static_cast<std::uint32_t>(parse_uint(kv("account")).value_or(0));
      if (const auto f = kv("flags"); !f.empty()) {
        e.flags = 0;
        if (f.find("cod") != std::string::npos) e.flags |= engine::SessionEntry::kCancelOnDisconnect;
        if (f.find("market") != std::string::npos) e.flags |= engine::SessionEntry::kMarketOrders;
        if (f.find("keepcross") != std::string::npos) e.flags |= engine::SessionEntry::kKeepCrossOrders;
        if (f.find("postonlycancel") != std::string::npos) e.flags |= engine::SessionEntry::kPostOnlyCancel;
      }
      if (const auto l = kv("late"); !l.empty()) {
        e.late_cross = l == "accept" ? engine::LateCrossPolicy::Accept
                       : l == "reject" ? engine::LateCrossPolicy::Reject
                                       : engine::LateCrossPolicy::Reprice;
      }
      sc.sessions.push_back(e);
    } else if (head == "risk") {
      if (w.size() < 4) return fail(ln, "risk ACCOUNT KIND VALUE [SYMBOL]");
      engine::RiskEntry e;
      e.account_id = static_cast<std::uint32_t>(parse_uint(w[1]).value_or(0));
      const auto k = parse_risk_kind(w[2]);
      if (!k) return fail(ln, k.error());
      e.kind = static_cast<engine::RiskKind>(*k);
      e.value = static_cast<std::int64_t>(parse_uint(w[3]).value_or(0));
      if (w.size() > 4) e.symbol = Symbol8(w[4]);
      sc.risk.push_back(e);
    } else if (head == "param") {
      if (w.size() < 3) return fail(ln, "param NAME VALUE");
      static const std::map<std::string, engine::Param> kParams = {
          {"halt-period", engine::Param::HaltPeriodSec},   {"luld-pause", engine::Param::LuldPauseSec},
          {"extension", engine::Param::ExtensionSec},      {"limit-state", engine::Param::LimitStateSec},
          {"mwcb-period", engine::Param::MwcbPeriodSec},   {"threshold-bps", engine::Param::ThresholdBps},
          {"threshold-min", engine::Param::ThresholdMin},  {"price-test-bps", engine::Param::PriceTestBps},
          {"price-test-min", engine::Param::PriceTestMin}, {"price-tests", engine::Param::PriceTests},
      };
      const auto it = kParams.find(w[1]);
      const auto v = parse_uint(w[2]);
      if (it == kParams.end() || !v) return fail(ln, "unknown param or value");
      engine::ScheduleEntry e;
      e.kind = static_cast<engine::TimerKind>(0);
      e.arg = static_cast<std::uint16_t>(it->second);
      e.time_ns = static_cast<Nanos>(*v);
      sc.params.push_back(e);
    } else if (head == "end") {
      if (w.size() < 2) return fail(ln, "end HH:MM:SS");
      const auto t = parse_time(w[1]);
      if (!t) return fail(ln, t.error());
      sc.end = *t;
    } else {
      // A timed action.
      const auto t = parse_time(head);
      if (!t) return fail(ln, "unknown line: " + head);
      if (*t < last_t) return fail(ln, "actions must be in time order");
      last_t = *t;
      if (w.size() < 2) return fail(ln, "missing action");
      Action a;
      a.t = *t;
      const std::string& verb = w[1];
      auto num = [&](std::size_t i) -> std::uint64_t { return i < w.size() ? parse_uint(w[i]).value_or(0) : 0; };
      if (verb == "login" || verb == "logout" || verb == "disconnect") {
        a.kind = Action::Session;
        a.session = static_cast<std::uint32_t>(num(2));
        a.event = verb == "login"    ? engine::SessionEventKind::Login
                  : verb == "logout" ? engine::SessionEventKind::Logout
                                     : engine::SessionEventKind::Disconnect;
      } else if (verb == "enter") {
        if (w.size() < 8) return fail(ln, "enter SESSION URN SIDE QTY SYMBOL PRICE|MKT ...");
        a.kind = Action::Ouch;
        a.session = static_cast<std::uint32_t>(num(2));
        engine::EnterArgs e;
        e.urn = static_cast<UserRefNum>(num(3));
        if (w[4].size() != 1 || std::string_view("BSTE").find(w[4][0]) == std::string_view::npos)
          return fail(ln, "side is B, S, T or E");
        e.side = static_cast<ouch50::Side>(w[4][0]);
        e.qty = static_cast<Qty>(num(5));
        e.symbol = w[6];
        const auto px = price_or_market(w[7]);
        if (!px) return fail(ln, px.error());
        e.price = *px;
        ouch50::TagSet tags;
        for (std::size_t i = 8; i < w.size(); ++i) {
          const std::string& o = w[i];
          if (o.starts_with("tif=")) {
            const std::string v = o.substr(4);
            e.tif = v == "ioc"   ? ouch50::TimeInForce::Ioc
                    : v == "gtx" ? ouch50::TimeInForce::Gtx
                    : v == "gtt" ? ouch50::TimeInForce::Gtt
                    : v == "ah"  ? ouch50::TimeInForce::AfterHours
                                 : ouch50::TimeInForce::Day;
          } else if (o.starts_with("display=") && o.size() == 9) {
            e.display = static_cast<ouch50::Display>(o[8]);
          } else if (o.starts_with("cross=") && o.size() == 7) {
            e.cross = static_cast<ouch50::CrossType>(o[6]);
          } else if (o.starts_with("maxfloor=")) {
            tags.set_max_floor(static_cast<std::uint32_t>(parse_uint(o.substr(9)).value_or(0)));
          } else if (o.starts_with("minqty=")) {
            tags.set_min_qty(static_cast<std::uint32_t>(parse_uint(o.substr(7)).value_or(0)));
          } else if (o.starts_with("expire=")) {
            const auto x = parse_hms(o.substr(7));
            if (!x) return fail(ln, x.error());
            tags.set_expire_time(*x);
          } else if (o == "peg") {
            tags.set_price_type(ouch50::PriceType::MidpointPeg);
          } else if (o == "io") {
            tags.set_handle_inst(ouch50::HandleInst::ImbalanceOnly);
          } else if (o == "postonly") {
            tags.set_post_only(ouch50::PostOnly::PostOnly);
          } else {
            return fail(ln, "unknown order option: " + o);
          }
        }
        a.bytes = engine::enter_msg(e, tags);
      } else if (verb == "cancel") {
        if (w.size() < 5) return fail(ln, "cancel SESSION URN QTY");
        a.kind = Action::Ouch;
        a.session = static_cast<std::uint32_t>(num(2));
        a.bytes = engine::cancel_msg(static_cast<UserRefNum>(num(3)), static_cast<Qty>(num(4)));
      } else if (verb == "replace") {
        if (w.size() < 7) return fail(ln, "replace SESSION ORIG NEW QTY PRICE");
        a.kind = Action::Ouch;
        a.session = static_cast<std::uint32_t>(num(2));
        engine::ReplaceArgs r;
        r.orig = static_cast<UserRefNum>(num(3));
        r.urn = static_cast<UserRefNum>(num(4));
        r.qty = static_cast<Qty>(num(5));
        const auto px = price_or_market(w[6]);
        if (!px) return fail(ln, px.error());
        r.price = *px;
        a.bytes = engine::replace_msg(r);
      } else if (verb == "admin") {
        std::vector<std::string_view> words(w.begin() + 2, w.end());
        const auto c = parse_command(words);
        if (!c) return fail(ln, c.error());
        a.kind = Action::Admin;
        a.command = c->command;
        a.bytes = c->args;
      } else if (verb == "run") {
        a.kind = Action::Run;
      } else {
        return fail(ln, "unknown action: " + verb);
      }
      if (a.kind == Action::Ouch) {
        a.account = account_of(a.session);
        if (a.account == 0) return fail(ln, "unknown session");
      }
      sc.actions.push_back(std::move(a));
    }
  }
  if (sc.symbols.empty() || sc.accounts.empty() || sc.sessions.empty()) return std::unexpected("no tables");
  if (sc.end < last_t) sc.end = last_t;
  return sc;
}

}  // namespace

std::expected<DayResult, std::string> run_day(const std::string& text) {
  auto parsed = parse(text);
  if (!parsed) return std::unexpected(parsed.error());
  Script& sc = *parsed;
  const Nanos midnight = local_midnight(sc.date);
  std::vector<engine::ScheduleEntry> sched = engine::standard_schedule(sc.early_close, true);
  sched.insert(sched.end(), sc.params.begin(), sc.params.end());
  const seq::EngineDay day(seq::EngineTables{sc.symbols, sc.accounts, sc.sessions, sc.risk, sched}, midnight);

  ManualClock clock;
  auto oq = std::make_unique<DayEnv::OuchQueue>();
  auto sq = std::make_unique<DayEnv::SessionQueue>();
  auto aq = std::make_unique<DayEnv::AdminQueue>();
  constexpr std::size_t kRingBytes = std::size_t{8} << 20;
  std::unique_ptr<std::uint64_t[]> storage(new std::uint64_t[kRingBytes / 8]());
  journal::L2Ring<2> ring;
  ring.init(reinterpret_cast<std::byte*>(storage.get()), kRingBytes, 0x5C1D7EDDA75EED01ull);
  seq::Sequencer<DayEnv> sequencer(clock, *oq, *sq, *aq, ring, day.timers());

  engine::Engine eng;
  DayResult res;
  itch50::Validator validator(true);
  struct Sink {
    DayResult& r;
    itch50::Validator& v;
    void itch(std::uint64_t, std::span<const std::byte> b) {
      if (v.check(b) != 0) ++r.invalid_itch;
      ++r.itch_types[static_cast<char>(b[0])];
      r.itch.emplace_back(b.begin(), b.end());
    }
    void ouch(std::uint64_t, std::uint32_t, std::span<const std::byte> b) {
      ++r.ouch;
      if (b.size() >= 26 && b[0] == std::byte{'E'}) ++r.liquidity[static_cast<char>(b[25])];
    }
    void audit(std::uint64_t, const engine::AuditEvent&) { ++r.audits; }
  } sink{res, validator};

  auto drain = [&]() {
    std::size_t n = 0, k;
    do {
      k = ring.drain(
          0,
          [&](const journal::RecordView& v) {
            ++res.records;
            if (v.type() == journal::RecordType::Timer) ++res.timers;
            eng.apply(engine::to_input(v), sink);
          },
          4096);
      n += k;
    } while (k != 0);
    while (ring.drain(1, [](const journal::RecordView&) {}, 4096) != 0) {
    }
    return n;
  };
  auto settle = [&]() {
    for (;;) {
      const bool progress = sequencer.poll();
      if (drain() == 0 && !progress) break;
    }
  };
  // The clock walks through every scheduled time on the way to `t`, so each
  // Timer record is stamped when it is due (as with a running clock), not at t.
  std::size_t next_timer = 0;
  const auto timers = day.timers();
  auto advance = [&](Nanos t) {
    while (next_timer < timers.size() && timers[next_timer].time <= midnight + t) {
      if (timers[next_timer].time > clock.real) clock.real = timers[next_timer].time;
      ++next_timer;
      settle();
    }
    if (midnight + t > clock.real) clock.real = midnight + t;
    settle();
  };

  clock.real = midnight + hms_ns(2, 59, 59);
  journal::DayStart ds;
  ds.trading_date = sc.date;
  ds.local_midnight_ns = midnight;
  ds.mold_session = {'L', 'L', 'E', '0', '0', '0', '0', '0', '0', '1'};
  ds.soup_session = ds.mold_session;
  if (!sequencer.start_day(ds, day.config(), 1, 1)) return std::unexpected(std::string("start_day failed"));
  drain();
  for (const Action& a : sc.actions) {
    advance(a.t);
    switch (a.kind) {
      case Action::Session:
        if (!sq->try_push(seq::SessionEventMsg{a.session, 0, static_cast<journal::SessionEventKind>(a.event), 0}))
          return std::unexpected(std::string("session queue full"));
        break;
      case Action::Ouch: {
        seq::InboundMsg m;
        m.session_id = a.session;
        m.account = a.account;
        m.len = static_cast<std::uint16_t>(a.bytes.size());
        std::copy(a.bytes.begin(), a.bytes.end(), m.bytes);
        if (!oq->try_push(m)) return std::unexpected(std::string("OUCH queue full"));
        break;
      }
      case Action::Admin: {
        seq::AdminMsg m;
        m.command = a.command;
        m.operator_id = 1;
        m.len = static_cast<std::uint32_t>(a.bytes.size());
        std::copy(a.bytes.begin(), a.bytes.end(), m.args);
        if (!aq->try_push(m)) return std::unexpected(std::string("admin queue full"));
        break;
      }
      case Action::Run: break;
    }
    settle();
  }
  advance(sc.end);
  res.state_hash = eng.state_hash();
  res.live_orders = eng.live_orders();
  return res;
}

bool write_binary_file(const std::string& path, const std::vector<std::vector<std::byte>>& msgs) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) return false;
  bool ok = true;
  for (const auto& m : msgs) {
    std::byte len[2];
    store_be16(len, static_cast<std::uint16_t>(m.size()));
    ok = ok && std::fwrite(len, 1, 2, f) == 2 && std::fwrite(m.data(), 1, m.size(), f) == m.size();
  }
  const std::byte end[2] = {};
  ok = ok && std::fwrite(end, 1, 2, f) == 2;
  return std::fclose(f) == 0 && ok;
}

}  // namespace lle::admin

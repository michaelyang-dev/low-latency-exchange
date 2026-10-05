#include "client/loadgen_profile.h"

#include <charconv>
#include <cstdio>
#include <fstream>
#include <sstream>

#include "client/cli.h"

namespace lle::client::lg {

namespace {

std::string trim(std::string s) {
  const auto b = s.find_first_not_of(" \t\r");
  if (b == std::string::npos) return {};
  const auto e = s.find_last_not_of(" \t\r");
  return s.substr(b, e - b + 1);
}

std::expected<std::int64_t, std::string> num(const std::string& v) {
  std::int64_t x = 0;
  const auto r = std::from_chars(v.data(), v.data() + v.size(), x);
  if (r.ec != std::errc{} || r.ptr != v.data() + v.size()) return std::unexpected("not an integer: " + v);
  return x;
}

std::expected<std::pair<std::uint32_t, std::uint32_t>, std::string> range(const std::string& v) {
  const auto d = v.find('-');
  if (d == std::string::npos) {
    auto x = num(v);
    if (!x || *x < 1) return std::unexpected("bad size: " + v);
    return std::pair{static_cast<std::uint32_t>(*x), static_cast<std::uint32_t>(*x)};
  }
  auto a = num(trim(v.substr(0, d))), b = num(trim(v.substr(d + 1)));
  if (!a || !b || *a < 1 || *b < *a) return std::unexpected("bad range (LO-HI): " + v);
  return std::pair{static_cast<std::uint32_t>(*a), static_cast<std::uint32_t>(*b)};
}

}  // namespace

std::expected<Profile, std::string> parse_profile(const std::string& text, const std::string& name) {
  Profile p;
  p.path = name;
  ScheduleConfig& c = p.base;
  c.sessions = 16;
  c.symbols = 2000;
  std::uint64_t prefill_per = 8;
  std::istringstream in(text);
  std::string line, section;
  int ln = 0;
  auto fail = [&](const std::string& m) { return std::unexpected(name + ":" + std::to_string(ln) + ": " + m); };
  while (std::getline(in, line)) {
    ++ln;
    if (const auto h = line.find('#'); h != std::string::npos) line.resize(h);
    line = trim(line);
    if (line.empty()) continue;
    if (line.front() == '[') {
      if (line.back() != ']') return fail("bad section header");
      section = line.substr(1, line.size() - 2);
      if (section != "mix" && section != "book" && section != "sessions" && section != "risk")
        return fail("unknown section [" + section + "]");
      continue;
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) return fail("expected KEY = VALUE");
    const std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
    if (section.empty()) {
      if (k == "status") p.status = v;
      else return fail("unknown key " + k);
      continue;
    }
    if (section == "mix") {
      auto x = num(v);
      if (!x || *x < 0 || *x > 100) return fail("bad percentage: " + v);
      const auto pc = static_cast<std::uint32_t>(*x);
      if (k == "enter") c.mix.enter_pct = pc;
      else if (k == "cancel") c.mix.cancel_pct = pc;
      else if (k == "replace") c.mix.replace_pct = pc;
      else if (k == "ioc") c.mix.ioc_pct = pc;
      else return fail("unknown mix kind " + k);
    } else if (section == "book") {
      if (k == "tick") {
        const auto px = cli::parse_price(v);
        if (!px || *px <= 0) return fail("bad tick: " + v);
        c.tick = *px;
      } else if (k == "lots" || k == "ioc") {
        auto r = range(v);
        if (!r) return fail(r.error());
        if (k == "lots") {
          c.lots_min = r->first;
          c.lots_max = r->second;
        } else {
          c.ioc_min = r->first;
          c.ioc_max = r->second;
        }
      } else {
        auto x = num(v);
        if (!x || *x < 0) return fail("bad value for " + k + ": " + v);
        const auto u = static_cast<std::uint32_t>(*x);
        if (k == "symbols") c.symbols = u;
        else if (k == "depth_ticks") c.depth_ticks = u;
        else if (k == "prefill_per_symbol") prefill_per = u;
        else if (k == "lot") c.lot = u;
        else if (k == "ioc_unit") c.ioc_unit = u;
        else if (k == "dup_guard") c.dup_guard = u;
        else return fail("unknown book key " + k);
      }
    } else if (section == "sessions") {
      if (k == "account") {
        if (v == "per-session") c.shared_account = false;
        else if (v == "shared") c.shared_account = true;
        else return fail("account = per-session | shared");
      } else {
        auto x = num(v);
        if (!x || *x < 1) return fail("bad value for " + k + ": " + v);
        if (k == "count") c.sessions = static_cast<std::uint32_t>(*x);
        else if (k == "user_base") p.user_base = static_cast<std::uint32_t>(*x);
        else return fail("unknown sessions key " + k);
      }
    } else {  // risk
      auto x = num(v);
      if (!x || *x < 0) return fail("bad risk value: " + v);
      p.risk_rows.emplace_back(k, *x);
      RiskLimits& r = c.risk;
      if (k == "max-order-qty") r.max_qty = *x;
      else if (k == "max-order-notional") r.max_notional = *x;
      else if (k == "port-rate") r.port_rate = *x;
      else if (k == "symbol-rate") r.symbol_rate = *x;
      else if (k == "gross-exposure") r.gross = *x;
      else if (k == "symbol-notional") r.symbol_notional = *x;
      else if (k == "dup-window-sec") r.dup_window_sec = *x;
      else if (k == "kill-exposure") r.kill_exposure = *x;
      // other kinds (permissions, fat-finger-*, lop, adv-pct, ...) are passed through
    }
  }
  if (c.mix.enter_pct + c.mix.cancel_pct + c.mix.replace_pct + c.mix.ioc_pct != 100) {
    ln = 0;
    return fail("[mix] must sum to 100");
  }
  if (c.symbols < 1 || c.symbols > 9999 || c.sessions < 1 || c.sessions > c.symbols) {
    ln = 0;
    return fail("need 1 <= sessions <= symbols <= 9999");
  }
  c.prefill = prefill_per * c.symbols;
  return p;
}

std::expected<Profile, std::string> load_profile(const std::string& path) {
  std::ifstream f(path);
  if (!f) return std::unexpected("cannot open " + path);
  std::stringstream ss;
  ss << f.rdbuf();
  return parse_profile(ss.str(), path);
}

std::string exchanged_risk_rows(const Profile& p, std::uint32_t first_account, std::uint32_t count) {
  std::string out = "[risk]\n";
  for (std::uint32_t a = first_account; a < first_account + count; ++a)
    for (const auto& [k, v] : p.risk_rows) out += std::to_string(a) + " " + k + " " + std::to_string(v) + "\n";
  return out;
}

}  // namespace lle::client::lg

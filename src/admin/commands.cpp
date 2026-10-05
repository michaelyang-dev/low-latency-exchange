#include "admin/commands.h"

#include <array>
#include <limits>
#include <utility>

#include "engine/records.h"

namespace lle::admin {

namespace {
using engine::AdminArgsBuilder;
using engine::AdminCommand;
using engine::AdminTag;

std::unexpected<std::string> err(std::string m) { return std::unexpected(std::move(m)); }

bool valid_symbol(std::string_view s) {
  if (s.empty() || s.size() > 8) return false;
  for (char c : s)
    if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
  return true;
}

constexpr std::array<std::pair<std::string_view, engine::RiskKind>, 15> kKinds = {{
    {"permissions", engine::RiskKind::Permissions},
    {"max-order-qty", engine::RiskKind::MaxOrderQty},
    {"max-order-notional", engine::RiskKind::MaxOrderNotional},
    {"fat-finger-bps", engine::RiskKind::FatFingerBps},
    {"fat-finger-abs", engine::RiskKind::FatFingerAbs},
    {"lop", engine::RiskKind::Lop},
    {"dup-window-sec", engine::RiskKind::DupWindowSec},
    {"port-rate", engine::RiskKind::PortRate},
    {"symbol-rate", engine::RiskKind::SymbolRate},
    {"gross-exposure", engine::RiskKind::GrossExposure},
    {"symbol-notional", engine::RiskKind::SymbolNotional},
    {"adv-pct", engine::RiskKind::AdvPct},
    {"restricted", engine::RiskKind::Restricted},
    {"hard-to-borrow", engine::RiskKind::HardToBorrow},
    {"kill-exposure", engine::RiskKind::KillExposure},
}};
}  // namespace

std::expected<std::uint64_t, std::string> parse_uint(std::string_view s) {
  if (s.empty()) return err("empty number");
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return err("not a number: " + std::string(s));
    const auto d = static_cast<std::uint64_t>(c - '0');
    if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) return err("number too large: " + std::string(s));
    v = v * 10 + d;
  }
  return v;
}

std::expected<std::int64_t, std::string> parse_decimal(std::string_view s, int decimals) {
  const std::size_t dot = s.find('.');
  const std::string_view ip = s.substr(0, dot);
  const std::string_view fp = dot == std::string_view::npos ? std::string_view{} : s.substr(dot + 1);
  if (ip.empty() && fp.empty()) return err("not a decimal: " + std::string(s));
  if (static_cast<int>(fp.size()) > decimals) return err("too many decimals: " + std::string(s));
  std::uint64_t v = 0;
  if (!ip.empty()) {
    const auto i = parse_uint(ip);
    if (!i) return err(i.error());
    v = *i;
  }
  for (int k = 0; k < decimals; ++k) {
    if (v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 10) return err("decimal too large");
    v *= 10;
  }
  std::uint64_t f = 0;
  for (std::size_t k = 0; k < static_cast<std::size_t>(decimals); ++k) {
    const char c = k < fp.size() ? fp[k] : '0';
    if (c < '0' || c > '9') return err("not a decimal: " + std::string(s));
    f = f * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (v + f > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return err("decimal too large");
  return static_cast<std::int64_t>(v + f);
}

std::expected<std::uint32_t, std::string> parse_hms(std::string_view s) {
  if (s.size() != 8 || s[2] != ':' || s[5] != ':') return err("time must be HH:MM:SS: " + std::string(s));
  const auto h = parse_uint(s.substr(0, 2)), m = parse_uint(s.substr(3, 2)), x = parse_uint(s.substr(6, 2));
  if (!h || !m || !x || *h > 23 || *m > 59 || *x > 59) return err("bad time: " + std::string(s));
  return static_cast<std::uint32_t>(*h * 3600 + *m * 60 + *x);
}

std::expected<std::uint16_t, std::string> parse_risk_kind(std::string_view s) {
  for (const auto& [name, kind] : kKinds)
    if (name == s) return static_cast<std::uint16_t>(kind);
  const auto n = parse_uint(s);
  if (!n || *n == 0 || *n > 15) return err("unknown risk kind: " + std::string(s));
  return static_cast<std::uint16_t>(*n);
}

std::expected<Command, std::string> parse_command(std::span<const std::string_view> w) {
  if (w.empty()) return err("no command");
  const std::string_view verb = w[0];
  // Positional words and --options after the verb.
  std::vector<std::string_view> pos;
  std::vector<std::pair<std::string_view, std::string_view>> opts;
  for (std::size_t i = 1; i < w.size(); ++i) {
    if (w[i].starts_with("--")) {
      if (i + 1 >= w.size()) return err("option without a value: " + std::string(w[i]));
      opts.emplace_back(w[i], w[i + 1]);
      ++i;
    } else {
      pos.push_back(w[i]);
    }
  }
  auto opt = [&](std::string_view name) -> std::string_view {
    for (const auto& [k, v] : opts)
      if (k == name) return v;
    return {};
  };
  auto need = [&](std::size_t lo, std::size_t hi) { return pos.size() >= lo && pos.size() <= hi; };
  Command c;
  AdminArgsBuilder b;
  auto symbol = [&](std::string_view s) -> bool {
    if (!valid_symbol(s)) return false;
    b.symbol(s);
    return true;
  };
  auto price = [&](AdminTag t, std::string_view s, int dec = 4) -> std::expected<void, std::string> {
    const auto p = parse_decimal(s, dec);
    if (!p) return std::unexpected(p.error());
    if (*p <= 0) return std::unexpected(std::string("price must be positive"));
    b.i64(t, *p);
    return {};
  };
  auto account = [&](std::string_view s) -> std::expected<void, std::string> {
    const auto a = parse_uint(s);
    if (!a || *a > 0xFFFFFFFFu) return std::unexpected("bad account: " + std::string(s));
    b.u32(AdminTag::Account, static_cast<std::uint32_t>(*a));
    return {};
  };
  std::expected<void, std::string> ok;
  if (verb == "halt") {
    if (!need(1, 2) || !symbol(pos[0])) return err("usage: halt SYMBOL [REASON]");
    if (pos.size() == 2) b.reason(pos[1]);
    c.command = static_cast<std::uint16_t>(AdminCommand::Halt);
  } else if (verb == "quote-only") {
    if (!need(1, 1) || !symbol(pos[0])) return err("usage: quote-only SYMBOL [--price P] [--reason R]");
    if (!opt("--reason").empty()) b.reason(opt("--reason"));
    if (!opt("--price").empty()) ok = price(AdminTag::Price, opt("--price"));
    c.command = static_cast<std::uint16_t>(AdminCommand::QuoteOnly);
  } else if (verb == "resume" || verb == "ipo-quote") {
    if (!need(1, 1) || !symbol(pos[0])) return err("usage: " + std::string(verb) + " SYMBOL");
    c.command = static_cast<std::uint16_t>(verb == "resume" ? AdminCommand::Resume : AdminCommand::IpoQuote);
  } else if (verb == "ipo-schedule") {
    if (!need(3, 3) || !symbol(pos[0])) return err("usage: ipo-schedule SYMBOL PRICE HH:MM:SS [--qualifier A|C]");
    ok = price(AdminTag::Price, pos[1]);
    const auto t = parse_hms(pos[2]);
    if (!t) return err(t.error());
    b.u32(AdminTag::Time, *t);
    const std::string_view q = opt("--qualifier");
    if (!q.empty()) {
      if (q != "A" && q != "C") return err("--qualifier is A or C");
      b.u8(AdminTag::Qualifier, static_cast<std::uint8_t>(q[0]));
    }
    c.command = static_cast<std::uint16_t>(AdminCommand::IpoSchedule);
  } else if (verb == "ipo-release") {
    if (!need(1, 1) || !symbol(pos[0])) return err("usage: ipo-release SYMBOL [--band B]");
    if (!opt("--band").empty()) ok = price(AdminTag::Band, opt("--band"));
    c.command = static_cast<std::uint16_t>(AdminCommand::IpoRelease);
  } else if (verb == "luld-bands") {
    if (!need(3, 3) || !symbol(pos[0])) return err("usage: luld-bands SYMBOL LOWER UPPER");
    ok = price(AdminTag::Lower, pos[1]);
    if (ok) ok = price(AdminTag::Upper, pos[2]);
    c.command = static_cast<std::uint16_t>(AdminCommand::LuldBands);
  } else if (verb == "mwcb-levels") {
    if (!need(3, 3)) return err("usage: mwcb-levels L1 L2 L3");
    ok = price(AdminTag::Level1, pos[0], 8);
    if (ok) ok = price(AdminTag::Level2, pos[1], 8);
    if (ok) ok = price(AdminTag::Level3, pos[2], 8);
    c.command = static_cast<std::uint16_t>(AdminCommand::MwcbLevels);
  } else if (verb == "mwcb-breach") {
    if (!need(1, 1) || (pos[0] != "1" && pos[0] != "2" && pos[0] != "3")) return err("usage: mwcb-breach 1|2|3");
    b.u8(AdminTag::Level, static_cast<std::uint8_t>(pos[0][0] - '0'));
    c.command = static_cast<std::uint16_t>(AdminCommand::MwcbBreach);
  } else if (verb == "kill-switch" || verb == "kill-reset" || verb == "cross-cancel-permit") {
    if (!need(1, 1)) return err("usage: " + std::string(verb) + " ACCOUNT");
    ok = account(pos[0]);
    c.command = static_cast<std::uint16_t>(verb == "kill-switch"  ? AdminCommand::KillSwitch
                                           : verb == "kill-reset" ? AdminCommand::KillReset
                                                                  : AdminCommand::CrossCancelPermit);
  } else if (verb == "risk-limit") {
    if (!need(3, 4)) return err("usage: risk-limit ACCOUNT KIND VALUE [SYMBOL]");
    ok = account(pos[0]);
    const auto k = parse_risk_kind(pos[1]);
    if (!k) return err(k.error());
    const auto v = parse_uint(pos[2]);
    if (!v || *v > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return err("bad value");
    b.u16(AdminTag::Kind, *k).i64(AdminTag::Value, static_cast<std::int64_t>(*v));
    if (pos.size() == 4 && !symbol(pos[3])) return err("bad symbol: " + std::string(pos[3]));
    c.command = static_cast<std::uint16_t>(AdminCommand::RiskLimit);
  } else if (verb == "regsho") {
    if (!need(2, 2) || !symbol(pos[0]) || (pos[1] != "0" && pos[1] != "1" && pos[1] != "2"))
      return err("usage: regsho SYMBOL 0|1|2");
    b.u8(AdminTag::Action, static_cast<std::uint8_t>(pos[1][0]));
    c.command = static_cast<std::uint16_t>(AdminCommand::RegSho);
  } else {
    return err("unknown command: " + std::string(verb));
  }
  if (!ok) return err(ok.error());
  c.args = b.bytes();
  if (c.args.size() > 240) return err("arguments too long");
  return c;
}

}  // namespace lle::admin

#include "exchanged/config.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

#include "admin/commands.h"
#include "common/time.h"
#include "net/common/endpoint.h"

namespace lle::exch {

namespace {

std::string trim(std::string_view s) {
  std::size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
  return std::string(s.substr(b, e - b));
}

std::vector<std::string> words(const std::string& s) {
  std::vector<std::string> v;
  std::istringstream in(s);
  std::string w;
  while (in >> w) v.push_back(w);
  return v;
}

std::unexpected<std::string> fail(int line, const std::string& m) {
  return std::unexpected("config line " + std::to_string(line) + ": " + m);
}

std::expected<std::uint64_t, std::string> num(const std::string& v) { return admin::parse_uint(v); }

std::expected<bool, std::string> boolean(const std::string& v) {
  if (v == "true" || v == "yes" || v == "on" || v == "1") return true;
  if (v == "false" || v == "no" || v == "off" || v == "0") return false;
  return std::unexpected("not a boolean: " + v);
}

std::expected<env::Endpoint, std::string> endpoint(const std::string& v) {
  const auto e = net::parse_endpoint(v);
  if (!e) return std::unexpected("not an endpoint (a.b.c.d:port): " + v);
  return *e;
}

std::string kv(const std::vector<std::string>& w, std::string_view key) {
  for (std::size_t i = 1; i < w.size(); ++i) {
    if (w[i].size() > key.size() && w[i].compare(0, key.size(), key) == 0 && w[i][key.size()] == '=')
      return w[i].substr(key.size() + 1);
  }
  return {};
}
bool has(const std::vector<std::string>& w, std::string_view flag) {
  return std::find(w.begin() + 1, w.end(), std::string(flag)) != w.end();
}

}  // namespace

Nanos local_midnight(std::uint32_t date, int utc_offset_hours) {
  const int y0 = static_cast<int>(date / 10000), m = static_cast<int>(date / 100 % 100), d = static_cast<int>(date % 100);
  const int y = m <= 2 ? y0 - 1 : y0;
  const int era = (y >= 0 ? y : y - 399) / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days = std::int64_t{era} * 146097 + doe - 719468;
  return (days * 86'400 - std::int64_t{utc_offset_hours} * 3'600) * kNsPerSec;
}

std::expected<Nanos, std::string> parse_time_of_day(std::string_view s) {
  const auto hms = admin::parse_hms(s.substr(0, std::min<std::size_t>(8, s.size())));
  if (!hms) return std::unexpected(hms.error());
  Nanos t = static_cast<Nanos>(*hms) * kNsPerSec;
  if (s.size() > 8) {
    if (s[8] != '.' || s.size() > 18) return std::unexpected("bad time fraction: " + std::string(s));
    std::string frac(s.substr(9));
    frac.resize(9, '0');
    const auto ns = admin::parse_uint(frac);
    if (!ns) return std::unexpected(ns.error());
    t += static_cast<Nanos>(*ns);
  }
  return t;
}

std::string ExchangeConfig::variant() const {
  if (backend == net::BackendKind::BusyPoll && busypoll_irq_suspend) return "busypoll-irq-suspend";
  return net::to_string(backend);
}

std::string ExchangeConfig::journal_dir() const { return data_dir + "/journal/" + std::to_string(date); }
std::string ExchangeConfig::outlog_root() const { return data_dir + "/outlog"; }
std::string ExchangeConfig::snapshots_dir() const {
  return !snapshots.empty() ? snapshots : data_dir + "/snapshots/" + std::to_string(date);
}
std::string ExchangeConfig::log_path() const { return data_dir + "/logs/" + name + "-" + std::to_string(date) + ".nlog"; }
Nanos ExchangeConfig::local_midnight() const { return exch::local_midnight(date, utc_offset_hours); }

std::vector<engine::ScheduleEntry> ExchangeConfig::schedule_table() const {
  std::vector<engine::ScheduleEntry> s;
  if (schedule == "standard") s = engine::standard_schedule(false, noii_clock);
  else if (schedule == "early-close") s = engine::standard_schedule(true, noii_clock);
  else {
    // No timers: the day opens in the Regular session and is driven by Admin records.
    engine::ScheduleEntry init;
    init.timer_id = 0;
    init.kind = static_cast<engine::TimerKind>(0);
    init.arg = static_cast<std::uint16_t>(engine::Param::InitialSession);
    init.time_ns = 'R';
    s.push_back(init);
  }
  s.insert(s.end(), params.begin(), params.end());
  return s;
}

std::expected<ExchangeConfig, std::string> parse_config(const std::string& text) {
  ExchangeConfig c;
  std::istringstream in(text);
  std::string raw, section;
  int ln = 0;
  std::string cores_text;
  std::map<std::uint32_t, std::uint32_t> session_account;
  while (std::getline(in, raw)) {
    ++ln;
    const std::size_t hash = raw.find('#');
    const std::string line = trim(hash == std::string::npos ? raw : raw.substr(0, hash));
    if (line.empty()) continue;
    if (line.front() == '[') {
      if (line.back() != ']') return fail(ln, "bad section header");
      section = line.substr(1, line.size() - 2);
      continue;
    }
    const bool table = section == "symbols" || section == "accounts" || section == "sessions" || section == "risk" ||
                       section == "params";
    if (table) {
      const std::vector<std::string> w = words(line);
      if (section == "symbols") {
        if (w[0].size() > 8) return fail(ln, "symbol longer than 8 characters");
        engine::SymbolEntry e;
        e.symbol = Symbol8(w[0]);
        if (const auto p = kv(w, "prior"); !p.empty()) {
          const auto v = admin::parse_decimal(p, 4);
          if (!v) return fail(ln, v.error());
          e.prior_close = *v;
        }
        if (const auto p = kv(w, "lot"); !p.empty()) {
          const auto v = num(p);
          if (!v || *v == 0 || *v > 0xFFFFFFFFu) return fail(ln, "bad lot");
          e.round_lot = static_cast<std::uint32_t>(*v);
        }
        if (const auto p = kv(w, "tick"); !p.empty()) {
          const auto v = admin::parse_decimal(p, 4);
          if (!v || *v <= 0) return fail(ln, "bad tick");
          e.tick = static_cast<std::uint32_t>(*v);
        }
        if (const auto p = kv(w, "tier"); !p.empty()) e.luld_tier = p[0];
        if (const auto p = kv(w, "category"); !p.empty()) e.market_category = p[0];
        if (const auto p = kv(w, "adv"); !p.empty()) {
          const auto v = num(p);
          if (!v) return fail(ln, v.error());
          e.adv = static_cast<std::uint32_t>(*v);
        }
        if (const auto p = kv(w, "regsho"); !p.empty()) e.regsho = p[0] == 'x' ? ' ' : p[0];
        if (has(w, "etp")) e.flags |= engine::SymbolEntry::kFlagEtp;
        if (has(w, "test")) e.flags |= engine::SymbolEntry::kFlagTest;
        c.symbols.push_back(e);
      } else if (section == "accounts") {
        if (w.size() < 2) return fail(ln, "account ID FIRM[,FIRM...]");
        const auto id = num(w[0]);
        if (!id || *id == 0 || *id > 0xFFFFFFFFu) return fail(ln, "bad account id");
        engine::AccountEntry e;
        e.account_id = static_cast<std::uint32_t>(*id);
        std::size_t k = 0, start = 0;
        while (k < engine::AccountEntry::kMaxFirms) {
          const std::size_t comma = w[1].find(',', start);
          const std::string f = w[1].substr(start, comma == std::string::npos ? std::string::npos : comma - start);
          if (f.empty() || f.size() > 4) return fail(ln, "firm must be 1..4 characters");
          e.firms[k++] = Mpid4(f);
          if (comma == std::string::npos) break;
          start = comma + 1;
        }
        c.accounts.push_back(e);
      } else if (section == "sessions") {
        const auto id = num(w[0]);
        if (!id || *id == 0 || *id > 999'999) return fail(ln, "session id must be 1..999999");
        engine::SessionEntry e;
        e.session_id = static_cast<std::uint32_t>(*id);
        const auto acct = num(kv(w, "account"));
        if (!acct || *acct == 0) return fail(ln, "session needs account=ID");
        e.account_id = static_cast<std::uint32_t>(*acct);
        if (const auto f = kv(w, "flags"); !f.empty()) {
          e.flags = 0;
          std::size_t start = 0;
          for (;;) {
            const std::size_t comma = f.find(',', start);
            const std::string flag = f.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (flag == "cod") e.flags |= engine::SessionEntry::kCancelOnDisconnect;
            else if (flag == "market") e.flags |= engine::SessionEntry::kMarketOrders;
            else if (flag == "keepcross") e.flags |= engine::SessionEntry::kKeepCrossOrders;
            else if (flag == "postonlycancel") e.flags |= engine::SessionEntry::kPostOnlyCancel;
            else if (flag != "none") return fail(ln, "unknown session flag " + flag);
            if (comma == std::string::npos) break;
            start = comma + 1;
          }
        }
        if (const auto l = kv(w, "late"); !l.empty()) {
          if (l == "accept") e.late_cross = engine::LateCrossPolicy::Accept;
          else if (l == "reprice") e.late_cross = engine::LateCrossPolicy::Reprice;
          else if (l == "reject") e.late_cross = engine::LateCrossPolicy::Reject;
          else return fail(ln, "late=accept|reprice|reject");
        }
        if (const auto a = kv(w, "aiq"); !a.empty()) e.default_aiq = a[0];
        gw::SessionSpec spec;
        spec.session_id = e.session_id;
        spec.account = e.account_id;
        spec.username = kv(w, "user");
        auto cred = gw::Credential::parse(kv(w, "password"));
        if (!cred) return fail(ln, cred.error());
        spec.credential = *cred;
        if (const auto g = kv(w, "gw"); !g.empty()) {
          const auto v = num(g);
          if (!v || *v > 1) return fail(ln, "gw=0|1");
          spec.gateway = static_cast<std::uint8_t>(*v);
        }
        spec.cancel_on_disconnect = (e.flags & engine::SessionEntry::kCancelOnDisconnect) != 0;
        c.sessions.push_back(e);
        c.session_specs.push_back(std::move(spec));
      } else if (section == "risk") {
        if (w.size() < 3) return fail(ln, "ACCOUNT KIND VALUE [SYMBOL]");
        engine::RiskEntry e;
        const auto a = num(w[0]);
        if (!a) return fail(ln, "bad account");
        e.account_id = static_cast<std::uint32_t>(*a);
        const auto k = admin::parse_risk_kind(w[1]);
        if (!k) return fail(ln, k.error());
        e.kind = static_cast<engine::RiskKind>(*k);
        const auto v = num(w[2]);
        if (!v) return fail(ln, v.error());
        e.value = static_cast<std::int64_t>(*v);
        if (w.size() > 3) e.symbol = Symbol8(w[3]);
        c.risk.push_back(e);
      } else if (section == "params") {
        if (w.size() < 2) return fail(ln, "NAME VALUE");
        static const std::map<std::string, engine::Param> kParams = {
            {"halt-period", engine::Param::HaltPeriodSec},   {"luld-pause", engine::Param::LuldPauseSec},
            {"extension", engine::Param::ExtensionSec},      {"limit-state", engine::Param::LimitStateSec},
            {"mwcb-period", engine::Param::MwcbPeriodSec},   {"threshold-bps", engine::Param::ThresholdBps},
            {"threshold-min", engine::Param::ThresholdMin},  {"price-test-bps", engine::Param::PriceTestBps},
            {"price-test-min", engine::Param::PriceTestMin}, {"price-tests", engine::Param::PriceTests},
        };
        const auto it = kParams.find(w[0]);
        const auto v = num(w[1]);
        if (it == kParams.end() || !v) return fail(ln, "unknown parameter or value");
        engine::ScheduleEntry e;
        e.kind = static_cast<engine::TimerKind>(0);
        e.arg = static_cast<std::uint16_t>(it->second);
        e.time_ns = static_cast<Nanos>(*v);
        c.params.push_back(e);
      }
      continue;
    }
    if (section == "cores") {
      // "gw0 = 8" -> "gw0=8" (rt::CoreMap separates entries by whitespace).
      std::string norm;
      for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == ' ' || line[i] == '\t') {
          const std::size_t j = line.find_first_not_of(" \t", i);
          const bool around_eq = (!norm.empty() && norm.back() == '=') || (j != std::string::npos && line[j] == '=');
          if (around_eq) continue;
        }
        norm.push_back(line[i]);
      }
      cores_text += norm + "\n";
      continue;
    }
    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) return fail(ln, "expected key = value");
    const std::string key = trim(line.substr(0, eq));
    const std::string v = trim(line.substr(eq + 1));
    const std::string k = section + "." + key;
    auto set_num = [&](auto& dst, std::uint64_t lo, std::uint64_t hi) -> std::expected<void, std::string> {
      const auto x = num(v);
      if (!x || *x < lo || *x > hi) return std::unexpected(k + ": number out of range");
      dst = static_cast<std::remove_reference_t<decltype(dst)>>(*x);
      return {};
    };
    auto set_ms = [&](Nanos& dst) -> std::expected<void, std::string> {
      const auto x = num(v);
      if (!x || *x == 0 || *x > 86'400'000) return std::unexpected(k + ": milliseconds out of range");
      dst = static_cast<Nanos>(*x) * 1'000'000;
      return {};
    };
    auto set_ep = [&](env::Endpoint& dst) -> std::expected<void, std::string> {
      const auto e = endpoint(v);
      if (!e) return std::unexpected(k + ": " + e.error());
      dst = *e;
      return {};
    };
    auto set_ip = [&](std::uint32_t& dst) -> std::expected<void, std::string> {
      const auto a = net::parse_ipv4(v);
      if (!a) return std::unexpected(k + ": not an IPv4 address: " + v);
      dst = *a;
      return {};
    };
    // "IF:QUEUE", or "IF" (queue 0).
    auto set_xsk = [&](XskStage& dst) -> std::expected<void, std::string> {
      const std::size_t colon = v.rfind(':');
      dst.ifname = v.substr(0, colon);
      dst.queue = 0;
      if (colon != std::string::npos) {
        const auto q = num(v.substr(colon + 1));
        if (!q || *q > 1023) return std::unexpected(k + ": IF:QUEUE");
        dst.queue = static_cast<std::uint32_t>(*q);
      }
      if (dst.ifname.empty() || dst.ifname.size() > 15) return std::unexpected(k + ": IF:QUEUE");
      return {};
    };
    auto set_bool = [&](bool& dst) -> std::expected<void, std::string> {
      const auto b = boolean(v);
      if (!b) return std::unexpected(k + ": " + b.error());
      dst = *b;
      return {};
    };
    std::expected<void, std::string> r{};
    if (k == "node.name") {
      if (v.empty() || v.size() > 20) return fail(ln, "node.name must be 1..20 characters");
      c.name = v;
    } else if (k == "node.id") r = set_num(c.node_id, 0, 1);
    else if (k == "node.data_dir") c.data_dir = v;
    else if (k == "node.mode") {
      if (v == "solo") c.mode = NodeMode::Solo;
      else if (v == "paired") c.mode = NodeMode::Paired;
      else return fail(ln, "node.mode = solo | paired");
    } else if (k == "node.runner") {
      if (v == "threads") c.runner = RunnerMode::Threads;
      else if (v == "inline") c.runner = RunnerMode::Inline;
      else return fail(ln, "node.runner = threads | inline");
    } else if (k == "node.backend") {
      if (v == "busypoll-irq-suspend" || v == "irq-suspend") {
        c.backend = net::BackendKind::BusyPoll;
        c.busypoll_irq_suspend = true;
      } else {
        const auto b = net::parse_backend(v);
        if (!b) return fail(ln, "node.backend: epoll | busypoll | busypoll-irq-suspend | uring | uring-napi | xsk");
        c.backend = *b;
        c.busypoll_irq_suspend = false;
      }
    } else if (k == "node.idle_sleep_us") r = set_num(c.idle_sleep_us, 0, 1'000'000);
    else if (k == "node.build_id") r = set_num(c.build_id, 0, ~std::uint64_t{0});
    else if (k == "node.metrics") r = set_bool(c.metrics);
    else if (k == "node.nlog") r = set_bool(c.nlog);
    else if (k == "day.date") r = set_num(c.date, 19700101, 29991231);
    else if (k == "day.mold_session") {
      if (v.empty() || v.size() > 10) return fail(ln, "day.mold_session: 1..10 characters");
      c.mold_session = v;
    } else if (k == "day.soup_session") {
      if (v.empty() || v.size() > 10) return fail(ln, "day.soup_session: 1..10 characters");
      c.soup_session = v;
    } else if (k == "day.schedule") {
      if (v != "standard" && v != "early-close" && v != "none") return fail(ln, "day.schedule");
      c.schedule = v;
    } else if (k == "day.noii_clock") r = set_bool(c.noii_clock);
    else if (k == "day.utc_offset") {
      const int sign = !v.empty() && v[0] == '-' ? -1 : 1;
      const auto x = num(sign < 0 || (!v.empty() && v[0] == '+') ? v.substr(1) : v);
      if (!x || *x > 14) return fail(ln, "day.utc_offset: hours in -14..14");
      c.utc_offset_hours = sign * static_cast<int>(*x);
    } else if (k == "day.clock") {
      if (v == "real") c.clock = ClockMode::Real;
      else if (v == "offset") c.clock = ClockMode::Offset;
      else if (v == "manual") c.clock = ClockMode::Manual;
      else return fail(ln, "day.clock = real | offset | manual");
    } else if (k == "day.start") {
      const auto t = parse_time_of_day(v);
      if (!t) return fail(ln, t.error());
      c.start = *t;
    } else if (k == "day.auto_end") r = set_bool(c.auto_end);
    else if (k == "journal.segment_mib") {
      std::uint64_t mib = 0;
      r = set_num(mib, 1, 1024);
      c.segment_bytes = mib << 20;
    } else if (k == "journal.spares") r = set_num(c.spares, 1, 8);
    else if (k == "journal.l2_mib") {
      std::uint64_t mib = 0;
      r = set_num(mib, 1, 4096);
      c.l2_bytes = static_cast<std::size_t>(mib) << 20;
      if ((c.l2_bytes & (c.l2_bytes - 1)) != 0) return fail(ln, "journal.l2_mib must be a power of two");
    } else if (k == "journal.l2_path") {
      c.l2_path = v;
    } else if (k == "journal.l2_page_kib") {
      std::size_t kib = 0;
      r = set_num(kib, 4, 1 << 20);
      c.l2_page_bytes = kib << 10;
    } else if (k == "journal.iopoll") {
      r = set_bool(c.journal_iopoll);
    } else if (k == "journal.snapshots") {
      c.snapshots = v;
    } else if (k == "journal.use_snapshots") {
      r = set_bool(c.use_snapshots);
    } else if (k == "journal.device") {
      if (v != "io_uring" && v != "posix") return fail(ln, "journal.device must be io_uring or posix");
      c.journal_io_uring = v == "io_uring";
    }
    else if (k == "journal.snapshot_every") r = set_num(c.snapshot_every, 0, ~std::uint64_t{0});
    else if (k == "gateway.gw0") r = set_ep(c.gw[0]);
    else if (k == "gateway.gw1") r = set_ep(c.gw[1]);
    else if (k == "gateway.heartbeat_ms") r = set_ms(c.soup_heartbeat);
    else if (k == "gateway.idle_timeout_ms") r = set_ms(c.soup_idle_timeout);
    else if (k == "gateway.login_timeout_ms") r = set_ms(c.soup_login_timeout);
    else if (k == "gateway.max_conns") r = set_num(c.max_conns, 2, 4096);
    else if (k == "gateway.replay_ring_msgs") r = set_num(c.replay_ring_msgs, 16, std::uint64_t{1} << 26);
    else if (k == "gateway.replay_ring_mib") {
      std::uint64_t mib = 0;
      r = set_num(mib, 1, 4096);
      c.replay_ring_bytes = static_cast<std::size_t>(mib) << 20;
    } else if (k == "md.line_a") r = set_ep(c.line_a);
    else if (k == "md.line_b") r = set_ep(c.line_b);
    else if (k == "md.rerequest") r = set_ep(c.rerequest);
    // A packet must hold the largest ITCH message (header 20 + length 2 + 50): a
    // packetizer refuses a message that cannot fit, which would desynchronize the line.
    else if (k == "md.max_packet_a") r = set_num(c.max_packet_a, 72, 65'507);
    else if (k == "md.max_packet_b") r = set_num(c.max_packet_b, 72, 65'507);
    else if (k == "md.heartbeat_ms") r = set_ms(c.md_heartbeat);
    else if (k == "md.eos_linger_ms") r = set_ms(c.md_eos_linger);
    else if (k == "md.multicast_if") c.multicast_if = v;
    else if (k == "md.ttl") r = set_num(c.ttl, 0, 255);
    else if (k == "md.loop") r = set_bool(c.multicast_loop);
    else if (k == "glimpse.listen") {
      env::Endpoint e{};
      r = set_ep(e);
      c.glimpse = e;
    } else if (k == "glimpse.user") c.glimpse_user = v;
    else if (k == "glimpse.password") {
      auto cred = gw::Credential::parse(v);
      if (!cred) return fail(ln, cred.error());
      c.glimpse_credential = *cred;
    } else if (k == "admin.port") r = set_num(c.admin_port, 0, 65'535);
    else if (k == "admin.bind") r = set_ip(c.admin_bind);
    else if (k == "control.bind") r = set_ip(c.control_bind);
    else if (k == "net.ifname") c.net_ifname = v;
    else if (k == "net.device_setup") r = set_bool(c.device_setup);
    else if (k == "xsk.gw0") r = set_xsk(c.xsk.gw[0]);
    else if (k == "xsk.gw1") r = set_xsk(c.xsk.gw[1]);
    else if (k == "xsk.md") r = set_xsk(c.xsk.md);
    else if (k == "xsk.allow_copy") r = set_bool(c.xsk.allow_copy);
    else if (k == "xsk.skb_mode") r = set_bool(c.xsk.skb_mode);
    else if (k == "xsk.bpf") c.xsk.bpf_object = v;
    else if (k == "xsk.busy_poll") r = set_bool(c.xsk.busy_poll);
    else if (k == "xsk.umem_frames") r = set_num(c.xsk.umem_frames, 1024, 1u << 20);
    else if (k == "xsk.local_ip") r = set_ip(c.xsk.local_ip);
    else if (k == "xsk.md_source_port") r = set_num(c.xsk.md_source_port, 1, 65'535);
    else if (k == "xsk.checksum_offload") r = set_bool(c.xsk.checksum_offload);
    else if (k == "xsk.next_hop_mac") {
      std::array<std::uint8_t, 6> mac{};
      unsigned b[6] = {};
      char tail = 0;
      if (std::sscanf(v.c_str(), "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return fail(ln, "xsk.next_hop_mac: aa:bb:cc:dd:ee:ff");
      for (int i = 0; i < 6; ++i) {
        if (b[i] > 0xFF) return fail(ln, "xsk.next_hop_mac: aa:bb:cc:dd:ee:ff");
        mac[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(b[i]);
      }
      c.xsk.next_hop_mac = mac;
    } else if (section == "admin" && key.starts_with("operator.")) {
      const auto id = num(key.substr(9));
      if (!id || *id == 0 || *id > 0xFFFFFFFFu) return fail(ln, "admin.operator.<id>");
      Operator op;
      op.id = static_cast<std::uint32_t>(*id);
      const auto bytes = gw::from_hex(v);
      if (!bytes || bytes->size() < 16) return fail(ln, "operator key: at least 16 hex bytes");
      op.key = *bytes;
      c.operators.push_back(op);
    } else if (k == "control.port") r = set_num(c.control_port, 0, 65'535);
    else if (k == "ha.bind") r = set_ep(c.ha_bind);
    else if (k == "ha.peer") r = set_ep(c.ha_peer);
    else if (k == "ha.witness") r = set_ep(c.witness);
    else if (k == "ha.primary") r = set_num(c.initial_primary, 0, 1);
    else if (k == "ha.heartbeat_ms") r = set_ms(c.ha_heartbeat);
    else if (k == "ha.repl_thread") r = set_bool(c.repl_thread);
    else if (k == "ha.rejoin_retry_ms") r = set_ms(c.rejoin_retry);
    else if (k == "ha.rto_ms") r = set_ms(c.ha_rto);
    else if (k == "ha.t_d_ms") r = set_ms(c.t_d);
    else if (k == "ha.t_ack_ms") r = set_ms(c.t_ack);
    else if (k == "ha.log_mib") {
      std::uint64_t mib = 0;
      r = set_num(mib, 1, 65'536);
      c.repl_log_bytes = static_cast<std::size_t>(mib) << 20;
    } else return fail(ln, "unknown key " + k);
    if (!r) return fail(ln, r.error());
  }
  if (!cores_text.empty()) {
    auto cm = rt::CoreMap::parse(cores_text);
    if (!cm) return std::unexpected("config [cores]: " + cm.error());
    c.cores = std::move(*cm);
  }
  if (c.symbols.empty()) return std::unexpected(std::string("config: no [symbols]"));
  if (c.accounts.empty()) return std::unexpected(std::string("config: no [accounts]"));
  if (c.sessions.empty()) return std::unexpected(std::string("config: no [sessions]"));
  if (c.mode == NodeMode::Paired && (c.ha_peer.port == 0 || c.witness.port == 0 || c.ha_bind.port == 0))
    return std::unexpected(std::string("config: paired mode needs ha.bind, ha.peer and ha.witness"));
  if (c.t_ack >= c.t_d) return std::unexpected(std::string("config: ha.t_ack_ms must be below ha.t_d_ms (10 §4)"));
  if (c.backend == net::BackendKind::Xsk) {
    const XskStage* st[] = {&c.xsk.gw[0], &c.xsk.gw[1], &c.xsk.md};
    for (const XskStage* s : st)
      if (!s->set()) return std::unexpected(std::string("config: backend xsk needs [xsk] gw0, gw1 and md (IF:QUEUE)"));
    for (int i = 0; i < 3; ++i) {
      for (int j = i + 1; j < 3; ++j) {
        if (st[i]->ifname == st[j]->ifname && st[i]->queue == st[j]->queue)
          return std::unexpected(std::string("config: [xsk] gw0, gw1 and md need distinct queues (one AF_XDP socket each)"));
      }
    }
  }
  for (const auto& s : c.sessions) {
    bool found = false;
    for (const auto& a : c.accounts) found = found || a.account_id == s.account_id;
    if (!found) return std::unexpected("config: session " + std::to_string(s.session_id) + " names an unknown account");
  }
  return c;
}

std::expected<ExchangeConfig, std::string> load_config(const std::string& path) {
  std::ifstream f(path);
  if (!f) return std::unexpected("cannot read " + path);
  std::stringstream ss;
  ss << f.rdbuf();
  return parse_config(ss.str());
}

}  // namespace lle::exch

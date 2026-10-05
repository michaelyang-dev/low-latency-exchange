// luld_feed: the LULD band simulator (05 §10 E-15). The engine does not
// compute LULD bands; it acts on Admin LuldBands records. This tool computes
// them from a trade stream with the LULD Plan's reference-price and
// percentage rules (admin/luld.h) and emits one command per band change:
// printed as lle-admin command lines, or sent to the admin port.
//
//   luld_feed --input FILE [--tier SYMBOL=1|2]... [--default-tier 1|2]
//             [--send --host H --port P --operator ID --key-file F]
//
// FILE is either an ITCH BinaryFILE (trades: 'E' via the added order's price,
// 'C' printable, 'P', 'Q' with shares) or a CSV of HH:MM:SS[.fraction],SYMBOL,PRICE.
// Output lines: "<HH:MM:SS.nnnnnnnnn> luld-bands SYMBOL LOWER UPPER".
// Exit status: 0 ok, 1 a command was rejected, 2 usage or I/O error.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "admin/commands.h"
#include "admin/luld.h"
#include "admin/net.h"
#include "admin/protocol.h"
#include "common/endian.h"
#include "common/time.h"
#include "proto/itch50/binary_file.h"

namespace {

using lle::Nanos;
using lle::PxE4;

std::string price_str(PxE4 p) {
  char b[32];
  std::snprintf(b, sizeof(b), "%lld.%04lld", static_cast<long long>(p / 10'000), static_cast<long long>(p % 10'000));
  return b;
}
std::string time_str(Nanos t) {
  char b[40];
  const long long s = t / lle::kNsPerSec;
  std::snprintf(b, sizeof(b), "%02lld:%02lld:%02lld.%09lld", s / 3600, (s / 60) % 60, s % 60,
                static_cast<long long>(t % lle::kNsPerSec));
  return b;
}
std::string trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
  return std::string(s);
}

struct Feed {
  std::map<std::string, char> tiers;
  char default_tier = '2';
  std::map<std::string, lle::admin::LuldSymbol> syms;
  // Sending.
  bool send = false;
  std::string host = "127.0.0.1";
  std::uint16_t port = 7500;
  std::uint32_t op = 0;
  lle::admin::Key key;
  std::uint64_t seq = 0;
  int rejected = 0;
  bool io_error = false;

  lle::admin::LuldSymbol& sym(const std::string& s) {
    auto it = syms.find(s);
    if (it != syms.end()) return it->second;
    const auto t = tiers.find(s);
    return syms.emplace(s, lle::admin::LuldSymbol(t != tiers.end() ? t->second : default_tier)).first->second;
  }
  void emit(Nanos t, const std::string& s, const lle::admin::LuldBands& b) {
    std::printf("%s luld-bands %s %s %s\n", time_str(t).c_str(), s.c_str(), price_str(b.lower).c_str(),
                price_str(b.upper).c_str());
    if (!send) return;
    const std::string lo = price_str(b.lower), hi = price_str(b.upper);
    const std::vector<std::string_view> words = {"luld-bands", s, lo, hi};
    const auto cmd = lle::admin::parse_command(words);
    if (!cmd) {
      ++rejected;
      return;
    }
    const auto frame = lle::admin::encode_request(lle::admin::Request{op, ++seq, cmd->command, 1, cmd->args}, key);
    const auto resp = lle::admin::exchange(host, port, frame);
    if (!resp) {
      std::fprintf(stderr, "luld_feed: %s\n", resp.error().c_str());
      io_error = true;
      return;
    }
    const auto r = lle::admin::decode_response(*resp, key);
    if (!r || !r->accepted) ++rejected;
  }
  void trade(Nanos t, const std::string& s, PxE4 px) {
    // Every symbol's clock first (doubling windows), then the trade.
    for (auto& [name, st] : syms)
      if (name != s)
        if (auto b = st.on_time(t)) emit(t, name, *b);
    if (auto b = sym(s).on_trade(t, px)) emit(t, s, *b);
  }
};

int usage(const char* why) {
  std::fprintf(stderr, "luld_feed: %s\n", why);
  std::fprintf(stderr,
               "usage: luld_feed --input FILE [--tier SYMBOL=1|2]... [--default-tier 1|2]\n"
               "                 [--send --host H --port P --operator ID --key-file F]\n");
  return 2;
}

int run_csv(Feed& f, const std::string& path) {
  std::ifstream in(path);
  if (!in) return usage("cannot read the input");
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    const std::size_t c1 = line.find(','), c2 = line.find(',', c1 + 1);
    if (c1 == std::string::npos || c2 == std::string::npos) return usage("bad CSV line");
    const std::string ts = trim(std::string_view(line).substr(0, c1));
    const auto hms = lle::admin::parse_hms(std::string_view(ts).substr(0, 8));
    if (!hms) return usage("bad CSV time");
    Nanos t = static_cast<Nanos>(*hms) * lle::kNsPerSec;
    if (ts.size() > 9 && ts[8] == '.') {
      std::string frac = ts.substr(9);
      frac.resize(9, '0');
      const auto ns = lle::admin::parse_uint(frac);
      if (!ns) return usage("bad CSV time fraction");
      t += static_cast<Nanos>(*ns);
    }
    const auto px = lle::admin::parse_decimal(trim(std::string_view(line).substr(c2 + 1)), 4);
    if (!px) return usage("bad CSV price");
    f.trade(t, trim(std::string_view(line).substr(c1 + 1, c2 - c1 - 1)), *px);
  }
  return 0;
}

int run_itch(Feed& f, const std::string& path) {
  lle::itch50::BinaryFileReader rd;
  if (auto ok = rd.open(path); !ok) return usage(ok.error().c_str());
  std::vector<std::string> names(65536);
  std::unordered_map<std::uint64_t, std::pair<std::uint16_t, PxE4>> orders;  // ref -> (locate, price); lookups only
  auto stock = [](const std::byte* p) {
    std::string s(reinterpret_cast<const char*>(p), 8);
    return trim(s);
  };
  for (;;) {
    const auto r = rd.next();
    if (r.status == lle::itch50::RecordStatus::EndOfSession) continue;
    if (r.status != lle::itch50::RecordStatus::Message) break;
    const std::byte* p = r.data.data();
    const std::size_t n = r.data.size();
    if (n < 11) continue;
    const char type = static_cast<char>(p[0]);
    const std::uint16_t loc = lle::load_be16(p + 1);
    const auto t = static_cast<Nanos>(lle::load_be48(p + 5));
    switch (type) {
      case 'R':
        if (n >= 19) names[loc] = stock(p + 11);
        break;
      case 'A':
      case 'F':
        if (n >= 36) orders[lle::load_be64(p + 11)] = {loc, static_cast<PxE4>(lle::load_be32(p + 32))};
        break;
      case 'U':
        if (n >= 35) {
          const auto it = orders.find(lle::load_be64(p + 11));
          if (it != orders.end()) {
            orders[lle::load_be64(p + 19)] = {it->second.first, static_cast<PxE4>(lle::load_be32(p + 31))};
            orders.erase(it);
          }
        }
        break;
      case 'E':
        if (n >= 31) {
          const auto it = orders.find(lle::load_be64(p + 11));
          if (it != orders.end()) f.trade(t, names[loc], it->second.second);
        }
        break;
      case 'C':
        if (n >= 36 && static_cast<char>(p[31]) == 'Y') f.trade(t, names[loc], static_cast<PxE4>(lle::load_be32(p + 32)));
        break;
      case 'P':
        if (n >= 44) f.trade(t, names[loc], static_cast<PxE4>(lle::load_be32(p + 32)));
        break;
      case 'Q':
        if (n >= 40 && lle::load_be64(p + 11) > 0) f.trade(t, names[loc], static_cast<PxE4>(lle::load_be32(p + 27)));
        break;
      default: break;
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Feed f;
  std::string input, key_file;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a(argv[i]);
    if (a == "--send") {
      f.send = true;
      continue;
    }
    if (i + 1 >= argc) return usage("missing option value");
    const std::string v(argv[++i]);
    if (a == "--input") {
      input = v;
    } else if (a == "--tier") {
      const auto eq = v.find('=');
      if (eq == std::string::npos || (v.substr(eq + 1) != "1" && v.substr(eq + 1) != "2"))
        return usage("--tier SYMBOL=1|2");
      f.tiers[v.substr(0, eq)] = v[eq + 1];
    } else if (a == "--default-tier") {
      if (v != "1" && v != "2") return usage("--default-tier 1|2");
      f.default_tier = v[0];
    } else if (a == "--host") {
      f.host = v;
    } else if (a == "--port") {
      const auto p = lle::admin::parse_uint(v);
      if (!p || *p == 0 || *p > 65535) return usage("bad port");
      f.port = static_cast<std::uint16_t>(*p);
    } else if (a == "--operator") {
      const auto p = lle::admin::parse_uint(v);
      if (!p || *p > 0xFFFFFFFFu) return usage("bad operator");
      f.op = static_cast<std::uint32_t>(*p);
    } else if (a == "--key-file") {
      key_file = v;
    } else {
      return usage("unknown option");
    }
  }
  if (input.empty()) return usage("--input is required");
  if (f.send) {
    auto k = lle::admin::load_key_file(key_file);
    if (!k) return usage(k.error().c_str());
    f.key = std::move(*k);
    f.seq = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
  }
  const bool csv = input.size() >= 4 && input.substr(input.size() - 4) == ".csv";
  const int rc = csv ? run_csv(f, input) : run_itch(f, input);
  if (rc != 0) return rc;
  if (f.io_error) return 2;
  return f.rejected != 0 ? 1 : 0;
}

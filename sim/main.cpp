// exsim: the deterministic simulator driver (09; R4b R2).
//
//   exsim --seed=<u64|0xhex|40-hex sha> [--seeds=N] [--mode=swarm|lite|no-faults]
//         [--disable=net,disk,crash,clock,buggify,partition,pause]
//         [--world=pingpong|wal|stream|witness|journal|arbiter|soupbin|utcp|ha|outlog|snapshot|single|
//          kill_switch_during_cross|exchange|exchange_ha|all] [--exclude-world=w1,w2]
//         [--ticks-max=N] [--safety-ms=N] [--bound-ms=N] [--trace-out=f] [--record-faults=f] [--replay=f]
//         [--check-determinism] [--canary] [--require-probes] [--quiet] [--verbose]
//
// Output is line-oriented key=value, parsed by tools/sim/campaign.py and
// tools/ledger/{verify_bugs,shrink}.py. Every run prints
// `events=N trace_hash=0x...`; a failure prints `signature=ORACLE:EVENT:0xHASH`.
// Exit codes: 0 pass, 1 oracle failure, 2 determinism mismatch,
// 3 must-hit probes missing (--require-probes), 64 usage error.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/hash.h"
#include "sim/worlds/worlds.h"
#include "sim/fault/injector.h"
#include "sim/fault/swarm.h"

namespace {

using namespace lle;
using namespace lle::sim;

struct Cli {
  std::uint64_t seed = 1;
  std::uint64_t seeds = 1;
  Mode mode = Mode::Swarm;
  std::uint32_t disabled = 0;
  std::vector<worlds::WorldKind> worlds{worlds::built_worlds().begin(), worlds::built_worlds().end()};
  std::uint64_t ticks_max = ~std::uint64_t{0};
  Nanos safety_ns = worlds::default_plan().safety_ns;
  Nanos bound_ns = worlds::default_plan().convergence_ns;
  std::string trace_out;
  std::string record_faults;
  std::string replay;
  bool check_determinism = false;
  bool canary = false;
  bool require_probes = false;
  bool quiet = false;
  bool verbose = false;
};

void usage() {
  std::fputs(
      "usage: exsim --seed=<u64|0xhex|sha> [--seeds=N] [--mode=swarm|lite|no-faults]\n"
      "             [--disable=net,disk,crash,clock,buggify,partition,pause]\n"
      "             [--world=pingpong|wal|stream|witness|journal|arbiter|soupbin|utcp|ha|outlog|snapshot|single|\n"
      "             kill_switch_during_cross|exchange|exchange_ha|all] [--exclude-world=w1,w2]\n"
      "             [--ticks-max=N] [--safety-ms=N] [--bound-ms=N]\n"
      "             [--trace-out=f] [--record-faults=f] [--replay=f] [--check-determinism]\n"
      "             [--canary] [--require-probes] [--quiet] [--verbose]\n",
      stderr);
}

std::optional<std::uint64_t> parse_u64(std::string_view s) {
  if (s.empty()) return std::nullopt;
  std::uint64_t v = 0;
  for (const char ch : s) {
    if (ch < '0' || ch > '9') return std::nullopt;
    const auto d = static_cast<std::uint64_t>(ch - '0');
    if (v > (~std::uint64_t{0} - d) / 10) return std::nullopt;
    v = v * 10 + d;
  }
  return v;
}

int hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

// Decimal, 0x-prefixed hex (<= 16 digits), or a longer hex string such as a
// 40-hex commit hash (TigerBeetle practice: CI seeds from the commit), which is
// folded to 64 bits 16 digits at a time.
std::optional<std::uint64_t> parse_seed(std::string_view s) {
  if (s.starts_with("0x") || s.starts_with("0X")) {
    s.remove_prefix(2);
  } else if (s.size() <= 20) {
    if (auto d = parse_u64(s)) return d;
  }
  if (s.empty()) return std::nullopt;
  std::uint64_t acc = 0;
  std::uint64_t chunk = 0;
  std::size_t n = 0;
  for (const char ch : s) {
    const int d = hex_digit(ch);
    if (d < 0) return std::nullopt;
    chunk = (chunk << 4) | static_cast<std::uint64_t>(d);
    if (++n % 16 == 0) {
      acc = n == 16 ? chunk : mix64(acc ^ chunk);
      chunk = 0;
    }
  }
  if (n < 16) return chunk;  // short hex: the value itself
  if (n == 16) return acc;   // exactly 64 bits
  if (n % 16 != 0) acc = mix64(acc ^ chunk);
  return acc;  // longer (e.g. a 40-hex commit sha): folded
}

std::optional<Cli> parse(int argc, char** argv) {
  Cli c;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    const std::size_t eq = a.find('=');
    const std::string_view key = a.substr(0, eq);
    const std::string_view val = eq == std::string_view::npos ? std::string_view{} : a.substr(eq + 1);
    if (key == "--seed") {
      auto s = parse_seed(val);
      if (!s) return std::nullopt;
      c.seed = *s;
    } else if (key == "--seeds") {
      auto s = parse_u64(val);
      if (!s || *s == 0) return std::nullopt;
      c.seeds = *s;
    } else if (key == "--mode") {
      auto m = parse_mode(val);
      if (!m) return std::nullopt;
      c.mode = *m;
    } else if (key == "--disable") {
      auto m = parse_disable_list(val);
      if (!m) return std::nullopt;
      c.disabled = *m;
    } else if (key == "--exclude-world") {
      // Comma list of worlds left out of the run (unbuilt ones are simply absent).
      std::string_view rest = val;
      while (!rest.empty()) {
        const std::size_t comma = rest.find(',');
        auto w = worlds::parse_world(rest.substr(0, comma));
        if (!w) return std::nullopt;
        std::erase(c.worlds, *w);
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
      }
    } else if (key == "--world") {
      if (val == "all") continue;
      c.worlds.clear();
      std::string_view rest = val;
      while (!rest.empty()) {
        const std::size_t comma = rest.find(',');
        auto w = worlds::parse_world(rest.substr(0, comma));
        if (!w) return std::nullopt;
        if (!worlds::world_built(*w)) {
          std::fprintf(stderr, "exsim: world '%.*s' is not part of this build (LLE_ONLY)\n",
                       static_cast<int>(worlds::world_name(*w).size()), worlds::world_name(*w).data());
          return std::nullopt;
        }
        c.worlds.push_back(*w);
        if (comma == std::string_view::npos) break;
        rest.remove_prefix(comma + 1);
      }
    } else if (key == "--ticks-max") {
      auto s = parse_u64(val);
      if (!s) return std::nullopt;
      c.ticks_max = *s;
    } else if (key == "--safety-ms") {
      auto s = parse_u64(val);
      if (!s) return std::nullopt;
      c.safety_ns = static_cast<Nanos>(*s) * 1'000'000;
    } else if (key == "--bound-ms") {
      auto s = parse_u64(val);
      if (!s) return std::nullopt;
      c.bound_ns = static_cast<Nanos>(*s) * 1'000'000;
    } else if (key == "--trace-out") {
      c.trace_out = std::string(val);
    } else if (key == "--record-faults") {
      c.record_faults = std::string(val);
    } else if (key == "--replay") {
      c.replay = std::string(val);
    } else if (key == "--check-determinism") {
      c.check_determinism = true;
    } else if (key == "--canary") {
      c.canary = true;
    } else if (key == "--require-probes") {
      c.require_probes = true;
    } else if (key == "--quiet") {
      c.quiet = true;
    } else if (key == "--verbose") {
      c.verbose = true;
    } else {
      return std::nullopt;
    }
  }
  return c;
}

std::optional<std::string> read_file(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (f == nullptr) return std::nullopt;
  std::string out;
  char buf[4096];
  std::size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
  std::fclose(f);
  return out;
}

struct SeedResult {
  bool failed = false;
  bool mismatch = false;
  std::uint64_t events = 0;
  std::uint64_t trace_hash = 0;
  std::vector<worlds::Report> reports;
  std::string signature;
  std::string failure_world;
  std::string failure_message;
};

// Runs every selected world once for a seed.
SeedResult run_seed(const Cli& cli, std::uint64_t seed, std::FILE* trace, const std::string* replay_text,
                    std::string* record_text) {
  SeedResult r;
  const FaultConfig cfg = draw_fault_config(seed, cli.mode, cli.disabled);
  Fnv1a64 combined;
  for (const worlds::WorldKind w : cli.worlds) {
    worlds::Options o;
    o.seed = seed;
    o.faults = cfg;
    o.canary = cli.canary;
    o.plan = worlds::default_plan();
    o.plan.safety_ns = cli.safety_ns;
    o.plan.convergence_ns = cli.bound_ns;
    o.plan.ticks_max = cli.ticks_max;
    o.trace = trace;
    o.verbose = cli.verbose;
    FaultSchedule replay;
    FaultSchedule record;
    if (replay_text != nullptr) {
      replay.parse(*replay_text, worlds::world_name(w));
      o.replay = &replay;
    }
    if (record_text != nullptr) o.record = &record;
    worlds::Report rep = worlds::run_world(w, o);
    if (record_text != nullptr) *record_text += record.format(worlds::world_name(w));
    combined.u(rep.run.events);
    combined.u(rep.run.trace_hash);
    r.events += rep.run.events;
    if (rep.run.failed && !r.failed) {
      r.failed = true;
      r.signature = rep.run.failure.str();
      r.failure_world = std::string(worlds::world_name(w));
      r.failure_message = rep.run.failure.message;
    }
    r.reports.push_back(std::move(rep));
  }
  r.trace_hash = combined.value();
  return r;
}

void print_world_line(const worlds::Report& rep) {
  std::printf("world=%.*s result=%s events=%llu trace_hash=0x%016llx vt_ms=%lld phase=%.*s truncated=%d "
              "faults_fired=%llu buggify_active=%llu %s\n",
              static_cast<int>(worlds::world_name(rep.world).size()), worlds::world_name(rep.world).data(),
              rep.run.failed ? "FAIL" : "PASS", static_cast<unsigned long long>(rep.run.events),
              static_cast<unsigned long long>(rep.run.trace_hash), static_cast<long long>(rep.run.virtual_ns / 1'000'000),
              static_cast<int>(phase_name(rep.run.phase).size()), phase_name(rep.run.phase).data(),
              rep.run.truncated ? 1 : 0, static_cast<unsigned long long>(rep.faults_fired),
              static_cast<unsigned long long>(rep.buggify_sites_active), rep.summary.c_str());
}

void print_faults(const FaultStats& s) {
  std::string line = "faults";
  s.for_each([&](const char* name, const char*, std::uint64_t v) {
    line += ' ';
    line += name;
    line += '=';
    line += std::to_string(v);
  });
  std::puts(line.c_str());
}

void print_probes(const ProbeRegistry& p) {
  p.for_each([](const ProbeInfo& info) {
    const std::string_view st = probe_status_name(ProbeRegistry::status(info));
    std::printf("probe %s hits=%llu status=%.*s%s\n", info.name.c_str(), static_cast<unsigned long long>(info.hits),
                static_cast<int>(st.size()), st.data(), info.rare ? " rare" : "");
  });
}

}  // namespace

int main(int argc, char** argv) {
  const std::optional<Cli> parsed = parse(argc, argv);
  if (!parsed) {
    usage();
    return 64;
  }
  const Cli& cli = *parsed;

  std::FILE* trace = nullptr;
  if (!cli.trace_out.empty()) {
    trace = std::fopen(cli.trace_out.c_str(), "w");
    if (trace == nullptr) {
      std::fprintf(stderr, "exsim: cannot open %s\n", cli.trace_out.c_str());
      return 64;
    }
  }
  std::optional<std::string> replay_text;
  if (!cli.replay.empty()) {
    replay_text = read_file(cli.replay);
    if (!replay_text) {
      std::fprintf(stderr, "exsim: cannot read %s\n", cli.replay.c_str());
      return 64;
    }
    // Lines carry a world prefix (as written by --record-faults).
    for (const worlds::WorldKind w : cli.worlds) {
      FaultSchedule s;
      if (!s.parse(*replay_text, worlds::world_name(w))) {
        std::fprintf(stderr, "exsim: malformed fault schedule %s\n", cli.replay.c_str());
        return 64;
      }
    }
  }

  std::string worlds;
  for (const worlds::WorldKind w : cli.worlds) {
    if (!worlds.empty()) worlds += ',';
    worlds += worlds::world_name(w);
  }
#if defined(LLE_SIM) && LLE_SIM
  const int lle_sim = 1;
#else
  const int lle_sim = 0;
#endif
  std::printf("exsim version=1 seed=0x%016llx seeds=%llu mode=%.*s disable=%s worlds=%s canary=%d lle_sim=%d\n",
              static_cast<unsigned long long>(cli.seed), static_cast<unsigned long long>(cli.seeds),
              static_cast<int>(mode_name(cli.mode).size()), mode_name(cli.mode).data(),
              format_disable_list(cli.disabled).c_str(), worlds.c_str(), cli.canary ? 1 : 0, lle_sim);

  const bool single = cli.seeds == 1;
  FaultStats total_stats;
  ProbeRegistry ensemble;
  std::uint64_t failed = 0;
  std::uint64_t mismatches = 0;
  std::uint64_t events_total = 0;
  std::uint64_t last_hash = 0;
  std::string first_signature;
  std::string record_text;

  for (std::uint64_t i = 0; i < cli.seeds; ++i) {
    const std::uint64_t seed = cli.seed + i;
    const FaultConfig cfg = draw_fault_config(seed, cli.mode, cli.disabled);
    if (single && !cli.quiet) {
      std::printf("swarm_digest=0x%016llx\n", static_cast<unsigned long long>(cfg.digest()));
      std::printf("swarm %s\n", cfg.describe().c_str());
    }
    SeedResult r = run_seed(cli, seed, trace, replay_text ? &*replay_text : nullptr,
                            cli.record_faults.empty() ? nullptr : &record_text);
    bool mismatch = false;
    if (cli.check_determinism) {
      const SeedResult again = run_seed(cli, seed, nullptr, replay_text ? &*replay_text : nullptr, nullptr);
      mismatch = again.events != r.events || again.trace_hash != r.trace_hash;
      for (std::size_t k = 0; k < r.reports.size() && k < again.reports.size(); ++k) {
        mismatch = mismatch || r.reports[k].run.trace_hash != again.reports[k].run.trace_hash;
      }
    }
    events_total += r.events;
    last_hash = r.trace_hash;
    for (const worlds::Report& rep : r.reports) {
      total_stats += rep.stats;
      ensemble.merge(rep.probes);
    }
    if (r.failed) {
      ++failed;
      if (first_signature.empty()) first_signature = r.signature;
    }
    if (mismatch) ++mismatches;

    if (single) {
      if (!cli.quiet) {
        for (const worlds::Report& rep : r.reports) print_world_line(rep);
      }
    } else {
      std::printf("seed=0x%016llx result=%s events=%llu trace_hash=0x%016llx%s%s%s%s%s\n",
                  static_cast<unsigned long long>(seed), r.failed ? "FAIL" : "PASS",
                  static_cast<unsigned long long>(r.events), static_cast<unsigned long long>(r.trace_hash),
                  cli.check_determinism ? (mismatch ? " determinism=MISMATCH" : " determinism=OK") : "",
                  r.failed ? " signature=" : "", r.failed ? r.signature.c_str() : "",
                  r.failed ? " world=" : "", r.failed ? r.failure_world.c_str() : "");
    }
    if (r.failed && single) {
      std::printf("signature=%s world=%s\n", r.signature.c_str(), r.failure_world.c_str());
      std::printf("failure_message=%s\n", r.failure_message.c_str());
    }
    std::fflush(stdout);
  }

  if (trace != nullptr) std::fclose(trace);
  if (!cli.record_faults.empty()) {
    std::FILE* f = std::fopen(cli.record_faults.c_str(), "w");
    if (f == nullptr) {
      std::fprintf(stderr, "exsim: cannot write %s\n", cli.record_faults.c_str());
      return 64;
    }
    std::fputs("# exsim fault schedule: <world> <at_ns> <kind> <node> <a> <b> <dur_ns>\n", f);
    std::fputs("# kind: 0 crash (a=1 host), 1 pause, 2 partition (node=1 symmetric, a/b node masks), 3 clock step\n",
               f);
    std::fputs(record_text.c_str(), f);
    std::fclose(f);
  }

  if (!cli.quiet) {
    print_faults(total_stats);
    print_probes(ensemble);
  }
  const std::vector<std::string> missing = ensemble.missing(/*include_rare=*/false);
  std::printf("probes_missing=%zu\n", missing.size());
  if (cli.check_determinism) {
    std::printf("determinism=%s runs=2 seeds=%llu mismatches=%llu\n", mismatches == 0 ? "OK" : "MISMATCH",
                static_cast<unsigned long long>(cli.seeds), static_cast<unsigned long long>(mismatches));
  }
  if (single) {
    std::printf("events=%llu trace_hash=0x%016llx\n", static_cast<unsigned long long>(events_total),
                static_cast<unsigned long long>(last_hash));
  } else {
    std::printf("sweep seeds=%llu passed=%llu failed=%llu events=%llu\n", static_cast<unsigned long long>(cli.seeds),
                static_cast<unsigned long long>(cli.seeds - failed), static_cast<unsigned long long>(failed),
                static_cast<unsigned long long>(events_total));
    if (!first_signature.empty()) std::printf("first_signature=%s\n", first_signature.c_str());
  }
  std::printf("result=%s\n", failed > 0 ? "FAIL" : (mismatches > 0 ? "MISMATCH" : "PASS"));
  if (failed > 0) return 1;
  if (mismatches > 0) return 2;
  if (cli.require_probes && !missing.empty()) return 3;
  return 0;
}

// exsim_ha: drives the `ha` world (sim/ha/ha_world.h).
//
//   exsim_ha --seed=<u64|0xhex> [--seeds=N] [--mode=swarm|lite|no-faults]
//            [--disable=net,disk,crash,clock,buggify,partition,pause]
//            [--safety-ms=N] [--bound-ms=N] [--no-crash] [--no-host-crash] [--no-ab-cut] [--ab-delay-ms=N]
//            [--clients=N] [--orders=N] [--check-determinism] [--tla-trace=DIR]
//            [--event-trace=FILE] [--probes] [--verbose] [--quiet]
//
// One line per seed: `seed=0x… result=pass|FAIL events=N trace_hash=0x… …`; a failure
// adds `signature=ORACLE:EVENT:0xHASH` and the oracle's message. --tla-trace writes
// DIR/ha-<seed>.ndjson for verify/tla/trace. --probes prints the ensemble's coverage
// probes (hits and must-hit status; 09 §8) after the summary. Exit codes: 0 pass, 1 oracle failure,
// 2 determinism mismatch, 64 usage.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "sim/fault/swarm.h"
#include "sim/ha/ha_world.h"

namespace {

using namespace lle;
using namespace lle::sim;

std::optional<std::uint64_t> parse_u64(std::string_view s) {
  if (s.empty()) return std::nullopt;
  int base = 10;
  if (s.starts_with("0x") || s.starts_with("0X")) {
    base = 16;
    s.remove_prefix(2);
  }
  std::uint64_t v = 0;
  for (const char ch : s) {
    int d = -1;
    if (ch >= '0' && ch <= '9') d = ch - '0';
    else if (base == 16 && ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
    else if (base == 16 && ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
    if (d < 0 || d >= base) return std::nullopt;
    v = v * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(d);
  }
  return v;
}

struct Cli {
  std::uint64_t seed = 1;
  std::uint64_t seeds = 1;
  Mode mode = Mode::Swarm;
  std::uint32_t disabled = 0;
  Nanos safety_ns = ha::default_plan().safety_ns;
  Nanos bound_ns = ha::default_plan().convergence_ns;
  bool check_determinism = false;
  bool quiet = false;
  bool verbose = false;
  bool no_crash = false;
  bool no_host = false;
  bool no_cut = false;
  std::uint64_t ab_delay_ms = 0;
  bool ungated = false;
  bool probes = false;
  std::uint32_t clients = 0;
  std::uint32_t orders = 0;
  std::string tla_dir;
  std::string event_trace;
};

void usage() {
  std::fputs(
      "usage: exsim_ha --seed=S [--seeds=N] [--mode=swarm|lite|no-faults] [--disable=LIST]\n"
      "                [--safety-ms=N] [--bound-ms=N] [--no-crash] [--no-host-crash] [--no-ab-cut] [--ab-delay-ms=N]\n"
      "                [--clients=N] [--orders=N] [--check-determinism] [--tla-trace=DIR]\n"
      "                [--event-trace=FILE] [--probes] [--verbose] [--quiet]\n",
      stderr);
}

ha::Report run_one(const Cli& cli, std::uint64_t seed, std::FILE* tla, std::FILE* ev) {
  ha::Options o;
  o.seed = seed;
  o.faults = draw_fault_config(seed, cli.mode, cli.disabled);
  o.plan = ha::default_plan();
  o.plan.safety_ns = cli.safety_ns;
  o.plan.convergence_ns = cli.bound_ns;
  o.tla_trace = tla;
  o.event_trace = ev;
  o.verbose = cli.verbose;
  o.no_crash = cli.no_crash;
  o.host_crashes = !cli.no_host;
  o.ab_cuts = !cli.no_cut;
  o.ab_delay_min = static_cast<Nanos>(cli.ab_delay_ms) * 1'000'000;
  o.ungated_disk_errors = cli.ungated;
  o.clients = cli.clients;
  o.orders_per_client = cli.orders;
  return ha::run(o);
}

}  // namespace

int main(int argc, char** argv) {
  Cli cli;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    const std::size_t eq = a.find('=');
    const std::string_view key = a.substr(0, eq);
    const std::string_view val = eq == std::string_view::npos ? std::string_view{} : a.substr(eq + 1);
    std::optional<std::uint64_t> num;
    if (key == "--seed" && (num = parse_u64(val))) cli.seed = *num;
    else if (key == "--seeds" && (num = parse_u64(val)) && *num > 0) cli.seeds = *num;
    else if (key == "--mode" && parse_mode(val)) cli.mode = *parse_mode(val);
    else if (key == "--disable" && parse_disable_list(val)) cli.disabled = expand_disable_mask(*parse_disable_list(val));
    else if (key == "--safety-ms" && (num = parse_u64(val))) cli.safety_ns = static_cast<Nanos>(*num) * 1'000'000;
    else if (key == "--bound-ms" && (num = parse_u64(val))) cli.bound_ns = static_cast<Nanos>(*num) * 1'000'000;
    else if (key == "--clients" && (num = parse_u64(val))) cli.clients = static_cast<std::uint32_t>(*num);
    else if (key == "--orders" && (num = parse_u64(val))) cli.orders = static_cast<std::uint32_t>(*num);
    else if (key == "--check-determinism") cli.check_determinism = true;
    else if (key == "--no-crash") cli.no_crash = true;
    else if (key == "--no-host-crash") cli.no_host = true;
    else if (key == "--no-ab-cut") cli.no_cut = true;
    else if (key == "--ab-delay-ms" && (num = parse_u64(val))) cli.ab_delay_ms = *num;
    else if (key == "--ungated-disk-errors") cli.ungated = true;
    else if (key == "--tla-trace") cli.tla_dir = std::string(val);
    else if (key == "--event-trace") cli.event_trace = std::string(val);
    else if (key == "--verbose") cli.verbose = true;
    else if (key == "--quiet") cli.quiet = true;
    else if (key == "--probes") cli.probes = true;
    else {
      usage();
      return 64;
    }
  }
  std::uint64_t failed = 0;
  std::uint64_t mismatched = 0;
  std::uint64_t takeovers = 0, solos = 0, resumes = 0, joins = 0, crashes = 0, truncations = 0, records = 0;
  ProbeRegistry ensemble;
  for (std::uint64_t k = 0; k < cli.seeds; ++k) {
    const std::uint64_t seed = cli.seed + k;
    std::FILE* tla = nullptr;
    if (!cli.tla_dir.empty()) {
      char name[64];
      std::snprintf(name, sizeof name, "/ha-%016llx.ndjson", static_cast<unsigned long long>(seed));
      tla = std::fopen((cli.tla_dir + name).c_str(), "w");
    }
    std::FILE* ev = cli.event_trace.empty() ? nullptr : std::fopen(cli.event_trace.c_str(), "w");
    const ha::Report r = run_one(cli, seed, tla, ev);
    if (tla != nullptr) std::fclose(tla);
    if (ev != nullptr) std::fclose(ev);
    bool mismatch = false;
    if (cli.check_determinism) {
      const ha::Report r2 = run_one(cli, seed, nullptr, nullptr);
      mismatch = r2.run.trace_hash != r.run.trace_hash || r2.run.events != r.run.events;
    }
    failed += r.run.failed ? 1 : 0;
    mismatched += mismatch ? 1 : 0;
    takeovers += r.takeovers;
    solos += r.solos;
    resumes += r.resumes;
    joins += r.joins;
    crashes += r.crashes;
    truncations += r.truncations;
    records += r.records;
    ensemble.merge(r.probes);
    if (!cli.quiet || r.run.failed || mismatch) {
      std::printf("seed=0x%016llx result=%s events=%llu trace_hash=0x%016llx virtual_ms=%lld converged=%d %s%s",
                  static_cast<unsigned long long>(seed), r.run.failed ? "FAIL" : (mismatch ? "MISMATCH" : "pass"),
                  static_cast<unsigned long long>(r.run.events), static_cast<unsigned long long>(r.run.trace_hash),
                  static_cast<long long>(r.run.virtual_ns / 1'000'000), r.run.converged ? 1 : 0, r.summary.c_str(),
                  r.run.truncated ? " truncated=1" : "");
      if (r.run.failed) {
        std::printf(" signature=%s message=\"%s\"", r.run.failure.str().c_str(), r.run.failure.message.c_str());
      }
      std::printf("\n");
      std::fflush(stdout);
    }
  }
  std::printf("seeds=%llu failed=%llu determinism_mismatches=%llu takeovers=%llu solos=%llu resumes=%llu joins=%llu "
              "crashes=%llu truncations=%llu records=%llu\n",
              static_cast<unsigned long long>(cli.seeds), static_cast<unsigned long long>(failed),
              static_cast<unsigned long long>(mismatched), static_cast<unsigned long long>(takeovers),
              static_cast<unsigned long long>(solos), static_cast<unsigned long long>(resumes),
              static_cast<unsigned long long>(joins), static_cast<unsigned long long>(crashes),
              static_cast<unsigned long long>(truncations), static_cast<unsigned long long>(records));
  if (cli.probes) {
    ensemble.for_each([](const ProbeInfo& p) {
      const std::string_view n = p.name;
      const bool ours = n.starts_with("repl.") || n.starts_with("ha.") || n.starts_with("client.") ||
                        n.starts_with("witness.") || n.starts_with("journal.") || n.starts_with("disk.");
      if (!ours) return;
      const std::string_view st = probe_status_name(ProbeRegistry::status(p));
      std::printf("probe %s hits=%llu status=%.*s%s\n", p.name.c_str(), static_cast<unsigned long long>(p.hits),
                  static_cast<int>(st.size()), st.data(), p.rare ? " rare" : "");
    });
  }
  if (failed != 0) return 1;
  if (mismatched != 0) return 2;
  return 0;
}

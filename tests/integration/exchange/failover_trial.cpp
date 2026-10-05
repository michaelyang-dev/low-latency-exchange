// exchange_failover_trial: one failover trial (ha_trial.h) as a process, for the trial
// harness (bench/failover/run_trials.py, plan 10 §7, R-10).
//
//   exchange_failover_trial --class F1|F1-partial|F1-divergent|F6|F7|F7-resume --out DIR [--seed N]
//       [--t-d-ms N] [--t-ack-ms N] [--tie-break-ms N] [--heartbeat-ms N]
//       [--phase1 N] [--phase2 N] [--phase3 N] [--no-rejoin] [--repl-thread] [--timeout-ms N]
//
// Writes DIR/trial.json (also printed) and leaves the artifacts the oracle checker reads
// (journals, capture.pcap, feed.bin, clients/). Exit status: 0 every oracle held,
// 1 a violation, 2 usage.
#include <cstdio>
#include <cstdlib>
#include <string>

#include "ha_trial.h"

int main(int argc, char** argv) {
  using namespace lle::exch::test;
  std::string cls;
  ha::TrialOptions o;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> std::string {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "exchange_failover_trial: %s needs a value\n", a.c_str());
        std::exit(2);
      }
      return argv[++i];
    };
    auto num = [&]() { return static_cast<int>(std::stol(next())); };
    if (a == "--class") cls = next();
    else if (a == "--out") o.dir = next();
    else if (a == "--seed") o.seed = static_cast<std::uint32_t>(num());
    else if (a == "--t-d-ms") o.t_d_ms = num();
    else if (a == "--t-ack-ms") o.t_ack_ms = num();
    else if (a == "--rto-ms") o.rto_ms = num();
    else if (a == "--tie-break-ms") o.tie_break_ms = num();
    else if (a == "--heartbeat-ms") o.heartbeat_ms = num();
    else if (a == "--phase1") o.phase1 = static_cast<std::uint32_t>(num());
    else if (a == "--phase2") o.phase2 = static_cast<std::uint32_t>(num());
    else if (a == "--phase3") o.phase3 = static_cast<std::uint32_t>(num());
    else if (a == "--no-rejoin") o.rejoin = false;
    else if (a == "--repl-thread") o.repl_thread = true;
    else if (a == "--timeout-ms") o.step_timeout = std::chrono::milliseconds(num());
    else {
      std::fprintf(stderr, "exchange_failover_trial: unknown argument %s\n", a.c_str());
      return 2;
    }
  }
  if (cls.empty() || o.dir.empty() || o.phase2 == 0 || o.t_ack_ms >= o.t_d_ms) {
    std::fprintf(stderr,
                 "usage: exchange_failover_trial --class F1|F1-partial|F1-divergent|F6|F7|F7-resume --out DIR [--seed N] [--t-d-ms N] "
                 "[--t-ack-ms N] [--rto-ms N] [--tie-break-ms N] [--heartbeat-ms N] [--phase1 N] [--phase2 N] [--phase3 N] "
                 "[--no-rejoin] [--repl-thread] [--timeout-ms N]\n");
    return 2;
  }
  std::filesystem::remove_all(o.dir);
  const ha::TrialResult r = ha::run_trial(cls, o);
  std::printf("%s", r.json().c_str());
  return r.pass ? 0 : 1;
}

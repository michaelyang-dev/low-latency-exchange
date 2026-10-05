#pragma once
// The `ha` world (09 §2, S-10; 10): two data nodes running the replication core
// (src/repl) over the simulated A–B data link and client network, each with the real
// journal writer, recovery, L2 ring and rejoin truncation on crash-faithful media; the
// production witness core (src/witness) on node W with its state on the simulated
// disk; scripted clients with mirror sessions on both data nodes.
//
// Faults: the swarm's pauses, partitions and clock steps; process and host crashes
// gated by the failure model (one failure at a time, never inside the residual
// window, 01 §9); A–B link cuts and "data NICs down" (a node silent to W and clients
// but not to its peer); disk latency, stalls and EIO on the journal.
//
// Oracles: O-PREFIX, O-NO-LOST-FILL, O-EXACTLY-ONCE, O-OUTPUT-COMMIT, O-ONE-PRIMARY,
// O-LIVE (plus O-REPLAY and the internal checks listed in docs/design/replication.md).
// The world can also export a protocol trace (NDJSON) for TLA+ trace validation.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "sim/fault/injector.h"
#include "sim/fault/probes.h"
#include "sim/fault/swarm.h"
#include "sim/oracles/registry.h"
#include "sim/stats.h"
#include "sim/world.h"

namespace lle::sim::ha {

struct Options {
  std::uint64_t seed = 1;
  FaultConfig faults = base_fault_config();
  PhasePlan plan;
  std::FILE* event_trace = nullptr;   // the world's per-event trace (bisecting)
  std::FILE* tla_trace = nullptr;     // NDJSON protocol trace for verify/tla/trace
  bool verbose = false;
  // Scenario knobs (0: drawn from the seed).
  std::uint32_t clients = 0;
  std::uint32_t orders_per_client = 0;
  bool no_crash = false;             // no process/host crashes of data nodes
  bool host_crashes = true;
  bool ab_cuts = true;
  // Opt-in variant (0: off, the swarm draws the A–B latency as usual): every datagram on
  // the A–B data link takes at least this long one way, so the round trip can exceed the
  // 5 ms rejoin retransmission interval on every exchange (the long-RTT case found by
  // integration tests of real processes under ASan). The detector and retransmission
  // timeouts are raised above that round trip.
  Nanos ab_delay_min = 0;
  // Diagnostics only: let journal EIO abort a node even outside the failure model
  // (both data nodes failing before either recovered needs a manual witness repair).
  bool ungated_disk_errors = false;
};

struct Report {
  RunResult run;
  FaultStats stats;
  ProbeRegistry probes;
  std::vector<OracleInfo> oracles;
  std::uint64_t faults_fired = 0;
  std::string summary;
  // Protocol counters.
  std::uint64_t takeovers = 0;
  std::uint64_t solos = 0;
  std::uint64_t resumes = 0;
  std::uint64_t joins = 0;
  std::uint64_t deposed = 0;
  std::uint64_t truncations = 0;
  std::uint64_t crashes = 0;
  std::uint64_t host_crashes = 0;
  std::uint64_t crashes_gated = 0;
  std::uint64_t records = 0;
  std::uint64_t fills = 0;
  std::uint64_t orders_acked = 0;
  std::uint64_t tla_events = 0;
};

[[nodiscard]] PhasePlan default_plan();
Report run(const Options& o);

}  // namespace lle::sim::ha

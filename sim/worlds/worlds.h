#pragma once
// Built-in demonstration worlds for exsim (09 §2 worlds; real worlds `single`,
// `arbiter`, `ha` and `utcp` arrive with their components).
//
// Each world runs toy components written against the env concepts through the
// full machinery (scheduler, network, disk, crashes, pauses, partitions, clock
// faults, buggify, probes, oracles) so the simulator itself has determinism
// and fault coverage before the exchange exists:
//   pingpong  datagram request/response with retransmission and multicast
//             heartbeats; oracle O-EXACTLY-ONCE (in-order, once per request).
//   wal       write-ahead log with fsync, crash and recovery; oracle
//             O-WAL-DURABLE (no acknowledged write lost).
//   stream    TCP-like echo with partitions, resets and reconnects; oracle
//             O-PREFIX (echo is a prefix of what was sent, per connection).
// Every world also checks O-LIVE (convergence within B after healing).
//
// --canary plants one known bug per world (TigerBeetle's infrastructure
// canary). Canary failures are never counted as bugs (09 §10).
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sim/fault/injector.h"
#include "sim/fault/probes.h"
#include "sim/fault/swarm.h"
#include "sim/oracles/registry.h"
#include "sim/stats.h"
#include "sim/world.h"

namespace lle::sim::worlds {

// Demo worlds (toy components) and real worlds (production components).
enum class WorldKind : std::uint8_t {
  PingPong, Wal, Stream, Witness, Journal, Arbiter, Soupbin, Utcp, Ha, Outlog, Snapshot, Single, KillSwitchCross,
  Exchange, ExchangeHa, ExchangeHaSplit
};
inline constexpr WorldKind kAllWorlds[] = {WorldKind::PingPong, WorldKind::Wal,     WorldKind::Stream,
                                           WorldKind::Witness,  WorldKind::Journal, WorldKind::Arbiter,
                                           WorldKind::Soupbin,  WorldKind::Utcp,    WorldKind::Ha,
                                           WorldKind::Outlog,   WorldKind::Snapshot,
                                           WorldKind::Single,   WorldKind::KillSwitchCross,
                                           WorldKind::Exchange, WorldKind::ExchangeHa,
                                           WorldKind::ExchangeHaSplit};

[[nodiscard]] std::string_view world_name(WorldKind w) noexcept;
// Whether this build contains the world's components (sim/CMakeLists.txt builds a
// real world only when they are part of LLE_ONLY), and the worlds it contains.
[[nodiscard]] bool world_built(WorldKind w) noexcept;
[[nodiscard]] std::span<const WorldKind> built_worlds() noexcept;
[[nodiscard]] std::optional<WorldKind> parse_world(std::string_view s) noexcept;

struct Options {
  std::uint64_t seed = 1;
  FaultConfig faults = base_fault_config();
  bool canary = false;
  PhasePlan plan;
  std::FILE* trace = nullptr;
  const FaultSchedule* replay = nullptr;  // install this schedule instead of generating one
  FaultSchedule* record = nullptr;        // receives the installed schedule
  bool verbose = false;                   // worlds log protocol decisions to stderr
};

struct Report {
  WorldKind world = WorldKind::PingPong;
  RunResult run;
  FaultStats stats;
  ProbeRegistry probes;
  std::vector<OracleInfo> oracles;
  std::uint64_t buggify_sites_active = 0;
  std::uint64_t faults_fired = 0;
  std::string summary;  // world-specific progress, for the report line
};

Report run_world(WorldKind w, const Options& o);

// Default phase plan for the demo worlds: 500 ms of faults, then bound B.
[[nodiscard]] PhasePlan default_plan();

namespace detail {
// Declares a must-hit probe of demo code. SIM_PROBE is compiled out unless
// LLE_SIM, so outside sim builds the declaration is skipped as well (a probe
// that cannot fire must not be reported as missing).
void declare_demo_probe(World& w, std::string_view name, bool rare = false);
Report run_pingpong(const Options& o);
Report run_wal(const Options& o);
Report run_stream(const Options& o);
Report run_witness(const Options& o);
Report run_journal(const Options& o);
Report run_arbiter(const Options& o);
Report run_soupbin(const Options& o);
Report run_utcp(const Options& o);
Report run_ha(const Options& o);
Report run_outlog(const Options& o);
Report run_snapshot(const Options& o);
Report run_single(const Options& o);
Report run_kill_switch_cross(const Options& o);
Report run_exchange(const Options& o);
Report run_exchange_ha(const Options& o);
Report run_exchange_ha_split(const Options& o);  // exchange_ha with [ha] repl_thread
// Shared tail: install faults, run phases, collect the report. `shape` lets a
// world restrict the generated fault schedule to its scenario (never applied
// to a --replay schedule, which is installed exactly).
Report finish(World& w, WorldKind kind, const Options& o, const std::function<bool()>& converged,
              const std::function<std::string()>& summary,
              const std::function<void(FaultSchedule&)>& shape = {});
}  // namespace detail

}  // namespace lle::sim::worlds

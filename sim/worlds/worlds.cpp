#include "sim/worlds/worlds.h"

#include <vector>

#include "common/assert.h"

#include "sim/node.h"

namespace lle::sim::worlds {

std::string_view world_name(WorldKind w) noexcept {
  switch (w) {
    case WorldKind::PingPong:
      return "pingpong";
    case WorldKind::Wal:
      return "wal";
    case WorldKind::Stream:
      return "stream";
    case WorldKind::Witness:
      return "witness";
    case WorldKind::Journal:
      return "journal";
    case WorldKind::Arbiter:
      return "arbiter";
    case WorldKind::Soupbin:
      return "soupbin";
    case WorldKind::Utcp:
      return "utcp";
    case WorldKind::Ha:
      return "ha";
    case WorldKind::Outlog:
      return "outlog";
    case WorldKind::Snapshot:
      return "snapshot";
    case WorldKind::Single:
      return "single";
    case WorldKind::KillSwitchCross:
      return "kill_switch_during_cross";
    case WorldKind::Exchange:
      return "exchange";
    case WorldKind::ExchangeHa:
      return "exchange_ha";
  }
  return "?";
}

#if !defined(LLE_WORLD_WITNESS)
#define LLE_WORLD_WITNESS 0
#endif
#if !defined(LLE_WORLD_JOURNAL)
#define LLE_WORLD_JOURNAL 0
#endif
#if !defined(LLE_WORLD_ARBITER)
#define LLE_WORLD_ARBITER 0
#endif
#if !defined(LLE_WORLD_SOUPBIN)
#define LLE_WORLD_SOUPBIN 0
#endif
#if !defined(LLE_WORLD_UTCP)
#define LLE_WORLD_UTCP 0
#endif
#if !defined(LLE_WORLD_HA)
#define LLE_WORLD_HA 0
#endif
#if !defined(LLE_WORLD_OUTLOG)
#define LLE_WORLD_OUTLOG 0
#endif
#if !defined(LLE_WORLD_SNAPSHOT)
#define LLE_WORLD_SNAPSHOT 0
#endif
#if !defined(LLE_WORLD_SINGLE)
#define LLE_WORLD_SINGLE 0
#endif
#if !defined(LLE_WORLD_EXCHANGE)
#define LLE_WORLD_EXCHANGE 0
#endif
#if !defined(LLE_WORLD_EXCHANGE_HA)
#define LLE_WORLD_EXCHANGE_HA 0
#endif

bool world_built(WorldKind w) noexcept {
  switch (w) {
    case WorldKind::PingPong:
    case WorldKind::Wal:
    case WorldKind::Stream:
      return true;
    case WorldKind::Witness:
      return LLE_WORLD_WITNESS != 0;
    case WorldKind::Journal:
      return LLE_WORLD_JOURNAL != 0;
    case WorldKind::Arbiter:
      return LLE_WORLD_ARBITER != 0;
    case WorldKind::Soupbin:
      return LLE_WORLD_SOUPBIN != 0;
    case WorldKind::Utcp:
      return LLE_WORLD_UTCP != 0;
    case WorldKind::Ha:
      return LLE_WORLD_HA != 0;
    case WorldKind::Outlog:
      return LLE_WORLD_OUTLOG != 0;
    case WorldKind::Snapshot:
      return LLE_WORLD_SNAPSHOT != 0;
    case WorldKind::Single:
    case WorldKind::KillSwitchCross:
      return LLE_WORLD_SINGLE != 0;
    case WorldKind::Exchange:
      return LLE_WORLD_EXCHANGE != 0;
    case WorldKind::ExchangeHa:
      return LLE_WORLD_EXCHANGE_HA != 0;
  }
  return false;
}

std::span<const WorldKind> built_worlds() noexcept {
  static const std::vector<WorldKind> built = [] {
    std::vector<WorldKind> v;
    for (const WorldKind w : kAllWorlds) {
      if (world_built(w)) v.push_back(w);
    }
    return v;
  }();
  return built;
}

std::optional<WorldKind> parse_world(std::string_view s) noexcept {
  for (const WorldKind w : kAllWorlds) {
    if (world_name(w) == s) return w;
  }
  return std::nullopt;
}

PhasePlan default_plan() {
  PhasePlan p;
  p.safety_ns = 500'000'000;
  p.convergence_ns = 30'000'000'000;
  return p;
}

Report run_world(WorldKind w, const Options& o) {
  switch (w) {
    case WorldKind::PingPong:
      return detail::run_pingpong(o);
    case WorldKind::Wal:
      return detail::run_wal(o);
    case WorldKind::Stream:
      return detail::run_stream(o);
#if LLE_WORLD_WITNESS
    case WorldKind::Witness:
      return detail::run_witness(o);
#endif
#if LLE_WORLD_JOURNAL
    case WorldKind::Journal:
      return detail::run_journal(o);
#endif
#if LLE_WORLD_ARBITER
    case WorldKind::Arbiter:
      return detail::run_arbiter(o);
#endif
#if LLE_WORLD_SOUPBIN
    case WorldKind::Soupbin:
      return detail::run_soupbin(o);
#endif
#if LLE_WORLD_UTCP
    case WorldKind::Utcp:
      return detail::run_utcp(o);
#endif
#if LLE_WORLD_HA
    case WorldKind::Ha:
      return detail::run_ha(o);
#endif
#if LLE_WORLD_OUTLOG
    case WorldKind::Outlog:
      return detail::run_outlog(o);
#endif
#if LLE_WORLD_SNAPSHOT
    case WorldKind::Snapshot:
      return detail::run_snapshot(o);
#endif
#if LLE_WORLD_SINGLE
    case WorldKind::Single:
      return detail::run_single(o);
    case WorldKind::KillSwitchCross:
      return detail::run_kill_switch_cross(o);
#endif
#if LLE_WORLD_EXCHANGE
    case WorldKind::Exchange:
      return detail::run_exchange(o);
#endif
#if LLE_WORLD_EXCHANGE_HA
    case WorldKind::ExchangeHa:
      return detail::run_exchange_ha(o);
#endif
    default:
      break;
  }
  LLE_ASSERT(false, "run_world: world not built (check world_built first)");
  return {};
}

namespace detail {

void declare_demo_probe([[maybe_unused]] World& w, [[maybe_unused]] std::string_view name, [[maybe_unused]] bool rare) {
#if defined(LLE_SIM) && LLE_SIM
  w.probes().declare(name, rare);
#endif
}

Report finish(World& w, WorldKind kind, const Options& o, const std::function<bool()>& converged,
              const std::function<std::string()>& summary, const std::function<void(FaultSchedule&)>& shape) {
  FaultSchedule sched;
  if (o.replay != nullptr) {
    sched = *o.replay;
  } else {
    sched = w.injector().generate(w.now(), w.now() + o.plan.safety_ns);
    if (shape) shape(sched);
  }
  if (o.record != nullptr) *o.record = sched;
  w.injector().install(sched);
  Report r;
  r.world = kind;
  r.run = w.run(o.plan, converged);
  r.stats = w.stats();
  r.probes = w.probes();
  r.oracles = w.oracles().list();
  w.buggify().for_each([&](const BuggifySite& s) { r.buggify_sites_active += s.active ? 1u : 0u; });
  r.faults_fired = w.injector().fired();
  r.summary = summary();
  return r;
}

}  // namespace detail

}  // namespace lle::sim::worlds

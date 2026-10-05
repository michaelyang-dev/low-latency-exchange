// `exsim --world=ha`: runs the replication world of sim/ha (ha_world.h) through
// the common world interface. sim/ha also has its own driver, exsim_ha, with the
// scenario knobs and the TLA+ trace export; this adapter uses the world's defaults.
// The ha world generates its own fault schedule, so --replay and
// --record-faults do not apply to it.
#include "sim/ha/ha_world.h"
#include "sim/worlds/worlds.h"

namespace lle::sim::worlds::detail {

Report run_ha(const Options& o) {
  ha::Options h;
  h.seed = o.seed;
  h.faults = o.faults;
  const PhasePlan dflt = default_plan();
  // The ha world's own phase plan, unless the command line changed the default.
  h.plan = o.plan.safety_ns == dflt.safety_ns && o.plan.convergence_ns == dflt.convergence_ns ? ha::default_plan()
                                                                                              : o.plan;
  h.event_trace = o.trace;
  h.verbose = o.verbose;
  const ha::Report r = ha::run(h);
  Report out;
  out.world = WorldKind::Ha;
  out.run = r.run;
  out.stats = r.stats;
  out.probes = r.probes;
  out.oracles = r.oracles;
  out.faults_fired = r.faults_fired;
  out.summary = r.summary;
  return out;
}

}  // namespace lle::sim::worlds::detail

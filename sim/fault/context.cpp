// Back ends of the SIM_BUGGIFY / SIM_PROBE macros (sim/fault/buggify.h).
// Each call site caches a pointer into the current world's registry, keyed by
// the world's epoch, so the steady-state cost is one compare and one counter.
#include "sim/fault/buggify.h"
#include "sim/world.h"

namespace lle::sim::detail {

bool buggify_eval(BuggifySiteDecl& site) noexcept {
  World* w = World::current();
  if (w == nullptr) return false;
  if (site.epoch != w->epoch() || site.state == nullptr) {
    site.state = w->buggify().site(site.name, site.file, site.line);
    site.epoch = w->epoch();
  }
  // Code-level faults are probabilistic faults: off from the heal phase on
  // (09 §5), like packet loss and EIO, so convergence is judged without them.
  if (!w->faults_active()) return false;
  return w->buggify().eval(*static_cast<BuggifySite*>(site.state));
}

void probe_hit(ProbeSiteDecl& site) noexcept {
  World* w = World::current();
  if (w == nullptr) return;
  if (site.epoch != w->epoch() || site.state == nullptr) {
    site.state = w->probes().site(site.name, site.rare);
    site.epoch = w->epoch();
  }
  ++static_cast<ProbeInfo*>(site.state)->hits;
}

}  // namespace lle::sim::detail

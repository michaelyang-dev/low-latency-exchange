#pragma once
// Helpers shared by the simulator unit tests.
#include <cstdint>
#include <functional>

#include "common/types.h"
#include "sim/fault/swarm.h"
#include "sim/world.h"

namespace lle::sim::test {

// Steps the world until pred() holds, the heap empties, or virtual time
// passes `limit_ns` from now. Returns pred().
inline bool run_until(World& w, const std::function<bool()>& pred, Nanos limit_ns) {
  const Nanos end = w.now() + limit_ns;
  while (!pred()) {
    if (w.pending_events() == 0 || w.next_event_time() > end) return pred();
    w.step();
  }
  return true;
}

// Steps every event up to (and including) now + d; virtual time ends at now + d.
inline void run_for(World& w, Nanos d) { w.run_until_time(w.now() + d); }

}  // namespace lle::sim::test

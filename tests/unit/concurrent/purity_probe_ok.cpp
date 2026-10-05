// Positive case for tools/ci/check_sim_purity.sh (concurrent_purity_positive must
// PASS the audit): the queues themselves are allowed in sim-built cores.
#include <cstdint>

#include "concurrent/broadcast_ring.h"
#include "concurrent/mpsc_scq.h"
#include "concurrent/spsc_byte_ring.h"
#include "concurrent/spsc_ring.h"

namespace lle::conc::probe {

bool use_queues(SpscRing<std::uint64_t, 64>& a, MpscScqRing<std::uint64_t, 64>& b, SpscByteRing& c,
                BroadcastRing<2>& d) {
  std::uint64_t v = 0;
  bool ok = a.try_push(1) && a.try_pop(v) && b.try_push(v) && b.try_pop(v);
  if (std::byte* p = c.try_reserve(8)) {
    p[0] = std::byte{1};
    c.commit();
  }
  std::uint32_t len = 0;
  ok = ok && d.peek(0, len) == nullptr;
  return ok;
}

}  // namespace lle::conc::probe

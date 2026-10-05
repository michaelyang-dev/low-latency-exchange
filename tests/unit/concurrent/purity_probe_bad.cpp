// Negative case for tools/ci/check_sim_purity.sh (wired as the
// concurrent_purity_negative test, which must FAIL the audit): code that waits the
// way a sim-built core must never do. spin_until with Backoff references
// lle::conc::detail::yield_thread and emits the cpu_relax spin hint.
#include <atomic>

#include "concurrent/wait.h"

namespace lle::conc::probe {

std::atomic<bool> g_flag{false};

void wait_for_flag() {
  spin_until([] { return g_flag.load(std::memory_order_acquire); }, Backoff{});
}

}  // namespace lle::conc::probe

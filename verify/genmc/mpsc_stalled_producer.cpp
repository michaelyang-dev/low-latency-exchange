// GenMC harness: the stalled producer (08-concurrency-runtime §5, §7) — the published
// evidence for "lock-free".
//
// P1 pushes kStall and stops forever right after claiming its slot (the
// LLE_TEST_STOP_AFTER_CLAIM hook abandons the push: a producer that is never scheduled
// again). P2 pushes kB and then sets a release flag. The consumer acquires the flag and
// calls try_pop once, which must return kB.
//   - MpscScqRing (default): passes. A dequeuer that reaches P1's claimed-but-unfilled
//     slot invalidates it and moves on to P2's entry.
//   - VyukovMpscRing (-DLLE_STALLED_VYUKOV): FAILS the assertion. When P1 claimed the
//     cell before P2, the consumer's cell is never published and try_pop reports empty
//     although P2's push has completed (not lock-free, not linearizable).
//   - With -DLLE_SPIN_CONSUMER the consumer spins on try_pop instead (Vyukov only: its
//     failing try_pop has no side effects, so GenMC's spin-assume transformation applies)
//     and `-check-liveness` reports the non-terminating spin loop. This variant also
//     orders P2 after P1's claim (LLE_ORDERED): otherwise GenMC's spin-assume also
//     treats Vyukov's push retry loop (which carries `pos` across iterations) as a pure
//     spin and reports a spurious liveness violation in a producer instead.
//
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/mpsc_stalled_producer.cpp
//   genmc -rc11 -- -std=c++20 -I src -DLLE_STALLED_VYUKOV verify/genmc/mpsc_stalled_producer.cpp   (expected: assertion violation)
//   genmc -rc11 -check-liveness -- -std=c++20 -I src -DLLE_STALLED_VYUKOV -DLLE_SPIN_CONSUMER verify/genmc/mpsc_stalled_producer.cpp
#include <atomic>

namespace {
constexpr int kStall = 7;
constexpr int kB = 42;
}  // namespace

#if defined(LLE_SPIN_CONSUMER) && !defined(LLE_ORDERED)
#define LLE_ORDERED 1
#endif

namespace {
std::atomic<int> claimed{0};  // set by P1 at its claim point

// Test hook (see mpsc_scq.h): abandon the push of kStall right after the claim.
bool stop_after_claim(int v) {
  if (v != kStall) return false;
  claimed.store(1, std::memory_order_release);
  return true;
}
}  // namespace
#define LLE_TEST_STOP_AFTER_CLAIM(v) stop_after_claim(v)

#include "harness.h"
#ifdef LLE_STALLED_VYUKOV
#include "concurrent/mpsc_vyukov.h"
using Queue = lle::conc::VyukovMpscRing<int, 2>;
#else
#include "concurrent/mpsc_scq.h"
using Queue = lle::conc::MpscScqRing<int, 2, lle_genmc::kScqSingleConsumer>;
#endif

namespace {

Queue* q;  // created by main before the threads start
std::atomic<int> flag{0};

void* stalled_producer(void*) {
  q->try_push(kStall);  // returns right after its claim: never publishes
  return nullptr;
}

void* healthy_producer(void*) {
#ifdef LLE_ORDERED
  __VERIFIER_assume(claimed.load(std::memory_order_acquire) == 1);
#endif
  const bool ok = q->try_push(kB);
  assert(ok);
  flag.store(1, std::memory_order_release);
  return nullptr;
}

void* consumer(void*) {
  int v = 0;
#ifdef LLE_SPIN_CONSUMER
  // Hoist the (plain) queue pointer out of the loop: GenMC's liveness check only treats
  // reads of coherence-tracked (atomic) locations as "latest value" reads.
  Queue* const queue = q;
  while (!queue->try_pop(v)) {
  }
  assert(v == kB);
#else
  __VERIFIER_assume(flag.load(std::memory_order_acquire) == 1);
  const bool ok = q->try_pop(v);
  assert(ok && v == kB);
#endif
  return nullptr;
}

}  // namespace

int main() {
  q = lle_genmc::make_shared_object<Queue>();
  pthread_t p1 = lle_genmc::spawn(stalled_producer);
  pthread_t p2 = lle_genmc::spawn(healthy_producer);
  pthread_t c = lle_genmc::spawn(consumer);
  lle_genmc::join(p1);
  lle_genmc::join(p2);
  lle_genmc::join(c);
  lle_genmc::destroy_shared_object(q);
  return 0;
}

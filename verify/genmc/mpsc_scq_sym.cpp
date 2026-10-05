// GenMC harness: MpscScqRing bounds with SYMMETRY REDUCTION (08-concurrency-runtime
// §7). Same configurations as mpsc_scq_2p1c.cpp / mpsc_scq_3p1c.cpp (PRODUCERS x
// PUSHES pushes, one consumer making POPS concurrent pops, n = CAP = 2), but every
// producer is the *same* thread: same function, same (null) argument, same pushed
// values 1..PUSHES, no access to its own thread id. Producers are spawned with
// __VERIFIER_spawn_symmetric so GenMC v0.19's symmetry reduction (SPORE) applies:
// executions that differ only by a permutation of producers are explored once.
//
// Soundness: the producers are identical programs, so permuting them maps executions
// to executions; every assertion below is invariant under that permutation (it counts
// values and compares prefix counts; it never asks which producer pushed what).
//
// What is checked (weaker than the per-producer-identity checks of mpsc_scq_2p1c.cpp,
// because values do not name their producer):
//   - multiset equality per value k: #received(k) == #producers whose push k succeeded;
//   - per-producer FIFO, in prefix form: in every prefix of the receive order,
//     #received(k+1) <= #received(k) + #producers whose push k failed but k+1 succeeded;
//   - the free-index ring is intact afterwards: CAP pushes succeed and pop back in
//     order, which catches an index handed out twice or leaked (the failure modes that
//     identical values could otherwise hide);
//   - no data race / uninitialized read on slots (GenMC built-in).
//
//   genmc -rc11 -- -std=c++20 -I src -DPRODUCERS=3 -DPUSHES=1 -DPOPS=3 verify/genmc/mpsc_scq_sym.cpp
//   genmc -rc11 -- -std=c++20 -I src -DPRODUCERS=2 -DPUSHES=2 -DPOPS=4 verify/genmc/mpsc_scq_sym.cpp
#include <cstdint>

#include "concurrent/mpsc_scq.h"
#include "harness.h"

#ifndef PRODUCERS
#define PRODUCERS 2
#endif
#ifndef PUSHES
#define PUSHES 2
#endif
#ifndef POPS
#define POPS (PRODUCERS * PUSHES)
#endif
#ifndef CAP
#define CAP 2
#endif

namespace {

constexpr int kProducers = PRODUCERS;
constexpr int kPushes = PUSHES;
constexpr int kTotal = kProducers * kPushes;
static_assert(kPushes <= 8, "success mask");

using Queue = lle::conc::MpscScqRing<int, CAP, lle_genmc::kScqSingleConsumer>;
Queue* q;  // heap object created by main (see harness.h)

int received[kTotal + POPS];  // written by the consumer, then by main after join
int nreceived = 0;

// Identical for every producer: pushes 1..kPushes, returns the success mask.
void* producer(void*) {
  std::uintptr_t ok = 0;
  for (int i = 0; i < kPushes; ++i) {
    if (q->try_push(i + 1)) ok |= std::uintptr_t{1} << i;
  }
  return reinterpret_cast<void*>(ok);
}

void* consumer(void*) {
  for (int k = 0; k < POPS; ++k) {
    int v = 0;
    if (q->try_pop(v)) received[nreceived++] = v;
  }
  return nullptr;
}

}  // namespace

int main() {
  q = lle_genmc::make_shared_object<Queue>();
#if LLE_GENMC
  __VERIFIER_thread_t prod[kProducers];
  prod[0] = __VERIFIER_spawn(producer, nullptr);
  for (int p = 1; p < kProducers; ++p) prod[p] = __VERIFIER_spawn_symmetric(producer, nullptr, prod[p - 1]);
  __VERIFIER_thread_t c = __VERIFIER_spawn(consumer, nullptr);
  std::uintptr_t mask[kProducers];
  for (int p = 0; p < kProducers; ++p) mask[p] = reinterpret_cast<std::uintptr_t>(__VERIFIER_join(prod[p]));
  __VERIFIER_join(c);
#else
  pthread_t prod[kProducers];
  for (int p = 0; p < kProducers; ++p) prod[p] = lle_genmc::spawn(producer);
  pthread_t c = lle_genmc::spawn(consumer);
  std::uintptr_t mask[kProducers];
  for (int p = 0; p < kProducers; ++p) {
    void* r = nullptr;
    pthread_join(prod[p], &r);
    mask[p] = reinterpret_cast<std::uintptr_t>(r);
  }
  lle_genmc::join(c);
#endif

  // Quiescent drain by main (the consumer has been joined: still a single consumer).
  for (int k = 0; k < kTotal; ++k) {
    int v = 0;
    if (!q->try_pop(v)) break;
    received[nreceived++] = v;
  }
  int v = 0;
  assert(!q->try_pop(v));

  int succeeded[kPushes + 1] = {};  // succeeded[k]: producers whose push k succeeded
  int skipped[kPushes + 1] = {};    // skipped[k]: producers whose push k failed, k+1 succeeded
  for (int p = 0; p < kProducers; ++p) {
    for (int i = 0; i < kPushes; ++i) {
      const bool ok = (mask[p] >> i) & 1;
      succeeded[i + 1] += ok ? 1 : 0;
      if (i + 1 < kPushes && !ok && ((mask[p] >> (i + 1)) & 1)) skipped[i + 1] += 1;
    }
  }
  int count[kPushes + 2] = {};
  for (int k = 0; k < nreceived; ++k) {
    const int x = received[k];
    assert(x >= 1 && x <= kPushes);
    ++count[x];
    for (int j = 1; j < kPushes; ++j) assert(count[j + 1] <= count[j] + skipped[j]);  // FIFO, prefix form
  }
  for (int j = 1; j <= kPushes; ++j) assert(count[j] == succeeded[j]);  // multiset equality
  // Post-condition: the free-index ring is intact. With the queue drained, exactly
  // CAP pushes succeed (no index leaked), and they pop back in order with their values
  // (no index handed out twice).
  for (int k = 0; k < CAP; ++k) {
    const bool pushed_ok = q->try_push(1000 + k);
    assert(pushed_ok);
  }
  const bool overfull = q->try_push(2000);
  assert(!overfull);
  for (int k = 0; k < CAP; ++k) {
    int w = 0;
    const bool popped_ok = q->try_pop(w);
    assert(popped_ok && w == 1000 + k);
  }
  lle_genmc::destroy_shared_object(q);
  return 0;
}

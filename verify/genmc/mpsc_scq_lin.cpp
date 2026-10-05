// GenMC harness: linearizability of MpscScqRing as a FIFO queue, checked with Relinche
// (Golovin, Kokologiannakis, Vafeiadis, POPL 2025; GenMC manual "Checking
// Linearizability") (08-concurrency-runtime §7).
//
// A Most-Parallel Client in the shape of GenMC's tests/correct/relinche/queue/mpc.c:
// main initializes the queue inside an "init_queue" method, then ENQ enqueuer threads
// (default 2) and ONE dequeuer thread (the single-consumer precondition) each perform a
// single annotated method call, with no other synchronization between them. Enqueued
// values are 100 + enqueuer index; a dequeue returns its value, or 0 when empty.
//
// The specification is collected from a sequential reference queue built from the same
// client (-DLLE_LIN_REFERENCE, each method under GenMC's partial lock), then the real
// SCQ is checked against it:
//   genmc -rc11 --disable-mm-detector --collect-lin-spec=spec.in -- -std=c++20 -I src -DLLE_LIN_REFERENCE verify/genmc/mpsc_scq_lin.cpp
//   genmc -rc11 --disable-mm-detector --check-lin-spec=spec.in   -- -std=c++20 -I src verify/genmc/mpsc_scq_lin.cpp
// tools/genmc/run_all.sh does both. With n = 2 and at most 2 enqueues the queue is never
// full, so every enqueue must succeed.
#include <cstdint>

#include "concurrent/mpsc_scq.h"
#include "harness.h"

#ifndef ENQ
#define ENQ 2
#endif

namespace {

#ifdef LLE_LIN_REFERENCE
struct RefQueue {
  unsigned items[8];
  int head;
  int tail;
};
RefQueue ref;
__VERIFIER_plock_t lock;

void init_queue() {
  __VERIFIER_plock_lock(&lock);
  ref.head = 0;
  ref.tail = 0;
  __VERIFIER_plock_unlock(&lock);
}
void enqueue(unsigned v) {
  __VERIFIER_plock_lock(&lock);
  ref.items[ref.tail++] = v;
  __VERIFIER_plock_unlock(&lock);
}
bool dequeue(unsigned* out) {
  __VERIFIER_plock_lock(&lock);
  if (ref.head == ref.tail) {
    __VERIFIER_plock_unlock(&lock);
    return false;
  }
  *out = ref.items[ref.head++];
  __VERIFIER_plock_unlock(&lock);
  return true;
}
#else
using Queue = lle::conc::MpscScqRing<unsigned, 2, lle_genmc::kScqSingleConsumer>;
Queue* q;

void init_queue() { q = lle_genmc::make_shared_object<Queue>(); }
void enqueue(unsigned v) {
  const bool ok = q->try_push(v);
  assert(ok);
}
bool dequeue(unsigned* out) { return q->try_pop(*out); }
#endif

void* enqueuer(void* arg) {
  const auto value = static_cast<int>(100 + reinterpret_cast<std::uintptr_t>(arg));
  __VERIFIER_method_begin("enqueue", value);
  enqueue(static_cast<unsigned>(value));
  __VERIFIER_method_end("enqueue", 0);
  return nullptr;
}

void* dequeuer(void*) {
  unsigned ret = 0;
  __VERIFIER_method_begin("dequeue", 0);
  const bool ok = dequeue(&ret);
  __VERIFIER_method_end("dequeue", ok ? static_cast<int>(ret) : 0);
  return nullptr;
}

}  // namespace

int main() {
  __VERIFIER_method_begin("init_queue", 0);
  init_queue();
  __VERIFIER_method_end("init_queue", 0);

  pthread_t enq[ENQ];
  for (int i = 0; i < ENQ; ++i) enq[i] = lle_genmc::spawn(enqueuer, reinterpret_cast<void*>(static_cast<std::uintptr_t>(i + 1)));
  pthread_t deq = lle_genmc::spawn(dequeuer);
  for (int i = 0; i < ENQ; ++i) lle_genmc::join(enq[i]);
  lle_genmc::join(deq);
  return 0;
}

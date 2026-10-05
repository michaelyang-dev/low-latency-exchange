// GenMC harness: MpscScqRing with TWO concurrent consumers. The production contract is
// one consumer, but apps/exchanged/repl_stage.h can pop the OUCH and session queues
// from the repl thread while the seq thread's sequencer is still popping, on a
// primary->backup demotion in split mode (docs/verification/queues-stress.md). Both
// index rings of the general MpscScqRing are the paper's full (multi-dequeuer) SCQ, so
// this should be safe; this harness checks it. (The single-consumer specialization,
// ADR-031, is NOT safe here and is not used.)
//
// PRODUCERS x PUSHES pushes; two consumer threads make POPS pops each; main drains.
// Asserts:
//   - multiset equality: every successful push received exactly once, nothing else;
//   - per-consumer order: within each consumer, each producer's items arrive in push
//     order (linearizability implies it);
//   - the free-index ring is intact afterwards.
//
//   genmc -rc11 -- -std=c++20 -I src -DPRODUCERS=1 -DPUSHES=2 -DPOPS=1 verify/genmc/mpsc_scq_2consumers.cpp
#include <cstdint>

#include "concurrent/mpsc_scq.h"
#include "harness.h"

#ifndef PRODUCERS
#define PRODUCERS 1
#endif
#ifndef PUSHES
#define PUSHES 2
#endif
#ifndef POPS
#define POPS 1
#endif
#ifndef CAP
#define CAP 2
#endif

namespace {

constexpr int kProducers = PRODUCERS;
constexpr int kPushes = PUSHES;
constexpr int kTotal = kProducers * kPushes;

using Queue = lle::conc::MpscScqRing<int, CAP>;
Queue* q;

bool pushed[kProducers][kPushes];
int got[2][POPS];  // got[c][k]: item, or -1 for an empty pop
int drained[kTotal];
int ndrained = 0;

int item(int p, int i) { return (p + 1) * 16 + i; }

void* producer(void* arg) {
  const int p = static_cast<int>(reinterpret_cast<long>(arg));
  for (int i = 0; i < kPushes; ++i) pushed[p][i] = q->try_push(item(p, i));
  return nullptr;
}

void* consumer(void* arg) {
  const int c = static_cast<int>(reinterpret_cast<long>(arg));
  for (int k = 0; k < POPS; ++k) {
    int v = 0;
    got[c][k] = q->try_pop(v) ? v : -1;
  }
  return nullptr;
}

}  // namespace

int main() {
  q = lle_genmc::make_shared_object<Queue>();
  pthread_t prod[kProducers];
  for (int p = 0; p < kProducers; ++p) prod[p] = lle_genmc::spawn(producer, reinterpret_cast<void*>(static_cast<long>(p)));
  pthread_t c0 = lle_genmc::spawn(consumer, reinterpret_cast<void*>(0L));
  pthread_t c1 = lle_genmc::spawn(consumer, reinterpret_cast<void*>(1L));
  for (int p = 0; p < kProducers; ++p) lle_genmc::join(prod[p]);
  lle_genmc::join(c0);
  lle_genmc::join(c1);
  for (int k = 0; k < kTotal; ++k) {
    int v = 0;
    if (!q->try_pop(v)) break;
    drained[ndrained++] = v;
  }
  for (int p = 0; p < kProducers; ++p) {
    for (int i = 0; i < kPushes; ++i) {
      int count = 0;
      for (int c = 0; c < 2; ++c) {
        for (int k = 0; k < POPS; ++k) count += got[c][k] == item(p, i) ? 1 : 0;
      }
      for (int k = 0; k < ndrained; ++k) count += drained[k] == item(p, i) ? 1 : 0;
      assert(count == (pushed[p][i] ? 1 : 0));  // multiset equality
    }
    for (int c = 0; c < 2; ++c) {  // per-consumer order
      int last = -1;
      for (int k = 0; k < POPS; ++k) {
        const int x = got[c][k];
        if (x / 16 == p + 1) {
          assert(x % 16 > last);
          last = x % 16;
        }
      }
    }
  }
  for (int k = 0; k < CAP; ++k) {
    const bool ok = q->try_push(1000 + k);
    assert(ok);
  }
  for (int k = 0; k < CAP; ++k) {
    int w = 0;
    const bool ok = q->try_pop(w);
    assert(ok && w == 1000 + k);
  }
  lle_genmc::destroy_shared_object(q);
  return 0;
}

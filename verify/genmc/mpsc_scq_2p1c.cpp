// GenMC harness: MpscScqRing, 2 producers x 2 pushes + 1 consumer, n = 2
// (08-concurrency-runtime §7, pre-registered bound). Each producer tries each of its
// pushes once (a push may legitimately fail when the queue is full); the consumer
// tries POPS pops concurrently; after joining, main drains the rest. Asserts:
//   - multiset equality: every successfully pushed item is received exactly once and
//     nothing else is received;
//   - per-producer FIFO: each producer's items are received in push order;
//   - the free-index ring is intact afterwards (CAP pushes succeed, pop back in order).
// Retrying is not modeled with __VERIFIER_assume here: a failed SCQ operation changes
// shared state (Head/Threshold/entries), so every attempt is explored as written.
//
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/mpsc_scq_2p1c.cpp
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

using Queue = lle::conc::MpscScqRing<int, CAP, lle_genmc::kScqSingleConsumer>;
Queue* q;  // heap object created by main (see harness.h)

bool pushed[kProducers][kPushes];  // written by producer p only, read by main after join
int received[kTotal + POPS];       // written by the consumer, then by main after join
int nreceived = 0;

int item(int p, int i) { return (p + 1) * 16 + i; }

void* producer(void* arg) {
  const int p = static_cast<int>(reinterpret_cast<long>(arg));
  for (int i = 0; i < kPushes; ++i) pushed[p][i] = q->try_push(item(p, i));
  return nullptr;
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
  pthread_t prod[kProducers];
  for (int p = 0; p < kProducers; ++p) prod[p] = lle_genmc::spawn(producer, reinterpret_cast<void*>(static_cast<long>(p)));
  pthread_t c = lle_genmc::spawn(consumer);
  for (int p = 0; p < kProducers; ++p) lle_genmc::join(prod[p]);
  lle_genmc::join(c);

  // Quiescent drain by main (the consumer has been joined: still a single consumer).
  for (int k = 0; k < kTotal; ++k) {
    int v = 0;
    if (!q->try_pop(v)) break;
    received[nreceived++] = v;
  }
  int v = 0;
  assert(!q->try_pop(v));

  int expected = 0;
  for (int p = 0; p < kProducers; ++p) {
    for (int i = 0; i < kPushes; ++i) expected += pushed[p][i] ? 1 : 0;
  }
  assert(nreceived == expected);
  for (int p = 0; p < kProducers; ++p) {
    int last = -1;
    for (int i = 0; i < kPushes; ++i) {
      int count = 0;
      for (int k = 0; k < nreceived; ++k) {
        if (received[k] == item(p, i)) {
          ++count;
          assert(k > last);  // per-producer FIFO
          last = k;
        }
      }
      assert(count == (pushed[p][i] ? 1 : 0));  // multiset equality
    }
  }
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

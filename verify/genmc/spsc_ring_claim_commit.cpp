// GenMC harness: SpscRing zero-copy path (08-concurrency-runtime §7). The producer
// fills each claimed slot field by field (try_claim, writes, commit); the consumer reads
// the fields in place through front() and frees the slot with pop(). Asserts that the
// consumer never observes a partially written slot; any overlap of the producer's
// writes with the consumer's reads is also reported by GenMC as a data race.
//
//   genmc -rc11 -- -std=c++20 -I src -DCAP=2 -DK=3 verify/genmc/spsc_ring_claim_commit.cpp
#include "concurrent/spsc_ring.h"
#include "harness.h"

#ifndef CAP
#define CAP 2
#endif
#ifndef K
#define K 3
#endif

namespace {

struct Msg {
  int seq;
  int a;
  int b;
};

using Ring = lle::conc::SpscRing<Msg, CAP>;
Ring* q;  // heap object created by main (see harness.h)

void* producer(void*) {
  for (int i = 1; i <= K; ++i) {
    Msg* m = q->try_claim();
    __VERIFIER_assume(m != nullptr);
    m->seq = i;
    m->a = 100 + i;
    m->b = 200 + i;
    q->commit();
  }
  return nullptr;
}

void* consumer(void*) {
  for (int i = 1; i <= K; ++i) {
    const Msg* m = q->front();
    __VERIFIER_assume(m != nullptr);
    assert(m->seq == i);
    assert(m->a == 100 + i);
    assert(m->b == 200 + i);
    q->pop();
  }
  return nullptr;
}

}  // namespace

int main() {
  q = lle_genmc::make_shared_object<Ring>();
  pthread_t p = lle_genmc::spawn(producer);
  pthread_t c = lle_genmc::spawn(consumer);
  lle_genmc::join(p);
  lle_genmc::join(c);
  assert(q->front() == nullptr);
  lle_genmc::destroy_shared_object(q);
  return 0;
}

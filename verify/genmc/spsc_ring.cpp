// GenMC harness: SpscRing<T, CAP> (08-concurrency-runtime §7).
// One producer pushes K items, one consumer pops K items (or drains them with
// -DUSE_DRAIN). Asserts values and order; GenMC additionally reports any data race on
// the non-atomic slots, which is how a missing acquire/release shows up. Items are
// scalars: GenMC cannot model the memcpy a struct assignment lowers to (multi-field
// slots are covered by spsc_ring_claim_commit.cpp through in-place field access).
//
//   genmc -rc11 -- -std=c++20 -I src -DCAP=2 -DK=4 verify/genmc/spsc_ring.cpp
//
// Blocking waits are modeled with __VERIFIER_assume(success): a failed try_* only
// refreshes a side-private cache, so retrying until success is equivalent to assuming
// the attempt that succeeds (GenMC's spin-assume argument).
#include "concurrent/spsc_ring.h"
#include "harness.h"

#ifndef CAP
#define CAP 2
#endif
#ifndef K
#define K 4
#endif

namespace {

using Ring = lle::conc::SpscRing<int, CAP>;
Ring* q;  // heap object created by main (see harness.h)

void* producer(void*) {
  for (int i = 1; i <= K; ++i) {
    const bool ok = q->try_push(i * 10);
    __VERIFIER_assume(ok);
  }
  return nullptr;
}

void* consumer(void*) {
#ifdef USE_DRAIN
  int expect = 1;
  for (int round = 0; round < K && expect <= K; ++round) {
    const std::size_t n = q->drain(
        [&](const int& v) {
          assert(v == expect * 10);
          ++expect;
        },
        2);
    __VERIFIER_assume(n > 0);
  }
  assert(expect == K + 1);
#else
  for (int i = 1; i <= K; ++i) {
    int v = 0;
    const bool ok = q->try_pop(v);
    __VERIFIER_assume(ok);
    assert(v == i * 10);
  }
#endif
  return nullptr;
}

}  // namespace

int main() {
  q = lle_genmc::make_shared_object<Ring>();
  pthread_t p = lle_genmc::spawn(producer);
  pthread_t c = lle_genmc::spawn(consumer);
  lle_genmc::join(p);
  lle_genmc::join(c);
  int v = 0;
  assert(!q->try_pop(v));
  assert(q->size_approx() == 0);
  lle_genmc::destroy_shared_object(q);
  return 0;
}

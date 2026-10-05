// Shared helpers for the GenMC harnesses (08-concurrency-runtime §7).
//
// Harnesses compile the REAL production headers from src/concurrent/ (never a copy):
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/<file>.cpp
// They use pthreads (GenMC's documented threading API) and only bounded loops. When
// built without GenMC (a plain compiler, for a syntax/smoke check), genmc.h is absent
// and the GenMC intrinsics fall back to ordinary C.
#pragma once

#include <pthread.h>

#include <cassert>
#include <cstdlib>
#include <new>

#if __has_include(<genmc.h>)
#include <genmc.h>
#define LLE_GENMC 1
#else
#include <cstdlib>
#define LLE_GENMC 0
// Native fallback: an unsatisfied assumption ends the run as "not explored".
#define __VERIFIER_assume(c) \
  do {                       \
    if (!(c)) std::exit(0);  \
  } while (0)
#define __VERIFIER_method_begin(name, arg) ((void)(name), (void)(arg))
#define __VERIFIER_method_end(name, ret) ((void)(name), (void)(ret))
#endif

namespace lle_genmc {

// -DLLE_SCQ_SINGLE_CONSUMER selects the single-consumer SCQ specialization (ADR-031)
// in every SCQ harness.
#ifdef LLE_SCQ_SINGLE_CONSUMER
inline constexpr bool kScqSingleConsumer = true;
#else
inline constexpr bool kScqSingleConsumer = false;
#endif

using ThreadFn = void* (*)(void*);

inline pthread_t spawn(ThreadFn fn, void* arg = nullptr) {
  pthread_t t;
  pthread_create(&t, nullptr, fn, arg);
  return t;
}

inline void join(pthread_t t) { pthread_join(t, nullptr); }

// Shared queue objects live on the heap (aligned_alloc + placement new), not in
// globals: GenMC v0.19.0's variable-naming pass mis-walks structs that start with an
// alignas-padded std::atomic and hits an internal check while printing an error
// report. Heap objects carry no debug naming, so counterexamples are reported
// normally. Exploration is unaffected either way.
template <class T>
T* make_shared_object() {
  static_assert(sizeof(T) % alignof(T) == 0);
  void* mem = std::aligned_alloc(alignof(T), sizeof(T));
  return ::new (mem) T;  // default-init: member initializers only, no zero-fill memset
}

template <class T>
void destroy_shared_object(T* p) {
  p->~T();
  std::free(p);
}

}  // namespace lle_genmc

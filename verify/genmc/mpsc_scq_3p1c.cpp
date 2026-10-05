// GenMC harness: MpscScqRing, 3 producers x 1 push + 1 consumer, n = 2
// (08-concurrency-runtime §7, pre-registered bound). Same client and assertions as
// mpsc_scq_2p1c.cpp. With n = 2 and three producers the queue can be full, and three
// concurrent producers exceed the paper's k <= n assumption on the free-index ring:
// try_push may then fail, but no item may be lost, duplicated or reordered.
//
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/mpsc_scq_3p1c.cpp
#define PRODUCERS 3
#define PUSHES 1
#include "mpsc_scq_2p1c.cpp"

# Concurrency microbenchmarks (08-concurrency-runtime §9). Indicative on macOS, which
# cannot pin threads; budgets are measured on host A with pinned cores.
find_package(Threads REQUIRED)
lle_bench(spsc_bench SOURCES spsc_bench.cpp DEPS lle_concurrent Threads::Threads)
lle_bench(mpsc_bench SOURCES mpsc_bench.cpp DEPS lle_concurrent Threads::Threads)
lle_bench(broadcast_bench SOURCES broadcast_bench.cpp DEPS lle_concurrent Threads::Threads)
lle_bench(byte_ring_bench SOURCES byte_ring_bench.cpp DEPS lle_concurrent Threads::Threads)

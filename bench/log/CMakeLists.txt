# T31 protocol variants (11-logging-observability §2). Custom mains: per-call
# fenced stamps and percentiles do not fit Google Benchmark's model.
lle_bench(nlog_bench SOURCES nlog_bench.cpp DEPS lle_log lle_runtime)
# M3 in-situ A/B (logging on vs off) on the ITCH order book until the engine is
# instrumented (T32).
if(TARGET lle_book)
  lle_bench(nlog_insitu_bench SOURCES nlog_insitu_bench.cpp DEPS lle_log lle_book)
endif()

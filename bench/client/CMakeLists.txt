# refclient hot-path microbenchmarks (indicative only on the dev Mac; the T18
# measurement is ttt_harness against refclient, 07 §4).
lle_bench(client_bench SOURCES client_bench.cpp DEPS lle_client)
target_include_directories(client_bench PRIVATE ${CMAKE_SOURCE_DIR}/tests/unit/client)  # itch_gen.h

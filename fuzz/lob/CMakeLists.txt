# Differential fuzzing of the ITCH book builder (04-order-book §8, T14).
string(REPLACE ";" "," _lle_san "${LLE_SANITIZE}")

# lobdiff: seeded swarm random walk, every variant vs RefBook, ledger writer.
lle_app(lobdiff SOURCES lobdiff.cpp DEPS lle_book)
target_compile_definitions(lobdiff PRIVATE
  LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
  LLE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
  LLE_SANITIZE_STR="${_lle_san}")

# itch_replay_diff: real ITCH files into every variant and RefBook (needs data/; not a ctest).
lle_app(itch_replay_diff SOURCES itch_replay_diff.cpp DEPS lle_book lle_itch50)
target_compile_definitions(itch_replay_diff PRIVATE
  LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
  LLE_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
  LLE_SANITIZE_STR="${_lle_san}")

# lobfuzz: libFuzzer harness; lle_fuzz() also builds lobfuzz_driver and a smoke test.
# FuzzedDataProvider ships with clang's compiler-rt; GCC builds skip lobfuzz.
include(CheckIncludeFileCXX)
check_include_file_cxx(fuzzer/FuzzedDataProvider.h LLE_HAVE_FUZZED_DATA_PROVIDER)
if(LLE_HAVE_FUZZED_DATA_PROVIDER)
  lle_fuzz(lobfuzz SOURCES lobfuzz.cpp DEPS lle_book SMOKE_ITERS 100)
endif()

if(LLE_BUILD_TESTS)
  lle_test(ref_book_test SOURCES ref_book_test.cpp gen_test.cpp DEPS lle_book)
  add_test(NAME lobdiff_smoke
    COMMAND lobdiff --variant=all --seed-start 1 --seeds 12 --ops-per-seed 5000 --full-check-every 1024)
  set_tests_properties(lobdiff_smoke PROPERTIES LABELS fuzz)
endif()

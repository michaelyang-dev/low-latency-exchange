# Differential fuzzing of the matching engine (05-matching-engine §9, E-05/E-08/E-14).
string(REPLACE ";" "," _lle_san "${LLE_SANITIZE}")
set(_lle_prov LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}" LLE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" LLE_SANITIZE_STR="${_lle_san}")

# enginediff: swarm generator, Engine vs RefEngine, ledger writer.
lle_app(enginediff SOURCES enginediff.cpp DEPS lle_engine)
target_compile_definitions(enginediff PRIVATE ${_lle_prov})

# crossdiff: CrossCalculator vs the brute force on random books.
lle_app(crossdiff SOURCES crossdiff.cpp DEPS lle_engine)
target_compile_definitions(crossdiff PRIVATE ${_lle_prov})

# engine_fuzz: arbitrary bytes as OUCH payloads, differential against RefEngine.
lle_fuzz(engine_fuzz SOURCES engine_fuzz.cpp DEPS lle_engine SMOKE_ITERS 1500)

# engine_restore_fuzz: mutated snapshots into Engine::restore (structure-aware).
lle_fuzz(engine_restore_fuzz SOURCES engine_restore_fuzz.cpp DEPS lle_engine SMOKE_ITERS 1500)

if(LLE_BUILD_TESTS)
  add_test(NAME enginediff_smoke
    COMMAND enginediff --seed-start 1 --seeds 8 --records-per-seed 5000 --check-every 256 --snapshot-every 1024)
  add_test(NAME crossdiff_smoke COMMAND crossdiff --seed-start 1 --seeds 4 --cases-per-seed 20000)
  set_tests_properties(enginediff_smoke crossdiff_smoke PROPERTIES LABELS fuzz)
endif()

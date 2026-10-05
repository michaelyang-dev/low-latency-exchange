# Full-day ITCH replay benchmark (04-order-book §5; T11a, T11b, T12).
lle_app(lob_replay SOURCES main.cpp input.cpp reference.cpp DEPS lle_book lle_itch50)
# RefBook (the independent reference for the digest gate) lives with the fuzzers.
target_include_directories(lob_replay PRIVATE "${CMAKE_SOURCE_DIR}/fuzz/lob")
string(TOUPPER "${CMAKE_BUILD_TYPE}" _lle_bt)
target_compile_definitions(lob_replay PRIVATE
  LLE_CXX_ID="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
  LLE_CXX_FLAGS="${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${_lle_bt}}"
  LLE_BUILD_TYPE="${CMAKE_BUILD_TYPE}")

if(LLE_BUILD_TESTS AND TARGET itch_synth)
  # End-to-end smoke runs on the synthetic day: every variant must pass the
  # digest gate against RefBook in every mode (timing is not checked here).
  set(_synth "${CMAKE_BINARY_DIR}/synth/synth-1.bin")
  foreach(mode throughput block all)
    add_test(NAME lob_replay_synth_${mode}
      COMMAND lob_replay --file "${_synth}" --variant all --mode ${mode} --prefetch 8 --check
              --ref compute --no-sha)
    set_tests_properties(lob_replay_synth_${mode} PROPERTIES FIXTURES_REQUIRED synth_day LABELS integration)
  endforeach()
  if(TARGET itch_validate)  # configured after apps/itch_validate (alphabetical)
    add_test(NAME itch_synth_validate_strict COMMAND itch_validate --strict "${_synth}")
    set_tests_properties(itch_synth_validate_strict PROPERTIES FIXTURES_REQUIRED synth_day LABELS integration)
  endif()
  add_test(NAME lob_replay_synth_sampled
    COMMAND lob_replay --file "${_synth}" --variant opt --mode sampled --no-baseline --ref compute --no-sha)
  set_tests_properties(lob_replay_synth_sampled PROPERTIES FIXTURES_REQUIRED synth_day LABELS integration)
endif()

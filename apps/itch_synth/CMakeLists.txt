# Seeded synthetic ITCH 5.0 days for CI (never used for headline numbers).
lle_app(itch_synth SOURCES main.cpp DEPS lle_itch50)
if(LLE_BUILD_TESTS)
  set(_synth "${CMAKE_BINARY_DIR}/synth/synth-1.bin")
  add_test(NAME itch_synth_generate
    COMMAND ${CMAKE_COMMAND} -E env sh -c "mkdir -p '${CMAKE_BINARY_DIR}/synth' && '$<TARGET_FILE:itch_synth>' --out '${_synth}' --messages 300000 --symbols 200 --live 20000 --seed 1")
  set_tests_properties(itch_synth_generate PROPERTIES FIXTURES_SETUP synth_day LABELS integration)
endif()

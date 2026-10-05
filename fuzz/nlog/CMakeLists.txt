# Decoder fuzzing (11-logging-observability §1; conventions: fuzz harnesses).
lle_fuzz(nlog_decode_fuzz SOURCES nlog_decode_fuzz.cpp DEPS lle_log_format)

# nlog-aware mutations on top of the shared driver: CRC repair so mutated payloads
# pass the checksums, and every truncation length of every seed.
add_executable(nlog_decode_structured_driver nlog_decode_fuzz.cpp nlog_decode_structured_driver.cpp)
target_link_libraries(nlog_decode_structured_driver PRIVATE lle_options lle_log_format)
if(LLE_BUILD_TESTS)
  add_test(NAME nlog_decode_structured_smoke COMMAND nlog_decode_structured_driver --iterations 20000 --seed 1)
  set_tests_properties(nlog_decode_structured_smoke PROPERTIES LABELS fuzz)
endif()

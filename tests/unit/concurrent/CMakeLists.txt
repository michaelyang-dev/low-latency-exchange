lle_test(concurrent_test
  SOURCES spsc_ring_test.cpp spsc_byte_ring_test.cpp broadcast_ring_test.cpp mpsc_test.cpp wait_test.cpp
  DEPS lle_concurrent)

# Multi-threaded stress (08 §8). concurrent_stress_test runs at quick counts (label
# "unit"; /4 under sanitizers). concurrent_stress_long_test is the same source at full
# counts (>= 1e8 items per production queue, never scaled), label "stress" only, so the
# default `ctest -L unit` runs skip it:  ctest -L stress --output-on-failure
lle_test(concurrent_stress_test SOURCES stress_test.cpp DEPS lle_concurrent)
add_executable(concurrent_stress_long_test stress_test.cpp)
target_compile_definitions(concurrent_stress_long_test PRIVATE LLE_STRESS_LONG=1)
target_link_libraries(concurrent_stress_long_test PRIVATE lle_options lle_concurrent GTest::gtest_main)
target_compile_options(concurrent_stress_long_test PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-else>)
include(GoogleTest)
gtest_discover_tests(concurrent_stress_long_test TEST_PREFIX "long." DISCOVERY_TIMEOUT 60
                     PROPERTIES LABELS stress TIMEOUT 21600)

# Defines the LLE_TEST_STOP_AFTER_CLAIM hook before including the MPSC queues, so it
# must stay a separate binary.
lle_test(concurrent_stalled_producer_test SOURCES stalled_producer_test.cpp DEPS lle_concurrent)

# Include allowlist for GenMC-compiled headers (08 §7).
add_test(NAME concurrent_include_allowlist
  COMMAND ${CMAKE_CURRENT_LIST_DIR}/../../../tools/genmc/check_includes.sh ${CMAKE_CURRENT_LIST_DIR}/../../../src/concurrent)
set_tests_properties(concurrent_include_allowlist PROPERTIES LABELS unit)

# Purity audit probes (tools/ci/check_sim_purity.sh): a wait primitive must be caught,
# the queues must pass. The negative test passes only if the audit FAILS.
add_library(concurrent_purity_probe_bad OBJECT purity_probe_bad.cpp)
target_link_libraries(concurrent_purity_probe_bad PRIVATE lle_options)
add_library(concurrent_purity_probe_ok OBJECT purity_probe_ok.cpp)
target_link_libraries(concurrent_purity_probe_ok PRIVATE lle_options)
add_test(NAME concurrent_purity_negative
  COMMAND ${CMAKE_CURRENT_LIST_DIR}/../../../tools/ci/check_sim_purity.sh $<TARGET_OBJECTS:concurrent_purity_probe_bad>)
add_test(NAME concurrent_purity_positive
  COMMAND ${CMAKE_CURRENT_LIST_DIR}/../../../tools/ci/check_sim_purity.sh $<TARGET_OBJECTS:concurrent_purity_probe_ok>)
set_tests_properties(concurrent_purity_negative PROPERTIES LABELS unit WILL_FAIL TRUE)
set_tests_properties(concurrent_purity_positive PROPERTIES LABELS unit)

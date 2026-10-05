# DST-001: a re-relayed JOIN for a restarted joiner got the old grant
# (sim/ledger/bugs.yaml). Registered under the bug id so verify_bugs.py can run
# `ctest -R ^DST-001_` at the found and fix trees.
add_executable(DST-001_witness_join_dedupe dst001_test.cpp)
target_link_libraries(DST-001_witness_join_dedupe PRIVATE lle_options lle_witness GTest::gtest_main)
add_test(NAME DST-001_witness_join_dedupe COMMAND DST-001_witness_join_dedupe)
set_tests_properties(DST-001_witness_join_dedupe PROPERTIES LABELS "unit;sim_regression")

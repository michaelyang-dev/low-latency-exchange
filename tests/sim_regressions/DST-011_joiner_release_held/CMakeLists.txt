# DST-011: a recovering joiner released nothing until it became the backup, so a catch-up
# longer than its egress ring and L2 together stopped its applier, then its L2, and it
# never reached zero lag: no JOIN for the rest of the day (sim/ledger/bugs.yaml).
# Registered under the bug id for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-011_joiner_release_held dst011_test.cpp)
  target_link_libraries(DST-011_joiner_release_held PRIVATE lle_options lle_repl lle_witness lle_journal
                        GTest::gtest_main)
  add_test(NAME DST-011_joiner_release_held COMMAND DST-011_joiner_release_held)
  set_tests_properties(DST-011_joiner_release_held PROPERTIES LABELS "unit;sim_regression")
endif()

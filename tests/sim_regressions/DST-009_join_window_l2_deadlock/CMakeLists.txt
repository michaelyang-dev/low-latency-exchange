# DST-009: the JOIN window froze a solo primary's release while its joiner, which may
# apply only up to that release, needed L2 room to drain to zero lag: no JOIN, no release
# for the rest of the day (sim/ledger/bugs.yaml). Registered under the bug id for
# verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-009_join_window_l2_deadlock dst009_test.cpp)
  target_link_libraries(DST-009_join_window_l2_deadlock PRIVATE lle_options lle_repl lle_witness lle_journal
                        GTest::gtest_main)
  add_test(NAME DST-009_join_window_l2_deadlock COMMAND DST-009_join_window_l2_deadlock)
  set_tests_properties(DST-009_join_window_l2_deadlock PROPERTIES LABELS "unit;sim_regression")
endif()

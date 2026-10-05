# DST-003: a solo primary gave up a JOIN that W had granted, on a late refusal of an
# earlier JOIN of the same epoch, and never learned W's epoch (sim/ledger/bugs.yaml).
# Registered under the bug id so verify_bugs.py can run `ctest -R ^DST-003_` at the
# found and fix trees.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-003_repl_join_pending dst003_test.cpp)
  target_link_libraries(DST-003_repl_join_pending PRIVATE lle_options lle_repl lle_witness lle_journal GTest::gtest_main)
  add_test(NAME DST-003_repl_join_pending COMMAND DST-003_repl_join_pending)
  set_tests_properties(DST-003_repl_join_pending PROPERTIES LABELS "unit;sim_regression")
endif()

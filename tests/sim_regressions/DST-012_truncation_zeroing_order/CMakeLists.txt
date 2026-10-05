# DST-012: a rejoin truncation stopped by a failed write (or a crash) during its zeroing
# left zeros after t and valid records beyond recovery's in-flight window: recovery
# refused the journal at every start (sim/ledger/bugs.yaml). Registered under the bug id
# for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-012_truncation_zeroing_order dst012_test.cpp)
  target_link_libraries(DST-012_truncation_zeroing_order PRIVATE lle_options lle_repl lle_journal GTest::gtest_main)
  add_test(NAME DST-012_truncation_zeroing_order COMMAND DST-012_truncation_zeroing_order)
  set_tests_properties(DST-012_truncation_zeroing_order PROPERTIES LABELS "unit;sim_regression")
endif()

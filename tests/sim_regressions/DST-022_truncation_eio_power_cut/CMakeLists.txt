# DST-022: after a rejoin truncation whose zeroing write failed and the truncation that
# retried it, a power cut brought the old records back past recovery's in-flight window:
# recovery refused the journal at every start (sim/ledger/bugs.yaml). Registered under the
# bug id for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-022_truncation_eio_power_cut dst022_test.cpp)
  target_link_libraries(DST-022_truncation_eio_power_cut PRIVATE lle_options lle_repl lle_journal GTest::gtest_main)
  add_test(NAME DST-022_truncation_eio_power_cut COMMAND DST-022_truncation_eio_power_cut)
  set_tests_properties(DST-022_truncation_eio_power_cut PROPERTIES LABELS "unit;sim_regression")
endif()

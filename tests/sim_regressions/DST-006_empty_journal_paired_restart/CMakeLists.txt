# DST-006: a paired node whose journal recovered empty after it had started the day ran
# the day start again (incarnation 1, start_paired as the day's first primary) while its
# partner ran the day (sim/ledger/bugs.yaml). Registered under the bug id for
# verify_bugs.py.
if(TARGET lle_sequencer AND TARGET lle_engine AND TARGET lle_journal AND TARGET lle_outlog
   AND TARGET lle_snapshot_engine AND TARGET lle_gateway AND TARGET lle_md AND TARGET lle_repl)
  add_executable(DST-006_empty_journal_paired_restart dst006_test.cpp)
  target_include_directories(DST-006_empty_journal_paired_restart PRIVATE "${CMAKE_SOURCE_DIR}/apps")
  target_link_libraries(DST-006_empty_journal_paired_restart PRIVATE lle_options lle_sequencer lle_engine lle_journal
                        lle_outlog lle_snapshot_engine lle_gateway lle_md lle_repl lle_concurrent GTest::gtest_main)
  add_test(NAME DST-006_empty_journal_paired_restart COMMAND DST-006_empty_journal_paired_restart)
  set_tests_properties(DST-006_empty_journal_paired_restart PROPERTIES LABELS "unit;sim_regression")
endif()

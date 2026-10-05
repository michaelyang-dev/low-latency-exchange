# DST-010: a node that became the backup after a JOIN did not acknowledge the JOIN epoch's
# EpochStart until something followed it; after the close the primary's T_ack ran out
# first and it went solo, every rejoin (sim/ledger/bugs.yaml). Registered under the bug
# id for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-010_join_epoch_start_unacked dst010_test.cpp)
  target_link_libraries(DST-010_join_epoch_start_unacked PRIVATE lle_options lle_repl lle_witness lle_journal
                        GTest::gtest_main)
  add_test(NAME DST-010_join_epoch_start_unacked COMMAND DST-010_join_epoch_start_unacked)
  set_tests_properties(DST-010_join_epoch_start_unacked PROPERTIES LABELS "unit;sim_regression")
endif()

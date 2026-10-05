# DST-005 (candidate): an incomplete day start was refused at restart as a configuration
# mismatch (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
if(TARGET lle_sequencer AND TARGET lle_engine AND TARGET lle_journal AND TARGET lle_outlog
   AND TARGET lle_snapshot_engine AND TARGET lle_gateway)
  add_executable(DST-005_incomplete_day_start_verdict dst005_test.cpp)
  target_include_directories(DST-005_incomplete_day_start_verdict PRIVATE "${CMAKE_SOURCE_DIR}/apps")
  target_link_libraries(DST-005_incomplete_day_start_verdict PRIVATE lle_options lle_sequencer lle_engine lle_journal
                        lle_outlog lle_snapshot_engine lle_gateway lle_concurrent GTest::gtest_main)
  add_test(NAME DST-005_incomplete_day_start_verdict COMMAND DST-005_incomplete_day_start_verdict)
  set_tests_properties(DST-005_incomplete_day_start_verdict PROPERTIES LABELS "unit;sim_regression")
endif()

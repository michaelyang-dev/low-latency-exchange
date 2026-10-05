# DST-004: cancel-on-disconnect left orders of a dropped connection open: the
# sequencer journaled a connection's Disconnect before OUCH its gateway had pushed
# earlier, and a reconnecting session's orders before the previous connection's
# Disconnect (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
if(TARGET lle_gateway AND TARGET lle_md AND TARGET lle_sequencer AND TARGET lle_engine AND TARGET lle_journal
   AND TARGET lle_soupbin)
  add_executable(DST-004_cod_session_order dst004_test.cpp)
  target_include_directories(DST-004_cod_session_order PRIVATE "${CMAKE_SOURCE_DIR}/tests/unit/gateway")
  target_link_libraries(DST-004_cod_session_order PRIVATE lle_options lle_gateway lle_md lle_sequencer lle_engine
                        lle_journal lle_soupbin lle_concurrent GTest::gtest_main)
  add_test(NAME DST-004_cod_session_order COMMAND DST-004_cod_session_order)
  set_tests_properties(DST-004_cod_session_order PROPERTIES LABELS "unit;sim_regression")
endif()

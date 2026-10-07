# DST-020: the gateway dropped session events: while the sequencer queue was full every
# reconnect still queued its Login, and a congested day's reconnects overflowed the
# backlog (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
if(TARGET lle_gateway AND TARGET lle_md AND TARGET lle_soupbin AND TARGET lle_outlog)
  add_executable(DST-020_session_event_backlog dst020_test.cpp)
  target_include_directories(DST-020_session_event_backlog PRIVATE "${CMAKE_SOURCE_DIR}/tests/unit/gateway")
  target_link_libraries(DST-020_session_event_backlog PRIVATE lle_options lle_gateway lle_md lle_soupbin lle_outlog
                        lle_concurrent GTest::gtest_main)
  add_test(NAME DST-020_session_event_backlog COMMAND DST-020_session_event_backlog)
  set_tests_properties(DST-020_session_event_backlog PROPERTIES LABELS "unit;sim_regression")
endif()

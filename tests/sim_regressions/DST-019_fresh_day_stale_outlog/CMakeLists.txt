# DST-019: a node starting the day afresh numbered its output from the output log an
# earlier start of the day had left (its journal moved aside), and a paired node served
# without its incarnation file (sim/ledger/bugs.yaml). Runs the exchanged binary through
# the end-to-end harness of tests/integration/exchange. Registered under the bug id for
# verify_bugs.py.
if(LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/exchanged" IN_LIST LLE_ONLY))
  add_executable(DST-019_fresh_day_stale_outlog dst019_test.cpp)
  target_include_directories(DST-019_fresh_day_stale_outlog PRIVATE "${CMAKE_SOURCE_DIR}/tests/integration/exchange")
  target_link_libraries(DST-019_fresh_day_stale_outlog PRIVATE lle_options lle_journal lle_gateway lle_md lle_admin
                        lle_soupbin lle_moldudp64 lle_ouch50 lle_engine lle_itch50 lle_metrics lle_glimpse
                        GTest::gtest_main)
  target_compile_definitions(DST-019_fresh_day_stale_outlog PRIVATE LLE_EXCHANGED="$<TARGET_FILE:exchanged>"
                             LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>"
                             LLE_ITCH_VALIDATE="$<TARGET_FILE:itch_validate>")
  add_dependencies(DST-019_fresh_day_stale_outlog exchanged journal_replay itch_validate)
  add_test(NAME DST-019_fresh_day_stale_outlog COMMAND DST-019_fresh_day_stale_outlog)
  set_tests_properties(DST-019_fresh_day_stale_outlog PROPERTIES LABELS "unit;sim_regression" TIMEOUT 300)
endif()

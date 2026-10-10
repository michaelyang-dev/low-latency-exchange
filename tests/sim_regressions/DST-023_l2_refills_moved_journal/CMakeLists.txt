# DST-023: a start left its L2 file's records valid after journaling them, so a later
# start journaled them again into a journal moved aside since (the incomplete-day-start
# runbook), and refused at every start (sim/ledger/bugs.yaml). Runs the exchanged binary
# through the end-to-end harness of tests/integration/exchange. Registered under the bug
# id for verify_bugs.py.
if(LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/exchanged" IN_LIST LLE_ONLY))
  add_executable(DST-023_l2_refills_moved_journal dst023_test.cpp)
  target_include_directories(DST-023_l2_refills_moved_journal PRIVATE "${CMAKE_SOURCE_DIR}/tests/integration/exchange")
  target_link_libraries(DST-023_l2_refills_moved_journal PRIVATE lle_options lle_journal lle_gateway lle_md lle_admin
                        lle_soupbin lle_moldudp64 lle_ouch50 lle_engine lle_itch50 lle_metrics lle_glimpse
                        GTest::gtest_main)
  target_compile_definitions(DST-023_l2_refills_moved_journal PRIVATE LLE_EXCHANGED="$<TARGET_FILE:exchanged>"
                             LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>"
                             LLE_ITCH_VALIDATE="$<TARGET_FILE:itch_validate>")
  add_dependencies(DST-023_l2_refills_moved_journal exchanged journal_replay itch_validate)
  add_test(NAME DST-023_l2_refills_moved_journal COMMAND DST-023_l2_refills_moved_journal)
  set_tests_properties(DST-023_l2_refills_moved_journal PROPERTIES LABELS "unit;sim_regression" TIMEOUT 300)
endif()

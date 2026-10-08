# DST-021: a rejoining replica took a record it could not read back yet (out of the
# record log's memory, not durable in L3) at its truncation point for a divergence: it
# raised a divergence alarm and threw its whole journal away (sim/ledger/bugs.yaml).
# Registered under the bug id for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-021_rejoin_unreadable_truncation_point dst021_test.cpp)
  target_link_libraries(DST-021_rejoin_unreadable_truncation_point PRIVATE lle_options lle_repl lle_witness
                        lle_journal GTest::gtest_main)
  add_test(NAME DST-021_rejoin_unreadable_truncation_point COMMAND DST-021_rejoin_unreadable_truncation_point)
  set_tests_properties(DST-021_rejoin_unreadable_truncation_point PROPERTIES LABELS "unit;sim_regression")
endif()

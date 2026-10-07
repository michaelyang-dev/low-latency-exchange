# DST-018: snapshotd's follow cursor, in a segment it had moved into without walking a
# record, positioned again after a rejoin truncation without the record it had delivered
# last, and took the partner's records for its history (sim/ledger/bugs.yaml).
# Registered under the bug id for verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-018_follow_cursor_segment_switch dst018_test.cpp)
  target_link_libraries(DST-018_follow_cursor_segment_switch PRIVATE lle_options lle_repl lle_journal GTest::gtest_main)
  add_test(NAME DST-018_follow_cursor_segment_switch COMMAND DST-018_follow_cursor_segment_switch)
  set_tests_properties(DST-018_follow_cursor_segment_switch PROPERTIES LABELS "unit;sim_regression")
endif()

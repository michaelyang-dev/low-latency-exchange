# DST-015: a replica reassembled a record that came in fragments only if they arrived in
# order, so over a network that reorders datagrams a record cut into many fragments (the
# day's schedule, with the 1 Hz clock) never arrived: a joiner's catch-up stalled at it
# for the rest of the day (sim/ledger/bugs.yaml). Registered under the bug id for
# verify_bugs.py.
lle_keep("src/repl" _lle_keep_repl)
if(_lle_keep_repl)
  add_executable(DST-015_fragments_out_of_order dst015_test.cpp)
  target_link_libraries(DST-015_fragments_out_of_order PRIVATE lle_options lle_repl lle_witness lle_journal
                        GTest::gtest_main)
  add_test(NAME DST-015_fragments_out_of_order COMMAND DST-015_fragments_out_of_order)
  set_tests_properties(DST-015_fragments_out_of_order PROPERTIES LABELS "unit;sim_regression")
endif()

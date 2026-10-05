# DST-013: a rejoin's reload regenerated the output log through the journal's end,
# including records the primary had not released; the joiner's gateways replayed them
# and the primary later lost them (sim/ledger/bugs.yaml). Registered under the bug id for
# verify_bugs.py.
if(TARGET lle_sequencer AND TARGET lle_engine AND TARGET lle_journal AND TARGET lle_outlog
   AND TARGET lle_snapshot_engine AND TARGET lle_gateway AND TARGET lle_md AND TARGET lle_repl)
  add_executable(DST-013_rejoin_unreleased_outputs dst013_test.cpp)
  target_include_directories(DST-013_rejoin_unreleased_outputs PRIVATE "${CMAKE_SOURCE_DIR}/apps")
  target_link_libraries(DST-013_rejoin_unreleased_outputs PRIVATE lle_options lle_sequencer lle_engine lle_journal
                        lle_outlog lle_snapshot_engine lle_snapshot lle_gateway lle_md lle_repl lle_concurrent
                        GTest::gtest_main)
  add_test(NAME DST-013_rejoin_unreleased_outputs COMMAND DST-013_rejoin_unreleased_outputs)
  set_tests_properties(DST-013_rejoin_unreleased_outputs PROPERTIES LABELS "unit;sim_regression")
endif()

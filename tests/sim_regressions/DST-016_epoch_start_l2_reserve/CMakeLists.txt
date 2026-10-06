# DST-016: a primary granted a new epoch with its L2 ring full could not append the
# epoch's EpochStart, and nothing could free the ring: release waits for that record,
# the engine for the release, L2 for the engine. The node froze for the rest of the day
# (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
if(TARGET lle_sequencer AND TARGET lle_journal AND TARGET lle_md AND TARGET lle_engine)
  add_executable(DST-016_epoch_start_l2_reserve dst016_test.cpp)
  target_include_directories(DST-016_epoch_start_l2_reserve PRIVATE "${CMAKE_SOURCE_DIR}/apps")
  target_link_libraries(DST-016_epoch_start_l2_reserve PRIVATE lle_options lle_sequencer lle_engine lle_journal lle_md
                        lle_concurrent GTest::gtest_main)
  add_test(NAME DST-016_epoch_start_l2_reserve COMMAND DST-016_epoch_start_l2_reserve)
  set_tests_properties(DST-016_epoch_start_l2_reserve PROPERTIES LABELS "unit;sim_regression")
endif()

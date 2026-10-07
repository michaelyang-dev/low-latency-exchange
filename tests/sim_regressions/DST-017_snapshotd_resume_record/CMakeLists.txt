# DST-017: snapshotd continued from a snapshot whose record a rejoin had since replaced
# (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
if(TARGET lle_sequencer AND TARGET lle_engine AND TARGET lle_journal AND TARGET lle_snapshot_engine)
  add_executable(DST-017_snapshotd_resume_record dst017_test.cpp)
  target_include_directories(DST-017_snapshotd_resume_record PRIVATE "${CMAKE_SOURCE_DIR}/apps")
  target_link_libraries(DST-017_snapshotd_resume_record PRIVATE lle_options lle_sequencer lle_engine lle_journal
                        lle_snapshot_engine lle_concurrent GTest::gtest_main)
  add_test(NAME DST-017_snapshotd_resume_record COMMAND DST-017_snapshotd_resume_record)
  set_tests_properties(DST-017_snapshotd_resume_record PROPERTIES LABELS "unit;sim_regression")
endif()

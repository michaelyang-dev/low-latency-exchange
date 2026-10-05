# DST-002: journal recovery reported page-cache-only records as durable
# (sim/ledger/bugs.yaml). Registered under the bug id for verify_bugs.py.
add_executable(DST-002_journal_recovery_repersist dst002_test.cpp)
target_link_libraries(DST-002_journal_recovery_repersist PRIVATE lle_options lle_journal lle_sim GTest::gtest_main)
add_test(NAME DST-002_journal_recovery_repersist COMMAND DST-002_journal_recovery_repersist)
set_tests_properties(DST-002_journal_recovery_repersist PROPERTIES LABELS "unit;sim_regression")

# DST-014: refclient's HA order entry read an Account Query Response's NextUserRefNum as
# the UserRefNum a message consumed and released the next Enter Order still pending,
# which a failover could then lose (sim/ledger/bugs.yaml). Registered under the bug id
# for verify_bugs.py.
if(TARGET lle_client)
  add_executable(DST-014_ha_client_account_query dst014_test.cpp)
  target_link_libraries(DST-014_ha_client_account_query PRIVATE lle_options lle_client GTest::gtest_main)
  add_test(NAME DST-014_ha_client_account_query COMMAND DST-014_ha_client_account_query)
  set_tests_properties(DST-014_ha_client_account_query PROPERTIES LABELS "unit;sim_regression")
endif()

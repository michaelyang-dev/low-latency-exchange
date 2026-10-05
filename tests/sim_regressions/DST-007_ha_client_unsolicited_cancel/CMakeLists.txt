# DST-007: refclient's HA order entry took an unsolicited cancel (cancel-on-disconnect,
# the close, IOC, a halt, the completion of an already answered Cancel) as the answer to
# a pending Cancel of that order and released every earlier pending message, which a
# failover could then lose (sim/ledger/bugs.yaml). Registered under the bug id for
# verify_bugs.py.
if(TARGET lle_client)
  add_executable(DST-007_ha_client_unsolicited_cancel dst007_test.cpp)
  target_link_libraries(DST-007_ha_client_unsolicited_cancel PRIVATE lle_options lle_client GTest::gtest_main)
  add_test(NAME DST-007_ha_client_unsolicited_cancel COMMAND DST-007_ha_client_unsolicited_cancel)
  set_tests_properties(DST-007_ha_client_unsolicited_cancel PROPERTIES LABELS "unit;sim_regression")
endif()

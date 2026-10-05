# DST-008: a takeover, JOIN or RESUME after the day's DayEnd restarted the sequencer:
# the new primary journaled InstanceDowns, input and another DayEnd after DayEnd
# (sim/ledger/bugs.yaml). Runs the paired node on the simulator (sim/exchange).
# Registered under the bug id for verify_bugs.py.
# tests/sim_regressions is configured before sim/, so the condition repeats the one that
# defines lle_sim_exchange (sim/CMakeLists.txt; LLE_SIM_EXCHANGE defaults to ON); the link
# resolves at generate time.
lle_keep("sim" _lle_keep_sim)
if(_lle_keep_sim AND (NOT DEFINED LLE_SIM_EXCHANGE OR LLE_SIM_EXCHANGE) AND TARGET lle_gateway AND TARGET lle_md
   AND TARGET lle_engine AND TARGET lle_sequencer AND TARGET lle_journal AND TARGET lle_outlog AND TARGET lle_snapshot_engine
   AND TARGET lle_soupbin AND TARGET lle_moldudp64 AND TARGET lle_ouch50 AND TARGET lle_itch50 AND TARGET lle_glimpse
   AND TARGET lle_book AND TARGET lle_repl AND TARGET lle_witness)
  add_executable(DST-008_takeover_after_day_end dst008_test.cpp)
  target_link_libraries(DST-008_takeover_after_day_end PRIVATE lle_options lle_sim_exchange GTest::gtest_main)
  add_test(NAME DST-008_takeover_after_day_end COMMAND DST-008_takeover_after_day_end)
  set_tests_properties(DST-008_takeover_after_day_end PROPERTIES LABELS "unit;sim_regression" TIMEOUT 300)
endif()

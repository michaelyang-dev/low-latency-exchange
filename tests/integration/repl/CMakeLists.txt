# Multi-node replication scenarios in the `ha` simulation world (sim/ha, built by
# sim/CMakeLists.txt when the simulator is part of the build), run as seeded campaigns.
lle_keep("sim" _lle_keep_sim)
lle_keep("src/repl" _lle_keep_repl)
lle_keep("src/snapshot" _lle_keep_snapshot)
if(_lle_keep_sim AND _lle_keep_repl AND _lle_keep_snapshot)
  lle_test(repl_ha_sim_test SOURCES ha_sim_test.cpp DEPS lle_sim_ha)
endif()

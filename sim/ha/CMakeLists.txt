# The `ha` simulation world (09 §2 S-10; 10): the replication core, the witness, the
# journal and mirror-session clients under the simulator's faults and oracles.
# sim/CMakeLists.txt adds this directory when lle_repl, lle_witness, lle_journal
# and lle_snapshot are part of the build; `exsim --world=ha` runs it too.
if(TARGET lle_sim_ha)
  return()
endif()

lle_library(lle_sim_ha
  SOURCES data_node.cpp ha_world.cpp
  DEPS lle_sim lle_repl lle_witness lle_journal lle_snapshot)

# exsim_ha: seeded campaigns, determinism checks and TLA+ trace export.
lle_app(exsim_ha SOURCES main.cpp DEPS lle_sim_ha)

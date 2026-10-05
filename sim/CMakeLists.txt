# Deterministic simulator (docs/plan/09-deterministic-simulation.md).
#
# lle_sim       simulator core: world, scheduler, clock, network, disk, node,
#               faults (swarm, injector, buggify, probes), oracles. Audited by
#               tools/ci/check_sim_purity.sh: no wall clock, threads or OS
#               randomness.
# lle_sim_worlds the worlds: demo worlds (toy components) and real worlds
#               running production components. A real world is built only
#               when its components are part of the build (LLE_ONLY), and
#               defines LLE_WORLD_<NAME>=1 for the dispatcher.
# ha/           the `ha` world (replication): lle_sim_ha and its own driver
#               exsim_ha (TLA+ trace export); also `exsim --world=ha`.
# exsim         the simulator driver.
lle_library(lle_sim
  SOURCES
    world.cpp
    scheduler.cpp
    node.cpp
    network.cpp
    disk.cpp
    fault/swarm.cpp
    fault/injector.cpp
    fault/probes.cpp
    fault/buggify_registry.cpp
    fault/context.cpp
    oracles/registry.cpp
  DEPS lle_common lle_env)  # runtime/stage.h is header-only; no thread libraries here
# Includes are "sim/..." from the repository root.
target_include_directories(lle_sim PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")

if(TARGET lle_repl AND TARGET lle_witness AND TARGET lle_journal AND TARGET lle_snapshot)
  add_subdirectory(ha)
endif()

set(_lle_world_srcs worlds/worlds.cpp demo/pingpong.cpp demo/wal.cpp demo/stream_echo.cpp)
set(_lle_world_deps lle_sim)
set(_lle_world_defs "")
# lle_sim_world(<NAME> <source> <component targets>...): adds the world if every
# component target exists in this build.
macro(lle_sim_world name src)
  set(_lle_world_ok TRUE)
  foreach(_lle_t ${ARGN})
    if(NOT TARGET ${_lle_t})
      set(_lle_world_ok FALSE)
    endif()
  endforeach()
  if(_lle_world_ok)
    list(APPEND _lle_world_srcs ${src})
    list(APPEND _lle_world_deps ${ARGN})
    list(APPEND _lle_world_defs LLE_WORLD_${name}=1)
  endif()
endmacro()
lle_sim_world(WITNESS worlds/witness_world.cpp lle_witness)
lle_sim_world(JOURNAL worlds/journal_world.cpp lle_journal)
lle_sim_world(ARBITER worlds/arbiter_world.cpp lle_moldudp64 lle_glimpse lle_book lle_itch50)
lle_sim_world(SOUPBIN worlds/soupbin_world.cpp lle_soupbin)
lle_sim_world(UTCP worlds/utcp_world.cpp lle_net_utcp)
lle_sim_world(HA worlds/ha_adapter.cpp lle_sim_ha)
lle_sim_world(OUTLOG worlds/outlog_world.cpp lle_outlog)
lle_sim_world(SNAPSHOT worlds/snapshot_world.cpp lle_snapshot)
lle_sim_world(SINGLE worlds/single_world.cpp lle_engine lle_sequencer lle_snapshot_engine lle_journal lle_concurrent)

# The assembled exchange node (apps/exchanged's stages and start-up, snapshotd's
# follower) on the simulator: lle_sim_exchange, and the worlds that run it. Built
# whenever its components are part of the build.
option(LLE_SIM_EXCHANGE "Build the exchange-node simulator worlds" ON)
if(LLE_SIM_EXCHANGE AND TARGET lle_gateway AND TARGET lle_md AND TARGET lle_engine AND TARGET lle_sequencer
   AND TARGET lle_journal AND TARGET lle_outlog AND TARGET lle_snapshot_engine AND TARGET lle_soupbin
   AND TARGET lle_moldudp64 AND TARGET lle_ouch50 AND TARGET lle_itch50 AND TARGET lle_glimpse AND TARGET lle_book
   AND TARGET lle_repl AND TARGET lle_witness)
  lle_library(lle_sim_exchange
    SOURCES exchange/exchange_node.cpp exchange/truth.cpp
    DEPS lle_sim lle_gateway lle_md lle_engine lle_sequencer lle_journal lle_outlog lle_snapshot_engine lle_soupbin
         lle_moldudp64 lle_ouch50 lle_itch50 lle_glimpse lle_book lle_concurrent lle_net_common lle_log lle_repl
         lle_witness)
  # Header-only stage and start-up code of the node (apps/exchanged, apps/snapshotd).
  target_include_directories(lle_sim_exchange PUBLIC "${CMAKE_SOURCE_DIR}/apps")
  # refclient's HA order entry (client::HaOrderEntry: SoupBinTCP and OUCH only) for the
  # exchange_ha world's clients, compiled in so the simulator does not link lle_client
  # (network backends, metrics).
  target_sources(lle_sim_exchange PRIVATE "${CMAKE_SOURCE_DIR}/src/client/order_entry.cpp")
endif()
lle_sim_world(EXCHANGE worlds/exchange_world.cpp lle_sim_exchange)
# The paired node (S7a/S7b: the replication stage, the rejoin) and the witness: the
# exchange_ha world.
option(LLE_SIM_EXCHANGE_HA "Build the paired exchange-node simulator world (exchange_ha)" ON)
if(LLE_SIM_EXCHANGE_HA)
  lle_sim_world(EXCHANGE_HA worlds/exchange_ha_world.cpp lle_sim_exchange)
endif()

lle_library(lle_sim_worlds SOURCES ${_lle_world_srcs} DEPS ${_lle_world_deps})
target_compile_definitions(lle_sim_worlds PUBLIC ${_lle_world_defs})

lle_app(exsim SOURCES main.cpp DEPS lle_sim_worlds)

# The exchange world runs a whole node per seed (about a second in Debug), so its
# determinism double-run takes fewer seeds than sim_determinism_128x2.
if(LLE_BUILD_TESTS AND TARGET lle_sim_exchange)
  add_test(NAME sim_determinism_exchange_16x2
    COMMAND exsim --world=exchange --seed=1000 --seeds=16 --check-determinism --quiet)
  set_tests_properties(sim_determinism_exchange_16x2 PROPERTIES LABELS "unit;sim" TIMEOUT 900)
  if(LLE_SIM_EXCHANGE_HA)
    add_test(NAME sim_determinism_exchange_ha_8x2
      COMMAND exsim --world=exchange_ha --seed=1000 --seeds=8 --check-determinism --quiet)
    set_tests_properties(sim_determinism_exchange_ha_8x2 PROPERTIES LABELS "unit;sim" TIMEOUT 900)
  endif()
endif()

# Simulator unit tests (docs/plan/09). Built against lle_sim_worlds, which
# pulls in the simulator core.
lle_test(sim_test
  SOURCES
    world_test.cpp
    clock_test.cpp
    fault_test.cpp
    network_test.cpp
    disk_test.cpp
    node_test.cpp
    oracle_test.cpp
    demo_test.cpp
    alloc_test.cpp
  DEPS lle_sim_worlds)

# 09 §9 PR determinism check: 128 seeds, each run twice, identical hashes.
add_test(NAME sim_determinism_128x2
  COMMAND exsim --seed=1000 --seeds=128 --check-determinism --quiet --exclude-world=exchange,exchange_ha)
set_tests_properties(sim_determinism_128x2 PROPERTIES LABELS "unit;sim" TIMEOUT 900)
# The exchange world has its own determinism test (sim/CMakeLists.txt): fewer seeds.

# Ledger and campaign tooling self-tests (python, no third-party modules
# required; PyYAML is used when present).
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  get_filename_component(_lle_repo "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
  add_test(NAME sim_ledger_tools_selftest
    COMMAND ${Python3_EXECUTABLE} "${_lle_repo}/tools/ledger/selftest.py" --exsim $<TARGET_FILE:exsim>
    WORKING_DIRECTORY "${_lle_repo}")
  set_tests_properties(sim_ledger_tools_selftest PROPERTIES LABELS "unit;tools" TIMEOUT 600)
  # Uncommitted fixes: every counted bug's found_patch must still apply (verify_bugs.py).
  add_test(NAME sim_ledger_found_patches_apply
    COMMAND ${Python3_EXECUTABLE} "${_lle_repo}/tools/ledger/check_found_patches.py"
    WORKING_DIRECTORY "${_lle_repo}")
  set_tests_properties(sim_ledger_found_patches_apply PROPERTIES LABELS "unit;tools" TIMEOUT 60)
endif()

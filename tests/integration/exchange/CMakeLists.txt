# exchanged end to end on one host over loopback (07 §3, N-03; T05, T06, T26 smoke).
# The tests run the real binaries: exchanged, witnessd, journal_replay, itch_validate.
if(LLE_BUILD_APPS AND (NOT LLE_ONLY OR "apps/exchanged" IN_LIST LLE_ONLY))
  set(_lle_e2e_defs
    LLE_EXCHANGED="$<TARGET_FILE:exchanged>"
    LLE_WITNESSD="$<TARGET_FILE:witnessd>"
    LLE_JOURNAL_REPLAY="$<TARGET_FILE:journal_replay>"
    LLE_ITCH_VALIDATE="$<TARGET_FILE:itch_validate>"
    LLE_NLOG_DECODE="$<TARGET_FILE:nlog_decode>"
    LLE_JOURNAL_DIFF="$<TARGET_FILE:journal_diff>"
    LLE_SNAPSHOTD="$<TARGET_FILE:snapshotd>"
    LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
  set(_lle_e2e_deps lle_journal lle_gateway lle_md lle_admin lle_soupbin lle_moldudp64 lle_ouch50 lle_engine lle_itch50 lle_metrics lle_glimpse)
  set(_lle_e2e_tools exchanged witnessd journal_replay itch_validate nlog_decode journal_diff snapshotd)
  set(_lle_e2e_tests exchange_smoke_test exchange_day_test exchange_restart_test exchange_ha_test exchange_failover_test)
  # GLIMPSE late joins through the reference client (when it is part of the build).
  if(NOT LLE_ONLY OR "apps/refclient" IN_LIST LLE_ONLY)
    list(APPEND _lle_e2e_defs LLE_REFCLIENT="$<TARGET_FILE:refclient>")
    list(APPEND _lle_e2e_tools refclient)
    list(APPEND _lle_e2e_tests exchange_glimpse_test)
  endif()
  # lle_top's STAGE WORK view of the day's metrics segment (T32).
  if(NOT LLE_ONLY OR "apps/lle_top" IN_LIST LLE_ONLY)
    list(APPEND _lle_e2e_defs LLE_LLE_TOP="$<TARGET_FILE:lle_top>")
    list(APPEND _lle_e2e_tools lle_top)
  endif()
  foreach(t ${_lle_e2e_tests})
    lle_test(${t} SOURCES ${t}.cpp DEPS ${_lle_e2e_deps})
    target_compile_definitions(${t} PRIVATE ${_lle_e2e_defs})
    add_dependencies(${t} ${_lle_e2e_tools})
  endforeach()
  # One failover trial per process, for bench/failover/run_trials.py (plan 10 §7, R-10).
  add_executable(exchange_failover_trial failover_trial.cpp)
  target_link_libraries(exchange_failover_trial PRIVATE lle_options ${_lle_e2e_deps} GTest::gtest)
  target_compile_options(exchange_failover_trial PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wno-dangling-else>)
  target_compile_definitions(exchange_failover_trial PRIVATE ${_lle_e2e_defs})
  add_dependencies(exchange_failover_trial ${_lle_e2e_tools})
  # Variant (iv) end to end: the node on AF_XDP behind a veth (root; label vm; 77 = skip).
  #   sudo ctest --test-dir <build> -L vm -R exchange_xsk --output-on-failure
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    foreach(t exchange_smoke_test exchange_day_test exchange_restart_test)
      add_test(NAME exchange_xsk_${t}
               COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/xsk_e2e.sh $<TARGET_FILE:${t}> --gtest_filter=-*Tshark*)
      set_tests_properties(exchange_xsk_${t} PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 900)
    endforeach()
    # Variants (ii) and (ii-s): the node applies and reports the busy-poll device settings.
    foreach(v busypoll busypoll-irq-suspend)
      add_test(NAME exchange_device_${v}
               COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/busypoll_device_e2e.sh ${v} $<TARGET_FILE:exchange_smoke_test>)
      set_tests_properties(exchange_device_${v} PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 300)
    endforeach()
  endif()
  # In-process: the node's configuration parser.
  lle_test(exchange_config_test SOURCES exchange_config_test.cpp DEPS lle_exchanged)
  lle_test(exchange_units_test SOURCES exchange_units_test.cpp DEPS lle_exchanged)
  target_compile_definitions(exchange_config_test PRIVATE LLE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
endif()

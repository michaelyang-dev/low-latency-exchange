# Loopback end-to-end tests of the client programs (07 §3; T10 on loopback). They
# run the real binaries: itch_synth for the day, mold_replay, refclient, loadgen,
# itch2ouch. Each test uses its own port range and scratch directory.
# The apps are added after the tests (top-level CMakeLists.txt), so their presence
# is decided from the build options and the LLE_ONLY filter, not with TARGET.
set(_have_apps ${LLE_BUILD_APPS})
foreach(_app itch_synth mold_replay refclient loadgen itch2ouch ttt_harness nlog_decode lle_top)
  lle_keep("apps/${_app}" _keep)
  if(NOT _keep)
    set(_have_apps OFF)
  endif()
endforeach()
if(NOT _have_apps)
  message(STATUS "tests/integration/client: client apps not in this build; skipped")
  return()
endif()
set(_d ${CMAKE_CURRENT_SOURCE_DIR})
set(_w ${CMAKE_CURRENT_BINARY_DIR})
# Each test's PORT_BASE (and the ~200 ports above it) lies below every OS's ephemeral
# range (Linux 32768-60999, macOS 49152-65535), so no socket another test opens meanwhile
# can be given one of them.
add_test(NAME client_feed_lossy_dual_lines
  COMMAND bash ${_d}/feed_lossy_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:mold_replay> $<TARGET_FILE:refclient>
          ${_w}/feed 28100)
add_test(NAME client_loadgen_loopback_server COMMAND bash ${_d}/loadgen_test.sh $<TARGET_FILE:loadgen> ${_w}/loadgen 28200)
add_test(NAME client_refclient_trading
  COMMAND bash ${_d}/refclient_trading_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:mold_replay>
          $<TARGET_FILE:refclient> $<TARGET_FILE:loadgen> ${_w}/trading 28300 $<TARGET_FILE:nlog_decode>
          $<TARGET_FILE:lle_top>)
add_test(NAME client_refclient_ha_takeover
  COMMAND bash ${_d}/refclient_ha_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:mold_replay>
          $<TARGET_FILE:refclient> $<TARGET_FILE:loadgen> ${_w}/ha 28400)
add_test(NAME client_refclient_glimpse_retry
  COMMAND bash ${_d}/refclient_glimpse_retry_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:mold_replay>
          $<TARGET_FILE:refclient> ${_w}/glimpse_retry 28700)
add_test(NAME client_itch2ouch_synthetic_day
  COMMAND bash ${_d}/itch2ouch_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:itch2ouch> ${_w}/i2o)
# T18 instrument loop over every kernel-socket variant this host has (the AF_XDP
# variants need root and veth: tests/integration/client/xsk_variants_test.sh, label vm).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(_variants epoll busypoll uring uring-napi)
else()
  set(_variants epoll)
endif()
add_test(NAME client_ttt_loop_variants
  COMMAND bash ${_d}/ttt_loop_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:ttt_harness> $<TARGET_FILE:refclient>
          ${_w}/ttt 28500 ${_variants})
set_tests_properties(client_feed_lossy_dual_lines client_loadgen_loopback_server client_refclient_trading
                     client_refclient_ha_takeover client_itch2ouch_synthetic_day client_ttt_loop_variants
                     client_refclient_glimpse_retry
                     PROPERTIES LABELS integration TIMEOUT 300)
if(LLE_SANITIZE)
  set_tests_properties(client_feed_lossy_dual_lines client_loadgen_loopback_server client_refclient_trading
                       client_refclient_ha_takeover client_itch2ouch_synthetic_day client_ttt_loop_variants
                       client_refclient_glimpse_retry PROPERTIES ${LLE_LOAD_SENSITIVE_PROPERTIES})
  set_tests_properties(client_ttt_loop_variants PROPERTIES ENVIRONMENT "LLE_TTT_RATE=20000;LLE_TTT_WAIT=90" TIMEOUT 900)
endif()
# The variants that need root and veth (busypoll's CAP_NET_ADMIN socket options, IRQ
# suspend on netdevsim, AF_XDP copy mode with utcp, the harness's AF_XDP feed):
#   sudo ctest --test-dir <build> -L vm -R client_xsk --output-on-failure
add_test(NAME client_xsk_variants_veth
  COMMAND bash ${_d}/xsk_variants_test.sh $<TARGET_FILE:itch_synth> $<TARGET_FILE:ttt_harness> $<TARGET_FILE:refclient>
          ${_w}/xskvar)
set_tests_properties(client_xsk_variants_veth PROPERTIES LABELS vm SKIP_RETURN_CODE 77 TIMEOUT 600)

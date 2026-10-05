# exchanged: the exchange node (07 §3, WP N-03). The node assembly is a library so the
# integration tests can use its configuration and helpers in-process.
lle_library(lle_exchanged
  SOURCES config.cpp metrics.cpp recovery.cpp node.cpp net_stages.cpp
  DEPS lle_gateway lle_md lle_sequencer lle_engine lle_journal lle_outlog lle_repl lle_witness lle_admin
       lle_net_backends lle_net_sock lle_runtime lle_log lle_metrics lle_soupbin lle_moldudp64 lle_ouch50
       lle_snapshot_engine)
target_include_directories(lle_exchanged PUBLIC "${CMAKE_SOURCE_DIR}/apps")
target_link_libraries(lle_exchanged PUBLIC lle_net_utcp)
# Variant (iv), AF_XDP (Linux with libbpf): xsk_net.h.
if(TARGET lle_net_xsk AND TARGET lle_net_utcp_linux)
  target_link_libraries(lle_exchanged PUBLIC lle_net_xsk lle_net_utcp_linux)
  target_compile_definitions(lle_exchanged PUBLIC LLE_EXCHANGED_HAVE_XSK=1)
endif()
lle_app(exchanged SOURCES main.cpp DEPS lle_exchanged)

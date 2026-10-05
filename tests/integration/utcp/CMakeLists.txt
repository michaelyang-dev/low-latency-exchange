# utcp integration tests (07 §2.4): randomized sessions over an in-memory lossy link
# (Utcp.LossReorderSeeds), the stream-port API, the allocation check, and the
# packetdrill-style scripted suite (*.pkt in this directory).
lle_test(utcp_sessions_test SOURCES random_sessions_test.cpp stream_port_test.cpp DEPS lle_net_utcp)
lle_test(utcp_alloc_test SOURCES stream_port_alloc_test.cpp DEPS lle_net_utcp)
lle_test(utcp_pkt_test SOURCES pkt_runner.cpp DEPS lle_net_utcp)
if(TARGET utcp_pkt_test)
  target_compile_definitions(utcp_pkt_test PRIVATE UTCP_PKT_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET lle_net_utcp_linux)
  add_subdirectory(interop)
endif()

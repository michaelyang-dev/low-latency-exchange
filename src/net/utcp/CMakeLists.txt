# utcp: in-repo user-space TCP (07 §2.4). The core is portable and sans-I/O; the Linux
# helpers (AF_PACKET frame port, netlink neighbour reader) build only on Linux.
lle_library(lle_net_utcp SOURCES wire.cpp arp.cpp connection.cpp DEPS lle_common lle_env ${LLE_SIM_HOOKS})

set(_utcp_linux_srcs linux/af_packet_port.cpp linux/neigh_netlink.cpp)
set(_utcp_linux_ok TRUE)
foreach(f IN LISTS _utcp_linux_srcs)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${f}")
    set(_utcp_linux_ok FALSE)
  endif()
endforeach()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND _utcp_linux_ok)
  lle_library(lle_net_utcp_linux SOURCES ${_utcp_linux_srcs} DEPS lle_net_utcp)
endif()

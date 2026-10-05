# Variant (iii)/(iii-n) io_uring backend (07-networking §2.2, WP N-07): Linux only,
# liburing via pkg-config (≥ 2.5 for the buffer-ring helpers; 2.12+ adds the TX
# timestamp command, detected at compile time).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LLE_NET_URING QUIET IMPORTED_TARGET liburing>=2.5)
  endif()
  if(LLE_NET_URING_FOUND)
    lle_library(lle_net_uring
      SOURCES ring.cpp udp_port.cpp tcp_port.cpp
      DEPS lle_net_sock PkgConfig::LLE_NET_URING)
  else()
    message(STATUS "lle_net_uring: liburing >= 2.5 not found; io_uring backend disabled")
  endif()
endif()

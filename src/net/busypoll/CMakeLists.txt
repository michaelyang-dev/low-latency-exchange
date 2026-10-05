# Variant (ii) busy polling (07-networking §1, WP N-06): EPIOCSPARAMS, per-socket
# SO_BUSY_POLL knobs, sysfs NAPI deferral, IRQ-suspend via netdev netlink. Linux only.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  lle_library(lle_net_busypoll SOURCES busypoll.cpp DEPS lle_net_sock)
endif()

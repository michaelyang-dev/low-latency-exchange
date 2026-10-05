set(_net_hwts_sources cmsg_test.cpp)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # Real SO_TIMESTAMPING plumbing on loopback (software stamps only) and the device
  # configuration flow against a fake ioctl.
  list(APPEND _net_hwts_sources errqueue_test.cpp device_test.cpp)
endif()
lle_test(net_hwts_test SOURCES ${_net_hwts_sources} DEPS lle_net_sock)

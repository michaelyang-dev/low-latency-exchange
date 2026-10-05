lle_test(net_sock_test
  SOURCES net_common_test.cpp udp_port_test.cpp tcp_port_test.cpp
  DEPS lle_net_sock)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET lle_net_busypoll)
  lle_test(net_busypoll_test SOURCES busypoll_test.cpp DEPS lle_net_busypoll)
endif()

# Kernel-socket backend (07-networking §2.1, WP N-02): edge-triggered epoll (Linux) /
# kqueue (macOS) reactor, UDP unicast+multicast port, TCP port. Variant (i) and the
# dev-host backend.
lle_library(lle_net_sock
  SOURCES poller.cpp socket_setup.cpp udp_port.cpp tcp_port.cpp
  DEPS lle_net_common lle_net_hwts)

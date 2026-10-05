# UDP ping-pong RTT benchmark over the kernel-socket and io_uring backends (07 §1).
# Open-loop sender, HdrHistogram; software timing only (see the file header). The
# AF_XDP benchmarks live in bench/net_xsk.
if(NOT TARGET hdr_histogram_static)
  message(STATUS "bench/net: HdrHistogram_c not available; net_udp_pingpong skipped")
  return()
endif()
lle_app(net_udp_pingpong SOURCES udp_pingpong.cpp DEPS lle_net_backends hdr_histogram_static)

# AF_XDP UDP ping-pong on veth (VM, copy mode; labelled, never a headline number).
#   sudo bench/net_xsk/run_pingpong.sh <build>/bench/net_xsk/xsk_pingpong [count]
if(NOT TARGET lle_net_xsk)
  return()
endif()
lle_app(xsk_pingpong SOURCES xsk_pingpong.cpp DEPS lle_net_xsk lle_net_utcp_linux)

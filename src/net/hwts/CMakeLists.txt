# Hardware timestamping (07-networking §2.5, WP N-08): cmsg/error-queue parsers, TX
# correlation and validity accounting (portable, tested everywhere), SO_TIMESTAMPING
# setup and NIC configuration (SIOCSHWTSTAMP, ethtool; Linux, ENOTSUP elsewhere).
lle_library(lle_net_hwts
  SOURCES cmsg.cpp socket_ts.cpp device.cpp
  DEPS lle_net_common)

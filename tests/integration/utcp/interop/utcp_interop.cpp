// utcp kernel-interop driver over an AF_PACKET raw socket (the AF_XDP variant is
// xsk_interop in tests/unit/net_xsk). See interop_driver.h; run by utcp_interop_test.sh.
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "interop_driver.h"
#include "net/utcp/linux/af_packet_port.h"

int main(int argc, char** argv) {
  using namespace lle::net::utcp;
  interop::Options o;
  std::string kind = "afpacket";
  if (!interop::parse_options(argc, argv, o, kind) || kind != "afpacket") {
    std::fprintf(stderr,
                 "usage: utcp_interop --if IF --local-ip IP (--peer-ip IP | --server) [--port P] [--bulk N] "
                 "[--messages N] [--max-msg N] [--pingpong N] [--close utcp|peer|peer-rst] [--duration-s S] "
                 "[--min-rto-ms N] [--mss N] [--seed N]\n");
    return 2;
  }
  auto port = AfPacketPort::open(o.ifname);
  if (!port) {
    std::fprintf(stderr, "utcp_interop: AF_PACKET on %s: %s\n", o.ifname.c_str(), std::strerror(port.error()));
    return 2;
  }
  lle::env::ProdClock clock;
  // utcp owns its own address on the link (the kernel in this namespace has none), so it
  // answers ARP itself and resolves the peer in-band.
  UtcpStreamPort<AfPacketPort, lle::env::ProdClock> stack(*port, clock, interop::stack_config(o, port->mac()));
  interop::Driver<AfPacketPort> d(stack, o);
  const int rc = d.run();
  std::printf("afpacket: rx_frames=%llu tx_frames=%llu tx_errors=%llu\n",
              static_cast<unsigned long long>(port->stats().rx_frames),
              static_cast<unsigned long long>(port->stats().tx_frames),
              static_cast<unsigned long long>(port->stats().tx_errors));
  return rc;
}

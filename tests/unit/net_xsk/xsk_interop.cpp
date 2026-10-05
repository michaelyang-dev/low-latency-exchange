// utcp over AF_XDP (XskFramePort) against Linux kernel TCP (07 §2.4 Utcp.InteropLinuxPeer,
// AF_XDP variant). The kernel in this namespace owns the address and answers ARP; the
// md_steer program redirects the utcp flow (local port) to the AF_XDP socket, so the
// kernel never sees it; the peer MAC comes from the kernel neighbour table (netlink).
// Copy mode on veth (dev/test override). Same phases and checks as utcp_interop.
#include <cstdio>
#include <cstring>

#include "interop_driver.h"
#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/linux/neigh_netlink.h"
#include "net/xsk/frame_port.h"
#include "net/xsk/socket.h"
#include "net/xsk/steer.h"

int main(int argc, char** argv) {
  using namespace lle::net;
  utcp::interop::Options o;
  std::string kind = "xsk";
  if (!utcp::interop::parse_options(argc, argv, o, kind)) {
    std::fprintf(stderr, "usage: xsk_interop --if IF --local-ip IP (--peer-ip IP | --server) [utcp_interop options]\n");
    return 2;
  }
  auto mac = utcp::interface_mac(o.ifname);
  if (!mac) return 2;
  auto prog = xsk::SteerProgram::load(xsk::SteerConfig{LLE_XSK_BPF_OBJECT, o.ifname, true, false});
  if (!prog) {
    std::fprintf(stderr, "xsk_interop: %s: %s\n", prog.error().what, std::strerror(prog.error().err));
    return 2;
  }
  auto umem = xsk::Umem::create(xsk::UmemConfig{});
  if (!umem) return 2;
  xsk::XskConfig xc;
  xc.ifname = o.ifname;
  xc.mode = xsk::BindMode::AllowCopy;
  xc.rx_metadata = true;
  auto sock = xsk::XskSocket::create(**umem, xc);
  if (!sock) {
    std::fprintf(stderr, "xsk_interop: %s: %s\n", sock.error().what, std::strerror(sock.error().err));
    return 2;
  }
  (void)(*prog)->set_xsk(0, (*sock)->fd());
  utcp::StackConfig sc = utcp::interop::stack_config(o, *mac);
  sc.arp_reply = false;  // the kernel owns the address and answers ARP
  if (o.server) {
    (void)(*prog)->add_utcp_port(o.port);
  } else {
    (void)(*prog)->add_utcp_port(sc.ephemeral_lo);  // the first active open uses it
    auto peer = utcp::resolve_via_kernel(o.ifname, o.peer_ip, 3000);
    if (!peer) {
      std::fprintf(stderr, "xsk_interop: peer MAC not resolved by the kernel\n");
      return 2;
    }
    sc.static_next_hop = *peer;
  }
  xsk::XskFramePort fp(**sock);
  lle::env::ProdClock clock;
  utcp::UtcpStreamPort<xsk::XskFramePort, lle::env::ProdClock> stack(fp, clock, sc);
  utcp::interop::Driver<xsk::XskFramePort> d(stack, o);
  const int rc = d.run();
  const xsk::XskStats xs = (*sock)->stats();
  const xsk::SteerStats st = (*prog)->stats();
  std::printf("xsk: mode=%s rx=%llu tx=%llu drops=%llu (rx_dropped=%llu rx_ring_full=%llu fill_empty=%llu "
              "tx_invalid=%llu) steer redirect_tcp=%llu drop_tcp=%llu pass=%llu\n",
              (*sock)->zero_copy() ? "zero-copy" : "copy", static_cast<unsigned long long>(xs.rx_frames),
              static_cast<unsigned long long>(xs.tx_frames), static_cast<unsigned long long>(xs.drops()),
              static_cast<unsigned long long>(xs.rx_dropped), static_cast<unsigned long long>(xs.rx_ring_full),
              static_cast<unsigned long long>(xs.rx_fill_ring_empty_descs),
              static_cast<unsigned long long>(xs.tx_invalid_descs), static_cast<unsigned long long>(st.redirect_tcp),
              static_cast<unsigned long long>(st.drop_tcp), static_cast<unsigned long long>(st.pass));
  return rc;
}

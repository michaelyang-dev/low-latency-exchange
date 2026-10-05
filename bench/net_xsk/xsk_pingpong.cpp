// UDP ping-pong RTT over AF_XDP (and a kernel-UDP baseline) between two network
// namespaces on a veth pair. VM / veth / copy mode: a functional smoke number, never a
// headline (07 §2.5, 12-benchmarking-evidence): veth has no zero-copy and no PHC, and
// the timestamps are CLOCK_MONOTONIC_RAW in user space.
//
//   xsk_pingpong --reflect --if IF --local-ip IP --port P [--kernel]
//   xsk_pingpong --client  --if IF --local-ip IP --peer-ip IP --port P [--kernel]
//                [--count N] [--warmup N] [--size BYTES] [--busy-poll]
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "env/prod_clock.h"
#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/linux/neigh_netlink.h"
#include "net/xsk/datagram_port.h"
#include "net/xsk/socket.h"
#include "net/xsk/steer.h"

namespace {

using namespace lle;
using namespace lle::net;

struct Opts {
  bool reflect = false;
  bool kernel = false;
  bool busy_poll = false;
  std::string ifname;
  std::uint32_t local_ip = 0;
  std::uint32_t peer_ip = 0;
  std::uint16_t port = 9500;
  long count = 100000;
  long warmup = 10000;
  std::size_t size = 64;
};

std::uint32_t ip(const char* s) {
  in_addr a{};
  return ::inet_pton(AF_INET, s, &a) == 1 ? ntohl(a.s_addr) : 0;
}

void report(const char* what, std::vector<Nanos>& rtt) {
  std::sort(rtt.begin(), rtt.end());
  auto p = [&](double q) { return static_cast<double>(rtt[std::min(rtt.size() - 1, static_cast<std::size_t>(q * static_cast<double>(rtt.size())))]) / 1000.0; };
  std::printf("xsk_pingpong %s: n=%zu RTT us p50=%.1f p90=%.1f p99=%.1f p99.9=%.1f max=%.1f  [VM veth, copy mode: not a headline]\n",
              what, rtt.size(), p(0.50), p(0.90), p(0.99), p(0.999), static_cast<double>(rtt.back()) / 1000.0);
}

int run_kernel(const Opts& o) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  sockaddr_in me{};
  me.sin_family = AF_INET;
  me.sin_port = htons(o.port);
  me.sin_addr.s_addr = htonl(o.local_ip);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&me), sizeof(me)) != 0) return 2;
  std::vector<char> buf(65536);
  sockaddr_in peer{};
  peer.sin_family = AF_INET;
  peer.sin_port = htons(o.port);
  peer.sin_addr.s_addr = htonl(o.peer_ip);
  if (o.reflect) {
    for (;;) {
      sockaddr_in from{};
      socklen_t fl = sizeof(from);
      const ssize_t n = ::recvfrom(fd, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&from), &fl);
      if (n > 0) (void)::sendto(fd, buf.data(), static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&from), fl);
    }
  }
  env::ProdClock clock;
  std::vector<Nanos> rtt;
  rtt.reserve(static_cast<std::size_t>(o.count));
  for (long i = 0; i < o.count + o.warmup; ++i) {
    const Nanos t0 = clock.now_mono();
    (void)::sendto(fd, buf.data(), o.size, 0, reinterpret_cast<sockaddr*>(&peer), sizeof(peer));
    while (::recv(fd, buf.data(), buf.size(), 0) <= 0) {
    }
    if (i >= o.warmup) rtt.push_back(clock.now_mono() - t0);
  }
  report("kernel-udp", rtt);
  return 0;
}

int run_xsk(const Opts& o) {
  auto mac = utcp::interface_mac(o.ifname);
  auto peer_mac = utcp::resolve_via_kernel(o.ifname, o.peer_ip, 3000);
  if (!mac || !peer_mac) {
    std::fprintf(stderr, "xsk_pingpong: cannot resolve MACs\n");
    return 2;
  }
  auto prog = xsk::SteerProgram::load(xsk::SteerConfig{LLE_XSK_BPF_OBJECT, o.ifname, true, false});
  if (!prog) {
    std::fprintf(stderr, "xsk_pingpong: %s: %s\n", prog.error().what, std::strerror(prog.error().err));
    return 2;
  }
  auto umem = xsk::Umem::create(xsk::UmemConfig{});
  if (!umem) return 2;
  xsk::XskConfig xc;
  xc.ifname = o.ifname;
  xc.mode = xsk::BindMode::AllowCopy;
  xc.busy_poll = o.busy_poll;
  auto sock = xsk::XskSocket::create(**umem, xc);
  if (!sock) {
    std::fprintf(stderr, "xsk_pingpong: %s: %s\n", sock.error().what, std::strerror(sock.error().err));
    return 2;
  }
  (void)(*prog)->set_xsk(0, (*sock)->fd());
  (void)(*prog)->add_md_port(o.port);
  xsk::XskDatagramConfig dc;
  dc.local_mac = *mac;
  dc.local_ip = o.local_ip;
  dc.local_port = o.port;
  dc.static_next_hop = *peer_mac;
  dc.rx_ports[0] = o.port;
  dc.verify_rx_checksum = false;
  xsk::XskDatagramPort dp(**sock, dc);
  std::vector<std::byte> payload(o.size);
  if (o.reflect) {
    for (;;) {
      (void)dp.poll_rx([&](const env::RxDatagram& r) { (void)dp.send(r.src, r.data); });
    }
  }
  env::ProdClock clock;
  std::vector<Nanos> rtt;
  rtt.reserve(static_cast<std::size_t>(o.count));
  for (long i = 0; i < o.count + o.warmup; ++i) {
    const Nanos t0 = clock.now_mono();
    if (!dp.send(env::Endpoint{o.peer_ip, o.port}, payload)) return 3;
    bool got = false;
    while (!got) (void)dp.poll_rx([&](const env::RxDatagram&) { got = true; });
    if (i >= o.warmup) rtt.push_back(clock.now_mono() - t0);
  }
  report((*sock)->zero_copy() ? "af_xdp(zero-copy)" : (o.busy_poll ? "af_xdp(copy,busy-poll)" : "af_xdp(copy)"), rtt);
  const xsk::XskStats st = (*sock)->stats();
  std::printf("xsk_pingpong: XDP_STATISTICS drops=%llu\n", static_cast<unsigned long long>(st.drops()));
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Opts o;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--reflect") o.reflect = true;
    else if (a == "--client") o.reflect = false;
    else if (a == "--kernel") o.kernel = true;
    else if (a == "--busy-poll") o.busy_poll = true;
    else if (a == "--if") o.ifname = next();
    else if (a == "--local-ip") o.local_ip = ip(next());
    else if (a == "--peer-ip") o.peer_ip = ip(next());
    else if (a == "--port") o.port = static_cast<std::uint16_t>(std::atoi(next()));
    else if (a == "--count") o.count = std::atol(next());
    else if (a == "--warmup") o.warmup = std::atol(next());
    else if (a == "--size") o.size = static_cast<std::size_t>(std::atol(next()));
    else {
      std::fprintf(stderr, "xsk_pingpong: unknown argument %s\n", a.c_str());
      return 2;
    }
  }
  if (o.ifname.empty() || o.local_ip == 0 || (!o.reflect && o.peer_ip == 0)) return 2;
  return o.kernel ? run_kernel(o) : run_xsk(o);
}

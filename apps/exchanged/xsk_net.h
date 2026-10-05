#pragma once
// Variant (iv) of the node (07 §1, §2.3, §2.4): the gateways serve SoupBinTCP over utcp
// on AF_XDP, and the md stage sends its lines and serves re-requests over AF_XDP UDP.
//
// Every AF_XDP stage owns one socket on its own (interface, NIC queue) ([xsk] gw0, gw1,
// md), with its own UMEM, polled by the stage's thread only. md_steer, one program per
// interface (XskDomain), redirects each stage's traffic to the socket of the queue it
// arrives on: the gateway's listening TCP port (utcp_ports) and the re-request UDP port
// (md_ports). Which queue a flow arrives on is the NIC's job: ethtool ntuple rules in
// the lab (lab/tune.sh), a tc skbedit queue_mapping on the peer of a veth in the VM test
// (tests/integration/exchange/xsk_e2e.sh). The kernel keeps the interface address and
// answers ARP. The GLIMPSE server (housekeeping) and replication stay on kernel sockets.
//
// Zero-copy is required (XskSocket refuses copy mode) unless [xsk] allow_copy is set,
// the dev/test override for veth and virtio; copy-mode runs are never measurements.
// Linux with libbpf only (LLE_EXCHANGED_HAVE_XSK).
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "env/concepts.h"
#include "env/prod_clock.h"
#include "exchanged/config.h"
#include "exchanged/xsk_config.h"
#include "net/common/error.h"
#include "net/common/port.h"
#include "net/utcp/linux/af_packet_port.h"
#include "net/utcp/stream_port.h"
#include "net/xsk/datagram_port.h"
#include "net/xsk/frame_port.h"
#include "net/xsk/socket.h"
#include "net/xsk/steer.h"
#include "net/xsk/umem.h"

namespace lle::exch {

// An interface's address as the kernel holds it (host order).
struct IfAddr {
  std::uint32_t ip = 0;
  std::uint32_t netmask = 0;
};
inline std::optional<IfAddr> interface_ipv4(const std::string& ifname) {
  ifaddrs* list = nullptr;
  if (::getifaddrs(&list) != 0) return std::nullopt;
  std::optional<IfAddr> out;
  for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
    if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET || ifname != a->ifa_name) continue;
    sockaddr_in sin;
    std::memcpy(&sin, a->ifa_addr, sizeof sin);
    IfAddr r;
    r.ip = ntohl(sin.sin_addr.s_addr);
    if (a->ifa_netmask != nullptr) {
      std::memcpy(&sin, a->ifa_netmask, sizeof sin);
      r.netmask = ntohl(sin.sin_addr.s_addr);
    }
    out = r;
    break;
  }
  ::freeifaddrs(list);
  return out;
}

// One stage's placement and addressing, resolved before the stages start.
struct XskStageNet {
  std::string ifname;
  std::uint32_t queue = 0;
  net::utcp::MacAddr mac;
  std::uint32_t local_ip = 0;
  std::uint32_t netmask = 0xFFFF'FF00u;
  std::uint16_t udp_source_port = 0;  // md: the lines' source port
};

// The md_steer programs of the node's interfaces, loaded on the main thread before the
// stages start (and detached when the node ends). Stages register their sockets and
// ports through the bpf maps from their own threads; the maps are kernel objects, and
// the program list is not modified after construction.
class XskDomain {
 public:
  static std::expected<std::unique_ptr<XskDomain>, std::string> create(const XskSettings& x) {
    std::unique_ptr<XskDomain> d(new XskDomain(x));
    for (const XskStage* s : {&x.gw[0], &x.gw[1], &x.md}) {
      if (d->find(s->ifname) != nullptr) continue;
      net::xsk::SteerConfig sc;
#if defined(LLE_XSK_BPF_OBJECT)
      sc.object_path = x.bpf_object.empty() ? std::string(LLE_XSK_BPF_OBJECT) : x.bpf_object;
#else
      sc.object_path = x.bpf_object;
#endif
      sc.ifname = s->ifname;
      sc.want_metadata = true;
      sc.allow_skb_mode = x.skb_mode;
      auto p = net::xsk::SteerProgram::load(sc);
      if (!p) {
        return std::unexpected("xsk: md_steer on " + s->ifname + ": " + p.error().what + ": " +
                               std::strerror(p.error().err));
      }
      d->progs_.emplace_back(s->ifname, std::move(*p));
    }
    return d;
  }

  // Placement and addressing of a stage ([xsk] local_ip, else the interface's address).
  std::expected<XskStageNet, std::string> stage(const XskStage& s) const {
    XskStageNet n;
    n.ifname = s.ifname;
    n.queue = s.queue;
    auto mac = net::utcp::interface_mac(s.ifname);
    if (!mac) return std::unexpected("xsk: " + s.ifname + ": no MAC address: " + std::strerror(mac.error()));
    n.mac = *mac;
    const auto a = interface_ipv4(s.ifname);
    n.local_ip = x_.local_ip != 0 ? x_.local_ip : (a ? a->ip : 0);
    if (a && a->netmask != 0) n.netmask = a->netmask;
    if (n.local_ip == 0) return std::unexpected("xsk: " + s.ifname + ": no IPv4 address ([xsk] local_ip)");
    return n;
  }

  [[nodiscard]] net::xsk::SteerProgram* find(const std::string& ifname) const noexcept {
    for (const auto& [name, p] : progs_)
      if (name == ifname) return p.get();
    return nullptr;
  }
  [[nodiscard]] const XskSettings& settings() const noexcept { return x_; }

 private:
  explicit XskDomain(const XskSettings& x) : x_(x) {}
  XskSettings x_;
  std::vector<std::pair<std::string, std::unique_ptr<net::xsk::SteerProgram>>> progs_;
};

inline net::Error xsk_error(const net::xsk::Error& e) noexcept { return net::Error{e.err, e.what}; }

class XskNet;

// env::StreamEndpointLike for a gateway: utcp over the stage's AF_XDP socket. Passive
// opens only (connect() refuses).
class XskStreamPort {
 public:
  using Utcp = net::utcp::UtcpStreamPort<net::xsk::XskFramePort, env::ProdClock>;

  std::size_t write(env::ConnId c, std::span<const std::byte> b) { return u_ ? u_->write(c, b) : 0; }
  template <class Cb>
  std::size_t poll(Cb&& cb) {
    return u_ ? u_->poll(std::forward<Cb>(cb)) : 0;
  }
  void close(env::ConnId c) {
    if (u_) u_->close(c);
  }
  // Listens on `ep` (address 0 or the stage's) and steers its port to this socket.
  net::Result<env::Endpoint> listen(env::Endpoint ep) {
    if (!u_) return net::fail("listen", EBADF);
    const auto bound = u_->listen(ep);
    if (!bound) return net::fail("listen", EADDRNOTAVAIL);
    if (steer_ != nullptr && !steer_->add_utcp_port(bound->port)) return net::fail("md_steer utcp_ports", EIO);
    return *bound;
  }
  net::Result<env::ConnId> connect(env::Endpoint) { return net::fail("connect", EOPNOTSUPP); }
  [[nodiscard]] const Utcp* stack() const noexcept { return u_.get(); }

 private:
  friend class XskNet;
  std::unique_ptr<net::xsk::XskFramePort> fp_;
  std::unique_ptr<Utcp> u_;
  net::xsk::SteerProgram* steer_ = nullptr;
};

// env::DatagramPortLike for the md stage: UDP over its AF_XDP socket. The line port
// only sends; the re-request port also receives (its port steered to this socket).
class XskUdpPort {
 public:
  bool send(env::Endpoint dst, std::span<const std::byte> p) noexcept { return d_ && d_->send(dst, p); }
  template <class Cb>
  std::size_t poll_rx(Cb&& cb) {
    return d_ ? d_->poll_rx(std::forward<Cb>(cb)) : 0;
  }
  [[nodiscard]] env::Endpoint local() const noexcept { return local_; }
  [[nodiscard]] const net::xsk::XskDatagramPort* port() const noexcept { return d_.get(); }

 private:
  friend class XskNet;
  std::unique_ptr<net::xsk::XskDatagramPort> d_;
  env::Endpoint local_{};
};

static_assert(env::StreamEndpointLike<XskStreamPort>);
static_assert(env::DatagramPortLike<XskUdpPort>);

// The Net of one AF_XDP stage (the gateway's or md's `Net`): configure() on the main
// thread, then open() and the ports on the stage's thread (its first poll).
class XskNet {
 public:
  using StreamPort = XskStreamPort;
  using DatagramPort = XskUdpPort;

  void configure(const XskDomain* domain, XskStageNet n) {
    domain_ = domain;
    n_ = std::move(n);
  }

  net::Result<void> open() {
    if (domain_ == nullptr) return net::fail("xsk: stage not configured", EINVAL);
    const XskSettings& x = domain_->settings();
    net::xsk::UmemConfig uc;
    uc.frame_count = x.umem_frames;
    auto umem = net::xsk::Umem::create(uc);
    if (!umem) return std::unexpected(xsk_error(umem.error()));
    umem_ = std::move(*umem);
    net::xsk::XskConfig xc;
    xc.ifname = n_.ifname;
    xc.queue = n_.queue;
    xc.mode = x.allow_copy ? net::xsk::BindMode::AllowCopy : net::xsk::BindMode::ZeroCopyRequired;
    xc.busy_poll = x.busy_poll;
    xc.rx_metadata = true;
    xc.fill_frames = std::min<std::uint32_t>(xc.fill_frames, x.umem_frames / 2);
    auto sock = net::xsk::XskSocket::create(*umem_, xc);
    if (!sock) return std::unexpected(xsk_error(sock.error()));
    sock_ = std::move(*sock);
    steer_ = domain_->find(n_.ifname);
    if (steer_ == nullptr || !steer_->set_xsk(n_.queue, sock_->fd())) return net::fail("md_steer xsks", EIO);
    return {};
  }

  net::Result<void> open(StreamPort& p, const net::TcpConfig& t) {
    if (!sock_) return net::fail("xsk: socket not open", EBADF);
    p.fp_ = std::make_unique<net::xsk::XskFramePort>(
        *sock_, net::xsk::XskFramePortConfig{domain_->settings().checksum_offload, false, false});
    p.u_ = std::make_unique<XskStreamPort::Utcp>(
        *p.fp_, clock_, gateway_stack_config(domain_->settings(), t, n_.mac, n_.local_ip, n_.netmask));
    p.steer_ = steer_;
    return {};
  }

  net::Result<void> open(DatagramPort& p, const net::UdpConfig& u) {
    if (!sock_) return net::fail("xsk: socket not open", EBADF);
    net::xsk::XskDatagramConfig dc;
    dc.local_mac = n_.mac;
    dc.local_ip = n_.local_ip;
    dc.netmask = n_.netmask;
    dc.static_next_hop = next_hop_of(domain_->settings());
    dc.checksum_offload = domain_->settings().checksum_offload;
    dc.local_port = u.bind.port != 0 ? u.bind.port : n_.udp_source_port;
    if (u.bind.port != 0) {
      dc.rx_ports[0] = u.bind.port;  // a receiving port: steered to this socket
      if (steer_ == nullptr || !steer_->add_md_port(u.bind.port)) return net::fail("md_steer md_ports", EIO);
    }
    p.d_ = std::make_unique<net::xsk::XskDatagramPort>(*sock_, dc);
    p.local_ = env::Endpoint{n_.local_ip, dc.local_port};
    return {};
  }

  // The stage polls its rings itself; nothing to wait for.
  int wait(Nanos) noexcept { return 0; }

  [[nodiscard]] const net::xsk::XskSocket* socket() const noexcept { return sock_.get(); }
  // "IF:Q copy|zero-copy: rx N tx N drops N" (shutdown report).
  [[nodiscard]] std::string report_line() const {
    std::string s = n_.ifname + ":" + std::to_string(n_.queue);
    if (!sock_) return s + " not open";
    const net::xsk::XskStats st = sock_->stats();
    return s + (sock_->zero_copy() ? " zero-copy" : " copy") + ": rx " + std::to_string(st.rx_frames) + " tx " +
           std::to_string(st.tx_frames) + " drops " + std::to_string(st.drops()) + " busy_poll " +
           (sock_->busy_poll_enabled() ? "on" : "off");
  }
  [[nodiscard]] const XskStageNet& placement() const noexcept { return n_; }

 private:
  const XskDomain* domain_ = nullptr;
  XskStageNet n_;
  env::ProdClock clock_;
  std::unique_ptr<net::xsk::Umem> umem_;
  std::unique_ptr<net::xsk::XskSocket> sock_;
  net::xsk::SteerProgram* steer_ = nullptr;
};

}  // namespace lle::exch

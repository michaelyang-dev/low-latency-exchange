#include "net/sock/socket_setup.h"

#include <sys/socket.h>

#include "net/common/iface.h"
#include "net/common/sockopt.h"
#include "net/hwts/socket_ts.h"

namespace lle::net::sock {

Result<UdpSocket> open_udp_socket(const UdpConfig& cfg) {
  auto fd = open_socket(SOCK_DGRAM);
  if (!fd) return std::unexpected(fd.error());
  const int s = fd->get();
  if (!cfg.groups.empty() || cfg.reuse_port) {
    if (auto r = set_reuse_addr(s, true); !r) return std::unexpected(r.error());
  }
  if (cfg.reuse_port) {
    if (auto r = set_reuse_port(s, true); !r) return std::unexpected(r.error());
  }
  if (cfg.rcvbuf > 0) {
    if (auto r = set_rcvbuf(s, cfg.rcvbuf); !r) return std::unexpected(r.error());
  }
  if (cfg.sndbuf > 0) {
    if (auto r = set_sndbuf(s, cfg.sndbuf); !r) return std::unexpected(r.error());
  }
  auto iface = lookup_iface(cfg.ifname);
  if (!iface) return std::unexpected(iface.error());
  if (auto r = bind_ipv4(s, cfg.bind); !r) return std::unexpected(r.error());
  auto local = local_endpoint(s);
  if (!local) return std::unexpected(local.error());
  for (const std::uint32_t g : cfg.groups) {
    if (auto r = join_multicast(s, g, *iface); !r) return std::unexpected(r.error());
  }
  if (!cfg.ifname.empty()) {
    if (auto r = set_multicast_if(s, *iface); !r) return std::unexpected(r.error());
  }
  if (auto r = set_multicast_ttl(s, cfg.mcast_ttl); !r) return std::unexpected(r.error());
  if (auto r = set_multicast_loop(s, cfg.mcast_loop); !r) return std::unexpected(r.error());
  if (cfg.dst_addr) {
    if (auto r = enable_dst_addr_cmsg(s); !r) return std::unexpected(r.error());
  }
  if (auto r = apply_busy_poll(s, cfg.busy_poll); !r) return std::unexpected(r.error());
  UdpSocket out;
  if (cfg.rx_ts != TsMode::Off || cfg.tx_ts != TsMode::Off) {
    auto f = hwts::enable_socket_timestamping(s, hwts::SocketTsRequest{cfg.rx_ts, cfg.tx_ts, false});
    if (!f) return std::unexpected(f.error());
    out.ts_flags = *f;
  }
  out.local = *local;
  out.fd = std::move(*fd);
  return out;
}

Result<void> setup_tcp_socket(int fd, const TcpConfig& cfg) {
  if (cfg.nodelay) {
    if (auto r = set_tcp_nodelay(fd, true); !r) return r;
  }
  if (cfg.rcvbuf > 0) {
    if (auto r = set_rcvbuf(fd, cfg.rcvbuf); !r) return r;
  }
  if (cfg.sndbuf > 0) {
    if (auto r = set_sndbuf(fd, cfg.sndbuf); !r) return r;
  }
  return apply_busy_poll(fd, cfg.busy_poll);
}

Result<TcpListener> open_tcp_listener(const TcpConfig& cfg, Endpoint bind) {
  auto fd = open_socket(SOCK_STREAM);
  if (!fd) return std::unexpected(fd.error());
  const int s = fd->get();
  if (auto r = set_reuse_addr(s, true); !r) return std::unexpected(r.error());
  // Accepted sockets inherit these; the ports repeat them per connection anyway.
  if (auto r = setup_tcp_socket(s, cfg); !r) return std::unexpected(r.error());
  if (auto r = bind_ipv4(s, bind); !r) return std::unexpected(r.error());
  if (::listen(s, cfg.backlog) != 0) return fail_errno("listen");
  auto local = local_endpoint(s);
  if (!local) return std::unexpected(local.error());
  return TcpListener{std::move(*fd), *local};
}

Result<std::uint32_t> enable_tcp_timestamps(int fd, const TcpConfig& cfg) {
  if (cfg.rx_ts == TsMode::Off && cfg.tx_ts == TsMode::Off) return 0u;
  return hwts::enable_socket_timestamping(fd, hwts::SocketTsRequest{cfg.rx_ts, cfg.tx_ts, true});
}

}  // namespace lle::net::sock

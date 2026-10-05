#include "net/common/sockopt.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

namespace lle::net {

Result<UniqueFd> open_socket(int type) {
#if defined(__linux__)
  UniqueFd fd(::socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
  if (!fd) return fail_errno("socket");
#else
  UniqueFd fd(::socket(AF_INET, type, 0));
  if (!fd) return fail_errno("socket");
  if (auto r = set_nonblocking(fd.get()); !r) return std::unexpected(r.error());
  if (::fcntl(fd.get(), F_SETFD, FD_CLOEXEC) != 0) return fail_errno("fcntl(FD_CLOEXEC)");
  if (auto r = set_int_option(fd.get(), SOL_SOCKET, SO_NOSIGPIPE, 1, "setsockopt(SO_NOSIGPIPE)"); !r)
    return std::unexpected(r.error());
#endif
  return fd;
}

Result<void> set_nonblocking(int fd) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl < 0) return fail_errno("fcntl(F_GETFL)");
  if (::fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) return fail_errno("fcntl(F_SETFL)");
  return {};
}

Result<void> set_int_option(int fd, int level, int name, int value, const char* op) {
  if (::setsockopt(fd, level, name, &value, sizeof(value)) != 0) return fail_errno(op);
  return {};
}

Result<int> get_int_option(int fd, int level, int name, const char* op) {
  int v = 0;
  socklen_t len = sizeof(v);
  if (::getsockopt(fd, level, name, &v, &len) != 0) return fail_errno(op);
  return v;
}

Result<void> set_reuse_addr(int fd, bool on) {
  return set_int_option(fd, SOL_SOCKET, SO_REUSEADDR, on ? 1 : 0, "setsockopt(SO_REUSEADDR)");
}

Result<void> set_reuse_port(int fd, bool on) {
  return set_int_option(fd, SOL_SOCKET, SO_REUSEPORT, on ? 1 : 0, "setsockopt(SO_REUSEPORT)");
}

Result<void> set_tcp_nodelay(int fd, bool on) {
  return set_int_option(fd, IPPROTO_TCP, TCP_NODELAY, on ? 1 : 0, "setsockopt(TCP_NODELAY)");
}

Result<void> set_rcvbuf(int fd, int bytes) {
  return set_int_option(fd, SOL_SOCKET, SO_RCVBUF, bytes, "setsockopt(SO_RCVBUF)");
}

Result<void> set_sndbuf(int fd, int bytes) {
  return set_int_option(fd, SOL_SOCKET, SO_SNDBUF, bytes, "setsockopt(SO_SNDBUF)");
}

Result<void> bind_ipv4(int fd, Endpoint local) {
  const sockaddr_in sa = to_sockaddr(local);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0) return fail_errno("bind");
  return {};
}

Result<Endpoint> local_endpoint(int fd) {
  sockaddr_in sa{};
  socklen_t len = sizeof(sa);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &len) != 0) return fail_errno("getsockname");
  return from_sockaddr(sa);
}

Result<Endpoint> peer_endpoint(int fd) {
  sockaddr_in sa{};
  socklen_t len = sizeof(sa);
  if (::getpeername(fd, reinterpret_cast<sockaddr*>(&sa), &len) != 0) return fail_errno("getpeername");
  return from_sockaddr(sa);
}

namespace {
Result<void> membership(int fd, int opt, std::uint32_t group, const Iface& iface, const char* op) {
  if (!is_multicast(group)) return fail(op, EINVAL);
#if defined(__linux__)
  ip_mreqn m{};
  m.imr_multiaddr.s_addr = htonl(group);
  m.imr_address.s_addr = htonl(iface.ipv4);
  m.imr_ifindex = static_cast<int>(iface.index);
#else
  ip_mreq m{};
  m.imr_multiaddr.s_addr = htonl(group);
  m.imr_interface.s_addr = htonl(iface.ipv4);
#endif
  if (::setsockopt(fd, IPPROTO_IP, opt, &m, sizeof(m)) != 0) return fail_errno(op);
  return {};
}
}  // namespace

Result<void> join_multicast(int fd, std::uint32_t group, const Iface& iface) {
  return membership(fd, IP_ADD_MEMBERSHIP, group, iface, "setsockopt(IP_ADD_MEMBERSHIP)");
}

Result<void> leave_multicast(int fd, std::uint32_t group, const Iface& iface) {
  return membership(fd, IP_DROP_MEMBERSHIP, group, iface, "setsockopt(IP_DROP_MEMBERSHIP)");
}

Result<void> set_multicast_if(int fd, const Iface& iface) {
#if defined(__linux__)
  ip_mreqn m{};
  m.imr_address.s_addr = htonl(iface.ipv4);
  m.imr_ifindex = static_cast<int>(iface.index);
  if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &m, sizeof(m)) != 0) return fail_errno("setsockopt(IP_MULTICAST_IF)");
#else
  in_addr a{};
  a.s_addr = htonl(iface.ipv4);
  if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &a, sizeof(a)) != 0) return fail_errno("setsockopt(IP_MULTICAST_IF)");
#endif
  return {};
}

Result<void> set_multicast_ttl(int fd, int ttl) {
#if defined(__APPLE__)
  const unsigned char v = static_cast<unsigned char>(ttl);
  if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &v, sizeof(v)) != 0) return fail_errno("setsockopt(IP_MULTICAST_TTL)");
  return {};
#else
  return set_int_option(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl, "setsockopt(IP_MULTICAST_TTL)");
#endif
}

Result<void> set_multicast_loop(int fd, bool on) {
#if defined(__APPLE__)
  const unsigned char v = on ? 1 : 0;
  if (::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &v, sizeof(v)) != 0) return fail_errno("setsockopt(IP_MULTICAST_LOOP)");
  return {};
#else
  return set_int_option(fd, IPPROTO_IP, IP_MULTICAST_LOOP, on ? 1 : 0, "setsockopt(IP_MULTICAST_LOOP)");
#endif
}

Result<void> enable_dst_addr_cmsg(int fd) {
#if defined(__linux__)
  return set_int_option(fd, IPPROTO_IP, IP_PKTINFO, 1, "setsockopt(IP_PKTINFO)");
#else
  return set_int_option(fd, IPPROTO_IP, IP_RECVDSTADDR, 1, "setsockopt(IP_RECVDSTADDR)");
#endif
}

Result<int> socket_error(int fd) { return get_int_option(fd, SOL_SOCKET, SO_ERROR, "getsockopt(SO_ERROR)"); }

Result<void> apply_busy_poll(int fd, const BusyPollOptions& o) {
  if (!o.any()) return {};
#if defined(__linux__)
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif
  if (o.busy_poll_us != 0) {
    if (auto r = set_int_option(fd, SOL_SOCKET, SO_BUSY_POLL, static_cast<int>(o.busy_poll_us), "setsockopt(SO_BUSY_POLL)");
        !r)
      return r;
  }
  if (o.prefer) {
    if (auto r = set_int_option(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, 1, "setsockopt(SO_PREFER_BUSY_POLL)"); !r) return r;
  }
  if (o.budget != 0) {
    if (auto r = set_int_option(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, o.budget, "setsockopt(SO_BUSY_POLL_BUDGET)"); !r)
      return r;
  }
  return {};
#else
  (void)fd;
  return fail("apply_busy_poll", ENOTSUP);
#endif
}

}  // namespace lle::net

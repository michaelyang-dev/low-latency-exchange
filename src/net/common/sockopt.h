#pragma once
// Socket creation and option helpers shared by every kernel-socket backend
// (07-networking §2.1). All of these run at setup time.
//
// Platform notes:
//   - Linux: SOCK_NONBLOCK|SOCK_CLOEXEC at creation; multicast uses ip_mreqn (by ifindex).
//   - macOS: fcntl for O_NONBLOCK/FD_CLOEXEC, SO_NOSIGPIPE instead of MSG_NOSIGNAL;
//     multicast uses ip_mreq (by interface address).
#include <cstdint>

#include "net/common/endpoint.h"
#include "net/common/error.h"
#include "net/common/fd.h"
#include "net/common/iface.h"

namespace lle::net {

// Per-socket busy-poll knobs (Linux ≥5.11, R3a Q5). Zero/false fields are left at the
// kernel default. Raising the budget above 8 or setting prefer needs CAP_NET_ADMIN.
struct BusyPollOptions {
  std::uint32_t busy_poll_us = 0;  // SO_BUSY_POLL
  bool prefer = false;             // SO_PREFER_BUSY_POLL
  std::uint16_t budget = 0;        // SO_BUSY_POLL_BUDGET

  [[nodiscard]] bool any() const noexcept { return busy_poll_us != 0 || prefer || budget != 0; }
};

// IPv4 socket (SOCK_DGRAM or SOCK_STREAM), non-blocking, close-on-exec, no SIGPIPE.
[[nodiscard]] Result<UniqueFd> open_socket(int type);

Result<void> set_nonblocking(int fd);
Result<void> set_int_option(int fd, int level, int name, int value, const char* op);
[[nodiscard]] Result<int> get_int_option(int fd, int level, int name, const char* op);

Result<void> set_reuse_addr(int fd, bool on);
Result<void> set_reuse_port(int fd, bool on);
Result<void> set_tcp_nodelay(int fd, bool on);
Result<void> set_rcvbuf(int fd, int bytes);
Result<void> set_sndbuf(int fd, int bytes);

Result<void> bind_ipv4(int fd, Endpoint local);
[[nodiscard]] Result<Endpoint> local_endpoint(int fd);
[[nodiscard]] Result<Endpoint> peer_endpoint(int fd);

// IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP on `iface` (07 §2.1: ip_mreqn on Linux).
Result<void> join_multicast(int fd, std::uint32_t group, const Iface& iface);
Result<void> leave_multicast(int fd, std::uint32_t group, const Iface& iface);
// Outgoing multicast interface, TTL and loopback.
Result<void> set_multicast_if(int fd, const Iface& iface);
Result<void> set_multicast_ttl(int fd, int ttl);
Result<void> set_multicast_loop(int fd, bool on);

// Delivers the datagram's destination address as a cmsg (IP_PKTINFO on Linux,
// IP_RECVDSTADDR on macOS) so multicast receivers can tell groups apart.
Result<void> enable_dst_addr_cmsg(int fd);

// SO_ERROR (pending socket error, cleared by the read).
[[nodiscard]] Result<int> socket_error(int fd);

// Applies the non-default fields of `o` (Linux only; ENOTSUP elsewhere if any field is set).
Result<void> apply_busy_poll(int fd, const BusyPollOptions& o);

}  // namespace lle::net

#pragma once
// Socket creation and configuration shared by every kernel-socket data path (the sock
// ports here and the io_uring ports in net/uring), so all variants open sockets with
// identical options (ADR-012: only the backend changes). Cold path.
#include <cstdint>

#include "net/common/endpoint.h"
#include "net/common/error.h"
#include "net/common/fd.h"
#include "net/common/port.h"

namespace lle::net::sock {

struct UdpSocket {
  UniqueFd fd;
  Endpoint local{};
  std::uint32_t ts_flags = 0;  // SO_TIMESTAMPING flags actually set
};

// Non-blocking UDP socket per `cfg`: reuse options, buffers, bind, multicast joins and
// TX settings (interface, TTL, loop), destination-address cmsgs, busy poll and
// SO_TIMESTAMPING.
[[nodiscard]] Result<UdpSocket> open_udp_socket(const UdpConfig& cfg);

// TCP_NODELAY, buffers and busy poll on a TCP socket.
Result<void> setup_tcp_socket(int fd, const TcpConfig& cfg);

struct TcpListener {
  UniqueFd fd;
  Endpoint local{};
};
[[nodiscard]] Result<TcpListener> open_tcp_listener(const TcpConfig& cfg, Endpoint bind);

// SO_TIMESTAMPING (with OPT_ID|OPT_ID_TCP for TX) on an *established* TCP socket: the
// kernel rejects OPT_ID in CLOSE/LISTEN state and OPT_ID_TCP keys count from write_seq
// when the option is set. Returns 0 when timestamping is off.
[[nodiscard]] Result<std::uint32_t> enable_tcp_timestamps(int fd, const TcpConfig& cfg);

}  // namespace lle::net::sock

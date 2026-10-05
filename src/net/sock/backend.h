#pragma once
// Variant (i) binding (07 §1): kernel UDP/TCP on an edge-triggered epoll set (kqueue on
// macOS), blocking waits allowed. net/busypoll binds variant (ii) to the same types.
#include "net/common/port.h"
#include "net/sock/poller.h"
#include "net/sock/tcp_port.h"
#include "net/sock/udp_port.h"

namespace lle::net {

template <>
struct Backend<BackendKind::Epoll> {
  static constexpr BackendKind kind = BackendKind::Epoll;
  using Reactor = sock::Poller;
  using DatagramPort = sock::UdpPort;
  using StreamPort = sock::TcpPort;
};

static_assert(env::DatagramPortLike<sock::UdpPort>);
static_assert(env::StreamPortLike<sock::TcpPort>);
static_assert(env::StreamEndpointLike<sock::TcpPort>);
static_assert(BackendTraits<Backend<BackendKind::Epoll>>);

}  // namespace lle::net

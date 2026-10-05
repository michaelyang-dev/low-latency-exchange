#pragma once
// Variant (iii) and (iii-n) bindings (07 §1). Both use the same port types; (iii-n)
// differs only in its Ring: RingConfig::napi.enable = true (IORING_REGISTER_NAPI
// {busy_poll_to=50, prefer_busy_poll=1}) and a loop that calls Ring::poll(t) with t > 0,
// because io_uring busy-polls NAPI only while waiting for completions.
#include "net/common/port.h"
#include "net/uring/ring.h"
#include "net/uring/tcp_port.h"
#include "net/uring/udp_port.h"

namespace lle::net {

template <>
struct Backend<BackendKind::Uring> {
  static constexpr BackendKind kind = BackendKind::Uring;
  using Reactor = uring::Ring;
  using DatagramPort = uring::UdpPort;
  using StreamPort = uring::TcpPort;
  static uring::RingConfig ring_config() { return uring::RingConfig{}; }
};

template <>
struct Backend<BackendKind::UringNapi> {
  static constexpr BackendKind kind = BackendKind::UringNapi;
  using Reactor = uring::Ring;
  using DatagramPort = uring::UdpPort;
  using StreamPort = uring::TcpPort;
  static uring::RingConfig ring_config() {
    uring::RingConfig c;
    c.napi = uring::NapiOptions{true, 50, true};
    return c;
  }
};

static_assert(env::DatagramPortLike<uring::UdpPort>);
static_assert(env::StreamPortLike<uring::TcpPort>);
static_assert(env::StreamEndpointLike<uring::TcpPort>);
static_assert(BackendTraits<Backend<BackendKind::Uring>>);
static_assert(BackendTraits<Backend<BackendKind::UringNapi>>);

}  // namespace lle::net

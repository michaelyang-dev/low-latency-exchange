#pragma once
// Backend selection for tools and stage wiring (07 §1, WP N-13): Stack<K> owns a
// variant's reactor, opens ports with that variant's settings and waits with its wait
// strategy; with_backend() maps a runtime BackendKind to the compile-time Stack.
// Link target: lle_net_backends (every backend compiled into this build).
//
// Wait strategies (07 §1):
//   (i)    Epoll      blocking epoll_wait / kevent (interrupt-driven)
//   (ii)   BusyPoll   EPIOCSPARAMS{50 us, 64, prefer} + per-socket SO_*BUSY_POLL; epoll_wait
//                     busy-polls NAPI before it sleeps
//   (iii)  Uring      SINGLE_ISSUER|DEFER_TASKRUN ring polled in spin mode
//   (iii-n) UringNapi IORING_REGISTER_NAPI{50 us, prefer}; waits with a timeout so the
//                     kernel busy-polls in the CQ wait path
// Each can be forced to Spin or Block for pilot runs.
#include <cstdint>

#include "net/common/port.h"
#include "net/sock/backend.h"
#if defined(__linux__)
#include "net/busypoll/busypoll.h"
#if defined(LLE_NET_HAVE_URING)
#include "net/uring/backend.h"
#endif
#endif

namespace lle::net {

enum class WaitPolicy : std::uint8_t { Default, Spin, Block };

[[nodiscard]] constexpr bool is_uring(BackendKind k) noexcept {
  return k == BackendKind::Uring || k == BackendKind::UringNapi;
}

template <BackendKind K>
class Stack {
 public:
  using B = Backend<K>;
  using Reactor = typename B::Reactor;
  using DatagramPort = typename B::DatagramPort;
  using StreamPort = typename B::StreamPort;
  static constexpr BackendKind kind = K;

  explicit Stack(WaitPolicy w = WaitPolicy::Default) noexcept : wait_(w) {}

  Result<void> open() {
    if constexpr (is_uring(K)) {
      return reactor_.open(B::ring_config());
    } else {
      if (auto r = reactor_.open(); !r) return r;
#if defined(__linux__)
      if constexpr (K == BackendKind::BusyPoll) return busypoll::configure_reactor(reactor_, busypoll::Config{});
#endif
      return {};
    }
  }

  Result<void> open(DatagramPort& p, UdpConfig cfg) {
#if defined(__linux__)
    if constexpr (K == BackendKind::BusyPoll) busypoll::apply_to(cfg, busypoll::Config{});
#endif
    return p.open(cfg, &reactor_);
  }

  Result<void> open(StreamPort& p, TcpConfig cfg) {
#if defined(__linux__)
    if constexpr (K == BackendKind::BusyPoll) busypoll::apply_to(cfg, busypoll::Config{});
#endif
    return p.open(cfg, &reactor_);
  }

  // One wait per the variant's strategy, never longer than `max_ns` (≥ 0).
  int wait(Nanos max_ns) noexcept {
    const bool spin = wait_ == WaitPolicy::Spin || (wait_ == WaitPolicy::Default && K == BackendKind::Uring);
    return reactor_.poll(spin ? 0 : max_ns);
  }

  [[nodiscard]] Reactor& reactor() noexcept { return reactor_; }
  [[nodiscard]] WaitPolicy wait_policy() const noexcept { return wait_; }

 private:
  Reactor reactor_;
  WaitPolicy wait_;
};

// Calls f.template operator()<K>() with the compile-time kind for `k`. Returns false if
// that backend is not compiled into this build (Xsk is wired by net/xsk).
template <class F>
bool with_backend(BackendKind k, F&& f) {
  switch (k) {
    case BackendKind::Epoll: f.template operator()<BackendKind::Epoll>(); return true;
#if defined(__linux__)
    case BackendKind::BusyPoll: f.template operator()<BackendKind::BusyPoll>(); return true;
#if defined(LLE_NET_HAVE_URING)
    case BackendKind::Uring: f.template operator()<BackendKind::Uring>(); return true;
    case BackendKind::UringNapi: f.template operator()<BackendKind::UringNapi>(); return true;
#endif
#endif
    default: return false;
  }
}

}  // namespace lle::net

#pragma once
// NetPort facade (07-networking §1, WP N-01): the configuration, statistics and
// backend-selection types every backend shares, so variant wiring (N-13) builds any
// backend from the same config and only the backend type changes (ADR-012).
//
// A backend is a set of three types bound by a specialization of Backend<K>:
//   Reactor       the per-thread readiness/completion source (epoll/kqueue set, io_uring);
//                 `poll(Nanos timeout)` waits per the variant's wait strategy.
//   DatagramPort  satisfies env::DatagramPortLike (UDP unicast + multicast).
//   StreamPort    satisfies env::StreamEndpointLike (StreamPortLike + listen/connect).
// Specializations live with each backend (net/sock/backend.h, net/uring/backend.h);
// net/xsk adds its own. Ports attach to a caller-owned Reactor shared by every port on
// the thread, or own a private one when constructed without it.
//
// Callback conventions (no batch storage, no per-message allocation):
//   DatagramPort::poll_rx(cb)      cb(const env::RxDatagram&)
//   DatagramPort::poll_rx_ts(cb)   cb(const env::RxDatagram&, const RxTimestamps&)
//   StreamPort::poll(cb)           cb(const env::StreamEvent&)
// Spans passed to callbacks are valid only during the call.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "env/concepts.h"
#include "net/common/endpoint.h"
#include "net/common/sockopt.h"
#include "net/common/timestamps.h"

namespace lle::net {

// The variants of 07 §1. UringNapi is (iii-n).
enum class BackendKind : std::uint8_t { Epoll, BusyPoll, Uring, UringNapi, Xsk };

inline constexpr std::array<BackendKind, 5> kAllBackends = {BackendKind::Epoll, BackendKind::BusyPoll, BackendKind::Uring,
                                                            BackendKind::UringNapi, BackendKind::Xsk};

[[nodiscard]] const char* to_string(BackendKind k) noexcept;
// Accepts "epoll" (alias "sock", "kqueue"), "busypoll", "uring", "uring-napi", "xsk".
[[nodiscard]] std::optional<BackendKind> parse_backend(std::string_view s) noexcept;
// True if this build/platform provides the backend's types (Xsk is owned by net/xsk and
// reported false here).
[[nodiscard]] bool backend_compiled(BackendKind k) noexcept;

struct UdpConfig {
  Endpoint bind{};                     // local address/port; port 0 = ephemeral. Multicast
                                       // receivers bind INADDR_ANY:port (or group:port).
  std::vector<std::uint32_t> groups;   // multicast groups to join (host order)
  std::string ifname;                  // joins and multicast TX; empty = kernel's choice
  int rcvbuf = 0;                      // bytes; 0 = OS default
  int sndbuf = 0;
  int mcast_ttl = 1;
  bool mcast_loop = false;             // receive our own multicast (tests, single host)
  bool reuse_port = false;             // several receivers on one port
  bool dst_addr = true;                // report RxDatagram::dst (IP_PKTINFO / IP_RECVDSTADDR)
  std::uint32_t batch = 32;            // datagrams per poll_rx call (recvmmsg vlen / CQE budget)
  std::uint32_t max_datagram = 2048;   // RX bytes per datagram (MoldUDP64 ≤ 1,472, 07 §2.2)
  std::uint32_t rx_buffers = 512;      // io_uring provided buffers (power of two)
  std::uint32_t tx_slots = 64;         // io_uring in-flight sends
  TsMode rx_ts = TsMode::Off;
  TsMode tx_ts = TsMode::Off;
  BusyPollOptions busy_poll{};         // per-socket busy poll (variant ii)
};

struct TcpConfig {
  std::uint32_t max_conns = 64;              // listener + connections share the table
  std::uint32_t rx_buf_bytes = 16 * 1024;    // sock: read scratch; io_uring: provided buffer size
  std::uint32_t rx_buffers = 256;            // io_uring provided buffers (power of two); RX memory
                                             // is rx_buffers × rx_buf_bytes per port
  std::uint32_t tx_staging_bytes = 64 * 1024;  // io_uring: per-connection send staging
  std::uint32_t max_reads_per_poll = 16;     // per connection per poll (fairness)
  bool nodelay = true;                       // TCP_NODELAY (07 §2.1)
  // One write() = one send() with MSG_EOR on Linux, so the kernel never merges two writes
  // into one skb and TX timestamps (OPT_ID_TCP) map 1:1 to orders (07 §2.1, R3a §3.3).
  bool one_msg_per_send = true;
  int rcvbuf = 0;
  int sndbuf = 0;
  int backlog = 128;
  TsMode rx_ts = TsMode::Off;
  TsMode tx_ts = TsMode::Off;
  BusyPollOptions busy_poll{};
};

struct DatagramStats {
  std::uint64_t rx_packets = 0;
  std::uint64_t rx_bytes = 0;
  std::uint64_t rx_truncated = 0;  // datagram larger than max_datagram
  std::uint64_t rx_errors = 0;
  std::uint64_t rx_calls = 0;      // receive syscalls (sock) / receive CQEs (io_uring)
  std::uint64_t tx_packets = 0;
  std::uint64_t tx_bytes = 0;
  std::uint64_t tx_dropped = 0;    // EAGAIN/ENOBUFS or no free TX slot
  std::uint64_t tx_errors = 0;
  std::uint64_t rearms = 0;        // io_uring multishot re-arms (CQE without F_MORE)
  std::uint64_t no_buffers = 0;    // io_uring -ENOBUFS (provided-buffer ring empty)
  TsValidity rx_ts{};
};

struct StreamStats {
  std::uint64_t accepted = 0;
  std::uint64_t accept_rejected = 0;  // table full: accepted and closed at once
  std::uint64_t connected = 0;
  std::uint64_t closed = 0;           // Closed events delivered
  std::uint64_t rx_bytes = 0;
  std::uint64_t rx_reads = 0;
  std::uint64_t tx_bytes = 0;
  std::uint64_t tx_sends = 0;         // send() calls / SEND SQEs
  std::uint64_t tx_short = 0;         // write() accepted fewer bytes than offered
  std::uint64_t errors = 0;
  std::uint64_t rearms = 0;
  std::uint64_t no_buffers = 0;
  TsValidity rx_ts{};
};

// Specialized by each backend. Primary template intentionally undefined.
template <BackendKind K>
struct Backend;

template <class B>
concept BackendTraits = env::DatagramPortLike<typename B::DatagramPort> &&
                        env::StreamEndpointLike<typename B::StreamPort> && requires(typename B::Reactor& r) {
                          { r.poll(Nanos{0}) } -> std::same_as<int>;
                        };

}  // namespace lle::net

#pragma once
// Variant (ii): kernel sockets with busy polling (07 §1, §2.1; R3a Q5). Linux only.
//
// The data path is the sock backend unchanged (same UdpPort/TcpPort/Poller types); this
// module adds the knobs that make the kernel poll the NIC instead of waiting for IRQs:
//   - per socket: SO_BUSY_POLL, SO_PREFER_BUSY_POLL, SO_BUSY_POLL_BUDGET (5.11);
//   - per epoll set: EPIOCSPARAMS{busy_poll_usecs, budget, prefer} (6.9). Busy polling
//     only works if every fd in one epoll set shares a NAPI ID, so build one Poller per
//     NIC queue (check with incoming_napi_id());
//   - per device: napi_defer_hard_irqs and gro_flush_timeout (sysfs), which keep IRQs
//     masked while the application keeps polling (the "promise" prefer_busy_poll makes);
//   - IRQ-suspend sub-variant (6.13): per-NAPI irq-suspend-timeout via netdev netlink
//     napi-set; IRQs stay suspended while epoll keeps finding events, with
//     defer_hard_irqs/gro_flush_timeout as the safety net when it does not.
// Device-level calls need CAP_NET_ADMIN and change host state; they run from the lab
// tuning scripts and the variant wiring, never from unit tests.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "net/common/error.h"
#include "net/common/port.h"
#include "net/common/sockopt.h"
#include "net/sock/backend.h"

namespace lle::net::busypoll {

// struct epoll_params (include/uapi/linux/eventpoll.h).
struct EpollParams {
  std::uint32_t busy_poll_usecs = 50;
  std::uint16_t budget = 64;  // > 64 needs CAP_NET_ADMIN
  bool prefer = true;
};

Result<void> set_epoll_params(int epfd, const EpollParams& p);
[[nodiscard]] Result<EpollParams> get_epoll_params(int epfd);

// Reads back SO_BUSY_POLL / SO_PREFER_BUSY_POLL. The kernel has no getter for
// SO_BUSY_POLL_BUDGET, so `budget` is reported as 0 unless a future kernel adds one.
[[nodiscard]] Result<BusyPollOptions> read_socket_options(int fd);
// SO_INCOMING_NAPI_ID: the NAPI instance the socket's last packet arrived on (0 = none,
// e.g. loopback, or nothing received yet).
[[nodiscard]] Result<std::uint32_t> incoming_napi_id(int fd);

// TcpExt BusyPollRxPackets from /proc/net/netstat (this network namespace): packets the
// kernel received by busy polling. The acceptance check that busy polling is really
// happening (it silently stops when, e.g., the socket has no NAPI ID; 07 §2.3, R3a Q1).
[[nodiscard]] Result<std::uint64_t> busy_poll_rx_packets();

// /sys/class/net/<if>/napi_defer_hard_irqs and gro_flush_timeout (ns).
Result<void> set_napi_defer_hard_irqs(std::string_view ifname, std::uint32_t n);
Result<void> set_gro_flush_timeout(std::string_view ifname, std::uint64_t ns);
[[nodiscard]] Result<std::uint64_t> napi_defer_hard_irqs(std::string_view ifname);
[[nodiscard]] Result<std::uint64_t> gro_flush_timeout(std::string_view ifname);

// netdev generic-netlink NAPI objects (napi-get dump / napi-set).
struct NapiInfo {
  std::uint32_t id = 0;
  std::uint32_t ifindex = 0;
  std::int32_t irq = -1;
  std::int32_t pid = -1;                   // threaded NAPI kthread
  std::uint32_t defer_hard_irqs = 0;
  std::uint64_t gro_flush_timeout_ns = 0;
  std::uint64_t irq_suspend_timeout_ns = 0;
};
// Fills `out` with the NAPI instances of `ifindex`; returns how many exist (may exceed
// out.size(), in which case only the first out.size() are written).
[[nodiscard]] Result<std::size_t> list_napi(std::uint32_t ifindex, std::span<NapiInfo> out);

struct NapiSettings {
  std::uint32_t napi_id = 0;
  std::optional<std::uint32_t> defer_hard_irqs;
  std::optional<std::uint64_t> gro_flush_timeout_ns;
  std::optional<std::uint64_t> irq_suspend_timeout_ns;
};
Result<void> set_napi(const NapiSettings& s);

enum class Mode : std::uint8_t { Plain, IrqSuspend };

// The pre-registered (ii) settings of 07 §1.
struct Config {
  EpollParams epoll{};
  BusyPollOptions socket{50, true, 64};
  Mode mode = Mode::Plain;
  std::uint32_t napi_defer_hard_irqs = 2;
  std::uint64_t gro_flush_timeout_ns = 200'000;
  std::uint64_t irq_suspend_timeout_ns = 20'000'000;  // IrqSuspend only
};

// EPIOCSPARAMS on the reactor's epoll fd.
Result<void> configure_reactor(sock::Poller& poller, const Config& c);
// Copies the per-socket knobs into port configs (applied when the ports open).
void apply_to(UdpConfig& u, const Config& c) noexcept;
void apply_to(TcpConfig& t, const Config& c) noexcept;
// Device setup (root): sysfs defer/gro on `ifname`; in IrqSuspend mode also napi-set
// irq-suspend-timeout (plus defer/gro) on every NAPI of the device.
Result<void> configure_device(std::string_view ifname, const Config& c);

}  // namespace lle::net::busypoll

namespace lle::net {

// Variant (ii) shares variant (i)'s types; only the configuration differs.
template <>
struct Backend<BackendKind::BusyPoll> {
  static constexpr BackendKind kind = BackendKind::BusyPoll;
  using Reactor = sock::Poller;
  using DatagramPort = sock::UdpPort;
  using StreamPort = sock::TcpPort;
};
static_assert(BackendTraits<Backend<BackendKind::BusyPoll>>);

}  // namespace lle::net

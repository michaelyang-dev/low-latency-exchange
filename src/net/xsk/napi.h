#pragma once
// NAPI control through the netdev generic-netlink family (07 §2.3 busy polling;
// R3a §1.1, Q5): queue -> NAPI id (queue-get, 6.8), NAPI thread PID (napi-get), and
// threaded busy polling (napi-set threaded=busy-poll, 6.19), equivalent to
//   ynl --family netdev --do napi-set --json '{"id": N, "threaded": "busy-poll"}'
// The busy-poll kthread is then pinned and RT-prioritized inside the 8-core set by the
// caller (sched_setaffinity / sched_setscheduler on the returned PID).
// Cold path; needs CAP_NET_ADMIN for napi-set.
#include <cstdint>
#include <expected>

namespace lle::net::xsk {

enum class NapiThreaded : std::uint32_t {
  Disabled = 0,  // NETDEV_NAPI_THREADED_DISABLED
  Enabled = 1,   // NETDEV_NAPI_THREADED_ENABLED (6.17)
  BusyPoll = 2,  // NETDEV_NAPI_THREADED_BUSY_POLL (6.19)
};

struct NapiInfo {
  std::uint32_t id = 0;
  std::int32_t ifindex = 0;
  std::int32_t irq = -1;
  std::int32_t pid = -1;           // kthread PID when threaded, else -1
  std::int32_t threaded = -1;      // NapiThreaded value, -1 if the kernel lacks the attribute
};

// NAPI id serving rx queue `queue` of `ifindex` (errno on failure; ENOENT when the
// driver does not link queues to NAPI instances, which XSK busy polling needs).
std::expected<std::uint32_t, int> napi_id_for_rx_queue(int ifindex, std::uint32_t queue);
std::expected<NapiInfo, int> napi_get(std::uint32_t napi_id);
// EINVAL/EOPNOTSUPP on kernels without the requested mode (busy-poll needs 6.19).
std::expected<void, int> napi_set_threaded(std::uint32_t napi_id, NapiThreaded mode);

}  // namespace lle::net::xsk

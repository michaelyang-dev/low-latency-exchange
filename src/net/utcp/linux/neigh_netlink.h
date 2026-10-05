#pragma once
// Kernel neighbour table via rtnetlink (07 §2.4 "ARP: static next hop or the kernel
// neighbour table via netlink"). Cold path: startup and next-hop refresh only.
//
// On the AF_XDP path the XDP program passes ARP to the kernel, which owns the
// interface address and resolves the peer; utcp copies the result from here.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>

#include "net/utcp/arp.h"

namespace lle::net::utcp {

struct KernelNeighbor {
  std::uint32_t ip = 0;  // host order
  MacAddr mac;
  std::uint16_t state = 0;  // NUD_* flags
};

// Dumps IPv4 neighbours of `ifindex` (RTM_GETNEIGH) in a usable state (REACHABLE,
// STALE, DELAY, PROBE, PERMANENT) and calls cb(const KernelNeighbor&). Returns the
// number reported, or errno.
template <class Cb>
std::expected<std::size_t, int> dump_kernel_neighbors(int ifindex, Cb&& cb);

// Copies the kernel's neighbours on `ifindex` into `t` (static entries by default).
std::expected<std::size_t, int> load_kernel_neighbors(NeighborTable& t, int ifindex, bool as_static = true);

// Looks up one neighbour.
std::optional<MacAddr> kernel_neighbor(int ifindex, std::uint32_t ip);

// Makes the kernel resolve `ip` on `ifname` (a UDP datagram to the discard port bound
// to the device triggers ARP), then polls the neighbour table for up to timeout_ms.
std::optional<MacAddr> resolve_via_kernel(const std::string& ifname, std::uint32_t ip, int timeout_ms);

namespace detail {
// Non-template core: fills up to `cap` entries; returns the count or errno.
std::expected<std::size_t, int> dump_neighbors(int ifindex, KernelNeighbor* out, std::size_t cap);
}  // namespace detail

template <class Cb>
std::expected<std::size_t, int> dump_kernel_neighbors(int ifindex, Cb&& cb) {
  KernelNeighbor tmp[256];
  auto n = detail::dump_neighbors(ifindex, tmp, 256);
  if (!n) return n;
  for (std::size_t i = 0; i < *n; ++i) cb(tmp[i]);
  return n;
}

}  // namespace lle::net::utcp

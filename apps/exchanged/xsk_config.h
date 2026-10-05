#pragma once
// Settings of the AF_XDP variant's network stacks (xsk_net.h): the gateways' utcp server
// and the md stage's UDP. Portable (no AF_XDP), so the configuration tests run on every
// platform.
#include <algorithm>
#include <cstdint>
#include <optional>

#include "env/entropy.h"
#include "exchanged/config.h"
#include "net/common/port.h"
#include "net/utcp/stream_port.h"
#include "net/utcp/wire.h"

namespace lle::exch {

[[nodiscard]] inline std::optional<net::utcp::MacAddr> next_hop_of(const XskSettings& x) noexcept {
  if (!x.next_hop_mac) return std::nullopt;
  return net::utcp::MacAddr{*x.next_hop_mac};
}

// The utcp stack of one gateway's AF_XDP socket. The kernel keeps the interface address
// and answers ARP (md_steer passes ARP up); a passive open replies to the SYN's source
// MAC, active opens are never made. The RFC 6528 ISN key is drawn from the OS CSPRNG at
// every start (env::os_entropy64): utcp's built-in key is for its tests and the
// simulator only, and would make ISNs predictable across restarts.
[[nodiscard]] inline net::utcp::StackConfig gateway_stack_config(const XskSettings& x, const net::TcpConfig& t,
                                                                 const net::utcp::MacAddr& mac, std::uint32_t local_ip,
                                                                 std::uint32_t netmask) {
  net::utcp::StackConfig sc;
  sc.local_mac = mac;
  sc.local_ip = local_ip;
  sc.netmask = netmask;
  sc.static_next_hop = next_hop_of(x);
  sc.arp_reply = false;
  sc.max_connections = static_cast<std::uint16_t>(std::clamp<std::uint32_t>(t.max_conns, 1, 0xFFFF));
  sc.max_listeners = 2;
  sc.conn.tx_checksum_offload = x.checksum_offload;
  sc.isn_secret = env::os_entropy64();
  return sc;
}

}  // namespace lle::exch

#pragma once
// XskDatagramPort: env::DatagramPortLike for UDP over AF_XDP (07 §2.3): Ethernet/IPv4/
// UDP framing built in place in UMEM chunks, multicast or unicast destinations, UDP
// checksum in software or via XDP_TXMD_FLAGS_CHECKSUM, RX filtered to the configured
// local ports with the NIC timestamp from the XDP program's metadata (zero-copy only;
// 0 in copy mode).
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include "env/concepts.h"
#include "net/utcp/arp.h"
#include "net/utcp/wire.h"
#include "net/xsk/socket.h"

namespace lle::net::xsk {

struct XskDatagramConfig {
  utcp::MacAddr local_mac;
  std::uint32_t local_ip = 0;   // host order
  std::uint16_t local_port = 0; // source port of sends
  std::optional<utcp::MacAddr> static_next_hop;  // unicast destinations via this MAC
  std::uint32_t netmask = 0xFFFFFF00u;
  std::uint32_t gateway = 0;
  // Ports accepted on RX (destination port); empty = all UDP.
  std::array<std::uint16_t, 8> rx_ports{};
  bool checksum_offload = false;  // XDP_TXMD_FLAGS_CHECKSUM
  bool verify_rx_checksum = true;
  bool tx_timestamps = false;
  bool share_with_frames = false; // non-UDP frames go to an XskFramePort on the same socket
  std::uint8_t ttl = 64;
};

struct XskDatagramStats {
  std::uint64_t sent = 0;
  std::uint64_t send_failed = 0;   // no frame / ring full / unresolved next hop / too big
  std::uint64_t received = 0;
  std::uint64_t rx_filtered = 0;   // UDP to another port, or not UDP
  std::uint64_t rx_bad = 0;        // malformed or bad checksum
};

class XskDatagramPort {
 public:
  static constexpr int kConsumer = 0;

  XskDatagramPort(XskSocket& s, const XskDatagramConfig& c) : s_(s), c_(c) {}

  // Sends one datagram; true when it was queued on the TX ring.
  bool send(env::Endpoint dst, std::span<const std::byte> payload) noexcept {
    std::optional<utcp::MacAddr> mac;
    if (utcp::ipv4_is_multicast(dst.ipv4)) {
      mac = utcp::MacAddr::ipv4_multicast(dst.ipv4);
    } else if (c_.static_next_hop) {
      mac = c_.static_next_hop;
    } else {
      const bool on_link = c_.gateway == 0 || (dst.ipv4 & c_.netmask) == (c_.local_ip & c_.netmask);
      mac = neighbors_.lookup(on_link ? dst.ipv4 : c_.gateway);
    }
    std::span<std::byte> b = s_.tx_acquire();
    if (!mac || b.size() < utcp::kUdpFrameOverhead + payload.size()) {
      if (!b.empty()) (void)s_.tx_commit(0);
      ++st_.send_failed;
      return false;
    }
    std::memcpy(b.data() + utcp::kUdpFrameOverhead, payload.data(), payload.size());
    utcp::UdpHeaderSpec h;
    h.src_mac = c_.local_mac;
    h.dst_mac = *mac;
    h.src_ip = c_.local_ip;
    h.dst_ip = dst.ipv4;
    h.src_port = c_.local_port;
    h.dst_port = dst.port;
    h.ip_id = ip_id_++;
    h.ttl = c_.ttl;
    const std::size_t n = utcp::finish_udp_in_place(b, h, payload.size(), c_.checksum_offload);
    TxOptions o;
    o.timestamp = c_.tx_timestamps;
    if (c_.tx_timestamps) o.cookie = tx_seq_ + 1;  // reported to the socket's completion handler
    if (c_.checksum_offload) {
      o.checksum = true;
      o.csum_start = static_cast<std::uint16_t>(utcp::kEthHeaderLen + utcp::kIpv4HeaderLen);
      o.csum_offset = 6;  // UDP checksum field
    }
    if (n == 0 || !s_.tx_commit(n, o)) {
      if (n == 0) (void)s_.tx_commit(0);
      ++st_.send_failed;
      return false;
    }
    if (c_.tx_timestamps) ++tx_seq_;
    s_.flush();
    ++st_.sent;
    return true;
  }

  // Cookie of the last datagram sent with a timestamp request (1, 2, ... in send order);
  // TX timestamps arrive through socket().set_tx_completion_handler().
  [[nodiscard]] std::uint64_t last_tx_cookie() const noexcept { return tx_seq_; }

  template <class Cb>
  std::size_t poll_rx(Cb&& cb, std::uint32_t budget = 64) {
    std::size_t delivered = 0;
    (void)s_.poll_rx(
        kConsumer,
        [&](std::span<const std::byte> f, const RxMeta& m) {
          auto d = utcp::parse_udp(f, utcp::LinkType::Ethernet, c_.verify_rx_checksum);
          if (!d) {
            if (d.error() == utcp::ParseError::NotUdp || d.error() == utcp::ParseError::NotIpv4) {
              if (c_.share_with_frames) return false;
              ++st_.rx_filtered;
            } else {
              ++st_.rx_bad;
            }
            return true;
          }
          if (!port_wanted(d->dst_port)) {
            ++st_.rx_filtered;
            return true;
          }
          env::RxDatagram r;
          r.data = d->payload;
          r.src = env::Endpoint{d->src_ip, d->src_port};
          r.dst = env::Endpoint{d->dst_ip, d->dst_port};
          r.hw_rx_ns = m.hw_rx_ns;
          ++st_.received;
          ++delivered;
          cb(r);
          return true;
        },
        budget);
    return delivered;
  }

  utcp::NeighborTable& neighbors() noexcept { return neighbors_; }
  [[nodiscard]] const XskDatagramStats& stats() const noexcept { return st_; }
  XskSocket& socket() noexcept { return s_; }

 private:
  [[nodiscard]] bool port_wanted(std::uint16_t p) const noexcept {
    bool any = false;
    for (const auto x : c_.rx_ports) {
      if (x == 0) continue;
      any = true;
      if (x == p) return true;
    }
    return !any;
  }

  XskSocket& s_;
  XskDatagramConfig c_;
  utcp::NeighborTable neighbors_;
  XskDatagramStats st_{};
  std::uint16_t ip_id_ = 0;
  std::uint64_t tx_seq_ = 0;
};

static_assert(env::DatagramPortLike<XskDatagramPort>);

}  // namespace lle::net::xsk

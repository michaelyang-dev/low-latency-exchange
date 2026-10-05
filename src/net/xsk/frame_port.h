#pragma once
// XskFramePort: utcp::FramePort over an AF_XDP socket (07 §2.3, §2.4). utcp builds
// frames directly into UMEM chunks (tx_acquire/tx_commit: zero-copy TX). With
// tcp_checksum_offload the TCP checksum is left to the NIC via XDP_TXMD_FLAGS_CHECKSUM
// (configure utcp's ConnConfig::tx_checksum_offload to match); RX frames carry the NIC
// timestamp from the XDP program's metadata (zero-copy sockets only). With tx_timestamps
// every frame requests a TX timestamp, delivered with the frame's sequence cookie
// (last_tx_cookie()) to the socket's completion handler.
//
// share_with_datagrams: the socket's queue also carries UDP for an XskDatagramPort
// (consumer 0); UDP frames polled here are stashed for it, and vice versa.
#include <cstddef>
#include <cstring>
#include <span>

#include "common/endian.h"
#include "common/types.h"
#include "net/utcp/wire.h"
#include "net/xsk/socket.h"

namespace lle::net::xsk {

struct XskFramePortConfig {
  bool tcp_checksum_offload = false;   // XDP_TXMD_FLAGS_CHECKSUM (mlx5 >= 6.8)
  bool tx_timestamps = false;          // XDP_TXMD_FLAGS_TIMESTAMP on every frame
  bool share_with_datagrams = false;
};

class XskFramePort {
 public:
  static constexpr int kConsumer = 1;

  XskFramePort(XskSocket& s, const XskFramePortConfig& c = {}) : s_(s), c_(c) {}

  bool send_frame(std::span<const std::byte> f) noexcept {
    std::span<std::byte> b = tx_acquire();
    if (b.size() < f.size()) {
      if (!b.empty()) tx_commit(0);
      return false;
    }
    std::memcpy(b.data(), f.data(), f.size());
    tx_commit(f.size());
    return true;
  }

  std::span<std::byte> tx_acquire() noexcept { return s_.tx_acquire(); }

  void tx_commit(std::size_t n) noexcept {
    TxOptions o;
    o.timestamp = c_.tx_timestamps;
    if (c_.tx_timestamps && n != 0) o.cookie = ++tx_seq_;  // reported to the socket's completion handler
    if (c_.tcp_checksum_offload && n != 0) set_tcp_csum(o, n);
    (void)s_.tx_commit(n, o);
  }

  // Cookie of the last frame committed with a timestamp request (frames are numbered
  // 1, 2, ... in commit order); TX timestamps arrive through
  // socket().set_tx_completion_handler() from whichever call reaps the completion.
  [[nodiscard]] std::uint64_t last_tx_cookie() const noexcept { return tx_seq_; }

  void flush() noexcept { s_.flush(); }

  template <class Cb>
  std::size_t poll_frames(Cb&& cb, std::uint32_t budget = 64) {
    return s_.poll_rx(
        kConsumer,
        [&](std::span<const std::byte> f, const RxMeta& m) {
          if (c_.share_with_datagrams && is_ipv4_proto(f, utcp::kIpProtoUdp)) return false;
          cb(f, m.hw_rx_ns);
          return true;
        },
        budget);
  }

  XskSocket& socket() noexcept { return s_; }

  static bool is_ipv4_proto(std::span<const std::byte> f, std::uint8_t proto) noexcept {
    return f.size() >= utcp::kEthHeaderLen + utcp::kIpv4HeaderLen && load_be16(f.data() + 12) == utcp::kEtherTypeIpv4 &&
           std::to_integer<std::uint8_t>(f[utcp::kEthHeaderLen + 9]) == proto;
  }

 private:
  void set_tcp_csum(TxOptions& o, std::size_t n) noexcept {
    std::span<std::byte> b = pending_view(n);
    if (!is_ipv4_proto(b, utcp::kIpProtoTcp)) return;
    const std::size_t ihl = std::size_t{std::to_integer<std::uint8_t>(b[utcp::kEthHeaderLen]) & 0x0Fu} * 4;
    o.checksum = true;
    o.csum_start = static_cast<std::uint16_t>(utcp::kEthHeaderLen + ihl);
    o.csum_offset = 16;  // TCP checksum field
  }
  std::span<std::byte> pending_view(std::size_t n) noexcept {
    std::span<std::byte> b = s_.tx_acquire();  // returns the pending buffer again
    return b.first(n < b.size() ? n : b.size());
  }

  XskSocket& s_;
  XskFramePortConfig c_;
  std::uint64_t tx_seq_ = 0;
};

}  // namespace lle::net::xsk

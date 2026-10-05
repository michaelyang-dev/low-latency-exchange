#pragma once
// AF_PACKET raw-socket FramePort (Linux). Carries utcp over a veth or TAP interface in
// tests and the kernel-interop suite; production uses AF_XDP (net/xsk XskFramePort).
//
// Frames we transmit are not looped back (PACKET_IGNORE_OUTGOING). TX goes through the
// interface's qdisc, so tc netem impairs it. The receive buffer is allocated once.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>

#include "common/types.h"
#include "net/utcp/wire.h"

namespace lle::net::utcp {

struct AfPacketStats {
  std::uint64_t rx_frames = 0;
  std::uint64_t tx_frames = 0;
  std::uint64_t tx_errors = 0;  // send() failed (e.g. ENOBUFS): the frame is lost
  std::uint64_t rx_truncated = 0;
};

class AfPacketPort {
 public:
  // Opens a raw socket bound to `ifname`. Returns errno on failure (EPERM without
  // CAP_NET_RAW).
  static std::expected<AfPacketPort, int> open(const std::string& ifname, int rcvbuf_bytes = 8 << 20);

  AfPacketPort(AfPacketPort&& o) noexcept;
  AfPacketPort& operator=(AfPacketPort&& o) noexcept;
  AfPacketPort(const AfPacketPort&) = delete;
  AfPacketPort& operator=(const AfPacketPort&) = delete;
  ~AfPacketPort();

  bool send_frame(std::span<const std::byte> f) noexcept;

  // Delivers up to `budget` queued frames as cb(frame, 0): veth/TAP carry no hardware
  // timestamps, and none are reported.
  template <class Cb>
  std::size_t poll_frames(Cb&& cb, std::size_t budget = 64) {
    std::size_t n = 0;
    for (std::size_t k = 0; k < budget; ++k) {
      const std::ptrdiff_t len = recv_one();
      if (len < 0) break;   // queue empty
      if (len == 0) continue;  // truncated frame skipped
      cb(std::span<const std::byte>(buf_.get(), static_cast<std::size_t>(len)), Nanos{0});
      ++n;
    }
    return n;
  }

  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] int ifindex() const noexcept { return ifindex_; }
  [[nodiscard]] const MacAddr& mac() const noexcept { return mac_; }
  [[nodiscard]] const AfPacketStats& stats() const noexcept { return stats_; }

 private:
  AfPacketPort() = default;
  // >0: frame length; 0: frame skipped; -1: nothing queued.
  std::ptrdiff_t recv_one() noexcept;

  static constexpr std::size_t kBufSize = 65536;
  int fd_ = -1;
  int ifindex_ = 0;
  MacAddr mac_;
  std::unique_ptr<std::byte[]> buf_;
  AfPacketStats stats_{};
};

// Interface MAC address and index (SIOCGIFHWADDR / if_nametoindex); errno on failure.
std::expected<MacAddr, int> interface_mac(const std::string& ifname);

}  // namespace lle::net::utcp

#pragma once
// Control-message parsing for socket timestamps (07 §2.5, R3a §3.3).
//
// Handles, by Linux UAPI value (hwts/abi.h):
//   SOL_SOCKET / SCM_TIMESTAMPING{,_NEW}   scm_timestamping(64): ts[0] software, ts[2] raw HW
//   SOL_SOCKET / SCM_TIMESTAMPNS{,_NEW}    software RX timestamp (timespec)
//   SOL_IP / IP_RECVERR, SOL_IPV6 / IPV6_RECVERR   sock_extended_err (error queue)
//   SOL_IP / IP_PKTINFO                    destination address (multicast group)
// and on macOS the native SCM_TIMESTAMP (software) and IP_RECVDSTADDR.
// Everything is parsed with memcpy (cmsg payloads are not guaranteed to be aligned for
// the payload type) and allocation-free.
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

#include "net/common/timestamps.h"
#include "net/hwts/abi.h"

namespace lle::net::hwts {

struct ControlInfo {
  RxTimestamps ts{};
  bool has_timestamp = false;
  bool has_ext_err = false;
  abi::SockExtendedErr ext_err{};
  bool has_dst = false;
  std::uint32_t dst_ipv4 = 0;  // host order
  std::uint32_t ifindex = 0;
  std::uint32_t malformed = 0;  // known cmsgs with a short payload (ignored)

  void clear() noexcept { *this = ControlInfo{}; }
};

// A timespec the kernel can produce: non-negative, tv_nsec in [0, 1e9), and
// representable in Nanos. A damaged control buffer can carry anything else.
[[nodiscard]] constexpr bool valid_timespec(const abi::KernelTimespec& t) noexcept {
  constexpr std::int64_t kMaxSec = std::numeric_limits<Nanos>::max() / kNsPerSec - 1;
  return t.tv_sec >= 0 && t.tv_sec <= kMaxSec && t.tv_nsec >= 0 && t.tv_nsec < kNsPerSec;
}
// Nanoseconds, or 0 ("no timestamp") for a timespec that is not valid_timespec().
[[nodiscard]] constexpr Nanos to_ns(const abi::KernelTimespec& t) noexcept {
  if (!valid_timespec(t)) return 0;
  return static_cast<Nanos>(t.tv_sec) * kNsPerSec + static_cast<Nanos>(t.tv_nsec);
}

// Feeds one control message into `out`. Unknown (level, type) pairs are ignored.
void parse_cmsg(int level, int type, std::span<const std::byte> payload, ControlInfo& out) noexcept;

// Walks every control message of a received msghdr (CMSG_FIRSTHDR/NXTHDR).
void parse_control(const msghdr& m, ControlInfo& out) noexcept;

// Same, over a raw control buffer of `len` bytes (as returned in msg_controllen).
void parse_control(const std::byte* control, std::size_t len, ControlInfo& out) noexcept;

// Error-queue message → TX timestamp. True only for a timestamp report
// (ee_errno == ENOMSG, ee_origin == SO_EE_ORIGIN_TIMESTAMPING) that carried a timestamp.
[[nodiscard]] bool to_tx_stamp(const ControlInfo& c, TxStamp& out) noexcept;

// Writes one cmsg (level, type, payload) at `buf` + `offset` using the platform's CMSG
// layout; returns the new offset (CMSG_SPACE-aligned) or 0 if it does not fit. Used by
// tests and fakes to handcraft control buffers.
std::size_t put_cmsg(std::span<std::byte> buf, std::size_t offset, int level, int type,
                     std::span<const std::byte> payload) noexcept;

}  // namespace lle::net::hwts

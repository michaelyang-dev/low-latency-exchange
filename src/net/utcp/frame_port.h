#pragma once
// FramePort: the link-layer port utcp runs over (07 §2.4). The same utcp code runs over
// AF_XDP (net/xsk XskFramePort), an AF_PACKET raw socket on a veth/TAP in tests
// (net/utcp/linux/af_packet_port.h), an in-memory link in unit tests, and the
// deterministic simulator.
#include <concepts>
#include <cstddef>
#include <span>

#include "common/types.h"

namespace lle::net::utcp {

struct NoopFrameCallback {
  void operator()(std::span<const std::byte>, Nanos) const noexcept {}
};

// Required:
//   send_frame(frame) -> bool    transmit one complete frame (copied before return);
//                                false when the TX path is full (the frame is dropped)
//   poll_frames(cb) -> size_t    deliver received frames as cb(frame, hw_rx_ns); each
//                                frame is valid only during the callback
template <class P>
concept FramePort = requires(P& p, std::span<const std::byte> f) {
  { p.send_frame(f) } -> std::same_as<bool>;
  { p.poll_frames(NoopFrameCallback{}) } -> std::same_as<std::size_t>;
};

// Optional zero-copy TX: tx_acquire() returns a writable frame buffer (empty when the TX
// path is full); tx_commit(n) transmits its first n bytes (n == 0 returns the buffer).
template <class P>
concept FramePortTxAcquire = requires(P& p, std::size_t n) {
  { p.tx_acquire() } -> std::same_as<std::span<std::byte>>;
  p.tx_commit(n);
};

// Optional: flush() kicks batched transmissions (AF_XDP need-wakeup sendto).
template <class P>
concept FramePortFlush = requires(P& p) { p.flush(); };

}  // namespace lle::net::utcp

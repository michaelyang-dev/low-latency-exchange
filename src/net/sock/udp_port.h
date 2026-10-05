#pragma once
// Kernel UDP port (07 §2.1): unicast and multicast send/receive on one non-blocking
// socket. Satisfies env::DatagramPortLike.
//
// RX: Linux uses recvmmsg (one syscall per batch of up to UdpConfig::batch datagrams);
// macOS loops recvmsg. Buffers, iovecs, address and control storage are allocated once
// in open(); poll_rx() hands the callback views into them, so nothing is allocated per
// message. Truncated datagrams (larger than max_datagram) are dropped and counted.
//
// Readiness: with a Poller the socket is registered edge-triggered for input only (a UDP
// socket's EPOLLOUT edge fires on every skb free and would wake blocking waits for
// nothing); poll_rx() then skips the syscall until the poller reports input. Without a
// Poller every poll_rx() tries a non-blocking receive, which with SO_BUSY_POLL set also
// runs one NAPI busy-poll pass in the kernel (variant ii spin mode).
//
// TX is a single non-blocking sendto per datagram; EAGAIN/ENOBUFS drops the datagram
// (counted) instead of buffering, because stale market data has no value.
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "env/concepts.h"
#include "net/common/buffer_arena.h"
#include "net/common/fd.h"
#include "net/common/port.h"
#include "net/hwts/socket_ts.h"
#include "net/sock/poller.h"

namespace lle::net::sock {

class UdpPort {
 public:
  UdpPort() = default;
  UdpPort(const UdpPort&) = delete;
  UdpPort& operator=(const UdpPort&) = delete;
  ~UdpPort() { close(); }

  Result<void> open(const UdpConfig& cfg, Poller* poller = nullptr);
  void close() noexcept;
  [[nodiscard]] bool is_open() const noexcept { return fd_.valid(); }

  // One datagram to `dst` (unicast or multicast group). False if the kernel did not take
  // the whole datagram (dropped, counted in stats().tx_dropped / tx_errors).
  bool send(Endpoint dst, std::span<const std::byte> data) noexcept;

  // Delivers up to one batch of received datagrams: cb(const env::RxDatagram&).
  template <class F>
  std::size_t poll_rx(F&& cb) {
    return poll_rx_ts([&cb](const env::RxDatagram& d, const RxTimestamps&) { cb(d); });
  }

  // Same, with the software/hardware timestamps of each datagram (zeros when off).
  template <class F>
  std::size_t poll_rx_ts(F&& cb) {
    if (poller_ != nullptr && (r_.events & (kReadable | kHangup)) == 0) return 0;
    const std::size_t n = recv_batch();
    for (std::size_t i = 0; i < n; ++i) cb(static_cast<const env::RxDatagram&>(rx_[i].d), rx_[i].ts);
    return n;
  }

  // Drains TX timestamps from the error queue: cb(const TxStamp&). Keys count successful
  // sends from 0 (OPT_ID); see hwts::TxCorrelator.
  template <class F>
  std::size_t drain_tx_timestamps(F&& cb) {
    const std::size_t n = errq_.drain(fd_.get(), cb);
    r_.events &= ~kErrored;
    return n;
  }

  [[nodiscard]] int fd() const noexcept { return fd_.get(); }
  [[nodiscard]] Endpoint local() const noexcept { return local_; }
  [[nodiscard]] const DatagramStats& stats() const noexcept { return stats_; }
  [[nodiscard]] std::uint32_t timestamping_flags() const noexcept { return ts_flags_; }
  [[nodiscard]] const UdpConfig& config() const noexcept { return cfg_; }

 private:
  struct RxSlot {
    env::RxDatagram d;
    RxTimestamps ts;
  };
  static constexpr std::size_t kControlBytes = 256;

  std::size_t recv_batch() noexcept;

  UdpConfig cfg_{};
  UniqueFd fd_;
  Poller* poller_ = nullptr;
  Readiness r_{};
  Endpoint local_{};
  BufferArena bufs_;                          // batch × max_datagram
  std::unique_ptr<RxSlot[]> rx_;              // views handed to the callback
  std::unique_ptr<std::byte[]> control_;      // batch × kControlBytes
#if defined(__linux__)
  std::unique_ptr<mmsghdr[]> msgs_;           // recvmmsg vector
#endif
  std::unique_ptr<iovec[]> iov_;
  std::unique_ptr<sockaddr_in[]> names_;
  hwts::ErrQueueReader errq_;
  DatagramStats stats_{};
  std::uint32_t ts_flags_ = 0;
  bool want_ts_ = false;
};

}  // namespace lle::net::sock

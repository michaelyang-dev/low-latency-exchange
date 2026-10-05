#pragma once
// Variant (iii) UDP port (07 §2.2): multishot recvmsg over a provided-buffer ring on a
// registered file, SEND for transmit, io_uring TX timestamps. Satisfies
// env::DatagramPortLike.
//
// RX: one IORING_OP_RECVMSG with IORING_RECV_MULTISHOT | IOSQE_BUFFER_SELECT stays armed;
// every datagram lands in a provided buffer laid out as io_uring_recvmsg_out + source
// address + control messages (SCM_TIMESTAMPING, IP_PKTINFO) + payload. The buffer goes
// back to the ring right after the callback. A CQE without IORING_CQE_F_MORE (e.g.
// -ENOBUFS when the application fell behind) ends the multishot request; the port
// re-arms it on the next poll and counts the event (stats().rearms / no_buffers).
//
// TX: send() copies the datagram into a preallocated TX slot (io_uring needs the bytes
// until the SEND completes, and env::DatagramPortLike only lends the span for the call),
// queues IORING_OP_SEND with the destination address on the registered file and submits
// at once; with DEFER_TASKRUN the send is issued inline in that io_uring_enter. A full
// slot pool drops the datagram (counted), like EAGAIN on a kernel socket.
//
// TX timestamps (07 §2.5): with tx_ts set the port arms SOCKET_URING_OP_TX_TIMESTAMP
// (kernel ≥ 6.17, needs a CQE32 ring) and falls back to reading MSG_ERRQUEUE when the
// ring lacks CQE32 or the kernel rejects the command.
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "env/concepts.h"
#include "net/common/buffer_arena.h"
#include "net/common/fd.h"
#include "net/common/port.h"
#include "net/hwts/socket_ts.h"
#include "net/uring/ring.h"

namespace lle::net::uring {

// TX-timestamp CQE → TxStamp (io_uring 6.17 format: res = OPT_ID key, flags carry
// IORING_CQE_F_TSTAMP_HW and the SCM_TSTAMP_* type, the CQE32 tail holds io_timespec).
[[nodiscard]] TxStamp tx_stamp_from_cqe(const Cqe& c) noexcept;

// Whether this build's liburing knows SOCKET_URING_OP_TX_TIMESTAMP.
[[nodiscard]] constexpr bool tx_timestamp_cmd_compiled() noexcept {
#if defined(IORING_TIMESTAMP_HW_SHIFT)
  return true;
#else
  return false;
#endif
}

class UdpPort {
 public:
  UdpPort() = default;
  UdpPort(const UdpPort&) = delete;
  UdpPort& operator=(const UdpPort&) = delete;
  ~UdpPort() { close(); }

  // With `ring` == nullptr the port owns a private Ring built from `own` (CQE32 is added
  // automatically when TX timestamps are requested) and polls it itself.
  Result<void> open(const UdpConfig& cfg, Ring* ring = nullptr, const RingConfig& own = {});
  void close() noexcept;
  [[nodiscard]] bool is_open() const noexcept { return fd_.valid(); }

  bool send(Endpoint dst, std::span<const std::byte> data) noexcept;

  template <class F>
  std::size_t poll_rx(F&& cb) {
    return poll_rx_ts([&cb](const env::RxDatagram& d, const RxTimestamps&) { cb(d); });
  }

  template <class F>
  std::size_t poll_rx_ts(F&& cb) {
    if (owns_) (void)ring_->poll(0);
    if (!tx_q_.empty()) reap_tx();
    std::size_t n = 0;
    while (n < cfg_.batch && !rx_q_.empty()) {
      const Cqe c = rx_q_.front();
      rx_q_.pop();
      if (aux_epoch(c.user_data) != epoch_) continue;  // a previous port's completion
      const int bid = cqe_buffer_id(c);
      if (bid >= 0) {
        env::RxDatagram d{};
        RxTimestamps ts{};
        if (parse_recv(c, static_cast<std::uint16_t>(bid), d, ts)) {
          cb(static_cast<const env::RxDatagram&>(d), static_cast<const RxTimestamps&>(ts));
          ++n;
        }
        bufs_.recycle(static_cast<std::uint16_t>(bid));
      } else {
        on_recv_error(c);
      }
      if (!cqe_more(c)) rx_armed_ = false;
    }
    bufs_.commit();
    if (!rx_armed_) arm_recv();
    return n;
  }

  // TX timestamps: cb(const TxStamp&). Keys count sends from 0 (OPT_ID).
  template <class F>
  std::size_t drain_tx_timestamps(F&& cb) {
    if (owns_) (void)ring_->poll(0);
    if (!ts_uring_) return errq_.drain(fd_.get(), cb);
    std::size_t n = 0;
    while (!ts_q_.empty()) {
      const Cqe c = ts_q_.front();
      ts_q_.pop();
      if (aux_epoch(c.user_data) != epoch_) continue;
      if (c.res >= 0) {
        const TxStamp s = tx_stamp_from_cqe(c);
        cb(s);
        ++n;
      } else {
        on_ts_error(c);
      }
      if (!cqe_more(c)) ts_armed_ = false;
    }
    if (ts_uring_ && !ts_armed_) arm_tx_ts();
    return n;
  }

  [[nodiscard]] int fd() const noexcept { return fd_.get(); }
  [[nodiscard]] Endpoint local() const noexcept { return local_; }
  [[nodiscard]] const DatagramStats& stats() const noexcept { return stats_; }
  [[nodiscard]] std::uint32_t timestamping_flags() const noexcept { return ts_flags_; }
  [[nodiscard]] bool tx_timestamps_via_uring() const noexcept { return ts_uring_; }
  [[nodiscard]] std::uint32_t fixed_index() const noexcept { return fixed_; }
  [[nodiscard]] Ring& ring() noexcept { return *ring_; }
  [[nodiscard]] std::uint32_t tx_slots_free() const noexcept { return tx_.free_count(); }

 private:
  enum Op : std::uint8_t { kOpRecv = 1, kOpSend = 2, kOpTxTs = 3 };
  static constexpr std::uint32_t kControlBytes = 128;

  bool parse_recv(const Cqe& c, std::uint16_t bid, env::RxDatagram& d, RxTimestamps& ts) noexcept;
  void on_recv_error(const Cqe& c) noexcept;
  void on_ts_error(const Cqe& c) noexcept;
  void arm_recv() noexcept;
  void arm_tx_ts() noexcept;
  void reap_tx() noexcept;

  Ring own_ring_;  // declared first: destroyed last
  Ring* ring_ = nullptr;
  bool owns_ = false;
  UdpConfig cfg_{};
  UniqueFd fd_;
  std::uint32_t fixed_ = 0;
  bool fixed_ok_ = false;
  std::uint16_t epoch_ = 0;
  Endpoint local_{};
  Sink rx_q_, tx_q_, ts_q_;
  std::uint8_t rx_sink_ = 0, tx_sink_ = 0, ts_sink_ = 0;
  ProvidedBuffers bufs_;
  msghdr tmpl_{};
  BufferArena tx_;
  std::unique_ptr<sockaddr_in[]> tx_addr_;
  bool rx_armed_ = false;
  bool armed_once_ = false;
  bool ts_armed_ = false;
  bool ts_uring_ = false;
  bool want_ts_ = false;
  hwts::ErrQueueReader errq_;
  DatagramStats stats_{};
  std::uint32_t ts_flags_ = 0;
};

}  // namespace lle::net::uring

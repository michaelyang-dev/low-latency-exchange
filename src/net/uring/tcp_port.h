#pragma once
// Variant (iii) TCP port (07 §2.2): multishot accept, async connect, multishot recvmsg
// over a provided-buffer ring, SEND on registered files. Satisfies env::StreamPortLike.
//
// - Sockets are opened and configured exactly like the sock backend's
//   (sock/socket_setup.h: TCP_NODELAY, buffers, busy poll, SO_TIMESTAMPING once
//   established) and registered in the ring's file table.
// - write() copies into the connection's preallocated staging buffer (io_uring reads the
//   bytes after write() returns) and returns the bytes accepted: all-or-nothing per
//   message when one_msg_per_send is set and the message fits, otherwise as much as
//   fits (flow control). At most one SEND is in flight per connection, so bytes leave in
//   order; with one_msg_per_send each staged message is its own SEND with MSG_EOR (one
//   TX timestamp per message, 07 §2.1), otherwise everything staged goes in one SEND.
// - poll(cb) delivers Accepted, Connected, Data (span valid during the call) and Closed
//   (EOF, reset, connect failure, send failure). close(c) is local: it cancels the
//   connection's requests and produces no event.
// - TX timestamps: SOCKET_URING_OP_TX_TIMESTAMP per connection on a CQE32 ring, else
//   the error queue.
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "env/concepts.h"
#include "net/common/buffer_arena.h"
#include "net/common/conn_table.h"
#include "net/common/fd.h"
#include "net/common/fixed_queue.h"
#include "net/common/port.h"
#include "net/hwts/socket_ts.h"
#include "net/uring/bip_buffer.h"
#include "net/uring/ring.h"
#include "net/uring/udp_port.h"

namespace lle::net::uring {

class TcpPort {
 public:
  TcpPort() = default;
  TcpPort(const TcpPort&) = delete;
  TcpPort& operator=(const TcpPort&) = delete;
  ~TcpPort() { shutdown(); }

  Result<void> open(const TcpConfig& cfg, Ring* ring = nullptr, const RingConfig& own = {});
  // Closes the listener and every connection (no events) and detaches from the ring.
  void shutdown() noexcept;

  [[nodiscard]] Result<Endpoint> listen(Endpoint bind);
  [[nodiscard]] Result<ConnId> connect(Endpoint peer);

  std::size_t write(ConnId c, std::span<const std::byte> data) noexcept;
  void close(ConnId c) noexcept;

  template <class F>
  std::size_t poll(F&& cb);

  // TX timestamps of one connection: cb(const TxStamp&) (OPT_ID_TCP byte keys).
  template <class F>
  std::size_t drain_tx_timestamps(ConnId c, F&& cb) {
    if (owns_) (void)ring_->poll(0);
    route_stamps();
    Conn* k = conns_.get(c);
    if (k == nullptr) return 0;
    if (!ts_uring_) return k->fd ? errq_.drain(k->fd.get(), cb) : 0;
    std::size_t n = 0;
    while (!k->stamps.empty()) {
      cb(static_cast<const TxStamp&>(k->stamps.front()));
      k->stamps.pop();
      ++n;
    }
    return n;
  }

  [[nodiscard]] bool is_open(ConnId c) const noexcept {
    const Conn* k = conns_.get(c);
    return k != nullptr && k->state == State::Open;
  }
  [[nodiscard]] int fd(ConnId c) const noexcept {
    const Conn* k = conns_.get(c);
    return k != nullptr ? k->fd.get() : -1;
  }
  // Bytes staged but not yet completed by a SEND.
  [[nodiscard]] std::size_t tx_pending(ConnId c) const noexcept {
    const Conn* k = conns_.get(c);
    return k != nullptr ? k->tx.size() : 0;
  }
  [[nodiscard]] Endpoint listen_endpoint() const noexcept { return listen_ep_; }
  [[nodiscard]] std::uint32_t live_conns() const noexcept { return conns_.live(); }
  [[nodiscard]] const StreamStats& stats() const noexcept { return stats_; }
  [[nodiscard]] bool tx_timestamps_via_uring() const noexcept { return ts_uring_; }
  [[nodiscard]] Ring& ring() noexcept { return *ring_; }

 private:
  enum Op : std::uint8_t { kOpAccept = 1, kOpConnect = 2, kOpRecv = 3, kOpSend = 4, kOpTxTs = 5 };
  enum class State : std::uint8_t { Free, Connecting, Open };
  static constexpr std::uint32_t kListenSlot = 0xFFFF;
  static constexpr std::uint32_t kControlBytes = 128;

  struct Conn {
    UniqueFd fd;
    std::uint32_t fixed = 0;
    bool fixed_ok = false;
    State state = State::Free;
    bool recv_armed = false;
    bool send_inflight = false;
    sockaddr_in peer{};
    BipBuffer tx;
    FixedQueue<std::uint32_t> recs;  // remaining bytes of each staged message
    FixedQueue<TxStamp> stamps;
  };

  // Outcome of one completion, produced by the non-template handlers below.
  struct Event {
    env::StreamEventKind kind = env::StreamEventKind::Data;
    ConnId conn = kNoConn;
    std::span<const std::byte> data{};
    Nanos hw_rx_ns = 0;
    int bid = -1;        // provided buffer to recycle after delivery
    bool emit = false;
    bool release = false;  // free the connection after delivering a Closed event
  };

  Event handle(const Cqe& c) noexcept;
  Event on_accept(const Cqe& c) noexcept;
  Event on_connect(const Cqe& c, ConnId id, Conn& k) noexcept;
  Event on_recv(const Cqe& c, ConnId id, Conn& k) noexcept;
  Event on_send(const Cqe& c, ConnId id, Conn& k) noexcept;
  void route_stamps() noexcept;
  void arm_accept() noexcept;
  void arm_recv(ConnId id, Conn& k) noexcept;
  void arm_tx_ts(ConnId id, Conn& k) noexcept;
  void issue_send(ConnId id, Conn& k) noexcept;
  void retry_stalled_sends() noexcept;
  Result<void> attach(ConnId id, Conn& k, UniqueFd fd);
  void become_open(ConnId id, Conn& k) noexcept;
  void release(ConnId c) noexcept;
  void cancel_fixed(std::uint32_t fixed) noexcept;
  // The aux payload is the ConnId itself (generation-checked on completion).
  [[nodiscard]] std::uint64_t ud(std::uint8_t sink, Op op, ConnId c) const noexcept {
    return make_ud(sink, op, make_aux(epoch_, c));
  }

  Ring own_ring_;  // declared first: destroyed last
  Ring* ring_ = nullptr;
  bool owns_ = false;
  bool opened_ = false;
  TcpConfig cfg_{};
  std::uint16_t epoch_ = 0;
  Sink q_;   // accept/connect/recv/send completions, in order
  Sink tsq_;  // TX timestamp completions
  std::uint8_t sink_ = 0, ts_sink_ = 0;
  ProvidedBuffers bufs_;
  msghdr tmpl_{};
  ConnTable<Conn> conns_;
  BufferArena tx_mem_;  // max_conns × tx_staging_bytes
  UniqueFd listen_fd_;
  std::uint32_t listen_fixed_ = 0;
  bool listen_ok_ = false;
  bool accept_armed_ = false;
  Endpoint listen_ep_{};
  bool ts_uring_ = false;
  bool want_rx_ts_ = false;
  bool send_stalled_ = false;  // a SEND could not get an SQE; retried from poll()
  hwts::ErrQueueReader errq_;
  StreamStats stats_{};
};

template <class F>
std::size_t TcpPort::poll(F&& cb) {
  if (owns_) (void)ring_->poll(0);
  route_stamps();
  std::size_t n = 0;
  while (!q_.empty()) {
    const Cqe c = q_.front();
    q_.pop();
    const Event e = handle(c);
    if (e.emit) {
      const env::StreamEvent ev{e.kind, e.conn, e.data, e.hw_rx_ns};
      cb(ev);
      ++n;
    }
    if (e.bid >= 0) bufs_.recycle(static_cast<std::uint16_t>(e.bid));
    if (e.release) release(e.conn);
  }
  bufs_.commit();
  if (listen_ok_ && !accept_armed_) arm_accept();
  if (send_stalled_) retry_stalled_sends();
  return n;
}

}  // namespace lle::net::uring

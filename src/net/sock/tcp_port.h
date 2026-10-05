#pragma once
// Kernel TCP port (07 §2.1): listen/accept, connect, flow-controlled writes and Closed
// events over non-blocking sockets. Satisfies env::StreamPortLike.
//
// - Connections live in a fixed ConnTable (generation-checked ConnIds); the listener,
//   the table, the ready list and the read buffer are allocated in open().
// - Every socket gets TCP_NODELAY. With one_msg_per_send (default) each write() is one
//   send(MSG_EOR) on Linux, so the kernel never merges two writes into one skb and TX
//   timestamps keyed by OPT_ID_TCP map 1:1 to messages (07 §2.1, R3a §3.3).
// - write() returns the bytes the kernel accepted (0..size); nothing is buffered here.
//   The caller keeps the remainder and retries (flow control).
// - poll(cb) delivers cb(const env::StreamEvent&): Accepted, Connected, Data (span valid
//   only during the call) and Closed (peer FIN/RST, connect failure, write failure). After
//   Closed the ConnId is dead. close(c) is local and produces no event.
// - Readiness comes from a Poller (edge-triggered). A port constructed without one owns a
//   private Poller and polls it with timeout 0 at the start of every poll(); with a shared
//   Poller the stage calls Poller::poll(timeout) once per loop and then polls each port.
//
// SO_TIMESTAMPING with OPT_ID is enabled per connection once it is established: the
// kernel rejects OPT_ID on TCP sockets in CLOSE/LISTEN state, and OPT_ID_TCP keys count
// from write_seq at the time the option is set.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "env/concepts.h"
#include "net/common/conn_table.h"
#include "net/common/fd.h"
#include "net/common/fixed_queue.h"
#include "net/common/port.h"
#include "net/hwts/socket_ts.h"
#include "net/sock/poller.h"

namespace lle::net::sock {

class TcpPort {
 public:
  TcpPort() = default;
  TcpPort(const TcpPort&) = delete;
  TcpPort& operator=(const TcpPort&) = delete;
  ~TcpPort() { shutdown(); }

  Result<void> open(const TcpConfig& cfg, Poller* shared = nullptr);
  // Closes the listener and every connection (no events).
  void shutdown() noexcept;

  // Starts listening; returns the bound endpoint (port 0 → ephemeral). One per port.
  [[nodiscard]] Result<Endpoint> listen(Endpoint bind);
  // Non-blocking connect; Connected (or Closed on failure) is reported by poll().
  [[nodiscard]] Result<ConnId> connect(Endpoint peer);

  std::size_t write(ConnId c, std::span<const std::byte> data) noexcept;
  void close(ConnId c) noexcept;

  template <class F>
  std::size_t poll(F&& cb);

  // TX timestamps of one connection: cb(const TxStamp&). Keys are last-byte offsets
  // (OPT_ID_TCP); feed write() results to hwts::TxCorrelator(KeyMode::Stream).
  template <class F>
  std::size_t drain_tx_timestamps(ConnId c, F&& cb) {
    Conn* k = conns_.get(c);
    return k != nullptr && k->fd ? errq_.drain(k->fd.get(), cb) : 0;
  }

  [[nodiscard]] bool is_open(ConnId c) const noexcept {
    const Conn* k = conns_.get(c);
    return k != nullptr && k->state == State::Open;
  }
  [[nodiscard]] int fd(ConnId c) const noexcept {
    const Conn* k = conns_.get(c);
    return k != nullptr ? k->fd.get() : -1;
  }
  [[nodiscard]] Endpoint listen_endpoint() const noexcept { return listen_ep_; }
  [[nodiscard]] std::uint32_t live_conns() const noexcept { return conns_.live(); }
  [[nodiscard]] const StreamStats& stats() const noexcept { return stats_; }
  [[nodiscard]] Poller& poller() noexcept { return *poller_; }
  [[nodiscard]] const TcpConfig& config() const noexcept { return cfg_; }

 private:
  enum class State : std::uint8_t { Free, Connecting, Open, Closing };
  enum class Step : std::uint8_t { Data, Again, Closed, Connected, Pending };
  struct Conn {
    UniqueFd fd;
    Readiness r;
    State state = State::Free;
  };
  struct Deferred {
    env::StreamEventKind kind = env::StreamEventKind::Closed;
    ConnId conn = kNoConn;
  };
  static constexpr std::uint32_t kListenToken = 0xFFFF'FFFFu;
  static constexpr std::uint32_t kAcceptBudget = 64;

  ConnId accept_one(bool& again) noexcept;
  Step finish_connect(Conn& k) noexcept;
  Step read_some(Conn& k, std::size_t& len, Nanos& hw) noexcept;
  void release(ConnId c) noexcept;
  Result<void> setup_socket(int fd) const;
  void enable_conn_timestamps(int fd) noexcept;
  void defer(env::StreamEventKind kind, ConnId c) noexcept;
  void init_readiness(Conn& k, ConnId id) noexcept;

  template <class F>
  std::size_t accept_ready(F& cb);
  template <class F>
  std::size_t read_conn(ConnId id, F& cb);

  TcpConfig cfg_{};
  Poller own_poller_;
  Poller* poller_ = nullptr;
  bool owns_poller_ = false;
  bool want_rx_ts_ = false;
  bool opened_ = false;
  UniqueFd listen_fd_;
  Readiness listen_r_{};
  Endpoint listen_ep_{};
  ConnTable<Conn> conns_;
  ReadyList ready_;
  FixedQueue<Deferred> deferred_;
  std::unique_ptr<std::byte[]> rx_;
  alignas(16) std::byte control_[256]{};
  hwts::ErrQueueReader errq_;
  StreamStats stats_{};
};

template <class F>
std::size_t TcpPort::poll(F&& cb) {
  if (owns_poller_) (void)poller_->poll(0);
  std::size_t n = 0;
  while (!deferred_.empty()) {
    const Deferred d = deferred_.front();
    deferred_.pop();
    if (conns_.get(d.conn) == nullptr) continue;
    const env::StreamEvent ev{d.kind, d.conn, {}, 0};
    cb(ev);
    ++n;
    if (d.kind == env::StreamEventKind::Closed) {
      ++stats_.closed;
      release(d.conn);
    }
  }
  // Records queued at entry only; anything re-queued waits for the next poll (fairness).
  for (std::size_t todo = ready_.size(); todo > 0; --todo) {
    Readiness* r = ready_.pop();
    if (r == nullptr) break;
    if (r->token == kListenToken) {
      n += accept_ready(cb);
      continue;
    }
    if (!conns_.in_use(r->token)) {
      r->events = 0;
      continue;
    }
    const ConnId id = conns_.id_of(r->token);
    Conn& k = conns_.at(r->token);
    if (k.state == State::Connecting) {
      if ((r->events & (kWritable | kHangup | kErrored)) == 0) continue;
      const Step s = finish_connect(k);
      if (s == Step::Pending) continue;
      const env::StreamEvent ev{s == Step::Connected ? env::StreamEventKind::Connected : env::StreamEventKind::Closed,
                                id, {}, 0};
      cb(ev);
      ++n;
      if (s == Step::Closed) {
        ++stats_.closed;
        release(id);
        continue;
      }
    }
    n += read_conn(id, cb);
  }
  return n;
}

template <class F>
std::size_t TcpPort::accept_ready(F& cb) {
  std::size_t n = 0;
  for (std::uint32_t i = 0; i < kAcceptBudget; ++i) {
    bool again = false;
    const ConnId c = accept_one(again);
    if (again) return n;
    if (c == kNoConn) continue;
    const env::StreamEvent ev{env::StreamEventKind::Accepted, c, {}, 0};
    cb(ev);
    ++n;
  }
  ready_.push(&listen_r_);  // budget exhausted: more connections may be waiting
  return n;
}

template <class F>
std::size_t TcpPort::read_conn(ConnId id, F& cb) {
  std::size_t n = 0;
  for (std::uint32_t i = 0; i < cfg_.max_reads_per_poll; ++i) {
    Conn* k = conns_.get(id);
    if (k == nullptr || k->state != State::Open) return n;  // closed meanwhile (callback)
    if ((k->r.events & (kReadable | kHangup)) == 0) return n;
    std::size_t len = 0;
    Nanos hw = 0;
    const Step s = read_some(*k, len, hw);
    if (s == Step::Again) return n;
    if (s == Step::Closed) {
      const env::StreamEvent ev{env::StreamEventKind::Closed, id, {}, 0};
      cb(ev);
      ++n;
      ++stats_.closed;
      release(id);
      return n;
    }
    const env::StreamEvent ev{env::StreamEventKind::Data, id, {rx_.get(), len}, hw};
    cb(ev);
    ++n;
  }
  if (Conn* k = conns_.get(id); k != nullptr && k->state == State::Open && (k->r.events & (kReadable | kHangup)) != 0)
    ready_.push(&k->r);  // read budget exhausted with input pending
  return n;
}

}  // namespace lle::net::sock

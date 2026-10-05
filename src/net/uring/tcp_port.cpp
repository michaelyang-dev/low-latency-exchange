#include "net/uring/tcp_port.h"

#include <cerrno>
#include <cstring>

#include "net/common/sockopt.h"
#include "net/hwts/cmsg.h"
#include "net/sock/socket_setup.h"

namespace lle::net::uring {

Result<void> TcpPort::open(const TcpConfig& cfg, Ring* ring, const RingConfig& own) {
  if (opened_ || ring_ != nullptr) return fail("uring::TcpPort::open", EALREADY);
  if (cfg.max_conns == 0 || cfg.max_conns >= kListenSlot || cfg.rx_buf_bytes == 0 || cfg.rx_buffers == 0 ||
      (cfg.rx_buffers & (cfg.rx_buffers - 1)) != 0 || cfg.tx_staging_bytes == 0)
    return fail("uring::TcpPort::open", EINVAL);
  cfg_ = cfg;
  if (ring == nullptr) {
    RingConfig rc = own;
    if (cfg.tx_ts != TsMode::Off) rc.cqe32 = true;
    const std::uint32_t need = 2 * (cfg.rx_buffers + 4 * cfg.max_conns);
    if (rc.cq_entries < need) rc.cq_entries = need;
    if (rc.max_files < cfg.max_conns + 1) rc.max_files = cfg.max_conns + 1;
    if (auto r = own_ring_.open(rc); !r) return r;
    ring_ = &own_ring_;
    owns_ = true;
  } else {
    if (!ring->is_open()) return fail("uring::TcpPort::open", EBADF);
    ring_ = ring;
  }
  opened_ = true;
  auto fail_close = [this](Error e) {
    shutdown();
    return std::unexpected(e);
  };
  epoch_ = ring_->next_epoch();
  // Bound on undrained completions: one per provided buffer, per connection a connect,
  // a send and a terminal recv, plus accepts (multishot accept keeps accepting up to the
  // listen backlog while the application is not polling; a dropped accept leaks an fd).
  const auto backlog = static_cast<std::size_t>(cfg.backlog > 0 ? cfg.backlog : 0);
  q_.init(std::size_t{cfg.rx_buffers} + 4 * std::size_t{cfg.max_conns} + backlog + 16);
  tsq_.init(64 * std::size_t{cfg.max_conns} + 64);
  auto s1 = ring_->add_sink(q_);
  if (!s1) return fail_close(s1.error());
  sink_ = *s1;
  auto s2 = ring_->add_sink(tsq_);
  if (!s2) return fail_close(s2.error());
  ts_sink_ = *s2;
  want_rx_ts_ = cfg.rx_ts != TsMode::Off;
  tmpl_ = msghdr{};
  tmpl_.msg_namelen = 0;
  tmpl_.msg_controllen = want_rx_ts_ ? kControlBytes : 0;
  const auto buf = static_cast<std::uint32_t>(sizeof(io_uring_recvmsg_out) + tmpl_.msg_controllen) + cfg.rx_buf_bytes;
  if (auto r = bufs_.init(*ring_, cfg.rx_buffers, buf); !r) return fail_close(r.error());
  conns_.init(cfg.max_conns);
  if (auto r = tx_mem_.init(cfg.max_conns, cfg.tx_staging_bytes, 64); !r) return fail_close(r.error());
  const std::size_t recs = cfg.tx_staging_bytes / 16 > 64 ? cfg.tx_staging_bytes / 16 : 64;
  for (std::uint32_t i = 0; i < cfg.max_conns; ++i) {
    Conn& k = conns_.at(i);
    k.tx.reset(tx_mem_.data(i), cfg.tx_staging_bytes);
    k.recs.init(recs);
    k.stamps.init(64);
  }
  ts_uring_ = cfg.tx_ts != TsMode::Off && tx_timestamp_cmd_compiled() && ring_->cqe32();
  return {};
}

void TcpPort::shutdown() noexcept {
  if (!opened_) return;
  if (ring_ != nullptr && ring_->is_open()) {
    for (std::uint32_t s = 0; s < conns_.capacity(); ++s) {
      if (conns_.in_use(s)) release(conns_.id_of(s));
    }
    if (listen_ok_) {
      cancel_fixed(listen_fixed_);
      ring_->unregister_file(listen_fixed_);
      listen_ok_ = false;
    }
    (void)ring_->poll(0);  // flush the cancellations
    bufs_.destroy();
    ring_->remove_sink(sink_);
    ring_->remove_sink(ts_sink_);
  }
  sink_ = ts_sink_ = 0;
  listen_fd_.reset();
  accept_armed_ = false;
  if (owns_) {
    own_ring_.close();
    owns_ = false;
  }
  ring_ = nullptr;
  opened_ = false;
}

void TcpPort::cancel_fixed(std::uint32_t fixed) noexcept {
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;
  io_uring_prep_cancel_fd(s, static_cast<int>(fixed), IORING_ASYNC_CANCEL_ALL | IORING_ASYNC_CANCEL_FD_FIXED);
  io_uring_sqe_set_data64(s, make_ud(0, 0, 0));
  (void)ring_->submit();
}

Result<Endpoint> TcpPort::listen(Endpoint bind) {
  if (!opened_) return fail("uring::TcpPort::listen", EBADF);
  if (listen_ok_) return fail("uring::TcpPort::listen", EALREADY);
  auto l = sock::open_tcp_listener(cfg_, bind);
  if (!l) return std::unexpected(l.error());
  auto fx = ring_->register_file(l->fd.get());
  if (!fx) return std::unexpected(fx.error());
  listen_fixed_ = *fx;
  listen_ok_ = true;
  listen_fd_ = std::move(l->fd);
  listen_ep_ = l->local;
  arm_accept();
  (void)ring_->submit();
  return listen_ep_;
}

void TcpPort::arm_accept() noexcept {
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;
  io_uring_prep_multishot_accept(s, static_cast<int>(listen_fixed_), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, ud(sink_, kOpAccept, make_conn_id(kListenSlot, 0)));
  if (accept_armed_) ++stats_.rearms;
  accept_armed_ = true;
}

Result<void> TcpPort::attach(ConnId id, Conn& k, UniqueFd fd) {
  (void)id;
  auto fx = ring_->register_file(fd.get());
  if (!fx) return std::unexpected(fx.error());
  k.fd = std::move(fd);
  k.fixed = *fx;
  k.fixed_ok = true;
  k.recv_armed = false;
  k.send_inflight = false;
  k.tx.clear();
  k.recs.clear();
  k.stamps.clear();
  return {};
}

void TcpPort::become_open(ConnId id, Conn& k) noexcept {
  k.state = State::Open;
  if (!sock::enable_tcp_timestamps(k.fd.get(), cfg_)) ++stats_.errors;
  arm_recv(id, k);
  if (ts_uring_) arm_tx_ts(id, k);
}

Result<ConnId> TcpPort::connect(Endpoint peer) {
  if (!opened_) return fail("uring::TcpPort::connect", EBADF);
  auto fd = open_socket(SOCK_STREAM);
  if (!fd) return std::unexpected(fd.error());
  if (auto r = sock::setup_tcp_socket(fd->get(), cfg_); !r) return std::unexpected(r.error());
  const ConnId id = conns_.alloc();
  if (id == kNoConn) return fail("uring::TcpPort::connect", ENOBUFS);
  Conn& k = conns_.at(conn_slot(id));  // id fresh from alloc()
  if (auto r = attach(id, k, std::move(*fd)); !r) {
    conns_.free(id);
    return std::unexpected(r.error());
  }
  k.peer = to_sockaddr(peer);
  k.state = State::Connecting;
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) {
    release(id);
    return fail("uring::TcpPort::connect", EBUSY);
  }
  io_uring_prep_connect(s, static_cast<int>(k.fixed), reinterpret_cast<const sockaddr*>(&k.peer), sizeof(sockaddr_in));
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, ud(sink_, kOpConnect, id));
  (void)ring_->submit();
  return id;
}

void TcpPort::arm_recv(ConnId id, Conn& k) noexcept {
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;
  io_uring_prep_recvmsg_multishot(s, static_cast<int>(k.fixed), &tmpl_, 0);
  s->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
  s->buf_group = bufs_.group();
  io_uring_sqe_set_data64(s, ud(sink_, kOpRecv, id));
  k.recv_armed = true;
}

void TcpPort::arm_tx_ts(ConnId id, Conn& k) noexcept {
#if defined(IORING_TIMESTAMP_HW_SHIFT)
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) return;
  io_uring_prep_cmd_sock(s, SOCKET_URING_OP_TX_TIMESTAMP, static_cast<int>(k.fixed), 0, 0, nullptr, 0);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, ud(ts_sink_, kOpTxTs, id));
#else
  (void)id;
  (void)k;
#endif
}

std::size_t TcpPort::write(ConnId c, std::span<const std::byte> data) noexcept {
  Conn* k = conns_.get(c);
  if (k == nullptr || k->state != State::Open || data.empty()) return 0;
  const std::size_t len = data.size();
  const std::uint32_t room = k->tx.max_reserve();
  std::uint32_t n;
  if (cfg_.one_msg_per_send && len <= k->tx.capacity()) {
    if (len > room) {  // all or nothing: a message is never split across sends
      ++stats_.tx_short;
      return 0;
    }
    n = static_cast<std::uint32_t>(len);
  } else {
    n = static_cast<std::uint32_t>(len < room ? len : room);
  }
  if (n == 0 || k->recs.full()) {
    ++stats_.tx_short;
    return 0;
  }
  std::byte* p = k->tx.reserve(n);
  if (p == nullptr) {
    ++stats_.tx_short;
    return 0;
  }
  std::memcpy(p, data.data(), n);
  k->tx.commit(n);
  (void)k->recs.push(n);
  if (n < len) ++stats_.tx_short;
  issue_send(c, *k);
  return n;
}

void TcpPort::issue_send(ConnId id, Conn& k) noexcept {
  if (k.send_inflight || k.tx.empty() || !k.fixed_ok) return;
  const std::span<std::byte> f = k.tx.front();
  auto len = static_cast<std::uint32_t>(f.size());
  if (cfg_.one_msg_per_send && !k.recs.empty() && k.recs.front() < len) len = k.recs.front();
  io_uring_sqe* s = ring_->sqe();
  if (s == nullptr) {
    send_stalled_ = true;
    return;
  }
  int flags = MSG_NOSIGNAL;
  if (cfg_.one_msg_per_send) flags |= MSG_EOR;
  io_uring_prep_send(s, static_cast<int>(k.fixed), f.data(), len, flags);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, ud(sink_, kOpSend, id));
  k.send_inflight = true;
  ++stats_.tx_sends;
  (void)ring_->submit();  // latency path: issue now
}

void TcpPort::retry_stalled_sends() noexcept {
  send_stalled_ = false;
  for (std::uint32_t s = 0; s < conns_.capacity(); ++s) {
    if (!conns_.in_use(s)) continue;
    Conn& k = conns_.at(s);
    if (k.state == State::Open) issue_send(conns_.id_of(s), k);
  }
}

void TcpPort::close(ConnId c) noexcept { release(c); }

void TcpPort::release(ConnId c) noexcept {
  Conn* k = conns_.get(c);
  if (k == nullptr) return;
  if (k->fixed_ok && ring_ != nullptr && ring_->is_open()) {
    cancel_fixed(k->fixed);
    ring_->unregister_file(k->fixed);
  }
  k->fixed_ok = false;
  k->fd.reset();
  k->state = State::Free;
  k->recv_armed = false;
  k->send_inflight = false;
  k->tx.clear();
  k->recs.clear();
  k->stamps.clear();
  conns_.free(c);
}

TcpPort::Event TcpPort::handle(const Cqe& c) noexcept {
  if (aux_epoch(c.user_data) != epoch_) return Event{};  // a previous port's completion
  const auto op = static_cast<Op>(ud_op(c.user_data));
  const ConnId id = aux_payload(c.user_data);
  if (op == kOpAccept) return on_accept(c);
  Conn* k = conns_.get(id);
  if (k == nullptr) {  // connection already closed: just give the buffer back
    Event e;
    e.bid = cqe_buffer_id(c);
    return e;
  }
  switch (op) {
    case kOpConnect: return on_connect(c, id, *k);
    case kOpRecv: return on_recv(c, id, *k);
    case kOpSend: return on_send(c, id, *k);
    default: return Event{};
  }
}

TcpPort::Event TcpPort::on_accept(const Cqe& c) noexcept {
  if (!cqe_more(c)) accept_armed_ = false;
  if (c.res < 0) {
    if (c.res != -ECANCELED) ++stats_.errors;
    return Event{};
  }
  UniqueFd fd(c.res);
  if (!listen_ok_) return Event{};
  const ConnId id = conns_.alloc();
  if (id == kNoConn) {
    ++stats_.accept_rejected;  // table full: close at once
    return Event{};
  }
  Conn& k = conns_.at(conn_slot(id));  // id fresh from alloc()
  if (!sock::setup_tcp_socket(fd.get(), cfg_) || !attach(id, k, std::move(fd))) {
    ++stats_.errors;
    conns_.free(id);
    return Event{};
  }
  become_open(id, k);
  ++stats_.accepted;
  Event e;
  e.kind = env::StreamEventKind::Accepted;
  e.conn = id;
  e.emit = true;
  return e;
}

TcpPort::Event TcpPort::on_connect(const Cqe& c, ConnId id, Conn& k) noexcept {
  Event e;
  e.conn = id;
  if (k.state != State::Connecting) return e;
  e.emit = true;
  if (c.res < 0) {
    ++stats_.errors;
    e.kind = env::StreamEventKind::Closed;
    e.release = true;
    ++stats_.closed;
    return e;
  }
  become_open(id, k);
  ++stats_.connected;
  e.kind = env::StreamEventKind::Connected;
  return e;
}

TcpPort::Event TcpPort::on_recv(const Cqe& c, ConnId id, Conn& k) noexcept {
  Event e;
  e.conn = id;
  e.bid = cqe_buffer_id(c);
  const bool more = cqe_more(c);
  if (!more) k.recv_armed = false;
  if (k.state != State::Open) return e;
  auto closed = [&] {
    e.kind = env::StreamEventKind::Closed;
    e.emit = true;
    e.release = true;
    ++stats_.closed;
    return e;
  };
  if (c.res < 0) {
    if (c.res == -ENOBUFS) {
      ++stats_.no_buffers;
      ++stats_.rearms;
      arm_recv(id, k);
      return e;
    }
    if (c.res == -ECANCELED) return e;
    ++stats_.errors;  // ECONNRESET, ...
    return closed();
  }
  if (e.bid < 0) return closed();  // res 0 without a buffer: EOF
  io_uring_recvmsg_out* out = io_uring_recvmsg_validate(bufs_.data(static_cast<std::uint16_t>(e.bid)), c.res, &tmpl_);
  if (out == nullptr) {
    ++stats_.errors;
    return e;
  }
  const unsigned len = io_uring_recvmsg_payload_length(out, c.res, &tmpl_);
  if (len == 0) return closed();  // EOF ends the multishot request with an empty payload
  ++stats_.rx_reads;
  stats_.rx_bytes += len;
  if (want_rx_ts_ && out->controllen > 0) {
    hwts::ControlInfo ci{};
    const auto* ctrl = static_cast<const std::byte*>(io_uring_recvmsg_name(out)) + tmpl_.msg_namelen;
    hwts::parse_control(ctrl, out->controllen, ci);
    e.hw_rx_ns = ci.ts.hw_ns;
    stats_.rx_ts.record(classify(ci.ts));
  } else if (want_rx_ts_) {
    stats_.rx_ts.record(TsKind::None);
  }
  e.kind = env::StreamEventKind::Data;
  e.data = {static_cast<const std::byte*>(io_uring_recvmsg_payload(out, &tmpl_)), len};
  e.emit = true;
  if (!more) {
    ++stats_.rearms;
    arm_recv(id, k);
  }
  return e;
}

TcpPort::Event TcpPort::on_send(const Cqe& c, ConnId id, Conn& k) noexcept {
  Event e;
  e.conn = id;
  k.send_inflight = false;
  if (k.state != State::Open) return e;
  if (c.res < 0) {
    if (c.res == -ECANCELED) return e;
    ++stats_.errors;  // EPIPE / ECONNRESET
    e.kind = env::StreamEventKind::Closed;
    e.emit = true;
    e.release = true;
    ++stats_.closed;
    return e;
  }
  auto n = static_cast<std::uint32_t>(c.res);
  stats_.tx_bytes += n;
  k.tx.consume(n);
  while (n > 0 && !k.recs.empty()) {
    std::uint32_t& r = k.recs.front();
    const std::uint32_t take = r < n ? r : n;
    r -= take;
    n -= take;
    if (r == 0) k.recs.pop();
  }
  issue_send(id, k);
  return e;
}

void TcpPort::route_stamps() noexcept {
  while (!tsq_.empty()) {
    const Cqe c = tsq_.front();
    tsq_.pop();
    if (aux_epoch(c.user_data) != epoch_) continue;
    const ConnId id = aux_payload(c.user_data);
    Conn* k = conns_.get(id);
    if (k == nullptr) continue;
    if (c.res >= 0) {
      if (!k->stamps.push(tx_stamp_from_cqe(c))) ++stats_.errors;  // reader fell behind
    } else if (c.res != -ECANCELED) {
      if (!cqe_more(c) && (c.res == -EINVAL || c.res == -EOPNOTSUPP || c.res == -ENOTTY)) {
        ts_uring_ = false;  // kernel without SOCKET_URING_OP_TX_TIMESTAMP: use the error queue
        continue;
      }
      ++stats_.errors;
    }
    if (!cqe_more(c) && c.res != -ECANCELED && ts_uring_ && k->state == State::Open) arm_tx_ts(id, *k);
  }
}

}  // namespace lle::net::uring

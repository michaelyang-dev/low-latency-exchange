#include "net/sock/tcp_port.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <cerrno>

#include "net/common/sockopt.h"
#include "net/hwts/cmsg.h"
#include "net/sock/socket_setup.h"

namespace lle::net::sock {

Result<void> TcpPort::open(const TcpConfig& cfg, Poller* shared) {
  if (opened_) return fail("TcpPort::open", EALREADY);
  if (cfg.max_conns == 0 || cfg.max_conns > ConnTable<Conn>::kMaxCapacity || cfg.rx_buf_bytes == 0 ||
      cfg.max_reads_per_poll == 0)
    return fail("TcpPort::open", EINVAL);
  cfg_ = cfg;
  if (shared == nullptr) {
    if (auto r = own_poller_.open(64); !r) return r;
    poller_ = &own_poller_;
    owns_poller_ = true;
  } else {
    poller_ = shared;
    owns_poller_ = false;
  }
  conns_.init(cfg.max_conns);
  ready_.init(std::size_t{cfg.max_conns} + 1);
  deferred_.init(2 * std::size_t{cfg.max_conns} + 2);
  rx_ = std::make_unique<std::byte[]>(cfg.rx_buf_bytes);
  want_rx_ts_ = cfg.rx_ts != TsMode::Off;
  opened_ = true;
  return {};
}

void TcpPort::shutdown() noexcept {
  if (!opened_) return;
  for (std::uint32_t s = 0; s < conns_.capacity(); ++s) {
    if (conns_.in_use(s)) release(conns_.id_of(s));
  }
  if (listen_fd_) {
    poller_->remove(listen_fd_.get(), listen_r_);
    listen_fd_.reset();
  }
  deferred_.clear();
}

Result<void> TcpPort::setup_socket(int fd) const { return setup_tcp_socket(fd, cfg_); }

void TcpPort::enable_conn_timestamps(int fd) noexcept {
  if (!enable_tcp_timestamps(fd, cfg_)) ++stats_.errors;
}

void TcpPort::defer(env::StreamEventKind kind, ConnId c) noexcept {
  const bool ok = deferred_.push(Deferred{kind, c});
  LLE_ASSERT(ok, "deferred stream event queue overflow");
}

void TcpPort::init_readiness(Conn& k, ConnId id) noexcept {
  // `queued` is left alone: a stale entry for this slot may still sit in the ready list,
  // and it must not be queued twice.
  k.r.events = 0;
  k.r.interest = 0;
  k.r.token = conn_slot(id);
  k.r.list = &ready_;
}

Result<Endpoint> TcpPort::listen(Endpoint bind) {
  if (!opened_) return fail("TcpPort::listen", EBADF);
  if (listen_fd_) return fail("TcpPort::listen", EALREADY);
  auto l = open_tcp_listener(cfg_, bind);
  if (!l) return std::unexpected(l.error());
  listen_r_ = Readiness{};
  listen_r_.token = kListenToken;
  listen_r_.list = &ready_;
  if (auto r = poller_->add(l->fd.get(), kReadable, listen_r_); !r) return std::unexpected(r.error());
  listen_fd_ = std::move(l->fd);
  listen_ep_ = l->local;
  return listen_ep_;
}

Result<ConnId> TcpPort::connect(Endpoint peer) {
  if (!opened_) return fail("TcpPort::connect", EBADF);
  auto fd = open_socket(SOCK_STREAM);
  if (!fd) return std::unexpected(fd.error());
  if (auto r = setup_socket(fd->get()); !r) return std::unexpected(r.error());
  const ConnId id = conns_.alloc();
  if (id == kNoConn) return fail("TcpPort::connect", ENOBUFS);
  Conn& k = conns_.at(conn_slot(id));  // id fresh from alloc()
  init_readiness(k, id);
  const sockaddr_in sa = to_sockaddr(peer);
  const int rc = ::connect(fd->get(), reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
  if (rc != 0 && errno != EINPROGRESS) {
    const int err = errno;
    conns_.free(id);
    return fail("connect", err);
  }
  const bool done = rc == 0;
  if (auto r = poller_->add(fd->get(), done ? kReadable : (kReadable | kWritable), k.r); !r) {
    conns_.free(id);
    return std::unexpected(r.error());
  }
  k.fd = std::move(*fd);
  if (done) {
    k.state = State::Open;
    enable_conn_timestamps(k.fd.get());
    ++stats_.connected;
    defer(env::StreamEventKind::Connected, id);
  } else {
    k.state = State::Connecting;
  }
  return id;
}

std::size_t TcpPort::write(ConnId c, std::span<const std::byte> data) noexcept {
  Conn* k = conns_.get(c);
  if (k == nullptr || k->state != State::Open || data.empty()) return 0;
  int flags = MSG_DONTWAIT;
#if defined(__linux__)
  flags |= MSG_NOSIGNAL;
  if (cfg_.one_msg_per_send) flags |= MSG_EOR;
#endif
  ssize_t n;
  do {
    n = ::send(k->fd.get(), data.data(), data.size(), flags);
  } while (n < 0 && errno == EINTR);
  ++stats_.tx_sends;
  if (n >= 0) {
    const auto sent = static_cast<std::size_t>(n);
    stats_.tx_bytes += sent;
    if (sent < data.size()) ++stats_.tx_short;
    return sent;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
    ++stats_.tx_short;
    return 0;
  }
  // EPIPE / ECONNRESET / ...: the connection is gone; Closed comes from the next poll().
  ++stats_.errors;
  poller_->remove(k->fd.get(), k->r);
  k->fd.reset();
  k->state = State::Closing;
  defer(env::StreamEventKind::Closed, c);
  return 0;
}

void TcpPort::close(ConnId c) noexcept { release(c); }

void TcpPort::release(ConnId c) noexcept {
  Conn* k = conns_.get(c);
  if (k == nullptr) return;
  if (k->fd) {
    poller_->remove(k->fd.get(), k->r);
    k->fd.reset();
  }
  k->state = State::Free;
  k->r.events = 0;
  conns_.free(c);
}

ConnId TcpPort::accept_one(bool& again) noexcept {
  sockaddr_in sa{};
  socklen_t len = sizeof(sa);
#if defined(__linux__)
  const int fd = ::accept4(listen_fd_.get(), reinterpret_cast<sockaddr*>(&sa), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
  const int fd = ::accept(listen_fd_.get(), reinterpret_cast<sockaddr*>(&sa), &len);
#endif
  if (fd < 0) {
    const int e = errno;
    if (e == EINTR || e == ECONNABORTED || e == EPROTO) return kNoConn;  // try the next one
    if (e != EAGAIN && e != EWOULDBLOCK) ++stats_.errors;  // EMFILE etc.
    listen_r_.events &= ~kReadable;
    again = true;
    return kNoConn;
  }
  UniqueFd guard(fd);
#if !defined(__linux__)
  if (!set_nonblocking(fd) || ::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 ||
      !set_int_option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1, "setsockopt(SO_NOSIGPIPE)")) {
    ++stats_.errors;
    return kNoConn;
  }
#endif
  const ConnId id = conns_.alloc();
  if (id == kNoConn) {
    ++stats_.accept_rejected;  // table full: close at once rather than leave it queued
    return kNoConn;
  }
  if (!setup_socket(fd)) {
    ++stats_.errors;
    conns_.free(id);
    return kNoConn;
  }
  Conn& k = conns_.at(conn_slot(id));  // id fresh from alloc()
  init_readiness(k, id);
  if (!poller_->add(fd, kReadable, k.r)) {
    ++stats_.errors;
    conns_.free(id);
    return kNoConn;
  }
  k.fd = std::move(guard);
  k.state = State::Open;
  enable_conn_timestamps(fd);
  ++stats_.accepted;
  return id;
}

TcpPort::Step TcpPort::finish_connect(Conn& k) noexcept {
  const auto err = socket_error(k.fd.get());
  if (!err || *err != 0) {
    ++stats_.errors;
    return Step::Closed;
  }
  if ((k.r.events & kWritable) == 0) return Step::Pending;
  // Drop write interest: TCP write-space edges would otherwise wake blocking waits.
  if (!poller_->modify(k.fd.get(), kReadable, k.r)) {
    ++stats_.errors;
    return Step::Closed;
  }
  k.r.events &= ~kWritable;
  k.state = State::Open;
  enable_conn_timestamps(k.fd.get());
  ++stats_.connected;
  return Step::Connected;
}

TcpPort::Step TcpPort::read_some(Conn& k, std::size_t& len, Nanos& hw) noexcept {
  const std::size_t cap = cfg_.rx_buf_bytes;
  ssize_t n;
  hwts::ControlInfo ci{};
  for (;;) {
    if (want_rx_ts_) {
      iovec iov{rx_.get(), cap};
      msghdr m{};
      m.msg_iov = &iov;
      m.msg_iovlen = 1;
      m.msg_control = control_;
      m.msg_controllen = sizeof(control_);
      n = ::recvmsg(k.fd.get(), &m, MSG_DONTWAIT);
      if (n > 0 && m.msg_controllen > 0) hwts::parse_control(m, ci);
    } else {
      n = ::recv(k.fd.get(), rx_.get(), cap, MSG_DONTWAIT);
    }
    if (n >= 0 || errno != EINTR) break;
  }
  ++stats_.rx_reads;
  if (n > 0) {
    len = static_cast<std::size_t>(n);
    stats_.rx_bytes += len;
    // A short read drains a stream socket (epoll(7)); new data raises a new edge. A
    // pending hangup stays set so the FIN is read on the next iteration.
    if (len < cap) k.r.events &= ~kReadable;
    if (want_rx_ts_) {
      hw = ci.ts.hw_ns;
      stats_.rx_ts.record(classify(ci.ts));
    }
    return Step::Data;
  }
  if (n == 0) return Step::Closed;
  if (errno == EAGAIN || errno == EWOULDBLOCK) {
    k.r.events &= ~(kReadable | kHangup);
    return Step::Again;
  }
  ++stats_.errors;  // ECONNRESET, ETIMEDOUT, ...
  return Step::Closed;
}

}  // namespace lle::net::sock

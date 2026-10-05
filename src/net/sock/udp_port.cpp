#include "net/sock/udp_port.h"

#include <cerrno>

#include "net/hwts/cmsg.h"
#include "net/sock/socket_setup.h"

namespace lle::net::sock {

Result<void> UdpPort::open(const UdpConfig& cfg, Poller* poller) {
  if (is_open()) return fail("UdpPort::open", EALREADY);
  if (cfg.batch == 0 || cfg.max_datagram == 0 || cfg.batch > 1024) return fail("UdpPort::open", EINVAL);
  cfg_ = cfg;
  auto so = open_udp_socket(cfg);
  if (!so) return std::unexpected(so.error());
  local_ = so->local;
  ts_flags_ = so->ts_flags;
  want_ts_ = cfg.rx_ts != TsMode::Off;

  // Startup allocation of every per-datagram structure.
  const std::uint32_t b = cfg.batch;
  if (auto r = bufs_.init(b, cfg.max_datagram, 64); !r) return r;
  rx_ = std::make_unique<RxSlot[]>(b);
  control_ = std::make_unique<std::byte[]>(std::size_t{b} * kControlBytes);
  iov_ = std::make_unique<iovec[]>(b);
  names_ = std::make_unique<sockaddr_in[]>(b);
  for (std::uint32_t i = 0; i < b; ++i) {
    iov_[i].iov_base = bufs_.data(i);
    iov_[i].iov_len = cfg.max_datagram;
  }
#if defined(__linux__)
  msgs_ = std::make_unique<mmsghdr[]>(b);
  for (std::uint32_t i = 0; i < b; ++i) {
    msghdr& h = msgs_[i].msg_hdr;
    h.msg_name = &names_[i];
    h.msg_namelen = sizeof(sockaddr_in);
    h.msg_iov = &iov_[i];
    h.msg_iovlen = 1;
    h.msg_control = control_.get() + std::size_t{i} * kControlBytes;
    h.msg_controllen = kControlBytes;
  }
#endif

  if (poller != nullptr) {
    r_ = Readiness{};
    r_.events = kReadable;  // try once: data may predate registration
    if (auto r = poller->add(so->fd.get(), kReadable, r_); !r) return r;
    poller_ = poller;
  }
  fd_ = std::move(so->fd);
  return {};
}

void UdpPort::close() noexcept {
  if (!fd_) return;
  if (poller_ != nullptr) poller_->remove(fd_.get(), r_);
  poller_ = nullptr;
  fd_.reset();
}

bool UdpPort::send(Endpoint dst, std::span<const std::byte> data) noexcept {
  const sockaddr_in sa = to_sockaddr(dst);
  int flags = MSG_DONTWAIT;
#if defined(__linux__)
  flags |= MSG_NOSIGNAL;
#endif
  const ssize_t n =
      ::sendto(fd_.get(), data.data(), data.size(), flags, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
  if (n >= 0 && static_cast<std::size_t>(n) == data.size()) {
    ++stats_.tx_packets;
    stats_.tx_bytes += data.size();
    return true;
  }
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
    ++stats_.tx_dropped;
  } else {
    ++stats_.tx_errors;
  }
  return false;
}

std::size_t UdpPort::recv_batch() noexcept {
  const std::uint32_t b = cfg_.batch;
  std::size_t out = 0;
#if defined(__linux__)
  for (std::uint32_t i = 0; i < b; ++i) {
    msghdr& h = msgs_[i].msg_hdr;
    h.msg_namelen = sizeof(sockaddr_in);
    h.msg_controllen = kControlBytes;
    h.msg_flags = 0;
  }
  ++stats_.rx_calls;
  const int n = ::recvmmsg(fd_.get(), msgs_.get(), b, MSG_DONTWAIT, nullptr);
  if (n <= 0) {
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) ++stats_.rx_errors;
    r_.events &= ~(kReadable | kHangup);
    return 0;
  }
  for (int i = 0; i < n; ++i) {
    const auto k = static_cast<std::size_t>(i);
    const msghdr& h = msgs_[k].msg_hdr;
    const std::size_t len = msgs_[k].msg_len;
    if ((h.msg_flags & MSG_TRUNC) != 0) {
      ++stats_.rx_truncated;
      continue;
    }
    hwts::ControlInfo ci{};
    if (h.msg_controllen > 0) hwts::parse_control(h, ci);
    RxSlot& s = rx_[out++];
    s.d.data = {bufs_.data(static_cast<std::uint32_t>(i)), len};
    s.d.src = from_sockaddr(names_[k]);
    s.d.dst = ci.has_dst ? Endpoint{ci.dst_ipv4, local_.port} : local_;
    s.d.hw_rx_ns = ci.ts.hw_ns;
    s.ts = ci.ts;
    if (want_ts_) stats_.rx_ts.record(classify(ci.ts));
    ++stats_.rx_packets;
    stats_.rx_bytes += len;
  }
  // A short batch means the queue was empty at that instant; new arrivals re-signal.
  if (static_cast<std::uint32_t>(n) < b) r_.events &= ~(kReadable | kHangup);
#else
  ++stats_.rx_calls;
  std::uint32_t i = 0;
  for (; i < b; ++i) {
    msghdr h{};
    h.msg_name = &names_[i];
    h.msg_namelen = sizeof(sockaddr_in);
    h.msg_iov = &iov_[i];
    h.msg_iovlen = 1;
    h.msg_control = control_.get() + std::size_t{i} * kControlBytes;
    h.msg_controllen = kControlBytes;
    const ssize_t n = ::recvmsg(fd_.get(), &h, MSG_DONTWAIT);
    if (n < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) ++stats_.rx_errors;
      break;
    }
    if ((h.msg_flags & MSG_TRUNC) != 0) {
      ++stats_.rx_truncated;
      continue;
    }
    const auto len = static_cast<std::size_t>(n);
    hwts::ControlInfo ci{};
    if (h.msg_controllen > 0) hwts::parse_control(h, ci);
    RxSlot& s = rx_[out++];
    s.d.data = {bufs_.data(i), len};
    s.d.src = from_sockaddr(names_[i]);
    s.d.dst = ci.has_dst ? Endpoint{ci.dst_ipv4, local_.port} : local_;
    s.d.hw_rx_ns = ci.ts.hw_ns;
    s.ts = ci.ts;
    if (want_ts_) stats_.rx_ts.record(classify(ci.ts));
    ++stats_.rx_packets;
    stats_.rx_bytes += len;
  }
  if (i < b) r_.events &= ~(kReadable | kHangup);
#endif
  return out;
}

}  // namespace lle::net::sock

#include "admin/net.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <utility>

namespace lle::admin {

namespace {
std::string sys_error(const char* what) { return std::string(what) + ": " + std::strerror(errno); }

bool set_nonblocking(int fd) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  return fl >= 0 && ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}
}  // namespace

std::expected<Key, std::string> parse_key_hex(std::string_view hex) {
  Key k;
  int hi = -1;
  for (char c : hex) {
    int v;
    if (c >= '0' && c <= '9') {
      v = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      v = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
      v = c - 'A' + 10;
    } else if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
      continue;
    } else {
      return std::unexpected(std::string("key: not hex"));
    }
    if (hi < 0) {
      hi = v;
    } else {
      k.push_back(static_cast<std::uint8_t>(hi * 16 + v));
      hi = -1;
    }
  }
  if (hi >= 0) return std::unexpected(std::string("key: odd number of hex digits"));
  if (k.size() < 16) return std::unexpected(std::string("key: at least 16 bytes"));
  return k;
}

std::expected<Key, std::string> load_key_file(const std::string& path) {
  std::ifstream f(path);
  if (!f) return std::unexpected("cannot read key file " + path);
  const std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return parse_key_hex(s);
}

std::expected<std::vector<std::byte>, std::string> exchange(const std::string& host, std::uint16_t port,
                                                            std::span<const std::byte> frame, int timeout_ms) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  const std::string ps = std::to_string(port);
  if (::getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || res == nullptr)
    return std::unexpected("cannot resolve " + host);
  int fd = -1;
  for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
    fd = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd < 0) continue;
    if (::connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(res);
  if (fd < 0) return std::unexpected(sys_error("connect"));
  std::size_t off = 0;
  while (off < frame.size()) {
    const ssize_t n = ::send(fd, frame.data() + off, frame.size() - off, 0);
    if (n <= 0) {
      ::close(fd);
      return std::unexpected(sys_error("send"));
    }
    off += static_cast<std::size_t>(n);
  }
  std::vector<std::byte> resp(kResponseBytes);
  off = 0;
  while (off < resp.size()) {
    pollfd p{fd, POLLIN, 0};
    if (::poll(&p, 1, timeout_ms) <= 0) {
      ::close(fd);
      return std::unexpected(std::string("no response from the admin port"));
    }
    const ssize_t n = ::recv(fd, resp.data() + off, resp.size() - off, 0);
    if (n <= 0) {
      ::close(fd);
      return std::unexpected(std::string("connection closed by the admin port"));
    }
    off += static_cast<std::size_t>(n);
  }
  ::close(fd);
  return resp;
}

std::expected<TcpListener, std::string> TcpListener::open(std::uint16_t port, OnBytes on_bytes, OnClose on_close) {
  return open(INADDR_LOOPBACK, port, std::move(on_bytes), std::move(on_close));
}

std::expected<TcpListener, std::string> TcpListener::open(std::uint32_t ipv4, std::uint16_t port, OnBytes on_bytes,
                                                         OnClose on_close) {
  TcpListener l;
  l.on_bytes_ = std::move(on_bytes);
  l.on_close_ = std::move(on_close);
  l.fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (l.fd_ < 0) return std::unexpected(sys_error("socket"));
  const int one = 1;
  (void)::setsockopt(l.fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(ipv4);
  if (::bind(l.fd_, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) != 0) return std::unexpected(sys_error("bind"));
  if (::listen(l.fd_, 16) != 0) return std::unexpected(sys_error("listen"));
  if (!set_nonblocking(l.fd_)) return std::unexpected(sys_error("fcntl"));
  socklen_t len = sizeof(a);
  if (::getsockname(l.fd_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return std::unexpected(sys_error("getsockname"));
  l.port_ = ntohs(a.sin_port);
  return l;
}

TcpListener::TcpListener(TcpListener&& o) noexcept
    : fd_(std::exchange(o.fd_, -1)), port_(o.port_), next_id_(o.next_id_), conns_(std::move(o.conns_)),
      on_bytes_(std::move(o.on_bytes_)), on_close_(std::move(o.on_close_)) {}

TcpListener::~TcpListener() {
  for (Conn& c : conns_)
    if (c.fd >= 0) ::close(c.fd);
  if (fd_ >= 0) ::close(fd_);
}

std::size_t TcpListener::connections() const noexcept {
  return static_cast<std::size_t>(std::count_if(conns_.begin(), conns_.end(), [](const Conn& c) { return c.fd >= 0; }));
}

void TcpListener::close_conn(Conn& c) {
  if (c.fd < 0) return;
  ::close(c.fd);
  c.fd = -1;
  if (on_close_) on_close_(c.id);
}

int TcpListener::step(int timeout_ms) {
  std::vector<pollfd> pf;
  pf.push_back(pollfd{fd_, POLLIN, 0});
  for (const Conn& c : conns_) {
    short ev = POLLIN;
    if (!c.pending.empty()) ev = static_cast<short>(ev | POLLOUT);
    pf.push_back(pollfd{c.fd, ev, 0});
  }
  const int n = ::poll(pf.data(), static_cast<nfds_t>(pf.size()), timeout_ms);
  if (n <= 0) return 0;
  int handled = 0;
  for (std::size_t i = 1; i < pf.size(); ++i) {
    Conn& c = conns_[i - 1];
    if (c.fd < 0) continue;
    if ((pf[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (pf[i].revents & POLLIN) == 0) {
      close_conn(c);
      continue;
    }
    if ((pf[i].revents & POLLIN) != 0) {
      std::byte buf[4096];
      const ssize_t r = ::recv(c.fd, buf, sizeof(buf), 0);
      if (r <= 0) {
        close_conn(c);
        continue;
      }
      ++handled;
      if (!on_bytes_(c.id, std::span<const std::byte>(buf, static_cast<std::size_t>(r)), c.pending)) {
        // Best effort: flush the responses, then close.
        (void)::send(c.fd, c.pending.data(), c.pending.size(), 0);
        close_conn(c);
        continue;
      }
    }
    if (!c.pending.empty()) {
      const ssize_t w = ::send(c.fd, c.pending.data(), c.pending.size(), 0);
      if (w > 0) c.pending.erase(c.pending.begin(), c.pending.begin() + w);
    }
  }
  std::erase_if(conns_, [](const Conn& c) { return c.fd < 0; });
  if ((pf[0].revents & POLLIN) != 0) {
    for (;;) {
      const int cfd = ::accept(fd_, nullptr, nullptr);
      if (cfd < 0) break;
      (void)set_nonblocking(cfd);
      const int one = 1;
      (void)::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
      conns_.push_back(Conn{cfd, next_id_++, {}});
      ++handled;
    }
  }
  return handled;
}

}  // namespace lle::admin

// Kernel-TCP echo peer for the utcp interop suite (07 §2.4 Utcp.InteropLinuxPeer).
// Runs in the peer network namespace and echoes every byte back to the utcp side.
//
//   kernel_peer --listen PORT [--bind IP] | --connect IP:PORT
//               [--close-after N [--rst]] [--timeout-s S]
//
// --close-after N: after echoing N bytes, close first (FIN) or, with --rst, reset
// (SO_LINGER 0) after a short pause so the echo is delivered. Without it the peer echoes
// until the utcp side closes. Prints one summary line; exit 0 on a clean end.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "kernel_peer: %s: %s\n", what, std::strerror(errno));
  std::exit(2);
}

bool write_all(int fd, const char* p, std::size_t n) {
  while (n != 0) {
    const ssize_t w = ::write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= static_cast<std::size_t>(w);
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  int listen_port = 0;
  std::string bind_ip = "0.0.0.0";
  std::string connect_to;
  unsigned long long close_after = 0;
  bool rst = false;
  int timeout_s = 600;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--listen") listen_port = std::atoi(next().c_str());
    else if (a == "--bind") bind_ip = next();
    else if (a == "--connect") connect_to = next();
    else if (a == "--close-after") close_after = std::strtoull(next().c_str(), nullptr, 10);
    else if (a == "--rst") rst = true;
    else if (a == "--timeout-s") timeout_s = std::atoi(next().c_str());
    else {
      std::fprintf(stderr, "kernel_peer: unknown argument %s\n", a.c_str());
      return 2;
    }
  }
  int fd = -1;
  const int one = 1;
  if (listen_port != 0) {
    const int ls = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (ls < 0) die("socket");
    (void)::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<std::uint16_t>(listen_port));
    ::inet_pton(AF_INET, bind_ip.c_str(), &sa.sin_addr);
    if (::bind(ls, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) die("bind");
    if (::listen(ls, 4) != 0) die("listen");
    pollfd p{ls, POLLIN, 0};
    if (::poll(&p, 1, timeout_s * 1000) <= 0) {
      std::fprintf(stderr, "kernel_peer: no connection within %d s\n", timeout_s);
      return 3;
    }
    fd = ::accept4(ls, nullptr, nullptr, SOCK_CLOEXEC);
    if (fd < 0) die("accept");
    ::close(ls);
  } else {
    const auto colon = connect_to.find(':');
    if (colon == std::string::npos) {
      std::fprintf(stderr, "kernel_peer: need --listen or --connect IP:PORT\n");
      return 2;
    }
    fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) die("socket");
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<std::uint16_t>(std::atoi(connect_to.substr(colon + 1).c_str())));
    ::inet_pton(AF_INET, connect_to.substr(0, colon).c_str(), &sa.sin_addr);
    bool ok = false;
    for (int attempt = 0; attempt < 100 && !ok; ++attempt) {
      ok = ::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0;
      if (!ok) {
        ::close(fd);
        fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    if (!ok) die("connect");
  }
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  std::vector<char> buf(1 << 18);
  unsigned long long echoed = 0;
  const auto start = std::chrono::steady_clock::now();
  bool clean = false;
  while (true) {
    pollfd p{fd, POLLIN, 0};
    const int pr = ::poll(&p, 1, 1000);
    if (pr < 0 && errno != EINTR) die("poll");
    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(timeout_s)) {
      std::fprintf(stderr, "kernel_peer: timeout after %llu bytes\n", echoed);
      return 3;
    }
    if (pr <= 0) continue;
    std::size_t want = buf.size();
    if (close_after != 0 && close_after - echoed < want) want = static_cast<std::size_t>(close_after - echoed);
    const ssize_t r = ::read(fd, buf.data(), want);
    if (r == 0) {
      clean = close_after == 0;  // the utcp side closed first
      break;
    }
    if (r < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "kernel_peer: read: %s after %llu bytes\n", std::strerror(errno), echoed);
      return 4;
    }
    if (!write_all(fd, buf.data(), static_cast<std::size_t>(r))) {
      std::fprintf(stderr, "kernel_peer: write: %s after %llu bytes\n", std::strerror(errno), echoed);
      return 4;
    }
    echoed += static_cast<unsigned long long>(r);
    if (close_after != 0 && echoed >= close_after) {
      if (rst) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const linger l{1, 0};
        (void)::setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
      } else {
        // Close first, then wait for the utcp side's FIN (its stream port closes on EOF).
        (void)::shutdown(fd, SHUT_WR);
        pollfd q{fd, POLLIN, 0};
        char tail[64];
        while (::poll(&q, 1, 10000) > 0 && ::read(fd, tail, sizeof(tail)) > 0) {
        }
      }
      clean = true;
      break;
    }
  }
  ::close(fd);
  std::printf("kernel_peer: echoed %llu bytes, %s\n", echoed, clean ? "clean" : "unclean");
  return clean ? 0 : 5;
}

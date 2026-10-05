// Kernel UDP echo server for the AF_XDP veth tests (runs in the peer namespace).
//   xsk_udp_echo IP PORT [IP PORT ...]   echoes every datagram back to its sender
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char** argv) {
  std::vector<pollfd> fds;
  for (int i = 1; i + 1 < argc; i += 2) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<std::uint16_t>(std::atoi(argv[i + 1])));
    ::inet_pton(AF_INET, argv[i], &sa.sin_addr);
    const int big = 4 << 20;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &big, sizeof(big));
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
      std::perror("bind");
      return 2;
    }
    fds.push_back(pollfd{fd, POLLIN, 0});
  }
  char buf[65536];
  while (true) {
    if (::poll(fds.data(), fds.size(), -1) < 0) continue;
    for (auto& p : fds) {
      if ((p.revents & POLLIN) == 0) continue;
      for (;;) {
        sockaddr_in from{};
        socklen_t fl = sizeof(from);
        const ssize_t n = ::recvfrom(p.fd, buf, sizeof(buf), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&from), &fl);
        if (n < 0) break;
        (void)::sendto(p.fd, buf, static_cast<std::size_t>(n), 0, reinterpret_cast<sockaddr*>(&from), fl);
      }
    }
  }
}

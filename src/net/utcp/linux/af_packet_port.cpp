#include "net/utcp/linux/af_packet_port.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace lle::net::utcp {

std::expected<MacAddr, int> interface_mac(const std::string& ifname) {
  const int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) return std::unexpected(errno);
  ifreq ifr{};
  std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
  const int rc = ::ioctl(s, SIOCGIFHWADDR, &ifr);
  const int err = errno;
  ::close(s);
  if (rc < 0) return std::unexpected(err);
  MacAddr m;
  std::memcpy(m.b.data(), ifr.ifr_hwaddr.sa_data, 6);
  return m;
}

std::expected<AfPacketPort, int> AfPacketPort::open(const std::string& ifname, int rcvbuf_bytes) {
  AfPacketPort p;
  p.ifindex_ = static_cast<int>(::if_nametoindex(ifname.c_str()));
  if (p.ifindex_ == 0) return std::unexpected(errno != 0 ? errno : ENODEV);
  auto mac = interface_mac(ifname);
  if (!mac) return std::unexpected(mac.error());
  p.mac_ = *mac;
  p.fd_ = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (p.fd_ < 0) return std::unexpected(errno);
  const int one = 1;
  // Our own transmissions are not delivered back to us (kernel >= 4.20).
  (void)::setsockopt(p.fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
  if (rcvbuf_bytes > 0) {
    if (::setsockopt(p.fd_, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_bytes, sizeof(rcvbuf_bytes)) != 0) {
      (void)::setsockopt(p.fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf_bytes, sizeof(rcvbuf_bytes));
    }
  }
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = p.ifindex_;
  if (::bind(p.fd_, reinterpret_cast<const sockaddr*>(&sll), sizeof(sll)) != 0) return std::unexpected(errno);
  p.buf_ = std::make_unique<std::byte[]>(kBufSize);
  return p;
}

AfPacketPort::AfPacketPort(AfPacketPort&& o) noexcept
    : fd_(o.fd_), ifindex_(o.ifindex_), mac_(o.mac_), buf_(std::move(o.buf_)), stats_(o.stats_) {
  o.fd_ = -1;
}

AfPacketPort& AfPacketPort::operator=(AfPacketPort&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    ifindex_ = o.ifindex_;
    mac_ = o.mac_;
    buf_ = std::move(o.buf_);
    stats_ = o.stats_;
    o.fd_ = -1;
  }
  return *this;
}

AfPacketPort::~AfPacketPort() {
  if (fd_ >= 0) ::close(fd_);
}

bool AfPacketPort::send_frame(std::span<const std::byte> f) noexcept {
  const ssize_t n = ::send(fd_, f.data(), f.size(), MSG_DONTWAIT);
  if (n != static_cast<ssize_t>(f.size())) {
    ++stats_.tx_errors;
    return false;
  }
  ++stats_.tx_frames;
  return true;
}

std::ptrdiff_t AfPacketPort::recv_one() noexcept {
  const ssize_t n = ::recv(fd_, buf_.get(), kBufSize, MSG_DONTWAIT | MSG_TRUNC);
  if (n <= 0) return -1;
  if (static_cast<std::size_t>(n) > kBufSize) {
    ++stats_.rx_truncated;
    return 0;
  }
  ++stats_.rx_frames;
  return n;
}

}  // namespace lle::net::utcp

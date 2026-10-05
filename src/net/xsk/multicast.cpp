#include "net/xsk/multicast.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace lle::net::xsk {

std::expected<MulticastMembership, Error> MulticastMembership::join(const std::string& ifname, std::uint32_t group,
                                                                    std::uint32_t source) {
  const unsigned ifindex = ::if_nametoindex(ifname.c_str());
  if (ifindex == 0) return std::unexpected(Error{errno != 0 ? errno : ENODEV, "if_nametoindex"});
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return std::unexpected(Error{errno, "socket(UDP)"});
  const int small = 4096;  // the data is redirected by XDP before it reaches this socket
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
  int rc;
  if (source == 0) {
    ip_mreqn m{};
    m.imr_multiaddr.s_addr = htonl(group);
    m.imr_ifindex = static_cast<int>(ifindex);
    rc = ::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
  } else {
    // SSM (RFC 4607) with the interface given by index: MCAST_JOIN_SOURCE_GROUP.
    group_source_req g{};
    g.gsr_interface = ifindex;
    sockaddr_in grp{};
    grp.sin_family = AF_INET;
    grp.sin_addr.s_addr = htonl(group);
    sockaddr_in src{};
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = htonl(source);
    std::memcpy(&g.gsr_group, &grp, sizeof(grp));
    std::memcpy(&g.gsr_source, &src, sizeof(src));
    rc = ::setsockopt(fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP, &g, sizeof(g));
  }
  if (rc != 0) {
    const int e = errno;
    ::close(fd);
    return std::unexpected(Error{e, source == 0 ? "IP_ADD_MEMBERSHIP" : "MCAST_JOIN_SOURCE_GROUP"});
  }
  return MulticastMembership(fd);
}

MulticastMembership& MulticastMembership::operator=(MulticastMembership&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

MulticastMembership::~MulticastMembership() {
  if (fd_ >= 0) ::close(fd_);
}

}  // namespace lle::net::xsk

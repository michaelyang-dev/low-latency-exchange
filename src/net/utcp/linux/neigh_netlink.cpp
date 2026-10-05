#include "net/utcp/linux/neigh_netlink.h"

#include <arpa/inet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

namespace lle::net::utcp {
namespace detail {

std::expected<std::size_t, int> dump_neighbors(int ifindex, KernelNeighbor* out, std::size_t cap) {
  const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return std::unexpected(errno);
  struct {
    nlmsghdr nh;
    ndmsg nd;
  } req{};
  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(ndmsg));
  req.nh.nlmsg_type = RTM_GETNEIGH;
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nh.nlmsg_seq = 1;
  req.nd.ndm_family = AF_INET;
  req.nd.ndm_ifindex = ifindex;
  sockaddr_nl kernel{};
  kernel.nl_family = AF_NETLINK;
  if (::sendto(fd, &req, req.nh.nlmsg_len, 0, reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) < 0) {
    const int e = errno;
    ::close(fd);
    return std::unexpected(e);
  }
  // Parsed with explicit offsets and memcpy (the NLMSG_*/RTA_* macros use C casts).
  constexpr std::size_t kAlign = 4;
  auto align = [](std::size_t n) { return (n + kAlign - 1) & ~(kAlign - 1); };
  static thread_local unsigned char buf[32768];
  std::size_t count = 0;
  bool done = false;
  while (!done) {
    const ssize_t got = ::recv(fd, buf, sizeof(buf), 0);
    if (got < 0) {
      const int e = errno;
      ::close(fd);
      return std::unexpected(e);
    }
    const auto len = static_cast<std::size_t>(got);
    std::size_t off = 0;
    while (off + sizeof(nlmsghdr) <= len) {
      nlmsghdr nh;
      std::memcpy(&nh, buf + off, sizeof(nh));
      if (nh.nlmsg_len < sizeof(nlmsghdr) || off + nh.nlmsg_len > len) break;
      const unsigned char* payload = buf + off + align(sizeof(nlmsghdr));
      const std::size_t plen = nh.nlmsg_len - align(sizeof(nlmsghdr));
      off += align(nh.nlmsg_len);
      if (nh.nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }
      if (nh.nlmsg_type == NLMSG_ERROR) {
        nlmsgerr err;
        std::memcpy(&err, payload, std::min(plen, sizeof(err)));
        ::close(fd);
        return std::unexpected(-err.error);
      }
      if (nh.nlmsg_type != RTM_NEWNEIGH || plen < sizeof(ndmsg)) continue;
      ndmsg nd;
      std::memcpy(&nd, payload, sizeof(nd));
      if (nd.ndm_family != AF_INET || (ifindex != 0 && nd.ndm_ifindex != ifindex)) continue;
      constexpr std::uint16_t kUsable = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT;
      if ((nd.ndm_state & kUsable) == 0) continue;
      KernelNeighbor kn;
      kn.state = nd.ndm_state;
      bool have_ip = false;
      bool have_mac = false;
      std::size_t aoff = align(sizeof(ndmsg));
      while (aoff + sizeof(rtattr) <= plen) {
        rtattr ra;
        std::memcpy(&ra, payload + aoff, sizeof(ra));
        if (ra.rta_len < sizeof(rtattr) || aoff + ra.rta_len > plen) break;
        const unsigned char* data = payload + aoff + align(sizeof(rtattr));
        const std::size_t dlen = ra.rta_len - align(sizeof(rtattr));
        if (ra.rta_type == NDA_DST && dlen == 4) {
          std::uint32_t be;
          std::memcpy(&be, data, 4);
          kn.ip = ntohl(be);
          have_ip = true;
        } else if (ra.rta_type == NDA_LLADDR && dlen == 6) {
          std::memcpy(kn.mac.b.data(), data, 6);
          have_mac = true;
        }
        aoff += align(ra.rta_len);
      }
      if (have_ip && have_mac && count < cap) out[count++] = kn;
    }
  }
  ::close(fd);
  return count;
}

}  // namespace detail

std::expected<std::size_t, int> load_kernel_neighbors(NeighborTable& t, int ifindex, bool as_static) {
  return dump_kernel_neighbors(ifindex, [&](const KernelNeighbor& n) { (void)t.set(n.ip, n.mac, as_static); });
}

std::optional<MacAddr> kernel_neighbor(int ifindex, std::uint32_t ip) {
  std::optional<MacAddr> found;
  (void)dump_kernel_neighbors(ifindex, [&](const KernelNeighbor& n) {
    if (n.ip == ip) found = n.mac;
  });
  return found;
}

std::optional<MacAddr> resolve_via_kernel(const std::string& ifname, std::uint32_t ip, int timeout_ms) {
  const int ifindex = static_cast<int>(::if_nametoindex(ifname.c_str()));
  if (ifindex == 0) return std::nullopt;
  if (auto m = kernel_neighbor(ifindex, ip)) return m;
  const int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s >= 0) {
    (void)::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname.c_str(), static_cast<socklen_t>(ifname.size()));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);  // discard
    dst.sin_addr.s_addr = htonl(ip);
    (void)::sendto(s, "", 0, MSG_DONTWAIT, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    ::close(s);
  }
  for (int waited = 0; waited <= timeout_ms; waited += 10) {
    if (auto m = kernel_neighbor(ifindex, ip)) return m;
    timespec ts{0, 10'000'000};
    ::nanosleep(&ts, nullptr);
  }
  return std::nullopt;
}

}  // namespace lle::net::utcp

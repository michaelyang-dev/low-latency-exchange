#pragma once
// Multicast membership helper for AF_XDP receivers (07 §2.3, R3a §1.5): a kernel UDP
// socket joins the group (IP_ADD_MEMBERSHIP, or MCAST_JOIN_SOURCE_GROUP for SSM), which programs
// the NIC's multicast MAC filter and lets the kernel send and answer IGMP (the XDP
// program passes IGMP). Its data never arrives (XDP redirects first), so the socket has
// a small SO_RCVBUF. Leaving = destroying the object.
#include <cstdint>
#include <expected>
#include <string>

#include "net/xsk/umem.h"

namespace lle::net::xsk {

class MulticastMembership {
 public:
  // group/source in host order; source 0 = any-source join.
  static std::expected<MulticastMembership, Error> join(const std::string& ifname, std::uint32_t group,
                                                        std::uint32_t source = 0);
  MulticastMembership(MulticastMembership&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  MulticastMembership& operator=(MulticastMembership&& o) noexcept;
  MulticastMembership(const MulticastMembership&) = delete;
  MulticastMembership& operator=(const MulticastMembership&) = delete;
  ~MulticastMembership();
  [[nodiscard]] int fd() const noexcept { return fd_; }

 private:
  explicit MulticastMembership(int fd) : fd_(fd) {}
  int fd_ = -1;
};

}  // namespace lle::net::xsk

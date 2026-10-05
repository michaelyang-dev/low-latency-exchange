#include "net/common/iface.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstring>
#include <string>

namespace lle::net {

Result<Iface> lookup_iface(std::string_view name) {
  if (name.empty()) return Iface{};
  const std::string n(name);
  Iface out;
  out.index = ::if_nametoindex(n.c_str());
  if (out.index == 0) return fail("if_nametoindex", ENODEV);
  ifaddrs* list = nullptr;
  if (::getifaddrs(&list) != 0) return fail_errno("getifaddrs");
  for (ifaddrs* it = list; it != nullptr; it = it->ifa_next) {
    if (it->ifa_addr == nullptr || it->ifa_addr->sa_family != AF_INET) continue;
    if (std::strcmp(it->ifa_name, n.c_str()) != 0) continue;
    sockaddr_in sa{};
    std::memcpy(&sa, it->ifa_addr, sizeof(sa));
    out.ipv4 = ntohl(sa.sin_addr.s_addr);
    break;
  }
  ::freeifaddrs(list);
  return out;
}

const char* loopback_ifname() noexcept {
#if defined(__APPLE__)
  return "lo0";
#else
  return "lo";
#endif
}

}  // namespace lle::net

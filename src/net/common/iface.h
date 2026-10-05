#pragma once
// Network interface lookup (cold path: startup only; getifaddrs allocates).
#include <cstdint>
#include <string_view>

#include "net/common/error.h"

namespace lle::net {

struct Iface {
  std::uint32_t index = 0;  // if_nametoindex; 0 = unspecified (kernel picks)
  std::uint32_t ipv4 = 0;   // first IPv4 address on the interface (host order); 0 if none
};

// Resolves an interface by name ("eth0", "lo"). An empty name returns {0, 0}, which
// every helper treats as "let the kernel choose".
[[nodiscard]] Result<Iface> lookup_iface(std::string_view name);

// Name of the loopback interface on this platform ("lo" on Linux, "lo0" on macOS).
[[nodiscard]] const char* loopback_ifname() noexcept;

}  // namespace lle::net

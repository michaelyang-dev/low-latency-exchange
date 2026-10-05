#pragma once
// IPv4 endpoint helpers over env::Endpoint (host byte order) and sockaddr_in.
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "env/concepts.h"

namespace lle::net {

using env::Endpoint;

[[nodiscard]] constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
  return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | std::uint32_t{d};
}

inline constexpr std::uint32_t kAnyV4 = 0;
inline constexpr std::uint32_t kLoopbackV4 = ipv4(127, 0, 0, 1);

// 224.0.0.0/4 (RFC 5771).
[[nodiscard]] constexpr bool is_multicast(std::uint32_t addr) noexcept { return (addr >> 28) == 0xEu; }

// Dotted quad ("10.0.0.1"); rejects anything else (no hostnames, no shorthand).
[[nodiscard]] std::optional<std::uint32_t> parse_ipv4(std::string_view s) noexcept;

// "a.b.c.d:port".
[[nodiscard]] std::optional<Endpoint> parse_endpoint(std::string_view s) noexcept;

[[nodiscard]] sockaddr_in to_sockaddr(Endpoint e) noexcept;
[[nodiscard]] Endpoint from_sockaddr(const sockaddr_in& sa) noexcept;

// Writes "a.b.c.d:port" (no NUL) into `out`; returns the length written (0 if `out` is
// shorter than 21 bytes). Allocation-free for hot-path logging.
std::size_t format_endpoint(Endpoint e, std::span<char> out) noexcept;
[[nodiscard]] std::string to_string(Endpoint e);
[[nodiscard]] std::string ipv4_to_string(std::uint32_t addr);

}  // namespace lle::net

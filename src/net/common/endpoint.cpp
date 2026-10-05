#include "net/common/endpoint.h"

#include <arpa/inet.h>

#include <array>
#include <charconv>
#include <cstring>

#include "net/common/error.h"

namespace lle::net {

std::string to_string(const Error& e) {
  std::string s = e.op;
  s += ": ";
  s += std::strerror(e.code);
  return s;
}

std::optional<std::uint32_t> parse_ipv4(std::string_view s) noexcept {
  std::uint32_t addr = 0;
  const char* p = s.data();
  const char* const end = s.data() + s.size();
  for (int i = 0; i < 4; ++i) {
    if (i > 0) {
      if (p == end || *p != '.') return std::nullopt;
      ++p;
    }
    if (p == end || *p < '0' || *p > '9') return std::nullopt;
    unsigned v = 0;
    auto [next, ec] = std::from_chars(p, end, v);
    if (ec != std::errc{} || v > 255 || next - p > 3) return std::nullopt;
    addr = (addr << 8) | v;
    p = next;
  }
  if (p != end) return std::nullopt;
  return addr;
}

std::optional<Endpoint> parse_endpoint(std::string_view s) noexcept {
  const auto colon = s.rfind(':');
  if (colon == std::string_view::npos) return std::nullopt;
  const auto ip = parse_ipv4(s.substr(0, colon));
  if (!ip) return std::nullopt;
  const std::string_view ps = s.substr(colon + 1);
  if (ps.empty() || ps.front() < '0' || ps.front() > '9') return std::nullopt;
  unsigned port = 0;
  auto [next, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), port);
  if (ec != std::errc{} || next != ps.data() + ps.size() || port > 65535) return std::nullopt;
  return Endpoint{*ip, static_cast<std::uint16_t>(port)};
}

sockaddr_in to_sockaddr(Endpoint e) noexcept {
  sockaddr_in sa{};
#if defined(__APPLE__)
  sa.sin_len = sizeof(sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = htons(e.port);
  sa.sin_addr.s_addr = htonl(e.ipv4);
  return sa;
}

Endpoint from_sockaddr(const sockaddr_in& sa) noexcept { return Endpoint{ntohl(sa.sin_addr.s_addr), ntohs(sa.sin_port)}; }

namespace {
std::size_t put_u(char* out, unsigned v) noexcept {
  auto [p, ec] = std::to_chars(out, out + 5, v);
  (void)ec;
  return static_cast<std::size_t>(p - out);
}
}  // namespace

std::size_t format_endpoint(Endpoint e, std::span<char> out) noexcept {
  if (out.size() < 21) return 0;  // "255.255.255.255:65535"
  char* p = out.data();
  for (int i = 3; i >= 0; --i) {
    p += put_u(p, (e.ipv4 >> (8 * i)) & 0xFFu);
    *p++ = i > 0 ? '.' : ':';
  }
  p += put_u(p, e.port);
  return static_cast<std::size_t>(p - out.data());
}

std::string to_string(Endpoint e) {
  std::array<char, 24> buf{};
  return std::string(buf.data(), format_endpoint(e, buf));
}

std::string ipv4_to_string(std::uint32_t addr) {
  std::string s = to_string(Endpoint{addr, 0});
  s.resize(s.size() - 2);  // drop ":0"
  return s;
}

}  // namespace lle::net

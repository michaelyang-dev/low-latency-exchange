#pragma once
// Helpers shared by the SoupBinTCP tests.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/endian.h"
#include "proto/soupbin/soupbin.h"

namespace lle::soup::test {

using Bytes = std::vector<std::byte>;

inline Bytes bytes(std::string_view s) {
  Bytes b;
  for (char c : s) b.push_back(static_cast<std::byte>(c));
  return b;
}

// Hand-assembled packet: u16 length (type + payload), type, payload.
inline Bytes packet(char type, std::string_view payload = {}) {
  Bytes b;
  const auto len = static_cast<std::uint16_t>(payload.size() + 1);
  b.push_back(static_cast<std::byte>(len >> 8));
  b.push_back(static_cast<std::byte>(len & 0xFF));
  b.push_back(static_cast<std::byte>(type));
  for (char c : payload) b.push_back(static_cast<std::byte>(c));
  return b;
}

inline Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes out;
  for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
  return out;
}

inline std::string str(std::span<const std::byte> b) {
  std::string s;
  for (std::byte x : b) s.push_back(std::to_integer<char>(x));
  return s;
}

inline std::string pad_left(std::string_view s, std::size_t n) { return std::string(n - s.size(), ' ') + std::string(s); }
inline std::string pad_right(std::string_view s, std::size_t n) { return std::string(s) + std::string(n - s.size(), ' '); }

// Login Request payload from explicit (already padded) fields.
inline std::string login_payload(std::string_view user, std::string_view pass, std::string_view session_field,
                                 std::string_view seq_field) {
  return pad_right(user, 6) + pad_right(pass, 10) + std::string(session_field) + std::string(seq_field);
}

// Parsed outbound packets (from a byte stream that holds whole packets).
struct Parsed {
  char type;
  std::string payload;
};
inline std::vector<Parsed> parse_all(std::span<const std::byte> b) {
  std::vector<Parsed> out;
  std::size_t pos = 0;
  while (pos + 2 <= b.size()) {
    const std::size_t len = load_be16(b.data() + pos);
    if (len == 0 || pos + 2 + len > b.size()) break;
    out.push_back({std::to_integer<char>(b[pos + 2]), str(b.subspan(pos + 3, len - 1))});
    pos += 2 + len;
  }
  return out;
}

struct TestPolicy {
  std::string user = "USER";
  std::string pass = "secret";
  bool live = false;  // the username already has a live connection on this port
  int calls = 0;
  LoginDecision authorize(const LoginRequest& r) {
    ++calls;
    if (!credential_equals(std::as_bytes(std::span(r.username.c)), user) ||
        !credential_equals(std::as_bytes(std::span(r.password.c)), pass))
      return LoginDecision::NotAuthorized;
    return live ? LoginDecision::SessionUnavailable : LoginDecision::Accept;
  }
};

}  // namespace lle::soup::test

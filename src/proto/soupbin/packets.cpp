#include "proto/soupbin/packets.h"

#include <cstring>
#include <limits>

#include "common/endian.h"

namespace lle::soup {

std::optional<std::uint64_t> parse_numeric(std::span<const std::byte> field) noexcept {
  std::size_t b = 0, e = field.size();
  while (b < e && field[b] == std::byte{' '}) ++b;
  while (e > b && field[e - 1] == std::byte{' '}) --e;
  if (b == e) return std::nullopt;  // no digits at all
  std::uint64_t v = 0;
  for (std::size_t i = b; i < e; ++i) {
    const auto c = std::to_integer<unsigned>(field[i]);
    if (c < '0' || c > '9') return std::nullopt;
    const std::uint64_t d = c - '0';
    if (v > (std::numeric_limits<std::uint64_t>::max() - d) / 10) return std::nullopt;
    v = v * 10 + d;
  }
  return v;
}

bool format_numeric(std::byte* p, std::size_t width, std::uint64_t v) noexcept {
  std::size_t digits = 1;
  for (std::uint64_t x = v; x >= 10; x /= 10) ++digits;
  if (digits > width) return false;
  // Shared helper (common/alpha.h): right-justified, left-padded with spaces.
  format_padded_decimal(reinterpret_cast<char*>(p), width, v);  // NOLINT: std::byte and char alias
  return true;
}

bool credential_equals(std::span<const std::byte> field, std::string_view expected) noexcept {
  std::size_t b = 0, e = field.size();
  while (b < e && field[b] == std::byte{' '}) ++b;
  while (e > b && field[e - 1] == std::byte{' '}) --e;
  std::size_t eb = 0, ee = expected.size();
  while (eb < ee && expected[eb] == ' ') ++eb;
  while (ee > eb && expected[ee - 1] == ' ') --ee;
  if (e - b != ee - eb) return false;
  auto lower = [](unsigned c) { return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c; };
  for (std::size_t i = 0; i < e - b; ++i)
    if (lower(std::to_integer<unsigned>(field[b + i])) != lower(static_cast<unsigned char>(expected[eb + i])))
      return false;
  return true;
}

std::optional<LoginRequest> parse_login_request(std::span<const std::byte> payload, Version version) noexcept {
  const bool v41 = version == Version::V410 && payload.size() == kLoginRequestPayload41;
  if (payload.size() != kLoginRequestPayload && !v41) return std::nullopt;
  LoginRequest r;
  r.username = Alpha<kUsernameLen>::from_wire(payload.data());
  r.password = Alpha<kPasswordLen>::from_wire(payload.data() + kUsernameLen);
  r.session = SessionId::from_field(payload.data() + kUsernameLen + kPasswordLen);
  const auto seq = parse_numeric(payload.subspan(kUsernameLen + kPasswordLen + kSessionLen, kSequenceLen));
  if (!seq) return std::nullopt;
  r.sequence = *seq;
  if (v41) {
    const auto hb = payload.subspan(kLoginRequestPayload, kHeartbeatTimeoutLen);
    bool blank = true;
    for (std::byte c : hb) blank &= c == std::byte{' '};
    if (!blank) {
      const auto ms = parse_numeric(hb);
      if (!ms) return std::nullopt;
      r.heartbeat_timeout_ms = static_cast<std::uint32_t>(*ms);  // at most 99,999
    }
  }
  return r;
}

std::optional<LoginAccepted> parse_login_accepted(std::span<const std::byte> payload) noexcept {
  if (payload.size() != kLoginAcceptedPayload) return std::nullopt;
  LoginAccepted a;
  a.session = SessionId::from_field(payload.data());
  const auto seq = parse_numeric(payload.subspan(kSessionLen, kSequenceLen));
  if (!seq) return std::nullopt;
  a.sequence = *seq;
  return a;
}

namespace {

// Writes the 3-byte header; returns a pointer to the payload or nullptr.
std::byte* header(std::span<std::byte> dst, PacketType type, std::size_t payload) noexcept {
  if (payload > kMaxPayload || dst.size() < packet_size(payload)) return nullptr;
  store_be16(dst.data(), static_cast<std::uint16_t>(payload + 1));
  dst[2] = static_cast<std::byte>(type);
  return dst.data() + kHeaderLen;
}

}  // namespace

std::size_t encode_packet(std::span<std::byte> dst, PacketType type, std::span<const std::byte> payload) noexcept {
  std::byte* p = header(dst, type, payload.size());
  if (p == nullptr) return 0;
  if (!payload.empty()) std::memcpy(p, payload.data(), payload.size());
  return packet_size(payload.size());
}

std::size_t encode_debug(std::span<std::byte> dst, std::string_view text) noexcept {
  return encode_packet(dst, PacketType::Debug, std::as_bytes(std::span(text.data(), text.size())));
}

std::size_t encode_login_accepted(std::span<std::byte> dst, const SessionId& session, SeqNo next) noexcept {
  std::byte* p = header(dst, PacketType::LoginAccepted, kLoginAcceptedPayload);
  if (p == nullptr) return 0;
  session.write_field(p);
  if (!format_numeric(p + kSessionLen, kSequenceLen, next)) return 0;
  return packet_size(kLoginAcceptedPayload);
}

std::size_t encode_login_rejected(std::span<std::byte> dst, LoginRejectReason reason) noexcept {
  std::byte* p = header(dst, PacketType::LoginRejected, kLoginRejectedPayload);
  if (p == nullptr) return 0;
  p[0] = static_cast<std::byte>(reason);
  return packet_size(kLoginRejectedPayload);
}

std::size_t encode_login_request(std::span<std::byte> dst, const LoginRequest& req, Version version) noexcept {
  const std::size_t payload = version == Version::V410 ? kLoginRequestPayload41 : kLoginRequestPayload;
  std::byte* p = header(dst, PacketType::LoginRequest, payload);
  if (p == nullptr) return 0;
  req.username.to_wire(p);  // right-padded (spec 2.3.1)
  req.password.to_wire(p + kUsernameLen);
  req.session.write_field(p + kUsernameLen + kPasswordLen);
  if (!format_numeric(p + kUsernameLen + kPasswordLen + kSessionLen, kSequenceLen, req.sequence)) return 0;
  if (version == Version::V410 &&
      !format_numeric(p + kLoginRequestPayload, kHeartbeatTimeoutLen, req.heartbeat_timeout_ms))
    return 0;
  return packet_size(payload);
}

}  // namespace lle::soup

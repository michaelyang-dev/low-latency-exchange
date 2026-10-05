#pragma once
// SoupBinTCP 3.00 logical packets (03-protocols s5; R1b D2). Every packet is a
// u16 big-endian Packet Length (counting the type byte plus payload), a type
// byte and a payload. Optional 4.10 additions: a Heartbeat Timeout field in the
// Login Request and server-to-client Unsequenced Data.
// Encoders write whole packets into caller buffers; nothing allocates.
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "common/alpha.h"
#include "common/types.h"

namespace lle::soup {

inline constexpr std::size_t kLengthFieldLen = 2;
inline constexpr std::size_t kHeaderLen = 3;  // Packet Length + Packet Type
inline constexpr std::size_t kMaxPacketLength = 65535;  // largest Packet Length value (u16)
inline constexpr std::size_t kMaxPayload = kMaxPacketLength - 1;

inline constexpr std::size_t kUsernameLen = 6;
inline constexpr std::size_t kPasswordLen = 10;
inline constexpr std::size_t kSessionLen = 10;
inline constexpr std::size_t kSequenceLen = 20;
inline constexpr std::size_t kHeartbeatTimeoutLen = 5;  // 4.10, milliseconds

// Payload sizes (bytes after the type byte).
inline constexpr std::size_t kLoginAcceptedPayload = kSessionLen + kSequenceLen;                            // 30
inline constexpr std::size_t kLoginRejectedPayload = 1;                                                      // reason
inline constexpr std::size_t kLoginRequestPayload = kUsernameLen + kPasswordLen + kSessionLen + kSequenceLen;  // 46
inline constexpr std::size_t kLoginRequestPayload41 = kLoginRequestPayload + kHeartbeatTimeoutLen;          // 51

enum class PacketType : char {
  Debug = '+',            // both directions; ignored by the receiver
  LoginAccepted = 'A',    // server
  LoginRejected = 'J',    // server
  SequencedData = 'S',    // server
  ServerHeartbeat = 'H',  // server
  EndOfSession = 'Z',     // server
  LoginRequest = 'L',     // client
  UnsequencedData = 'U',  // client (3.00); also server in 4.10 mode
  ClientHeartbeat = 'R',  // client
  LogoutRequest = 'O',    // client
};

enum class LoginRejectReason : char { NotAuthorized = 'A', SessionUnavailable = 'S' };

enum class Version : std::uint8_t { V300, V410 };

// Session identifier (up to 10 ASCII characters). Stored without padding; the
// wire field is accepted left- or right-padded and emitted left-padded
// (right-justified), as the Login Accepted definition says (spec 2.2.1).
class SessionId {
 public:
  constexpr SessionId() noexcept = default;

  // Leading/trailing spaces are dropped; longer input is truncated to 10.
  static constexpr SessionId from(std::string_view s) noexcept {
    std::size_t b = 0, e = s.size();
    while (b < e && s[b] == ' ') ++b;
    while (e > b && s[e - 1] == ' ') --e;
    SessionId id;
    for (std::size_t i = b; i < e && id.n_ < kSessionLen; ++i) id.c_[id.n_++] = s[i];
    return id;
  }
  static SessionId from_field(const std::byte* p) noexcept {
    char tmp[kSessionLen];
    for (std::size_t i = 0; i < kSessionLen; ++i) tmp[i] = std::to_integer<char>(p[i]);
    return from(std::string_view(tmp, kSessionLen));
  }
  void write_field(std::byte* p) const noexcept {
    const std::size_t pad = kSessionLen - n_;
    for (std::size_t i = 0; i < pad; ++i) p[i] = std::byte{' '};
    for (std::size_t i = 0; i < n_; ++i) p[pad + i] = static_cast<std::byte>(c_[i]);
  }
  [[nodiscard]] constexpr std::string_view view() const noexcept { return {c_.data(), n_}; }
  [[nodiscard]] constexpr bool blank() const noexcept { return n_ == 0; }
  friend constexpr bool operator==(const SessionId& a, const SessionId& b) noexcept { return a.view() == b.view(); }

 private:
  std::array<char, kSessionLen> c_{};
  std::uint8_t n_ = 0;
};

// Strict parse of an ASCII numeric field: optional left or right space padding
// around at least one digit; no interior spaces; no overflow of u64.
[[nodiscard]] std::optional<std::uint64_t> parse_numeric(std::span<const std::byte> field) noexcept;

// Writes `v` right-justified (left-padded with spaces) into `width` bytes.
// Returns false (and writes nothing) when `v` needs more than `width` digits.
bool format_numeric(std::byte* p, std::size_t width, std::uint64_t v) noexcept;

// Case-insensitive comparison of a padded credential field with `expected`
// (spec 2.3.1: username and password are case-insensitive, space padded).
[[nodiscard]] bool credential_equals(std::span<const std::byte> field, std::string_view expected) noexcept;

struct LoginRequest {
  Alpha<kUsernameLen> username;
  Alpha<kPasswordLen> password;
  SessionId session;              // blank = the currently active session
  SeqNo sequence = 1;             // next sequence the client wants; 0 = most recent message
  std::uint32_t heartbeat_timeout_ms = 0;  // 4.10 only; 0 = absent / server default
};

struct LoginAccepted {
  SessionId session;
  SeqNo sequence = 0;  // next sequenced message the server will send
};

// Payload parsers. 3.00 Login Requests are exactly 46 bytes; in 4.10 mode both
// 46 and 51 (with Heartbeat Timeout) are accepted. nullopt = malformed.
[[nodiscard]] std::optional<LoginRequest> parse_login_request(std::span<const std::byte> payload,
                                                              Version version) noexcept;
[[nodiscard]] std::optional<LoginAccepted> parse_login_accepted(std::span<const std::byte> payload) noexcept;

[[nodiscard]] constexpr std::size_t packet_size(std::size_t payload) noexcept { return kHeaderLen + payload; }

// Encoders: write the whole packet into dst. Return the bytes written, or 0
// when dst is too small or the payload exceeds kMaxPayload.
std::size_t encode_packet(std::span<std::byte> dst, PacketType type, std::span<const std::byte> payload) noexcept;
std::size_t encode_debug(std::span<std::byte> dst, std::string_view text) noexcept;
std::size_t encode_login_accepted(std::span<std::byte> dst, const SessionId& session, SeqNo next) noexcept;
std::size_t encode_login_rejected(std::span<std::byte> dst, LoginRejectReason reason) noexcept;
std::size_t encode_login_request(std::span<std::byte> dst, const LoginRequest& req, Version version) noexcept;

}  // namespace lle::soup

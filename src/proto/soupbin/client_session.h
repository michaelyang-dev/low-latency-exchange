#pragma once
// Sans-I/O SoupBinTCP client session (03-protocols s5), the mirror image of
// ServerSession: connect() queues the Login Request (spec 2.3.1: sent
// immediately on connect); sequenced messages are numbered locally starting
// at the Login Accepted sequence (spec 1.2); 'R' is sent after
// heartbeat_interval of send silence once logged in (spec 1.3); the link is
// declared dead after idle_timeout of receive silence.
// Reconnect: build a new session from resume_config(), which requests the
// current session and the next expected sequence number.
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "common/alpha.h"
#include "common/types.h"
#include "proto/soupbin/actions.h"
#include "proto/soupbin/framer.h"
#include "proto/soupbin/packets.h"

namespace lle::soup {

struct ClientConfig {
  Alpha<kUsernameLen> username;
  Alpha<kPasswordLen> password;
  SessionId session;  // requested session; blank = currently active
  SeqNo sequence = 1;  // requested next sequence; 0 = most recent message
  Version version = Version::V300;
  std::uint32_t heartbeat_timeout_ms = 0;  // 4.10 Login Request field (0 = server default)
  Nanos heartbeat_interval = kNsPerSec;
  Nanos idle_timeout = 15 * kNsPerSec;
  Nanos login_timeout = 30 * kNsPerSec;
  std::size_t max_packet_length = kMaxPacketLength;  // inbound limit
  std::size_t tx_capacity = 64 * 1024;
};

class ClientSession {
 public:
  enum class State : std::uint8_t { Idle, AwaitingLoginResponse, Active, Closed };

  explicit ClientSession(const ClientConfig& cfg);

  // The TCP connection is up: queues the Login Request.
  const Actions& connect(Nanos now);
  // Bytes received from the server.
  const Actions& on_bytes(std::span<const std::byte> in, Nanos now);
  const Actions& on_timer(Nanos now);
  // Unsequenced Data to the server; only after Login Accepted (spec 1.2).
  const Actions& send_unsequenced(std::span<const std::byte> msg, Nanos now);
  const Actions& send_debug(std::string_view text, Nanos now);
  // Logout Request; the connection closes after it is flushed.
  const Actions& logout(Nanos now);
  void consume_tx(std::size_t n) noexcept;

  [[nodiscard]] const Actions& actions() const noexcept { return a_; }
  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] SeqNo next_expected() const noexcept { return next_; }
  [[nodiscard]] const SessionId& session() const noexcept { return session_; }
  // Config for the next connection: same credentials, the session learned from
  // Login Accepted, and the next expected sequence number.
  [[nodiscard]] ClientConfig resume_config() const noexcept;

 private:
  void begin() noexcept;
  const Actions& end(Nanos now) noexcept;
  Nanos deadline() const noexcept;
  bool on_packet(const Packet& p, Nanos now);
  bool violation(std::string_view text);
  void close(CloseReason why) noexcept;
  bool write_packet(PacketType t, std::span<const std::byte> payload) noexcept;

  ClientConfig cfg_;
  Framer framer_;
  TxBuffer tx_;
  Actions a_;
  State state_ = State::Idle;
  SessionId session_;
  SeqNo next_ = 1;
  Nanos connected_at_ = 0;
  Nanos last_rx_ = 0;
  Nanos last_tx_ = 0;
};

}  // namespace lle::soup

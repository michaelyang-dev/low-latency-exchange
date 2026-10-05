#pragma once
// Sans-I/O SoupBinTCP server session (03-protocols s5): one TCP connection's
// state machine. Bytes and time in; Actions out. The documented decisions
// (src/proto/soupbin/DECISIONS.md) are implemented here:
//   - requested sequence above the server's next -> '+' debug, Login Rejected 'S', SequenceAhead alarm
//   - requested sequence 0 -> start at the most recent message: max(1, highest)
//   - blank requested session -> current session; any other unknown session -> 'S'
//   - second login on the same port -> 'S' (decided by the LoginPolicy; the live connection is untouched)
//   - unknown packet type, data before login, a packet over max_packet_length -> '+' debug, then close
//   - numeric and session fields accepted left- or right-padded, emitted left-padded
// Timers: 'H' after heartbeat_interval of send silence; close after idle_timeout
// of receive silence; close when no Login Request arrives within login_timeout.
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "common/types.h"
#include "env/buggify.h"
#include "proto/soupbin/actions.h"
#include "proto/soupbin/framer.h"
#include "proto/soupbin/packets.h"
#include "proto/soupbin/sequenced_store.h"

namespace lle::soup {

enum class LoginDecision : std::uint8_t {
  Accept,
  NotAuthorized,       // -> 'J' 'A'
  SessionUnavailable,  // -> 'J' 'S' (e.g. the username is already logged in on this port)
};

// Credentials and port-level policy (session table, duplicate logins).
template <class P>
concept LoginPolicyLike = requires(P& p, const LoginRequest& r) {
  { p.authorize(r) } -> std::same_as<LoginDecision>;
};

struct ServerConfig {
  SessionId session;  // the currently active session
  Version version = Version::V300;
  Nanos heartbeat_interval = kNsPerSec;   // spec 1.3: at most 1 s of silence
  Nanos idle_timeout = 15 * kNsPerSec;    // spec 1.3: "typically 15 seconds"
  Nanos login_timeout = 30 * kNsPerSec;   // spec 2.3.1: "typically 30 seconds"
  std::size_t max_packet_length = 1024;   // inbound Packet Length limit (03-protocols s5)
  std::size_t tx_capacity = 64 * 1024;
  std::size_t max_replay_per_call = 4096;  // bounds the work of one call during replay
};

template <SequencedStoreLike Store, LoginPolicyLike Policy>
class ServerSession {
 public:
  enum class State : std::uint8_t { AwaitingLogin, Active, Closed };

  ServerSession(const ServerConfig& cfg, Store& store, Policy& policy, Nanos now)
      : cfg_(cfg), store_(store), policy_(policy), framer_(cfg.max_packet_length), tx_(cfg.tx_capacity),
        connected_at_(now), last_rx_(now), last_tx_(now), idle_timeout_(cfg.idle_timeout) {}

  // Bytes received from the client.
  const Actions& on_bytes(std::span<const std::byte> in, Nanos now) {
    begin();
    if (state_ != State::Closed && !in.empty()) {
      last_rx_ = now;
      a_.consumed = framer_.feed(in, [&](const Packet& p) { return on_packet(p, now); });
      if (state_ != State::Closed && framer_.status() != Framer::Status::Ok) {
        violation(framer_.status() == Framer::Status::TooLong ? std::string_view("packet too long")
                                                              : std::string_view("zero-length packet"),
                  now);
      }
      if (state_ == State::Closed) a_.consumed = in.size();
    } else {
      a_.consumed = in.size();
    }
    pump(now);
    return end(now);
  }

  // Timers; also delivers messages appended to the store directly.
  const Actions& on_timer(Nanos now) {
    begin();
    if (state_ == State::AwaitingLogin && now - connected_at_ >= cfg_.login_timeout) {
      close(CloseReason::LoginTimeout);
    } else if (state_ == State::Active && now - last_rx_ >= idle_timeout_) {
      close(CloseReason::IdleTimeout);
    }
    pump(now);
    if (state_ == State::Active && now - last_tx_ >= cfg_.heartbeat_interval) {
      if (write_packet(PacketType::ServerHeartbeat, {})) last_tx_ = now;
    }
    return end(now);
  }

  // Appends one message to the session's stream and sends it if this connection
  // is logged in and caught up; otherwise replay delivers it later.
  const Actions& send_sequenced(std::span<const std::byte> msg, Nanos now) {
    begin();
    if (ending_ || msg.size() > kMaxPayload) {
      a_.accepted = false;
    } else if (!store_.append(msg)) {
      a_.accepted = false;
      a_.events.push_back(Event{EventKind::StoreFull, CloseReason::None, 0, store_.next_seq(), 0});
    }
    pump(now);
    return end(now);
  }

  // Best-effort server-to-client Unsequenced Data: SoupBinTCP 4.10 mode only.
  const Actions& send_unsequenced(std::span<const std::byte> msg, Nanos now) {
    begin();
    a_.accepted = cfg_.version == Version::V410 && state_ == State::Active && caught_up() &&
                  write_packet(PacketType::UnsequencedData, msg);
    if (a_.accepted) last_tx_ = now;
    return end(now);
  }

  const Actions& send_debug(std::string_view text, Nanos now) {
    begin();
    a_.accepted = state_ != State::Closed && write_debug(text);
    if (a_.accepted) last_tx_ = now;
    return end(now);
  }

  // Ends the session: remaining stored messages are delivered first, then 'Z',
  // then the connection closes (spec 2.2.5).
  const Actions& end_session(Nanos now) {
    begin();
    ending_ = true;
    if (state_ == State::AwaitingLogin) close(CloseReason::EndOfSession);
    pump(now);
    return end(now);
  }

  // The caller wrote n bytes of actions().write. Returns true when replay is
  // pending and on_timer() should be called to continue it.
  bool consume_tx(std::size_t n) noexcept {
    tx_.consume(n);
    a_.write = tx_.pending();
    a_.deadline = deadline(last_now_);
    return state_ == State::Active && (!caught_up() || ending_);
  }

  [[nodiscard]] const Actions& actions() const noexcept { return a_; }
  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] SeqNo next_to_send() const noexcept { return next_; }
  [[nodiscard]] const LoginRequest& login() const noexcept { return login_; }
  [[nodiscard]] Nanos idle_timeout() const noexcept { return idle_timeout_; }

 private:
  void begin() noexcept {
    a_.delivered.clear();
    a_.events.clear();
    a_.consumed = 0;
    a_.accepted = true;
  }

  const Actions& end(Nanos now) noexcept {
    last_now_ = now;
    a_.write = tx_.pending();
    a_.close = state_ == State::Closed;
    a_.deadline = deadline(now);
    return a_;
  }

  [[nodiscard]] bool caught_up() const noexcept { return next_ >= store_.next_seq(); }

  Nanos deadline(Nanos now) const noexcept {
    switch (state_) {
      case State::AwaitingLogin: return connected_at_ + cfg_.login_timeout;
      case State::Active: {
        Nanos d = std::min(last_tx_ + cfg_.heartbeat_interval, last_rx_ + idle_timeout_);
        if ((!caught_up() || ending_) && tx_.room() > kHeaderLen) d = std::min(d, now);
        return d;
      }
      case State::Closed: break;
    }
    return kNever;
  }

  bool on_packet(const Packet& p, Nanos now) {
    switch (static_cast<PacketType>(p.type)) {
      case PacketType::Debug: return true;  // spec 2.1: ignored
      case PacketType::LoginRequest:
        if (state_ != State::AwaitingLogin) return violation("duplicate login request", now);
        return handle_login(p.payload, now);
      case PacketType::UnsequencedData:
        if (state_ != State::Active) return violation("data before login", now);
        a_.delivered.push_back(Delivered{p.payload, 0});
        return !a_.delivered.full();
      case PacketType::ClientHeartbeat:
        if (state_ != State::Active) return violation("data before login", now);
        if (!p.payload.empty()) return violation("malformed client heartbeat", now);
        return true;
      case PacketType::LogoutRequest:
        if (!p.payload.empty()) return violation("malformed logout request", now);
        close(CloseReason::LogoutRequested);  // spec 2.3.4: terminate immediately
        return false;
      default: return violation(state_ == State::Active ? "unknown packet type" : "data before login", now);
    }
  }

  bool handle_login(std::span<const std::byte> payload, Nanos now) {
    const auto req = parse_login_request(payload, cfg_.version);
    if (!req) return violation("malformed login request", now);
    login_ = *req;
    switch (policy_.authorize(*req)) {
      case LoginDecision::NotAuthorized: return reject(LoginRejectReason::NotAuthorized);
      case LoginDecision::SessionUnavailable: return reject(LoginRejectReason::SessionUnavailable);
      case LoginDecision::Accept: break;
    }
    if (!req->session.blank() && !(req->session == cfg_.session)) {
      write_debug(DebugText().str("unknown session ").str(req->session.view()).view());
      return reject(LoginRejectReason::SessionUnavailable);
    }
    if (ending_) return reject(LoginRejectReason::SessionUnavailable);
    const SeqNo next = store_.next_seq();
    if (req->sequence > next) {
      write_debug(DebugText().str("requested sequence ").num(req->sequence).str(" is ahead of next ").num(next).view());
      a_.events.push_back(Event{EventKind::SequenceAhead, CloseReason::None, 0, req->sequence, next});
      return reject(LoginRejectReason::SessionUnavailable);
    }
    // Requested 0: "start receiving the most recently generated message".
    const SeqNo start = req->sequence == 0 ? std::max<SeqNo>(1, next - 1) : req->sequence;
    if (req->sequence > 1) SIM_PROBE("soup.relogin_mid_stream");
    std::byte* p = tx_.reserve(packet_size(kLoginAcceptedPayload));
    if (p == nullptr) return violation("transmit buffer full", now);
    tx_.commit(encode_login_accepted(std::span<std::byte>(p, packet_size(kLoginAcceptedPayload)), cfg_.session, start));
    last_tx_ = now;
    next_ = start;
    state_ = State::Active;
    if (cfg_.version == Version::V410 && req->heartbeat_timeout_ms > 0)
      idle_timeout_ = static_cast<Nanos>(req->heartbeat_timeout_ms) * 1'000'000;
    a_.events.push_back(Event{EventKind::LoggedIn, CloseReason::None, 0, start, 0});
    return true;
  }

  bool reject(LoginRejectReason r) {
    std::byte* p = tx_.reserve(packet_size(kLoginRejectedPayload));
    if (p != nullptr) tx_.commit(encode_login_rejected(std::span<std::byte>(p, packet_size(kLoginRejectedPayload)), r));
    a_.events.push_back(Event{EventKind::LoginRejected, CloseReason::None, static_cast<char>(r), 0, 0});
    close(CloseReason::LoginRejected);
    return false;
  }

  bool violation(std::string_view text, Nanos) {
    write_debug(text);
    close(CloseReason::ProtocolViolation);
    return false;
  }

  void close(CloseReason why) noexcept {
    if (state_ == State::Closed) return;
    state_ = State::Closed;
    a_.events.push_back(Event{EventKind::Closed, why, 0, 0, 0});
  }

  bool write_packet(PacketType t, std::span<const std::byte> payload) noexcept {
    const std::size_t n = packet_size(payload.size());
    std::byte* p = tx_.reserve(n);
    if (p == nullptr) return false;
    tx_.commit(encode_packet(std::span<std::byte>(p, n), t, payload));
    return true;
  }

  bool write_debug(std::string_view text) noexcept {
    return write_packet(PacketType::Debug, std::as_bytes(std::span(text.data(), text.size())));
  }

  // Sends stored messages from next_ while the transmit buffer has room.
  void pump(Nanos now) {
    if (state_ != State::Active) return;
    std::size_t sent = 0;
    while (!caught_up() && sent < cfg_.max_replay_per_call) {
      const auto msg = store_.get(next_);
      if (!msg) {
        write_debug(DebugText().str("sequence ").num(next_).str(" unavailable").view());
        close(CloseReason::StoreUnavailable);
        return;
      }
      if (!write_packet(PacketType::SequencedData, *msg)) {
        SIM_PROBE("soup.replay_waits_for_tx_room");
        break;
      }
      ++next_;
      ++sent;
      // Fault: a short replay step; the deadline (now) brings the caller back.
      if (SIM_BUGGIFY("soup.server_replay_short")) break;
    }
    if (sent > 0) last_tx_ = now;
    if (ending_ && caught_up() && write_packet(PacketType::EndOfSession, {})) {
      if (sent > 0) SIM_PROBE("soup.end_of_session_after_replay");
      last_tx_ = now;
      a_.events.push_back(Event{EventKind::EndOfSession, CloseReason::None, 0, next_, 0});
      close(CloseReason::EndOfSession);
    }
  }

  ServerConfig cfg_;
  Store& store_;
  Policy& policy_;
  Framer framer_;
  TxBuffer tx_;
  Actions a_;
  LoginRequest login_;
  State state_ = State::AwaitingLogin;
  SeqNo next_ = 1;
  Nanos connected_at_;
  Nanos last_rx_;
  Nanos last_tx_;
  Nanos idle_timeout_;
  Nanos last_now_ = 0;
  bool ending_ = false;
};

}  // namespace lle::soup

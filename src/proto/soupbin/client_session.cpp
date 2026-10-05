#include "proto/soupbin/client_session.h"

#include <algorithm>

namespace lle::soup {

ClientSession::ClientSession(const ClientConfig& cfg)
    : cfg_(cfg), framer_(cfg.max_packet_length), tx_(cfg.tx_capacity), session_(cfg.session), next_(cfg.sequence) {}

void ClientSession::begin() noexcept {
  a_.delivered.clear();
  a_.events.clear();
  a_.consumed = 0;
  a_.accepted = true;
}

const Actions& ClientSession::end(Nanos) noexcept {
  a_.write = tx_.pending();
  a_.close = state_ == State::Closed;
  a_.deadline = deadline();
  return a_;
}

Nanos ClientSession::deadline() const noexcept {
  switch (state_) {
    case State::AwaitingLoginResponse: return connected_at_ + cfg_.login_timeout;
    case State::Active: return std::min(last_tx_ + cfg_.heartbeat_interval, last_rx_ + cfg_.idle_timeout);
    case State::Idle:
    case State::Closed: break;
  }
  return kNever;
}

const Actions& ClientSession::connect(Nanos now) {
  begin();
  if (state_ == State::Idle) {
    connected_at_ = last_rx_ = last_tx_ = now;
    LoginRequest req;
    req.username = cfg_.username;
    req.password = cfg_.password;
    req.session = cfg_.session;
    req.sequence = cfg_.sequence;
    req.heartbeat_timeout_ms = cfg_.heartbeat_timeout_ms;
    const std::size_t n = packet_size(cfg_.version == Version::V410 ? kLoginRequestPayload41 : kLoginRequestPayload);
    std::byte* p = tx_.reserve(n);
    if (p != nullptr && encode_login_request(std::span<std::byte>(p, n), req, cfg_.version) == n) {
      tx_.commit(n);
      state_ = State::AwaitingLoginResponse;
    } else {
      a_.accepted = false;
      close(CloseReason::ProtocolViolation);  // unencodable config (e.g. sequence too wide)
    }
  }
  return end(now);
}

const Actions& ClientSession::on_bytes(std::span<const std::byte> in, Nanos now) {
  begin();
  if (state_ == State::Idle || state_ == State::Closed || in.empty()) {
    a_.consumed = in.size();
    return end(now);
  }
  last_rx_ = now;
  a_.consumed = framer_.feed(in, [&](const Packet& p) { return on_packet(p, now); });
  if (state_ != State::Closed && framer_.status() != Framer::Status::Ok) {
    violation(framer_.status() == Framer::Status::TooLong ? "packet too long" : "zero-length packet");
  }
  if (state_ == State::Closed) a_.consumed = in.size();
  return end(now);
}

bool ClientSession::on_packet(const Packet& p, Nanos) {
  const bool active = state_ == State::Active;
  switch (static_cast<PacketType>(p.type)) {
    case PacketType::Debug: return true;  // spec 2.1: ignored
    case PacketType::LoginAccepted: {
      if (active) return violation("unexpected login accepted");
      const auto acc = parse_login_accepted(p.payload);
      if (!acc || acc->sequence == 0) return violation("malformed login accepted");
      session_ = acc->session;
      next_ = acc->sequence;
      state_ = State::Active;
      a_.events.push_back(Event{EventKind::LoggedIn, CloseReason::None, 0, next_, 0});
      return true;
    }
    case PacketType::LoginRejected:
      if (active || p.payload.size() != kLoginRejectedPayload) return violation("unexpected login rejected");
      a_.events.push_back(Event{EventKind::LoginRejected, CloseReason::None, std::to_integer<char>(p.payload[0]), 0, 0});
      close(CloseReason::LoginRejected);
      return false;
    case PacketType::SequencedData:
      if (!active) return violation("sequenced data before login accepted");
      a_.delivered.push_back(Delivered{p.payload, next_++});
      return !a_.delivered.full();
    case PacketType::UnsequencedData:
      // 4.10: best effort, does not advance the sequence number.
      if (!active || cfg_.version != Version::V410) return violation("unexpected unsequenced data");
      a_.delivered.push_back(Delivered{p.payload, 0});
      return !a_.delivered.full();
    case PacketType::ServerHeartbeat:
      if (!active) return violation("heartbeat before login accepted");
      if (!p.payload.empty()) return violation("malformed server heartbeat");
      return true;
    case PacketType::EndOfSession:
      if (!active) return violation("end of session before login accepted");
      a_.events.push_back(Event{EventKind::EndOfSession, CloseReason::None, 0, next_, 0});
      close(CloseReason::EndOfSession);
      return false;
    default: return violation("unknown packet type");
  }
}

const Actions& ClientSession::on_timer(Nanos now) {
  begin();
  if (state_ == State::AwaitingLoginResponse && now - connected_at_ >= cfg_.login_timeout) {
    close(CloseReason::LoginTimeout);
  } else if (state_ == State::Active) {
    if (now - last_rx_ >= cfg_.idle_timeout) {
      close(CloseReason::IdleTimeout);
    } else if (now - last_tx_ >= cfg_.heartbeat_interval && write_packet(PacketType::ClientHeartbeat, {})) {
      last_tx_ = now;
    }
  }
  return end(now);
}

const Actions& ClientSession::send_unsequenced(std::span<const std::byte> msg, Nanos now) {
  begin();
  a_.accepted = state_ == State::Active && msg.size() <= kMaxPayload && write_packet(PacketType::UnsequencedData, msg);
  if (a_.accepted) last_tx_ = now;
  return end(now);
}

const Actions& ClientSession::send_debug(std::string_view text, Nanos now) {
  begin();
  a_.accepted = (state_ == State::AwaitingLoginResponse || state_ == State::Active) &&
                write_packet(PacketType::Debug, std::as_bytes(std::span(text.data(), text.size())));
  if (a_.accepted) last_tx_ = now;
  return end(now);
}

const Actions& ClientSession::logout(Nanos now) {
  begin();
  if (state_ == State::AwaitingLoginResponse || state_ == State::Active) {
    a_.accepted = write_packet(PacketType::LogoutRequest, {});
    close(CloseReason::LogoutRequested);
  } else {
    a_.accepted = false;
  }
  return end(now);
}

void ClientSession::consume_tx(std::size_t n) noexcept {
  tx_.consume(n);
  a_.write = tx_.pending();
}

ClientConfig ClientSession::resume_config() const noexcept {
  ClientConfig c = cfg_;
  c.session = session_;
  c.sequence = next_;
  return c;
}

bool ClientSession::violation(std::string_view text) {
  write_packet(PacketType::Debug, std::as_bytes(std::span(text.data(), text.size())));
  close(CloseReason::ProtocolViolation);
  return false;
}

void ClientSession::close(CloseReason why) noexcept {
  if (state_ == State::Closed) return;
  state_ = State::Closed;
  a_.events.push_back(Event{EventKind::Closed, why, 0, 0, 0});
}

bool ClientSession::write_packet(PacketType t, std::span<const std::byte> payload) noexcept {
  const std::size_t n = packet_size(payload.size());
  std::byte* p = tx_.reserve(n);
  if (p == nullptr) return false;
  tx_.commit(encode_packet(std::span<std::byte>(p, n), t, payload));
  return true;
}

}  // namespace lle::soup

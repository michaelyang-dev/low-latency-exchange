#pragma once
// MoldUDP64 publisher core (03-protocols §6), sans-I/O: messages and time in,
// packets out through an `emit(std::span<const std::byte>)` callback (the
// bytes are valid only during the call).
//
// Opportunistic batching: messages accumulate in the open packet; the packet
// is emitted when the next message does not fit or when the caller reports
// that its input queue is empty (flush). It never waits on a timer.
// Heartbeats (count 0, sequence = next expected) go out after
// `heartbeat_interval` without any packet. After end_session() an
// end-of-session packet (count 0xFFFF) is sent immediately and then repeated
// every heartbeat interval for `end_of_session_linger`.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/types.h"
#include "env/buggify.h"
#include "proto/moldudp64/moldudp64.h"

namespace lle::mold {

struct PacketizerConfig {
  Session session;
  std::size_t max_packet = kDefaultMaxPacket;  // whole MoldUDP64 packet (the UDP payload)
  Nanos heartbeat_interval = kNsPerSec;
  Nanos end_of_session_linger = 30 * kNsPerSec;
  SeqNo first_seq = 1;
};

struct PacketizerStats {
  std::uint64_t data_packets = 0;
  std::uint64_t messages = 0;
  std::uint64_t heartbeats = 0;
  std::uint64_t end_of_session_packets = 0;
  std::uint64_t bytes = 0;
  std::uint64_t rejected_too_large = 0;
};

class Packetizer {
 public:
  enum class AppendResult : std::uint8_t { Ok, TooLarge, SessionEnded };
  static constexpr Nanos kNever = std::numeric_limits<Nanos>::max();

  explicit Packetizer(const PacketizerConfig& cfg)
      : cfg_(cfg), buf_(std::make_unique<std::byte[]>(cfg.max_packet)), next_seq_(cfg.first_seq),
        open_seq_(cfg.first_seq) {
    LLE_ASSERT(cfg.max_packet > kHeaderLen + kBlockPrefixLen && cfg.max_packet <= (std::size_t{1} << 20));
    LLE_ASSERT(cfg.heartbeat_interval > 0 && cfg.first_seq >= 1);
  }

  // Adds one message. If it does not fit in the open packet, that packet is
  // emitted first. A message that cannot fit even in an empty packet is refused.
  template <class Emit>
  AppendResult append(std::span<const std::byte> msg, Nanos now, Emit&& emit) {
    if (state_ != State::Open) return AppendResult::SessionEnded;
    if (msg.size() > kMaxMessageLen || kHeaderLen + kBlockPrefixLen + msg.size() > cfg_.max_packet) {
      ++stats_.rejected_too_large;
      return AppendResult::TooLarge;
    }
    if (count_ == kMaxMessagesPerPacket || used_ + kBlockPrefixLen + msg.size() > cfg_.max_packet ||
        (count_ != 0 && SIM_BUGGIFY("mold.packetizer_early_emit"))) {  // other packet boundaries
      emit_open(now, emit);
    }
    store_be16(buf_.get() + used_, static_cast<std::uint16_t>(msg.size()));
    if (!msg.empty()) std::memcpy(buf_.get() + used_ + kBlockPrefixLen, msg.data(), msg.size());
    used_ += kBlockPrefixLen + msg.size();
    ++count_;
    ++next_seq_;
    return AppendResult::Ok;
  }

  // The caller's input is empty: emit the open packet, if any. Returns true if
  // a packet was emitted.
  template <class Emit>
  bool flush(Nanos now, Emit&& emit) {
    if (count_ == 0) return false;
    emit_open(now, emit);
    return true;
  }

  // Heartbeat or end-of-session repeat when due. An open packet the caller
  // never flushed is emitted at the heartbeat deadline instead of a heartbeat
  // (a liveness backstop; flush() is the zero-latency path).
  template <class Emit>
  bool on_timer(Nanos now, Emit&& emit) {
    if (state_ == State::Open) {
      if (now - last_send_ < cfg_.heartbeat_interval) return false;
      if (count_ != 0) {
        emit_open(now, emit);
        return true;
      }
      send_control(now, false, emit);
      ++stats_.heartbeats;
      return true;
    }
    if (state_ == State::Ending) {
      if (now >= eos_until_) {
        state_ = State::Done;
        return false;
      }
      if (now - last_send_ < cfg_.heartbeat_interval) return false;
      send_control(now, true, emit);
      ++stats_.end_of_session_packets;
      return true;
    }
    return false;
  }

  // Flushes, then sends the first end-of-session packet. Further messages are refused.
  template <class Emit>
  void end_session(Nanos now, Emit&& emit) {
    if (state_ != State::Open) return;
    if (count_ != 0) emit_open(now, emit);
    state_ = State::Ending;
    eos_until_ = now + cfg_.end_of_session_linger;
    send_control(now, true, emit);
    ++stats_.end_of_session_packets;
  }

  // Earliest time on_timer() has work (kNever when done).
  [[nodiscard]] Nanos next_deadline() const noexcept {
    if (state_ == State::Done) return kNever;
    const Nanos hb = last_send_ + cfg_.heartbeat_interval;
    return state_ == State::Ending && hb >= eos_until_ ? eos_until_ : hb;
  }

  // Sequence number the next appended message will get.
  [[nodiscard]] SeqNo next_seq() const noexcept { return next_seq_; }
  // Sequence number receivers expect next (messages in the open packet are not yet sent).
  [[nodiscard]] SeqNo next_expected() const noexcept { return open_seq_; }
  [[nodiscard]] std::uint16_t pending_messages() const noexcept { return count_; }
  [[nodiscard]] bool ended() const noexcept { return state_ != State::Open; }
  [[nodiscard]] bool done() const noexcept { return state_ == State::Done; }
  [[nodiscard]] const PacketizerStats& stats() const noexcept { return stats_; }
  [[nodiscard]] const PacketizerConfig& config() const noexcept { return cfg_; }

 private:
  enum class State : std::uint8_t { Open, Ending, Done };

  template <class Emit>
  void emit_open(Nanos now, Emit& emit) {
    encode_header(buf_.get(), PacketHeader{cfg_.session, open_seq_, count_});
    const std::span<const std::byte> pkt(buf_.get(), used_);
    ++stats_.data_packets;
    stats_.messages += count_;
    stats_.bytes += used_;
    open_seq_ += count_;
    count_ = 0;
    used_ = kHeaderLen;
    last_send_ = now;
    emit(pkt);
  }

  template <class Emit>
  void send_control(Nanos now, bool eos, Emit& emit) {
    std::byte hdr[kHeaderLen];
    encode_header(hdr, PacketHeader{cfg_.session, open_seq_, eos ? kEndOfSessionCount : kHeartbeatCount});
    stats_.bytes += kHeaderLen;
    last_send_ = now;
    emit(std::span<const std::byte>(hdr, kHeaderLen));
  }

  PacketizerConfig cfg_;
  std::unique_ptr<std::byte[]> buf_;
  std::size_t used_ = kHeaderLen;
  std::uint16_t count_ = 0;
  SeqNo next_seq_;
  SeqNo open_seq_;  // sequence of the first message in the open packet
  Nanos last_send_ = 0;
  Nanos eos_until_ = 0;
  State state_ = State::Open;
  PacketizerStats stats_;
};

}  // namespace lle::mold

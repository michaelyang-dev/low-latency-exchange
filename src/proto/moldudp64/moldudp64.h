#pragma once
// MoldUDP64 1.00 packet codec (03-protocols §6; R1b D1).
//
// Downstream packet:  Session(0/10 alpha) Sequence(10/8 u64) Count(18/2 u16)
//                     then Count message blocks [u16 length][data].
//   Count 0      = heartbeat; Sequence = next expected sequence number.
//   Count 0xFFFF = end of session; Sequence = next expected sequence number.
// Request packet:     Session(0/10) Sequence(10/8) Requested Count(18/2), 20 bytes.
//
// All numeric fields are big-endian. Zero-length message blocks are valid
// sequenced messages. Parsing is strict: a packet must be exactly the header
// plus its blocks (heartbeat and end-of-session packets are exactly 20 bytes),
// so a packet is either delivered whole or rejected whole.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>

#include "common/alpha.h"
#include "common/endian.h"
#include "common/types.h"

namespace lle::mold {

using Session = Alpha<10>;

inline constexpr std::size_t kHeaderLen = 20;
inline constexpr std::size_t kRequestLen = 20;
inline constexpr std::size_t kBlockPrefixLen = 2;
inline constexpr std::uint16_t kHeartbeatCount = 0;
inline constexpr std::uint16_t kEndOfSessionCount = 0xFFFF;
inline constexpr std::uint16_t kMaxMessagesPerPacket = 0xFFFE;
// 1500-byte Ethernet MTU - 20 (IPv4) - 8 (UDP), as used by NASDAQ Nordic (R1b D7).
inline constexpr std::size_t kDefaultMaxPacket = 1472;
inline constexpr std::size_t kMaxMessageLen = 0xFFFF;

struct PacketHeader {
  Session session;
  SeqNo seq = 0;
  std::uint16_t count = 0;

  [[nodiscard]] constexpr bool is_heartbeat() const noexcept { return count == kHeartbeatCount; }
  [[nodiscard]] constexpr bool is_end_of_session() const noexcept { return count == kEndOfSessionCount; }
  // Messages carried (0 for heartbeat and end of session).
  [[nodiscard]] constexpr std::uint16_t message_count() const noexcept {
    return count == kEndOfSessionCount ? std::uint16_t{0} : count;
  }
  friend constexpr bool operator==(const PacketHeader&, const PacketHeader&) = default;
};

inline void encode_header(std::byte* p, const PacketHeader& h) noexcept {
  h.session.to_wire(p);
  store_be64(p + 10, h.seq);
  store_be16(p + 18, h.count);
}

[[nodiscard]] inline PacketHeader decode_header(const std::byte* p) noexcept {
  return PacketHeader{Session::from_wire(p), load_be64(p + 10), load_be16(p + 18)};
}

enum class PacketError : std::uint8_t {
  TooShort,          // fewer than 20 bytes
  TruncatedBlock,    // a block's length prefix or data runs past the packet
  TrailingBytes,     // bytes after the last block (or after a heartbeat/EOS header)
  SequenceOverflow,  // seq + count wraps around 2^64
};

[[nodiscard]] constexpr std::string_view to_string(PacketError e) noexcept {
  switch (e) {
    case PacketError::TooShort:
      return "too_short";
    case PacketError::TruncatedBlock:
      return "truncated_block";
    case PacketError::TrailingBytes:
      return "trailing_bytes";
    case PacketError::SequenceOverflow:
      return "sequence_overflow";
  }
  return "?";
}

// A validated downstream packet. Iteration walks the message blocks in order.
class PacketView {
 public:
  [[nodiscard]] static std::expected<PacketView, PacketError> parse(std::span<const std::byte> pkt) noexcept {
    if (pkt.size() < kHeaderLen) return std::unexpected(PacketError::TooShort);
    const PacketHeader h = decode_header(pkt.data());
    const std::size_t n = h.message_count();
    if (h.seq > ~SeqNo{0} - n) return std::unexpected(PacketError::SequenceOverflow);
    std::size_t at = kHeaderLen;
    for (std::size_t i = 0; i < n; ++i) {
      if (pkt.size() - at < kBlockPrefixLen) return std::unexpected(PacketError::TruncatedBlock);
      const std::size_t len = load_be16(pkt.data() + at);
      at += kBlockPrefixLen;
      if (pkt.size() - at < len) return std::unexpected(PacketError::TruncatedBlock);
      at += len;
    }
    if (at != pkt.size()) return std::unexpected(PacketError::TrailingBytes);
    return PacketView(pkt, h);
  }

  [[nodiscard]] const PacketHeader& header() const noexcept { return h_; }
  [[nodiscard]] SeqNo seq() const noexcept { return h_.seq; }
  [[nodiscard]] std::uint16_t message_count() const noexcept { return h_.message_count(); }
  [[nodiscard]] SeqNo end_seq() const noexcept { return h_.seq + h_.message_count(); }  // exclusive
  [[nodiscard]] bool is_heartbeat() const noexcept { return h_.is_heartbeat(); }
  [[nodiscard]] bool is_end_of_session() const noexcept { return h_.is_end_of_session(); }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return pkt_; }

  // Calls f(SeqNo, std::span<const std::byte>) for every message, in order.
  template <class F>
  void for_each(F&& f) const {
    std::size_t at = kHeaderLen;
    const std::size_t n = h_.message_count();
    for (std::size_t i = 0; i < n; ++i) {
      const std::size_t len = load_be16(pkt_.data() + at);
      f(h_.seq + i, pkt_.subspan(at + kBlockPrefixLen, len));
      at += kBlockPrefixLen + len;
    }
  }

  // As for_each, starting at message index `skip` (blocks before it are walked, not reported).
  template <class F>
  void for_each_from(std::size_t skip, F&& f) const {
    std::size_t at = kHeaderLen;
    const std::size_t n = h_.message_count();
    for (std::size_t i = 0; i < n; ++i) {
      const std::size_t len = load_be16(pkt_.data() + at);
      if (i >= skip) f(h_.seq + i, pkt_.subspan(at + kBlockPrefixLen, len));
      at += kBlockPrefixLen + len;
    }
  }

 private:
  PacketView(std::span<const std::byte> pkt, const PacketHeader& h) noexcept : pkt_(pkt), h_(h) {}
  std::span<const std::byte> pkt_;
  PacketHeader h_;
};

// Re-request packet (client to re-request server, unicast).
struct RequestPacket {
  Session session;
  SeqNo seq = 0;
  std::uint16_t count = 0;
  friend constexpr bool operator==(const RequestPacket&, const RequestPacket&) = default;
};

inline std::size_t encode_request(std::span<std::byte> out, const RequestPacket& r) noexcept {
  if (out.size() < kRequestLen) return 0;
  r.session.to_wire(out.data());
  store_be64(out.data() + 10, r.seq);
  store_be16(out.data() + 18, r.count);
  return kRequestLen;
}

// Exactly 20 bytes; anything else is malformed.
[[nodiscard]] inline std::expected<RequestPacket, PacketError> decode_request(std::span<const std::byte> in) noexcept {
  if (in.size() < kRequestLen) return std::unexpected(PacketError::TooShort);
  if (in.size() > kRequestLen) return std::unexpected(PacketError::TrailingBytes);
  return RequestPacket{Session::from_wire(in.data()), load_be64(in.data() + 10), load_be16(in.data() + 18)};
}

// Writes a heartbeat (count 0) or end-of-session (count 0xFFFF) packet.
inline std::size_t encode_control(std::span<std::byte> out, const Session& s, SeqNo next_seq, bool end_of_session) noexcept {
  if (out.size() < kHeaderLen) return 0;
  encode_header(out.data(), PacketHeader{s, next_seq, end_of_session ? kEndOfSessionCount : kHeartbeatCount});
  return kHeaderLen;
}

// Builds one downstream data packet in a caller-provided buffer.
class PacketBuilder {
 public:
  PacketBuilder(std::span<std::byte> buf, const Session& s, SeqNo first_seq) noexcept
      : buf_(buf), session_(s), seq_(first_seq) {}
  // Appends a block if it fits; returns false otherwise (packet unchanged).
  bool add(std::span<const std::byte> msg) noexcept {
    if (msg.size() > kMaxMessageLen || count_ >= kMaxMessagesPerPacket) return false;
    if (buf_.size() < used_ + kBlockPrefixLen + msg.size()) return false;
    store_be16(buf_.data() + used_, static_cast<std::uint16_t>(msg.size()));
    if (!msg.empty()) std::memcpy(buf_.data() + used_ + kBlockPrefixLen, msg.data(), msg.size());
    used_ += kBlockPrefixLen + msg.size();
    ++count_;
    return true;
  }
  [[nodiscard]] std::uint16_t count() const noexcept { return count_; }
  // Finalizes the header and returns the packet bytes.
  std::span<const std::byte> finish() noexcept {
    encode_header(buf_.data(), PacketHeader{session_, seq_, count_});
    return buf_.first(used_);
  }

 private:
  std::span<std::byte> buf_;
  Session session_;
  SeqNo seq_;
  std::size_t used_ = kHeaderLen;
  std::uint16_t count_ = 0;
};

}  // namespace lle::mold

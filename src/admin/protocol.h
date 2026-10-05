#pragma once
// The authenticated admin channel (05 §10 E-15; ADR-028: after day start,
// configuration changes only as journaled Admin records). Operators send
// framed commands to the admin port of the sequencer node; the port verifies
// them and hands them to the sequencer's admin queue, which journals them as
// Admin records the engine acts on (engine/records.h AdminCommand, TLV args).
//
// Sans-I/O: bytes in, decisions and bytes out. All integers big-endian except
// the TLV arguments, which are the journal's little-endian TLVs verbatim.
//
// Request (type 'R'), 22 + n + 32 bytes:
//   off size
//     0   2  frame length       bytes after this field (20 + n + 32)
//     2   1  version            1
//     3   1  type               'R'
//     4   4  operator id
//     8   8  sequence           strictly increasing per operator (replay protection)
//    16   2  command            engine::AdminCommand (1..14)
//    18   2  TLV version        1
//    20   2  args length n      <= kMaxArgs (the sequencer's AdminMsg capacity)
//    22   n  args               engine TLVs (engine::AdminArgsBuilder)
//  22+n  32  mac                HMAC-SHA256(operator key, bytes [2, 22 + n))
//
// Response (type 'A' accepted / 'N' rejected), 17 + 32 bytes:
//     0   2  frame length       47
//     2   1  version            1
//     3   1  type               'A' or 'N'
//     4   4  operator id        as received (0 if the frame could not be parsed)
//     8   8  sequence           as received
//    16   1  reason             NackReason ('A': 0)
//    17  32  mac                HMAC-SHA256(operator key, bytes [2, 17)); zero when
//                               the operator is unknown (nothing to sign with)
//
// The port accepts a command only if the operator is known, the MAC verifies
// (constant-time compare), the sequence is above the operator's last accepted
// one, the command and TLV version are known, and the arguments parse
// (engine::parse_admin_args). Semantic checks (an unknown symbol, a resume of a
// trading symbol) stay with the engine, which audits them: the journal is the
// record of what the operator asked for.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <span>
#include <string_view>
#include <vector>

namespace lle::admin {

inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kMaxArgs = 240;
inline constexpr std::size_t kMacBytes = 32;
inline constexpr std::size_t kRequestHead = 22;
inline constexpr std::size_t kResponseBytes = 2 + 15 + kMacBytes;
inline constexpr std::size_t kMaxFrame = kRequestHead + kMaxArgs + kMacBytes;

using Mac = std::array<std::uint8_t, kMacBytes>;
using Key = std::vector<std::uint8_t>;

// HMAC-SHA256 (RFC 2104 / FIPS 198-1).
[[nodiscard]] Mac hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::byte> msg) noexcept;
[[nodiscard]] bool equal_ct(const Mac& a, std::span<const std::byte> b) noexcept;  // constant time

enum class NackReason : std::uint8_t {
  None = 0,
  Malformed = 'M',        // length, version, type or args length
  UnknownOperator = 'O',
  BadMac = 'S',
  Replay = 'R',           // sequence not above the last accepted one
  UnknownCommand = 'C',
  BadArgs = 'T',          // TLV version or arguments do not parse
  Busy = 'B',             // the sequencer's admin queue is full; send again
};
[[nodiscard]] std::string_view to_string(NackReason r) noexcept;

struct Request {
  std::uint32_t operator_id = 0;
  std::uint64_t sequence = 0;
  std::uint16_t command = 0;
  std::uint16_t tlv_version = 1;
  std::span<const std::byte> args;  // into the frame
};

struct Response {
  bool accepted = false;
  std::uint32_t operator_id = 0;
  std::uint64_t sequence = 0;
  NackReason reason = NackReason::None;
};

// Client side.
[[nodiscard]] std::vector<std::byte> encode_request(const Request& r, std::span<const std::uint8_t> key);
// Parses a response; nullopt-like error if malformed or the MAC does not verify
// (an unsigned 'N' for an unknown operator verifies only with `allow_unsigned`).
[[nodiscard]] std::expected<Response, NackReason> decode_response(std::span<const std::byte> frame,
                                                                  std::span<const std::uint8_t> key,
                                                                  bool allow_unsigned = true);

// Server side: the operator table and replay state.
class Verifier {
 public:
  void add_operator(std::uint32_t id, Key key) { ops_[id] = Op{std::move(key), 0}; }
  [[nodiscard]] std::size_t operators() const noexcept { return ops_.size(); }

  // Checks one complete request frame. On success the operator's sequence
  // advances (call commit()) only if the command is handed on: verify() does
  // not consume the sequence, so a Busy nack can be retried with the same one.
  [[nodiscard]] std::expected<Request, NackReason> verify(std::span<const std::byte> frame) const noexcept;
  void commit(const Request& r) noexcept;

  // A signed response frame.
  [[nodiscard]] std::array<std::byte, kResponseBytes> respond(const Response& r) const noexcept;

 private:
  struct Op {
    Key key;
    std::uint64_t last = 0;
  };
  std::map<std::uint32_t, Op> ops_;
};

// Splits a byte stream into frames. Bytes are appended with feed(); next()
// returns complete frames in order. A length outside [min, kMaxFrame] poisons
// the stream (the caller closes the connection).
class FrameAssembler {
 public:
  void feed(std::span<const std::byte> b) { buf_.insert(buf_.end(), b.begin(), b.end()); }
  // The next frame (bytes valid until the next feed/next call), empty if none yet.
  [[nodiscard]] std::span<const std::byte> next();
  [[nodiscard]] bool poisoned() const noexcept { return poisoned_; }

 private:
  std::vector<std::byte> buf_;
  std::vector<std::byte> frame_;
  bool poisoned_ = false;
};

}  // namespace lle::admin

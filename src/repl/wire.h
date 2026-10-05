#pragma once
// Replication data-plane messages between the two data nodes (10 §2, §3, §5).
//
// Internal protocol on the dedicated A–B link: little-endian, CRC32C-protected,
// one message per UDP datagram, at most kMaxDatagram (1,400) bytes so that it
// fits the standard MTU and a 4 KiB AF_XDP chunk. Every datagram:
//
//   0   u32  magic "LRP1"
//   4   u8   version (1)
//   5   u8   type (MsgType)
//   6   u8   from (sender node id, 0 or 1)
//   7   u8   flags (type-specific; undefined bits are zero)
//   8   u16  body length
//  10   u16  reserved (0)
//  12   ...  body (all padding and reserved bytes zero)
// 12+n  u32  CRC32C over bytes [0, 12+n)
//
// Bodies (offsets relative to the body):
//
//   APPEND (56 + 16·hash + 16·soup + record_bytes)            flags: 1 catch-up, 2 hash
//      0 u64 epoch           sender's epoch (records may carry older epochs)
//      8 u64 first_index     record the bytes start in
//     16 u64 commit_index    paired: commit_index; catch-up: the primary's release watermark
//     24 u64 mold_watermark  MoldUDP64 sequence released by the primary (line B gating)
//     32 u64 target_inc      receiver incarnation this stream is addressed to
//     40 u32 first_offset    byte offset inside record first_index (0: a record boundary)
//     44 u32 first_len       length of record first_index
//     48 u16 record_bytes    > 0
//     50 u8  soup_count      SoupBinTCP watermark entries
//     51 u8 + u32 reserved
//     56 [u64 hash_index, u64 state_hash]                 if flag 2
//        soup_count x [u32 session_id, u32 reserved, u64 next_seq]
//        record bytes: either whole canonical journal records (first_offset 0, the
//        first of length first_len), or one fragment of record first_index
//        (first_offset + record_bytes <= first_len) when that record does not fit
//        an empty datagram.
//   ACK (40)                                                  flags: 1 catch-up
//      0 u64 epoch  8 u64 l2_index (cumulative)  16 u64 inc
//     24 u64 snap_index  32 u64 snap_offset   (catch-up snapshot progress; 0 otherwise)
//   NACK (24)                                                 flags: 1 catch-up
//      0 u64 epoch  8 u64 expected_index  16 u64 inc
//   HEARTBEAT (96)                                            flags: 1 admitted by W's copy
//      0 u64 epoch  8 u64 last  16 u64 commit  24 u64 applied  32 u64 released
//     40 u64 durable  48 u64 inc  56 u64 build_id  64 u64 hash_index  72 u64 state_hash
//     80 u64 partner_inc (a primary: the backup incarnation it is paired with)
//     88 u8 role  89 u8 members  90 u8 primary  91 u8 + u32 reserved
//   FORWARD (48 + len)
//      0 u64 epoch  8 u64 inc (forwarding node)  16 u64 seq (per session instance, from 1)
//     24 u32 session_id  28 u32 account  32 u16 instance  34 u8 kind  35 u8 event
//     36 u16 len  38 u16 record_flags (journal record flags, kOuch only)
//     40 u64 requested_seq  48 bytes[len]
//   EPOCH_END_QUERY (32)
//      0 u64 epoch (querier's last record epoch)  8 u64 inc  16 u64 build_id  24 u64 query_id
//   EPOCH_END (64)                                            flags: 1 refused
//      0 u64 query_epoch  8 u64 end_index  16 u32 end_crc  20 u32 end_epoch
//     24 u64 primary_epoch  32 u64 query_id  40 u64 tail
//     48 u64 start_index (first record of epoch end_epoch)  56 u32 start_crc  60 u32 reserved
//   CATCHUP_REQ (40)
//      0 u64 from_index  8 u32 prev_crc  12 u32 attempt (the joiner's rejoin attempt)
//     16 u64 inc  24 u64 build_id  32 u64 epoch (the primary's, at the handshake)
//   SNAPSHOT_CHUNK (48 + len)
//      0 u64 snap_index  8 u64 total  16 u64 offset  24 u64 inc  32 u64 epoch
//     40 u16 len  42 u16 + u32 reserved  48 bytes[len]
//
// The decoder accepts only the canonical form (exact lengths, known type and flags,
// zero padding, correct CRC, well-framed record bytes), so decode followed by encode
// reproduces the datagram byte for byte. Journal record contents (seal, chain,
// epoch) are validated by the receiving state machine, not here.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <variant>

#include "witness/control.h"

namespace lle::repl::wire {

inline constexpr std::uint32_t kWireMagic = 0x3150'524Cu;  // "LRP1"
inline constexpr std::uint8_t kWireVersion = 1;
inline constexpr std::size_t kMaxDatagram = 1400;
inline constexpr std::size_t kHeaderBytes = 12;
inline constexpr std::size_t kTrailerBytes = 4;
inline constexpr std::size_t kMaxBody = kMaxDatagram - kHeaderBytes - kTrailerBytes;

inline constexpr std::size_t kAppendFixed = 56;
inline constexpr std::size_t kHashBytes = 16;
inline constexpr std::size_t kSoupEntryBytes = 16;
inline constexpr std::size_t kMaxSoup = 8;
// Record bytes an APPEND without optional fields can carry.
inline constexpr std::size_t kMaxAppendRecordBytes = kMaxBody - kAppendFixed;
inline constexpr std::size_t kForwardFixed = 48;
inline constexpr std::size_t kMaxForwardBytes = kMaxBody - kForwardFixed;
inline constexpr std::size_t kSnapshotFixed = 48;
inline constexpr std::size_t kMaxSnapshotChunk = kMaxBody - kSnapshotFixed;

using NodeId = witness::NodeId;

enum class MsgType : std::uint8_t {
  kAppend = 1,
  kAck = 2,
  kNack = 3,
  kHeartbeat = 4,
  kForward = 5,
  kEpochEndQuery = 6,
  kEpochEnd = 7,
  kCatchupReq = 8,
  kSnapshotChunk = 9,
};
inline constexpr std::uint8_t kMaxMsgType = 9;

struct SoupWatermark {
  std::uint32_t session_id = 0;
  std::uint64_t next_seq = 0;
  friend bool operator==(const SoupWatermark&, const SoupWatermark&) = default;
};

struct StateHash {
  std::uint64_t index = 0;  // the hash covers the state after applying records 1..index
  std::uint64_t hash = 0;
  friend bool operator==(const StateHash&, const StateHash&) = default;
};

struct Append {
  NodeId from = 0;
  bool catchup = false;
  std::uint64_t epoch = 0;
  std::uint64_t first_index = 0;
  std::uint64_t commit_index = 0;
  std::uint64_t mold_watermark = 0;
  std::uint64_t target_inc = 0;
  std::uint32_t first_offset = 0;
  std::uint32_t first_len = 0;
  bool has_hash = false;
  StateHash hash;
  std::uint8_t soup_count = 0;
  std::array<SoupWatermark, kMaxSoup> soup{};
  std::span<const std::byte> records;  // a view into the datagram (decode) or the caller's bytes (encode)
};

struct Ack {
  NodeId from = 0;
  bool catchup = false;
  std::uint64_t epoch = 0;
  std::uint64_t l2_index = 0;
  std::uint64_t inc = 0;
  std::uint64_t snap_index = 0;
  std::uint64_t snap_offset = 0;
  friend bool operator==(const Ack&, const Ack&) = default;
};

struct Nack {
  NodeId from = 0;
  bool catchup = false;
  std::uint64_t epoch = 0;
  std::uint64_t expected_index = 0;
  std::uint64_t inc = 0;
  friend bool operator==(const Nack&, const Nack&) = default;
};

struct Heartbeat {
  NodeId from = 0;
  std::uint64_t epoch = 0;
  std::uint64_t last = 0;
  std::uint64_t commit = 0;
  std::uint64_t applied = 0;
  std::uint64_t released = 0;
  std::uint64_t durable = 0;
  std::uint64_t inc = 0;
  std::uint64_t build_id = 0;
  StateHash hash;  // index 0: none yet
  std::uint64_t partner_inc = 0;
  std::uint8_t role = 0;
  witness::Members members = 0;
  NodeId primary = 0;
  // A backup that W's own copy of the JOIN grant admitted (addressed to the incarnation W
  // recorded): proof for a primary that cannot tell which of its JOINs W granted.
  bool admitted = false;
  friend bool operator==(const Heartbeat&, const Heartbeat&) = default;
};

enum class ForwardKind : std::uint8_t { kOuch = 1, kSessionEvent = 2 };

struct Forward {
  NodeId from = 0;
  std::uint64_t epoch = 0;
  std::uint64_t inc = 0;
  std::uint64_t seq = 0;
  std::uint32_t session_id = 0;
  std::uint32_t account = 0;
  std::uint16_t instance = 0;
  ForwardKind kind = ForwardKind::kOuch;
  std::uint8_t event = 0;           // journal::SessionEventKind for kSessionEvent, else 0
  std::uint64_t requested_seq = 0;  // session events
  std::span<const std::byte> bytes;  // raw OUCH message (kOuch), empty for session events
  // Journal record flags the gateway gave the inbound (journal::kFlagMalformedInput for a
  // truncated, over-long packet): the primary sequences it exactly as a direct
  // submission. kOuch only; zero for session events.
  std::uint16_t record_flags = 0;
};

struct EpochEndQuery {
  NodeId from = 0;
  std::uint64_t epoch = 0;
  std::uint64_t inc = 0;
  std::uint64_t build_id = 0;
  std::uint64_t query_id = 0;
  friend bool operator==(const EpochEndQuery&, const EpochEndQuery&) = default;
};

struct EpochEnd {
  NodeId from = 0;
  bool refused = false;
  std::uint64_t query_epoch = 0;
  std::uint64_t end_index = 0;
  std::uint32_t end_crc = 0;
  std::uint32_t end_epoch = 0;
  std::uint64_t primary_epoch = 0;
  std::uint64_t query_id = 0;
  std::uint64_t tail = 0;
  std::uint64_t start_index = 0;
  std::uint32_t start_crc = 0;
  friend bool operator==(const EpochEnd&, const EpochEnd&) = default;
};

struct CatchupReq {
  NodeId from = 0;
  std::uint64_t from_index = 0;
  std::uint32_t prev_crc = 0;
  std::uint32_t attempt = 0;
  std::uint64_t inc = 0;
  std::uint64_t build_id = 0;
  std::uint64_t epoch = 0;  // the primary's epoch at the handshake that opened this session
  friend bool operator==(const CatchupReq&, const CatchupReq&) = default;
};

struct SnapshotChunk {
  NodeId from = 0;
  std::uint64_t snap_index = 0;
  std::uint64_t total = 0;
  std::uint64_t offset = 0;
  std::uint64_t inc = 0;
  std::uint64_t epoch = 0;
  std::span<const std::byte> bytes;
};

using Message = std::variant<Append, Ack, Nack, Heartbeat, Forward, EpochEndQuery, EpochEnd, CatchupReq, SnapshotChunk>;

[[nodiscard]] MsgType type_of(const Message& m) noexcept;
[[nodiscard]] const char* to_string(MsgType t) noexcept;

enum class DecodeError : std::uint8_t { kShort, kMagic, kVersion, kType, kLength, kCrc, kPadding, kField, kFlags };
[[nodiscard]] const char* to_string(DecodeError e) noexcept;

// Encodes `m` into `out` (at least kMaxDatagram bytes for any message). Returns the
// datagram length, or 0 if the message is malformed (for example, more record bytes
// than an APPEND can carry); the encoder never writes past out.size().
[[nodiscard]] std::size_t encode(const Message& m, std::span<std::byte> out) noexcept;

// Decodes one datagram. Views in the result (records, bytes) point into `datagram`.
[[nodiscard]] std::expected<Message, DecodeError> decode(std::span<const std::byte> datagram) noexcept;

// Structural framing of APPEND record bytes: whole records starting at a boundary
// (each of valid length, the first of length first_len), or a single fragment of
// record first_index. Shared by the decoder and the receiver.
[[nodiscard]] bool append_framing_ok(std::uint32_t first_offset, std::uint32_t first_len,
                                     std::span<const std::byte> records) noexcept;

// Room for record bytes in an APPEND with the given optional fields.
[[nodiscard]] constexpr std::size_t append_capacity(bool has_hash, std::size_t soup_count) noexcept {
  return kMaxBody - kAppendFixed - (has_hash ? kHashBytes : 0) - soup_count * kSoupEntryBytes;
}

}  // namespace lle::repl::wire

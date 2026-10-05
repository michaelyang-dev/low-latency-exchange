#pragma once
// Journal record format (01-architecture §6, 06 §3).
//
// Every record is little-endian, 8-byte aligned, and starts with the 40-byte header
// below. `len` counts header + payload + zero padding and is a multiple of 8.
//
// Two CRCs are involved, both CRC32C (common/crc32c.h):
//
//   content crc  CRC32C (seed 0) over the record with the `crc32c` field zeroed. It is
//                the record's medium-independent identity: `prev_crc` of every record
//                holds the content crc of its predecessor (the hash chain), and the
//                segment header's "previous segment last CRC" is a content crc too. It
//                is therefore identical on the primary, the backup and in replays.
//   seal         the stored `crc32c` field: CRC32C over the same bytes SEEDED with the
//                medium's 64-bit nonce, i.e. CRC32C(le64(nonce) || record with crc
//                zeroed). Each L3 segment (06 §3, §6) and each L2 ring instance has its
//                own nonce, drawn fresh whenever it is (re)initialized, so stale records
//                left in a recycled segment never validate.
//
// CRC32C is linear, so seal = content ^ M(len, seed) where M depends only on the
// record length and the nonce seed. `Sealer` precomputes M for every legal length:
// computing the content crc and the seal costs one CRC pass, and moving a record from
// one medium to another (L2 ring -> L3 segment) re-seals it with one XOR instead of a
// second pass over the bytes.
//
// Pad records (06 §6: each write is padded to 4 KiB) are sealed like any record but are
// not part of the chain: a Pad repeats the index and prev_crc of the last real record
// before it, and the next real record chains to that real record.
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#include "common/endian.h"
#include "common/types.h"

namespace lle::journal {

inline constexpr std::uint32_t kFormatVersion = 1;
inline constexpr std::uint32_t kHeaderBytes = 40;
inline constexpr std::uint32_t kRecordAlign = 8;
// Largest record. Half the 64 KiB group-commit batch (06 §6), so a batch always holds at
// least one record plus its 4 KiB padding. Larger config tables are chunked (Config).
inline constexpr std::uint32_t kMaxRecordBytes = 32 * 1024;
inline constexpr std::uint32_t kMaxPayloadBytes = kMaxRecordBytes - kHeaderBytes;

enum class RecordType : std::uint16_t {
  DayStart = 1,  // trading date, session names, format version, build id
  Config,        // one chunk of one config table (symbols, accounts, risk limits, schedule)
  SessionEvent,  // login / logout / disconnect / mirror-attach / instance-down
  OuchInbound,   // session id, instance, account, raw OUCH message bytes
  Timer,         // scheduled event: system event, NOII, cross, state change, expiry, day end
  Admin,         // operator command (versioned TLV arguments)
  SnapshotMark,  // deterministic snapshot point
  EpochStart,    // first record of a new epoch
  DayEnd,        // final record of the trading day
  Pad            // filler to 4 KiB write boundaries (not chained, no index of its own)
};
inline constexpr std::uint16_t kMinRecordType = 1;
inline constexpr std::uint16_t kMaxRecordType = 10;

[[nodiscard]] constexpr bool valid_record_type(std::uint16_t t) noexcept {
  return t >= kMinRecordType && t <= kMaxRecordType;
}
[[nodiscard]] std::string_view to_string(RecordType t) noexcept;

// Header flags.
// OuchInbound: the gateway saw a packet longer than any legal OUCH message and forwards
// a malformed marker with a prefix of the bytes; the engine decides the reject (03 §2).
inline constexpr std::uint16_t kFlagMalformedInput = 1u << 0;

// In-memory form of the header. On-media encoding is explicit (encode/decode_header)
// so the format does not depend on host byte order.
struct alignas(8) RecordHeader {
  std::uint32_t len = 0;       // total bytes incl. header and payload, multiple of 8
  std::uint32_t crc32c = 0;    // seal: over the record with this field zeroed, seeded with the nonce
  std::uint64_t index = 0;     // dense, starts at 1 each trading day
  std::int64_t ts_ns = 0;      // exchange time (ns since UNIX epoch), assigned by the sequencer
  std::uint32_t epoch = 0;     // replication epoch decreed by the witness
  std::uint16_t type = 0;      // RecordType
  std::uint16_t flags = 0;
  std::uint32_t prev_crc = 0;  // content crc of the previous (non-Pad) record: the hash chain
  std::uint32_t reserved = 0;
  friend constexpr bool operator==(const RecordHeader&, const RecordHeader&) = default;
};
static_assert(sizeof(RecordHeader) == 40);

// Byte offsets of the header fields on media.
namespace hdr {
inline constexpr std::size_t kLen = 0;
inline constexpr std::size_t kCrc = 4;
inline constexpr std::size_t kIndex = 8;
inline constexpr std::size_t kTs = 16;
inline constexpr std::size_t kEpoch = 24;
inline constexpr std::size_t kType = 28;
inline constexpr std::size_t kFlags = 30;
inline constexpr std::size_t kPrevCrc = 32;
inline constexpr std::size_t kReserved = 36;
}  // namespace hdr
static_assert(offsetof(RecordHeader, len) == hdr::kLen);
static_assert(offsetof(RecordHeader, crc32c) == hdr::kCrc);
static_assert(offsetof(RecordHeader, index) == hdr::kIndex);
static_assert(offsetof(RecordHeader, ts_ns) == hdr::kTs);
static_assert(offsetof(RecordHeader, epoch) == hdr::kEpoch);
static_assert(offsetof(RecordHeader, type) == hdr::kType);
static_assert(offsetof(RecordHeader, flags) == hdr::kFlags);
static_assert(offsetof(RecordHeader, prev_crc) == hdr::kPrevCrc);
static_assert(offsetof(RecordHeader, reserved) == hdr::kReserved);

[[nodiscard]] constexpr std::uint32_t align_record(std::uint32_t n) noexcept {
  return (n + (kRecordAlign - 1)) & ~(kRecordAlign - 1);
}
[[nodiscard]] constexpr std::uint32_t record_bytes_for_payload(std::uint32_t payload) noexcept {
  return align_record(kHeaderBytes + payload);
}

inline void encode_header(std::byte* p, const RecordHeader& h) noexcept {
  store_le32(p + hdr::kLen, h.len);
  store_le32(p + hdr::kCrc, h.crc32c);
  store_le64(p + hdr::kIndex, h.index);
  store_le64(p + hdr::kTs, static_cast<std::uint64_t>(h.ts_ns));
  store_le32(p + hdr::kEpoch, h.epoch);
  store_le16(p + hdr::kType, h.type);
  store_le16(p + hdr::kFlags, h.flags);
  store_le32(p + hdr::kPrevCrc, h.prev_crc);
  store_le32(p + hdr::kReserved, h.reserved);
}

[[nodiscard]] inline RecordHeader decode_header(const std::byte* p) noexcept {
  RecordHeader h;
  h.len = load_le32(p + hdr::kLen);
  h.crc32c = load_le32(p + hdr::kCrc);
  h.index = load_le64(p + hdr::kIndex);
  h.ts_ns = static_cast<std::int64_t>(load_le64(p + hdr::kTs));
  h.epoch = load_le32(p + hdr::kEpoch);
  h.type = load_le16(p + hdr::kType);
  h.flags = load_le16(p + hdr::kFlags);
  h.prev_crc = load_le32(p + hdr::kPrevCrc);
  h.reserved = load_le32(p + hdr::kReserved);
  return h;
}

// ---- CRCs -------------------------------------------------------------------------

// CRC32C (seed 0) of `len` record bytes with the crc field treated as zero.
[[nodiscard]] std::uint32_t content_crc(const std::byte* rec, std::uint32_t len) noexcept;

// 32-bit CRC seed derived from a 64-bit nonce: CRC32C of its 8 little-endian bytes, so
// seal(record) == CRC32C(le64(nonce) || record with crc zeroed).
[[nodiscard]] std::uint32_t nonce_seed(std::uint64_t nonce) noexcept;

// Nonce 0 is reserved for the canonical (unsealed) form, where seal == content crc;
// a nonce whose seed is 0 would behave the same. Media never use either.
[[nodiscard]] inline bool usable_nonce(std::uint64_t nonce) noexcept { return nonce != 0 && nonce_seed(nonce) != 0; }

// Seals records for one medium (one L3 segment or one L2 ring instance). Holds the
// length-dependent masks M(len, seed) for every legal record length (16 KiB);
// construct it on cold paths only (segment switch, ring creation).
class Sealer {
 public:
  Sealer() noexcept;  // nonce 0: seed 0, seal == content crc (canonical form)
  explicit Sealer(std::uint64_t nonce) noexcept;

  [[nodiscard]] std::uint64_t nonce() const noexcept { return nonce_; }
  [[nodiscard]] std::uint32_t seed() const noexcept { return seed_; }

  // M(len, seed). `len` must be a legal record length (multiple of 8, <= kMaxRecordBytes).
  [[nodiscard]] std::uint32_t mask(std::uint32_t len) const noexcept { return masks_[len / kRecordAlign]; }

  // Stores the seal of a fully built record (crc field ignored); returns its content crc.
  std::uint32_t seal(std::byte* rec) const noexcept;

  // Re-seals a record sealed by `from` for this medium in O(1); returns its content crc.
  std::uint32_t reseal(std::byte* rec, const Sealer& from) const noexcept;

  // Content crc of a record sealed by this medium, from its stored seal, in O(1).
  [[nodiscard]] std::uint32_t content_of(const std::byte* rec) const noexcept;

  // Recomputes the record's crc; returns its content crc if the stored seal matches.
  // The caller has checked the length (parse_record()).
  [[nodiscard]] std::optional<std::uint32_t> verify(const std::byte* rec) const noexcept;

 private:
  std::uint64_t nonce_ = 0;
  std::uint32_t seed_ = 0;
  std::array<std::uint32_t, kMaxRecordBytes / kRecordAlign + 1> masks_{};
};

// ---- Views and parsing ------------------------------------------------------------

enum class ParseError : std::uint8_t {
  Truncated,   // fewer bytes than a header, or than `len`
  BadLength,   // len < 40, not a multiple of 8, or > kMaxRecordBytes
  BadType,     // type outside RecordType
};
[[nodiscard]] std::string_view to_string(ParseError e) noexcept;

// Zero-copy view of one complete record (header fields read on demand).
class RecordView {
 public:
  constexpr RecordView() noexcept = default;
  // `rec` holds exactly one structurally valid record (see parse_record()).
  explicit RecordView(std::span<const std::byte> rec) noexcept : p_(rec.data()), n_(static_cast<std::uint32_t>(rec.size())) {}

  [[nodiscard]] std::uint32_t len() const noexcept { return load_le32(p_ + hdr::kLen); }
  [[nodiscard]] std::uint32_t crc() const noexcept { return load_le32(p_ + hdr::kCrc); }
  [[nodiscard]] std::uint64_t index() const noexcept { return load_le64(p_ + hdr::kIndex); }
  [[nodiscard]] Nanos ts_ns() const noexcept { return static_cast<Nanos>(load_le64(p_ + hdr::kTs)); }
  [[nodiscard]] std::uint32_t epoch() const noexcept { return load_le32(p_ + hdr::kEpoch); }
  [[nodiscard]] std::uint16_t type_raw() const noexcept { return load_le16(p_ + hdr::kType); }
  [[nodiscard]] RecordType type() const noexcept { return static_cast<RecordType>(type_raw()); }
  [[nodiscard]] std::uint16_t flags() const noexcept { return load_le16(p_ + hdr::kFlags); }
  [[nodiscard]] std::uint32_t prev_crc() const noexcept { return load_le32(p_ + hdr::kPrevCrc); }
  [[nodiscard]] std::uint32_t reserved() const noexcept { return load_le32(p_ + hdr::kReserved); }
  [[nodiscard]] RecordHeader header() const noexcept { return decode_header(p_); }

  [[nodiscard]] const std::byte* data() const noexcept { return p_; }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {p_, n_}; }
  [[nodiscard]] std::span<const std::byte> payload() const noexcept { return {p_ + kHeaderBytes, n_ - kHeaderBytes}; }
  [[nodiscard]] bool empty() const noexcept { return p_ == nullptr; }

  // Content crc (one CRC pass).
  [[nodiscard]] std::uint32_t content() const noexcept { return content_crc(p_, n_); }

 private:
  const std::byte* p_ = nullptr;
  std::uint32_t n_ = 0;
};

// Structural checks only (length bounds, alignment, type); seals are checked by
// Sealer::verify and the chain by the reader. Never reads outside `buf`.
[[nodiscard]] std::expected<RecordView, ParseError> parse_record(std::span<const std::byte> buf) noexcept;

// ---- Payloads (06 §3) -------------------------------------------------------------
// Each payload type P provides: kType, payload_size(P), encode_payload(std::byte*, P)
// (writes exactly payload_size bytes), and a decode_<name>(RecordView) that checks the
// record type and the exact record length, and never reads outside the record.

// Decoders accept only the canonical form the builder produces: exact length, zero
// reserved fields and zero padding (so decode -> encode reproduces the bytes).
enum class DecodeError : std::uint8_t { WrongType, BadSize, BadField, NonCanonical };
[[nodiscard]] std::string_view to_string(DecodeError e) noexcept;

inline constexpr std::size_t kSessionNameBytes = 10;  // SoupBinTCP / MoldUDP64 session (10 alnum)
using SessionName = std::array<char, kSessionNameBytes>;

// DayStart payload (48 bytes):
//   0 u32 format_version   4 u32 trading_date (YYYYMMDD)   8 i64 local_midnight_ns
//  16 u64 build_id        24 char[10] mold_session         34 char[10] soup_session
//  44 u32 reserved (0)
struct DayStart {
  static constexpr RecordType kType = RecordType::DayStart;
  std::uint32_t format_version = kFormatVersion;
  std::uint32_t trading_date = 0;
  Nanos local_midnight_ns = 0;  // UNIX ns of local midnight (ITCH/OUCH timestamps are relative to it)
  std::uint64_t build_id = 0;
  SessionName mold_session{};
  SessionName soup_session{};
  friend bool operator==(const DayStart&, const DayStart&) = default;
};

enum class ConfigTable : std::uint16_t { Symbols = 1, Firms, Accounts, Sessions, RiskLimits, Schedule };
inline constexpr std::uint16_t kMaxConfigTable = 6;

// Config payload (16-byte head + chunk bytes): one chunk of one serialized config table
// (ADR-028). The table encoding belongs to the engine; the journal only frames it.
//   0 u16 table   2 u16 chunk_index   4 u16 chunk_count   6 u16 reserved (0)
//   8 u32 table_bytes (whole table)  12 u32 chunk_bytes   16 bytes[chunk_bytes]
struct ConfigChunk {
  static constexpr RecordType kType = RecordType::Config;
  static constexpr std::uint32_t kHeadBytes = 16;
  static constexpr std::uint32_t kMaxChunkBytes = kMaxPayloadBytes - kHeadBytes;
  ConfigTable table = ConfigTable::Symbols;
  std::uint16_t chunk_index = 0;
  std::uint16_t chunk_count = 1;
  std::uint32_t table_bytes = 0;
  std::span<const std::byte> bytes;
};

enum class SessionEventKind : std::uint8_t { Login = 1, Logout, Disconnect, MirrorAttach, InstanceDown };
inline constexpr std::uint8_t kMaxSessionEventKind = 5;

// SessionEvent payload (16 bytes):
//   0 u32 session_id   4 u16 instance   6 u8 event   7 u8 reserved (0)   8 u64 requested_seq
struct SessionEvent {
  static constexpr RecordType kType = RecordType::SessionEvent;
  std::uint32_t session_id = 0;
  std::uint16_t instance = 0;
  SessionEventKind event = SessionEventKind::Login;
  std::uint64_t requested_seq = 0;
  friend bool operator==(const SessionEvent&, const SessionEvent&) = default;
};

// OuchInbound payload (16-byte head + raw OUCH bytes). The fields of 06 §3 are
// reordered for natural alignment (as the header is):
//   0 u32 session_id   4 u32 account   8 u16 instance   10 u16 msg_len   12 u32 reserved (0)
//  16 bytes[msg_len]   (the original wire bytes: decoding is replayable and auditable)
struct OuchInbound {
  static constexpr RecordType kType = RecordType::OuchInbound;
  static constexpr std::uint32_t kHeadBytes = 16;
  std::uint32_t session_id = 0;
  std::uint32_t account = 0;
  std::uint16_t instance = 0;
  std::span<const std::byte> msg;
};

enum class TimerKind : std::uint16_t { SystemEvent = 1, Eoii, Noii, Cross, StateChange, ExpirySweep, DayEnd };
inline constexpr std::uint16_t kMaxTimerKind = 7;

// Timer payload (16 bytes):
//   0 u32 timer_id   4 u16 kind   6 u16 reserved (0)   8 i64 scheduled_ns
struct Timer {
  static constexpr RecordType kType = RecordType::Timer;
  std::uint32_t timer_id = 0;
  TimerKind kind = TimerKind::SystemEvent;
  Nanos scheduled_ns = 0;
  friend bool operator==(const Timer&, const Timer&) = default;
};

// Admin payload (16-byte head + TLV arguments):
//   0 u16 command   2 u16 tlv_version   4 u32 operator_id   8 u32 args_len   12 u32 reserved (0)
//  16 bytes[args_len]
struct Admin {
  static constexpr RecordType kType = RecordType::Admin;
  static constexpr std::uint32_t kHeadBytes = 16;
  std::uint16_t command = 0;
  std::uint16_t tlv_version = 1;
  std::uint32_t operator_id = 0;
  std::span<const std::byte> args;
};

// SnapshotMark payload (8 bytes): 0 u64 snapshot_id
struct SnapshotMark {
  static constexpr RecordType kType = RecordType::SnapshotMark;
  std::uint64_t snapshot_id = 0;
  friend bool operator==(const SnapshotMark&, const SnapshotMark&) = default;
};

// EpochStart payload (16 bytes): 0 u32 epoch   4 u32 primary_node   8 u64 config_digest
struct EpochStart {
  static constexpr RecordType kType = RecordType::EpochStart;
  std::uint32_t epoch = 0;
  std::uint32_t primary_node = 0;
  std::uint64_t config_digest = 0;
  friend bool operator==(const EpochStart&, const EpochStart&) = default;
};

// DayEnd payload (24 bytes): 0 u64 final_index   8 u64 itch_messages   16 u64 soup_messages
struct DayEnd {
  static constexpr RecordType kType = RecordType::DayEnd;
  std::uint64_t final_index = 0;
  std::uint64_t itch_messages = 0;  // MoldUDP64 output sequence total
  std::uint64_t soup_messages = 0;  // sum of SoupBinTCP sequenced messages over sessions
  friend bool operator==(const DayEnd&, const DayEnd&) = default;
};

[[nodiscard]] constexpr std::uint32_t payload_size(const DayStart&) noexcept { return 48; }
[[nodiscard]] constexpr std::uint32_t payload_size(const ConfigChunk& c) noexcept {
  return ConfigChunk::kHeadBytes + static_cast<std::uint32_t>(c.bytes.size());
}
[[nodiscard]] constexpr std::uint32_t payload_size(const SessionEvent&) noexcept { return 16; }
[[nodiscard]] constexpr std::uint32_t payload_size(const OuchInbound& o) noexcept {
  return OuchInbound::kHeadBytes + static_cast<std::uint32_t>(o.msg.size());
}
[[nodiscard]] constexpr std::uint32_t payload_size(const Timer&) noexcept { return 16; }
[[nodiscard]] constexpr std::uint32_t payload_size(const Admin& a) noexcept {
  return Admin::kHeadBytes + static_cast<std::uint32_t>(a.args.size());
}
[[nodiscard]] constexpr std::uint32_t payload_size(const SnapshotMark&) noexcept { return 8; }
[[nodiscard]] constexpr std::uint32_t payload_size(const EpochStart&) noexcept { return 16; }
[[nodiscard]] constexpr std::uint32_t payload_size(const DayEnd&) noexcept { return 24; }

void encode_payload(std::byte* p, const DayStart& v) noexcept;
void encode_payload(std::byte* p, const ConfigChunk& v) noexcept;
void encode_payload(std::byte* p, const SessionEvent& v) noexcept;
void encode_payload(std::byte* p, const OuchInbound& v) noexcept;
void encode_payload(std::byte* p, const Timer& v) noexcept;
void encode_payload(std::byte* p, const Admin& v) noexcept;
void encode_payload(std::byte* p, const SnapshotMark& v) noexcept;
void encode_payload(std::byte* p, const EpochStart& v) noexcept;
void encode_payload(std::byte* p, const DayEnd& v) noexcept;

[[nodiscard]] std::expected<DayStart, DecodeError> decode_day_start(const RecordView& r) noexcept;
[[nodiscard]] std::expected<ConfigChunk, DecodeError> decode_config(const RecordView& r) noexcept;
[[nodiscard]] std::expected<SessionEvent, DecodeError> decode_session_event(const RecordView& r) noexcept;
[[nodiscard]] std::expected<OuchInbound, DecodeError> decode_ouch_inbound(const RecordView& r) noexcept;
[[nodiscard]] std::expected<Timer, DecodeError> decode_timer(const RecordView& r) noexcept;
[[nodiscard]] std::expected<Admin, DecodeError> decode_admin(const RecordView& r) noexcept;
[[nodiscard]] std::expected<SnapshotMark, DecodeError> decode_snapshot_mark(const RecordView& r) noexcept;
[[nodiscard]] std::expected<EpochStart, DecodeError> decode_epoch_start(const RecordView& r) noexcept;
[[nodiscard]] std::expected<DayEnd, DecodeError> decode_day_end(const RecordView& r) noexcept;

template <class P>
concept PayloadLike = requires(const P& p, std::byte* out) {
  { P::kType } -> std::convertible_to<RecordType>;
  { payload_size(p) } -> std::same_as<std::uint32_t>;
  encode_payload(out, p);
};

// ---- Building ---------------------------------------------------------------------

// The position of a journal stream: the last real (non-Pad) record.
struct ChainState {
  std::uint64_t last_index = 0;  // 0: nothing yet (the next record is index 1)
  std::uint32_t last_crc = 0;    // content crc of the last record (next prev_crc)
  Nanos last_ts = 0;
  std::uint32_t epoch = 0;
  friend constexpr bool operator==(const ChainState&, const ChainState&) = default;
};

struct Stamp {
  std::uint64_t index = 0;
  Nanos ts_ns = 0;
  std::uint32_t epoch = 0;
  std::uint32_t prev_crc = 0;
  std::uint16_t flags = 0;
};

[[nodiscard]] constexpr std::uint32_t record_size(const PayloadLike auto& p) noexcept {
  return record_bytes_for_payload(payload_size(p));
}

// Writes header + payload + zero padding at `out` (record_size(p) bytes), seals it with
// `sealer`, and returns the content crc. The payload must fit kMaxPayloadBytes.
template <PayloadLike P>
std::uint32_t build_record(std::byte* out, const Stamp& s, const P& p, const Sealer& sealer) noexcept {
  const std::uint32_t psize = payload_size(p);
  const std::uint32_t len = record_bytes_for_payload(psize);
  RecordHeader h;
  h.len = len;
  h.index = s.index;
  h.ts_ns = s.ts_ns;
  h.epoch = s.epoch;
  h.type = static_cast<std::uint16_t>(P::kType);
  h.flags = s.flags;
  h.prev_crc = s.prev_crc;
  encode_header(out, h);
  encode_payload(out + kHeaderBytes, p);
  std::memset(out + kHeaderBytes + psize, 0, len - kHeaderBytes - psize);
  return sealer.seal(out);
}

// A Pad record of `len` bytes (>= kHeaderBytes, multiple of 8) that repeats the chain
// position `c` (06 §6). Returns nothing: pads do not move the chain.
void build_pad(std::byte* out, std::uint32_t len, const ChainState& c, const Sealer& sealer) noexcept;

// Builds consecutive records of one stream: index = last + 1, prev_crc = last content
// crc. Timestamps are supplied by the caller (the sequencer's max(last+1, now) rule
// lives in lle::seq), but are clamped to be strictly increasing here too.
class RecordBuilder {
 public:
  explicit RecordBuilder(const Sealer& sealer, ChainState start = {}) noexcept : sealer_(&sealer), chain_(start) {}

  [[nodiscard]] const ChainState& chain() const noexcept { return chain_; }
  void set_epoch(std::uint32_t e) noexcept { chain_.epoch = e; }
  void reset(ChainState c) noexcept { chain_ = c; }
  [[nodiscard]] const Sealer& sealer() const noexcept { return *sealer_; }

  // Builds the next record into `out` (at least record_size(p) bytes); returns the
  // record's bytes, or an empty span if `out` is too small or the payload too large.
  template <PayloadLike P>
  std::span<std::byte> append(std::span<std::byte> out, Nanos ts, const P& p, std::uint16_t flags = 0) noexcept {
    const std::uint32_t psize = payload_size(p);
    if (psize > kMaxPayloadBytes) return {};
    const std::uint32_t len = record_bytes_for_payload(psize);
    if (out.size() < len) return {};
    const Nanos stamped = ts > chain_.last_ts ? ts : chain_.last_ts + 1;
    const Stamp s{chain_.last_index + 1, stamped, chain_.epoch, chain_.last_crc, flags};
    const std::uint32_t c = build_record(out.data(), s, p, *sealer_);
    chain_.last_index = s.index;
    chain_.last_crc = c;
    chain_.last_ts = stamped;
    return out.first(len);
  }

 private:
  const Sealer* sealer_;
  ChainState chain_;
};

// Identity of a record ignoring the medium seal: every header field except crc32c,
// plus the payload. Used by journal_diff and tests.
[[nodiscard]] bool same_content(const RecordView& a, const RecordView& b) noexcept;

}  // namespace lle::journal

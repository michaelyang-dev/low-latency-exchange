#include "repl/wire.h"

#include <cstring>
#include <optional>
#include <type_traits>

#include "common/crc32c.h"
#include "common/endian.h"
#include "journal/record.h"

namespace lle::repl::wire {
namespace {

constexpr std::uint8_t kFlagCatchup = 1;
constexpr std::uint8_t kFlagHash = 2;
constexpr std::uint8_t kFlagRefused = 1;

constexpr std::size_t kAckBody = 40;
constexpr std::size_t kNackBody = 24;
constexpr std::size_t kHeartbeatBody = 96;
constexpr std::size_t kQueryBody = 32;
constexpr std::size_t kEpochEndBody = 64;
constexpr std::size_t kCatchupBody = 40;

bool zero(const std::byte* p, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n; ++i)
    if (p[i] != std::byte{0}) return false;
  return true;
}

std::uint8_t u8(const std::byte* p) noexcept { return static_cast<std::uint8_t>(p[0]); }
void put8(std::byte* p, std::uint8_t v) noexcept { p[0] = static_cast<std::byte>(v); }

bool valid_record_len(std::uint32_t len) noexcept {
  return len >= journal::kHeaderBytes && len <= journal::kMaxRecordBytes && len % journal::kRecordAlign == 0;
}

// ---- per-type body sizes and encoders --------------------------------------

std::size_t append_body(const Append& m) noexcept {
  return kAppendFixed + (m.has_hash ? kHashBytes : 0) + std::size_t{m.soup_count} * kSoupEntryBytes + m.records.size();
}

std::uint8_t flags_of(const Message& m) noexcept {
  return std::visit(
      [](const auto& x) -> std::uint8_t {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, Append>) {
          return static_cast<std::uint8_t>((x.catchup ? kFlagCatchup : 0) | (x.has_hash ? kFlagHash : 0));
        } else if constexpr (std::is_same_v<T, Ack> || std::is_same_v<T, Nack>) {
          return x.catchup ? kFlagCatchup : 0;
        } else if constexpr (std::is_same_v<T, EpochEnd>) {
          return x.refused ? kFlagRefused : 0;
        } else {
          return 0;
        }
      },
      m);
}

NodeId from_of(const Message& m) noexcept {
  return std::visit([](const auto& x) { return x.from; }, m);
}

std::size_t body_size(const Message& m) noexcept {
  return std::visit(
      [](const auto& x) -> std::size_t {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, Append>) return append_body(x);
        else if constexpr (std::is_same_v<T, Ack>) return kAckBody;
        else if constexpr (std::is_same_v<T, Nack>) return kNackBody;
        else if constexpr (std::is_same_v<T, Heartbeat>) return kHeartbeatBody;
        else if constexpr (std::is_same_v<T, Forward>) return kForwardFixed + x.bytes.size();
        else if constexpr (std::is_same_v<T, EpochEndQuery>) return kQueryBody;
        else if constexpr (std::is_same_v<T, EpochEnd>) return kEpochEndBody;
        else if constexpr (std::is_same_v<T, CatchupReq>) return kCatchupBody;
        else return kSnapshotFixed + x.bytes.size();
      },
      m);
}

bool well_formed(const Message& m) noexcept {
  return std::visit(
      [](const auto& x) -> bool {
        using T = std::decay_t<decltype(x)>;
        if (!witness::valid_node(x.from)) return false;
        if constexpr (std::is_same_v<T, Append>) {
          return x.soup_count <= kMaxSoup && !x.records.empty() && x.records.size() <= 0xFFFF &&
                 x.first_index != 0 && valid_record_len(x.first_len) &&
                 append_framing_ok(x.first_offset, x.first_len, x.records);
        } else if constexpr (std::is_same_v<T, Forward>) {
          if (x.kind == ForwardKind::kOuch) return x.event == 0 && x.requested_seq == 0 && !x.bytes.empty();
          return x.kind == ForwardKind::kSessionEvent && x.bytes.empty() && x.event >= 1 &&
                 x.event <= journal::kMaxSessionEventKind;
        } else if constexpr (std::is_same_v<T, Heartbeat>) {
          return x.role <= 7 && x.members < (1u << witness::kNodes) && witness::valid_node(x.primary);
        } else {
          return true;
        }
      },
      m);
}

void put_body(std::byte* b, const Append& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.first_index);
  store_le64(b + 16, m.commit_index);
  store_le64(b + 24, m.mold_watermark);
  store_le64(b + 32, m.target_inc);
  store_le32(b + 40, m.first_offset);
  store_le32(b + 44, m.first_len);
  store_le16(b + 48, static_cast<std::uint16_t>(m.records.size()));
  put8(b + 50, m.soup_count);
  std::size_t p = kAppendFixed;
  if (m.has_hash) {
    store_le64(b + p, m.hash.index);
    store_le64(b + p + 8, m.hash.hash);
    p += kHashBytes;
  }
  for (std::size_t i = 0; i < m.soup_count; ++i) {
    store_le32(b + p, m.soup[i].session_id);
    store_le64(b + p + 8, m.soup[i].next_seq);
    p += kSoupEntryBytes;
  }
  if (!m.records.empty()) std::memcpy(b + p, m.records.data(), m.records.size());
}
void put_body(std::byte* b, const Ack& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.l2_index);
  store_le64(b + 16, m.inc);
  store_le64(b + 24, m.snap_index);
  store_le64(b + 32, m.snap_offset);
}
void put_body(std::byte* b, const Nack& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.expected_index);
  store_le64(b + 16, m.inc);
}
void put_body(std::byte* b, const Heartbeat& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.last);
  store_le64(b + 16, m.commit);
  store_le64(b + 24, m.applied);
  store_le64(b + 32, m.released);
  store_le64(b + 40, m.durable);
  store_le64(b + 48, m.inc);
  store_le64(b + 56, m.build_id);
  store_le64(b + 64, m.hash.index);
  store_le64(b + 72, m.hash.hash);
  store_le64(b + 80, m.partner_inc);
  put8(b + 88, m.role);
  put8(b + 89, m.members);
  put8(b + 90, m.primary);
}
void put_body(std::byte* b, const Forward& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.inc);
  store_le64(b + 16, m.seq);
  store_le32(b + 24, m.session_id);
  store_le32(b + 28, m.account);
  store_le16(b + 32, m.instance);
  put8(b + 34, static_cast<std::uint8_t>(m.kind));
  put8(b + 35, m.event);
  store_le16(b + 36, static_cast<std::uint16_t>(m.bytes.size()));
  store_le16(b + 38, m.record_flags);
  store_le64(b + 40, m.requested_seq);
  if (!m.bytes.empty()) std::memcpy(b + kForwardFixed, m.bytes.data(), m.bytes.size());
}
void put_body(std::byte* b, const EpochEndQuery& m) noexcept {
  store_le64(b + 0, m.epoch);
  store_le64(b + 8, m.inc);
  store_le64(b + 16, m.build_id);
  store_le64(b + 24, m.query_id);
}
void put_body(std::byte* b, const EpochEnd& m) noexcept {
  store_le64(b + 0, m.query_epoch);
  store_le64(b + 8, m.end_index);
  store_le32(b + 16, m.end_crc);
  store_le32(b + 20, m.end_epoch);
  store_le64(b + 24, m.primary_epoch);
  store_le64(b + 32, m.query_id);
  store_le64(b + 40, m.tail);
  store_le64(b + 48, m.start_index);
  store_le32(b + 56, m.start_crc);
}
void put_body(std::byte* b, const CatchupReq& m) noexcept {
  store_le64(b + 0, m.from_index);
  store_le32(b + 8, m.prev_crc);
  store_le32(b + 12, m.attempt);
  store_le64(b + 16, m.inc);
  store_le64(b + 24, m.build_id);
  store_le64(b + 32, m.epoch);
}
void put_body(std::byte* b, const SnapshotChunk& m) noexcept {
  store_le64(b + 0, m.snap_index);
  store_le64(b + 8, m.total);
  store_le64(b + 16, m.offset);
  store_le64(b + 24, m.inc);
  store_le64(b + 32, m.epoch);
  store_le16(b + 40, static_cast<std::uint16_t>(m.bytes.size()));
  if (!m.bytes.empty()) std::memcpy(b + kSnapshotFixed, m.bytes.data(), m.bytes.size());
}

// ---- decoders ---------------------------------------------------------------

using Result = std::expected<Message, DecodeError>;

Result get_append(NodeId from, std::uint8_t flags, const std::byte* b, std::size_t n) {
  if ((flags & ~(kFlagCatchup | kFlagHash)) != 0) return std::unexpected(DecodeError::kFlags);
  if (n < kAppendFixed) return std::unexpected(DecodeError::kLength);
  Append m;
  m.from = from;
  m.catchup = (flags & kFlagCatchup) != 0;
  m.has_hash = (flags & kFlagHash) != 0;
  m.epoch = load_le64(b + 0);
  m.first_index = load_le64(b + 8);
  m.commit_index = load_le64(b + 16);
  m.mold_watermark = load_le64(b + 24);
  m.target_inc = load_le64(b + 32);
  m.first_offset = load_le32(b + 40);
  m.first_len = load_le32(b + 44);
  const std::uint16_t rec = load_le16(b + 48);
  m.soup_count = u8(b + 50);
  if (!zero(b + 51, 5)) return std::unexpected(DecodeError::kPadding);
  if (m.soup_count > kMaxSoup) return std::unexpected(DecodeError::kField);
  const std::size_t want = kAppendFixed + (m.has_hash ? kHashBytes : 0) + std::size_t{m.soup_count} * kSoupEntryBytes + rec;
  if (want != n) return std::unexpected(DecodeError::kLength);
  std::size_t p = kAppendFixed;
  if (m.has_hash) {
    m.hash.index = load_le64(b + p);
    m.hash.hash = load_le64(b + p + 8);
    p += kHashBytes;
  }
  for (std::size_t i = 0; i < m.soup_count; ++i) {
    if (!zero(b + p + 4, 4)) return std::unexpected(DecodeError::kPadding);
    m.soup[i].session_id = load_le32(b + p);
    m.soup[i].next_seq = load_le64(b + p + 8);
    p += kSoupEntryBytes;
  }
  m.records = std::span<const std::byte>(b + p, rec);
  if (rec == 0 || m.first_index == 0 || !valid_record_len(m.first_len) ||
      !append_framing_ok(m.first_offset, m.first_len, m.records)) {
    return std::unexpected(DecodeError::kField);
  }
  return m;
}

Result get_body(MsgType t, NodeId from, std::uint8_t flags, const std::byte* b, std::size_t n) {
  const auto fixed = [&](std::size_t want, std::uint8_t allowed) -> std::optional<DecodeError> {
    if ((flags & ~allowed) != 0) return DecodeError::kFlags;
    if (n != want) return DecodeError::kLength;
    return std::nullopt;
  };
  switch (t) {
    case MsgType::kAppend:
      return get_append(from, flags, b, n);
    case MsgType::kAck: {
      if (const auto e = fixed(kAckBody, kFlagCatchup)) return std::unexpected(*e);
      return Ack{from,           (flags & kFlagCatchup) != 0, load_le64(b), load_le64(b + 8), load_le64(b + 16),
                 load_le64(b + 24), load_le64(b + 32)};
    }
    case MsgType::kNack: {
      if (const auto e = fixed(kNackBody, kFlagCatchup)) return std::unexpected(*e);
      return Nack{from, (flags & kFlagCatchup) != 0, load_le64(b), load_le64(b + 8), load_le64(b + 16)};
    }
    case MsgType::kHeartbeat: {
      if (const auto e = fixed(kHeartbeatBody, 0)) return std::unexpected(*e);
      if (!zero(b + 91, 5)) return std::unexpected(DecodeError::kPadding);
      Heartbeat m;
      m.from = from;
      m.epoch = load_le64(b + 0);
      m.last = load_le64(b + 8);
      m.commit = load_le64(b + 16);
      m.applied = load_le64(b + 24);
      m.released = load_le64(b + 32);
      m.durable = load_le64(b + 40);
      m.inc = load_le64(b + 48);
      m.build_id = load_le64(b + 56);
      m.hash.index = load_le64(b + 64);
      m.hash.hash = load_le64(b + 72);
      m.partner_inc = load_le64(b + 80);
      m.role = u8(b + 88);
      m.members = u8(b + 89);
      m.primary = u8(b + 90);
      if (m.role > 7 || m.members >= (1u << witness::kNodes) || !witness::valid_node(m.primary))
        return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kForward: {
      if (flags != 0) return std::unexpected(DecodeError::kFlags);
      if (n < kForwardFixed) return std::unexpected(DecodeError::kLength);
      const std::uint16_t len = load_le16(b + 36);
      if (n != kForwardFixed + len) return std::unexpected(DecodeError::kLength);
      Forward m;
      m.from = from;
      m.epoch = load_le64(b + 0);
      m.inc = load_le64(b + 8);
      m.seq = load_le64(b + 16);
      m.session_id = load_le32(b + 24);
      m.account = load_le32(b + 28);
      m.instance = load_le16(b + 32);
      const std::uint8_t kind = u8(b + 34);
      m.event = u8(b + 35);
      m.requested_seq = load_le64(b + 40);
      m.record_flags = load_le16(b + 38);
      m.bytes = std::span<const std::byte>(b + kForwardFixed, len);
      if (kind == static_cast<std::uint8_t>(ForwardKind::kOuch)) {
        m.kind = ForwardKind::kOuch;
        if (m.event != 0 || m.requested_seq != 0 || len == 0 ||
            (m.record_flags & ~journal::kFlagMalformedInput) != 0)
          return std::unexpected(DecodeError::kField);
      } else if (kind == static_cast<std::uint8_t>(ForwardKind::kSessionEvent)) {
        m.kind = ForwardKind::kSessionEvent;
        if (len != 0 || m.event < 1 || m.event > journal::kMaxSessionEventKind || m.record_flags != 0)
          return std::unexpected(DecodeError::kField);
      } else {
        return std::unexpected(DecodeError::kField);
      }
      return m;
    }
    case MsgType::kEpochEndQuery: {
      if (const auto e = fixed(kQueryBody, 0)) return std::unexpected(*e);
      return EpochEndQuery{from, load_le64(b), load_le64(b + 8), load_le64(b + 16), load_le64(b + 24)};
    }
    case MsgType::kEpochEnd: {
      if (const auto e = fixed(kEpochEndBody, kFlagRefused)) return std::unexpected(*e);
      if (!zero(b + 60, 4)) return std::unexpected(DecodeError::kPadding);
      return EpochEnd{from,
                      (flags & kFlagRefused) != 0,
                      load_le64(b),
                      load_le64(b + 8),
                      load_le32(b + 16),
                      load_le32(b + 20),
                      load_le64(b + 24),
                      load_le64(b + 32),
                      load_le64(b + 40),
                      load_le64(b + 48),
                      load_le32(b + 56)};
    }
    case MsgType::kCatchupReq: {
      if (const auto e = fixed(kCatchupBody, 0)) return std::unexpected(*e);
      return CatchupReq{from,           load_le64(b),      load_le32(b + 8), load_le32(b + 12),
                        load_le64(b + 16), load_le64(b + 24), load_le64(b + 32)};
    }
    case MsgType::kSnapshotChunk: {
      if (flags != 0) return std::unexpected(DecodeError::kFlags);
      if (n < kSnapshotFixed) return std::unexpected(DecodeError::kLength);
      const std::uint16_t len = load_le16(b + 40);
      if (n != kSnapshotFixed + len) return std::unexpected(DecodeError::kLength);
      if (!zero(b + 42, 6)) return std::unexpected(DecodeError::kPadding);
      SnapshotChunk m;
      m.from = from;
      m.snap_index = load_le64(b + 0);
      m.total = load_le64(b + 8);
      m.offset = load_le64(b + 16);
      m.inc = load_le64(b + 24);
      m.epoch = load_le64(b + 32);
      m.bytes = std::span<const std::byte>(b + kSnapshotFixed, len);
      if (len == 0 || m.offset > m.total || m.total - m.offset < len) return std::unexpected(DecodeError::kField);
      return m;
    }
  }
  return std::unexpected(DecodeError::kType);
}

}  // namespace

bool append_framing_ok(std::uint32_t first_offset, std::uint32_t first_len, std::span<const std::byte> records) noexcept {
  if (records.empty() || first_offset >= first_len) return false;
  const std::size_t n = records.size();
  if (first_offset != 0 || n < first_len) {
    // One fragment of record first_index.
    return std::size_t{first_offset} + n <= first_len;
  }
  // Whole records from a boundary.
  std::size_t off = 0;
  bool first = true;
  while (off < n) {
    if (n - off < journal::kHeaderBytes) return false;
    const std::uint32_t len = load_le32(records.data() + off + journal::hdr::kLen);
    if (!valid_record_len(len) || (first && len != first_len) || len > n - off) return false;
    off += len;
    first = false;
  }
  return true;
}

MsgType type_of(const Message& m) noexcept { return static_cast<MsgType>(m.index() + 1); }

const char* to_string(MsgType t) noexcept {
  switch (t) {
    case MsgType::kAppend: return "APPEND";
    case MsgType::kAck: return "ACK";
    case MsgType::kNack: return "NACK";
    case MsgType::kHeartbeat: return "HEARTBEAT";
    case MsgType::kForward: return "FORWARD";
    case MsgType::kEpochEndQuery: return "EPOCH_END_QUERY";
    case MsgType::kEpochEnd: return "EPOCH_END";
    case MsgType::kCatchupReq: return "CATCHUP_REQ";
    case MsgType::kSnapshotChunk: return "SNAPSHOT_CHUNK";
  }
  return "?";
}

const char* to_string(DecodeError e) noexcept {
  switch (e) {
    case DecodeError::kShort: return "short";
    case DecodeError::kMagic: return "magic";
    case DecodeError::kVersion: return "version";
    case DecodeError::kType: return "type";
    case DecodeError::kLength: return "length";
    case DecodeError::kCrc: return "crc";
    case DecodeError::kPadding: return "padding";
    case DecodeError::kField: return "field";
    case DecodeError::kFlags: return "flags";
  }
  return "?";
}

std::size_t encode(const Message& m, std::span<std::byte> out) noexcept {
  if (!well_formed(m)) return 0;
  const std::size_t n = body_size(m);
  if (n > kMaxBody || out.size() < kHeaderBytes + n + kTrailerBytes) return 0;
  std::byte* p = out.data();
  std::memset(p, 0, kHeaderBytes + n);
  store_le32(p, kWireMagic);
  put8(p + 4, kWireVersion);
  put8(p + 5, static_cast<std::uint8_t>(type_of(m)));
  put8(p + 6, from_of(m));
  put8(p + 7, flags_of(m));
  store_le16(p + 8, static_cast<std::uint16_t>(n));
  std::visit([&](const auto& x) { put_body(p + kHeaderBytes, x); }, m);
  store_le32(p + kHeaderBytes + n, crc32c(p, kHeaderBytes + n));
  return kHeaderBytes + n + kTrailerBytes;
}

std::expected<Message, DecodeError> decode(std::span<const std::byte> d) noexcept {
  if (d.size() < kHeaderBytes + kTrailerBytes) return std::unexpected(DecodeError::kShort);
  const std::byte* p = d.data();
  if (load_le32(p) != kWireMagic) return std::unexpected(DecodeError::kMagic);
  if (u8(p + 4) != kWireVersion) return std::unexpected(DecodeError::kVersion);
  const std::uint8_t traw = u8(p + 5);
  if (traw < 1 || traw > kMaxMsgType) return std::unexpected(DecodeError::kType);
  const std::size_t n = load_le16(p + 8);
  if (n > kMaxBody || d.size() != kHeaderBytes + n + kTrailerBytes) return std::unexpected(DecodeError::kLength);
  if (load_le32(p + kHeaderBytes + n) != crc32c(p, kHeaderBytes + n)) return std::unexpected(DecodeError::kCrc);
  if (!zero(p + 10, 2)) return std::unexpected(DecodeError::kPadding);
  const NodeId from = u8(p + 6);
  if (!witness::valid_node(from)) return std::unexpected(DecodeError::kField);
  return get_body(static_cast<MsgType>(traw), from, u8(p + 7), p + kHeaderBytes, n);
}

}  // namespace lle::repl::wire

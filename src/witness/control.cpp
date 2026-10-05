#include "witness/control.h"

#include <cstring>
#include <type_traits>

#include "common/crc32c.h"
#include "common/endian.h"

namespace lle::witness {
namespace {

constexpr std::size_t kHeader = 8;
constexpr std::size_t kTrailer = 4;

constexpr std::size_t body_len(MsgType t) noexcept {
  switch (t) {
    case MsgType::kHeartbeat: return 24;
    case MsgType::kPromote: return 32;
    case MsgType::kSolo: return 24;
    case MsgType::kJoin: return 40;
    case MsgType::kResume: return 24;
    case MsgType::kGrant: return 32;
    case MsgType::kReject: return 32;
  }
  return 0;
}

constexpr bool valid_role(std::uint8_t r) noexcept { return r >= 1 && r <= 5; }
constexpr bool valid_request(std::uint8_t t) noexcept { return t >= 2 && t <= 5; }
constexpr bool valid_reason(std::uint8_t r) noexcept { return r >= 1 && r <= 8; }

bool zero(const std::byte* p, std::size_t n) noexcept {
  for (std::size_t i = 0; i < n; ++i)
    if (p[i] != std::byte{0}) return false;
  return true;
}

std::uint8_t u8(const std::byte* p) noexcept { return static_cast<std::uint8_t>(p[0]); }
void put8(std::byte* p, std::uint8_t v) noexcept { p[0] = static_cast<std::byte>(v); }

void put_body(std::byte* b, const Heartbeat& m) noexcept {
  put8(b + 0, m.node);
  put8(b + 1, static_cast<std::uint8_t>(m.role));
  store_le64(b + 8, m.incarnation);
  store_le64(b + 16, m.epoch);
}
void put_body(std::byte* b, const Promote& m) noexcept {
  store_le64(b + 0, m.from_epoch);
  put8(b + 8, m.candidate);
  store_le64(b + 16, m.incarnation);
  store_le64(b + 24, m.last_index);
}
void put_body(std::byte* b, const Solo& m) noexcept {
  store_le64(b + 0, m.from_epoch);
  put8(b + 8, m.primary);
  store_le64(b + 16, m.incarnation);
}
void put_body(std::byte* b, const Join& m) noexcept {
  store_le64(b + 0, m.from_epoch);
  put8(b + 8, m.primary);
  put8(b + 9, m.node);
  store_le64(b + 16, m.primary_incarnation);
  store_le64(b + 24, m.node_incarnation);
  store_le64(b + 32, m.last_index);
}
void put_body(std::byte* b, const Resume& m) noexcept {
  store_le64(b + 0, m.from_epoch);
  put8(b + 8, m.node);
  store_le64(b + 16, m.incarnation);
}
void put_body(std::byte* b, const Grant& m) noexcept {
  store_le64(b + 0, m.epoch);
  put8(b + 8, m.primary);
  put8(b + 9, m.members);
  put8(b + 10, static_cast<std::uint8_t>(m.request));
  put8(b + 11, m.to_node);
  store_le64(b + 16, m.incarnation);
  store_le64(b + 24, m.from_epoch);
}
void put_body(std::byte* b, const Reject& m) noexcept {
  store_le64(b + 0, m.epoch);
  put8(b + 8, m.primary);
  put8(b + 9, m.members);
  put8(b + 10, static_cast<std::uint8_t>(m.request));
  put8(b + 11, static_cast<std::uint8_t>(m.reason));
  put8(b + 12, m.to_node);
  store_le64(b + 16, m.incarnation);
  store_le64(b + 24, m.from_epoch);
}

// Each body decoder checks its padding and field ranges.
std::expected<Message, DecodeError> get_body(MsgType t, const std::byte* b) noexcept {
  switch (t) {
    case MsgType::kHeartbeat: {
      if (!zero(b + 2, 6)) return std::unexpected(DecodeError::kPadding);
      Heartbeat m{u8(b), static_cast<Role>(u8(b + 1)), load_le64(b + 8), load_le64(b + 16)};
      if (!valid_node(m.node) || !valid_role(u8(b + 1))) return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kPromote: {
      if (!zero(b + 9, 7)) return std::unexpected(DecodeError::kPadding);
      Promote m{load_le64(b), u8(b + 8), load_le64(b + 16), load_le64(b + 24)};
      if (!valid_node(m.candidate)) return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kSolo: {
      if (!zero(b + 9, 7)) return std::unexpected(DecodeError::kPadding);
      Solo m{load_le64(b), u8(b + 8), load_le64(b + 16)};
      if (!valid_node(m.primary)) return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kJoin: {
      if (!zero(b + 10, 6)) return std::unexpected(DecodeError::kPadding);
      Join m{load_le64(b), u8(b + 8), u8(b + 9), load_le64(b + 16), load_le64(b + 24), load_le64(b + 32)};
      if (!valid_node(m.primary) || !valid_node(m.node) || m.primary == m.node)
        return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kResume: {
      if (!zero(b + 9, 7)) return std::unexpected(DecodeError::kPadding);
      Resume m{load_le64(b), u8(b + 8), load_le64(b + 16)};
      if (!valid_node(m.node)) return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kGrant: {
      if (!zero(b + 12, 4)) return std::unexpected(DecodeError::kPadding);
      Grant m{load_le64(b),   u8(b + 8), u8(b + 9), static_cast<MsgType>(u8(b + 10)), u8(b + 11),
              load_le64(b + 16), load_le64(b + 24)};
      if (!valid_node(m.primary) || !valid_members(m.members) || !is_member(m.members, m.primary) ||
          !valid_request(u8(b + 10)) || !valid_node(m.to_node))
        return std::unexpected(DecodeError::kField);
      return m;
    }
    case MsgType::kReject: {
      if (!zero(b + 13, 3)) return std::unexpected(DecodeError::kPadding);
      Reject m{load_le64(b),
               u8(b + 8),
               u8(b + 9),
               static_cast<MsgType>(u8(b + 10)),
               static_cast<RejectReason>(u8(b + 11)),
               u8(b + 12),
               load_le64(b + 16),
               load_le64(b + 24)};
      if (!valid_node(m.primary) || !valid_members(m.members) || !is_member(m.members, m.primary) ||
          !valid_request(u8(b + 10)) || !valid_reason(u8(b + 11)) || !valid_node(m.to_node))
        return std::unexpected(DecodeError::kField);
      return m;
    }
  }
  return std::unexpected(DecodeError::kType);
}

}  // namespace

MsgType type_of(const Message& m) noexcept {
  return std::visit(
      [](const auto& x) -> MsgType {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, Heartbeat>) return MsgType::kHeartbeat;
        else if constexpr (std::is_same_v<T, Promote>) return MsgType::kPromote;
        else if constexpr (std::is_same_v<T, Solo>) return MsgType::kSolo;
        else if constexpr (std::is_same_v<T, Join>) return MsgType::kJoin;
        else if constexpr (std::is_same_v<T, Resume>) return MsgType::kResume;
        else if constexpr (std::is_same_v<T, Grant>) return MsgType::kGrant;
        else return MsgType::kReject;
      },
      m);
}

const char* to_string(MsgType t) noexcept {
  switch (t) {
    case MsgType::kHeartbeat: return "HEARTBEAT_W";
    case MsgType::kPromote: return "PROMOTE";
    case MsgType::kSolo: return "SOLO";
    case MsgType::kJoin: return "JOIN";
    case MsgType::kResume: return "RESUME";
    case MsgType::kGrant: return "GRANT";
    case MsgType::kReject: return "REJECT";
  }
  return "?";
}

const char* to_string(RejectReason r) noexcept {
  switch (r) {
    case RejectReason::kStaleEpoch: return "stale_epoch";
    case RejectReason::kNotMember: return "not_member";
    case RejectReason::kIsPrimary: return "is_primary";
    case RejectReason::kWrongIncarnation: return "wrong_incarnation";
    case RejectReason::kPrimaryAlive: return "primary_alive";
    case RejectReason::kNotPrimary: return "not_primary";
    case RejectReason::kAlreadyMember: return "already_member";
    case RejectReason::kNotSoloOfRecord: return "not_solo_of_record";
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
  }
  return "?";
}

Encoded encode(const Message& m) noexcept {
  Encoded e;
  const MsgType t = type_of(m);
  const std::size_t n = body_len(t);
  std::byte* p = e.bytes.data();
  store_le32(p, kControlMagic);
  put8(p + 4, kControlVersion);
  put8(p + 5, static_cast<std::uint8_t>(t));
  store_le16(p + 6, static_cast<std::uint16_t>(n));
  std::visit([&](const auto& x) { put_body(p + kHeader, x); }, m);
  store_le32(p + kHeader + n, crc32c(p, kHeader + n));
  e.size = kHeader + n + kTrailer;
  return e;
}

std::expected<Message, DecodeError> decode(std::span<const std::byte> d) noexcept {
  if (d.size() < kHeader + kTrailer) return std::unexpected(DecodeError::kShort);
  const std::byte* p = d.data();
  if (load_le32(p) != kControlMagic) return std::unexpected(DecodeError::kMagic);
  if (u8(p + 4) != kControlVersion) return std::unexpected(DecodeError::kVersion);
  const std::uint8_t traw = u8(p + 5);
  if (traw < 1 || traw > 7) return std::unexpected(DecodeError::kType);
  const auto t = static_cast<MsgType>(traw);
  const std::size_t n = body_len(t);
  if (load_le16(p + 6) != n || d.size() != kHeader + n + kTrailer) return std::unexpected(DecodeError::kLength);
  if (load_le32(p + kHeader + n) != crc32c(p, kHeader + n)) return std::unexpected(DecodeError::kCrc);
  return get_body(t, p + kHeader);
}

}  // namespace lle::witness

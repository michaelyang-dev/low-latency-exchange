#pragma once
// Control-plane messages between the data nodes and the witness (10 §2).
//
// Internal protocol between our own processes, so little-endian and fixed size
// per type. Every datagram:
//
//   0   u32  magic "LWC1"
//   4   u8   version (1)
//   5   u8   type (MsgType)
//   6   u16  body length (fixed per type)
//   8   ...  body (all padding bytes zero)
//   8+n u32  CRC32C over bytes [0, 8+n)
//
// The decoder accepts only the canonical form: exact length, known type, valid
// node ids and member sets, zero padding, correct CRC.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <variant>

namespace lle::witness {

inline constexpr std::uint32_t kControlMagic = 0x3143'574Cu;  // "LWC1" little-endian
inline constexpr std::uint8_t kControlVersion = 1;
inline constexpr std::size_t kNodes = 2;     // data nodes A (0) and B (1)
inline constexpr std::size_t kMaxDatagram = 64;

using NodeId = std::uint8_t;
using Members = std::uint8_t;  // bit n set: node n is a member
[[nodiscard]] constexpr Members member_bit(NodeId n) noexcept { return static_cast<Members>(1u << n); }
[[nodiscard]] constexpr bool is_member(Members m, NodeId n) noexcept { return (m & member_bit(n)) != 0; }
[[nodiscard]] constexpr bool valid_node(NodeId n) noexcept { return n < kNodes; }
[[nodiscard]] constexpr bool valid_members(Members m) noexcept { return m != 0 && m < (1u << kNodes); }

enum class MsgType : std::uint8_t {
  kHeartbeat = 1,  // HEARTBEAT_W
  kPromote = 2,
  kSolo = 3,
  kJoin = 4,
  kResume = 5,
  kGrant = 6,
  kReject = 7,
};

enum class Role : std::uint8_t { kPrimary = 1, kSoloPrimary = 2, kBackup = 3, kCandidate = 4, kRecovering = 5 };

enum class RejectReason : std::uint8_t {
  kStaleEpoch = 1,         // from_epoch != W.epoch
  kNotMember = 2,          // PROMOTE from a node outside W.members
  kIsPrimary = 3,          // PROMOTE from W.primary itself
  kWrongIncarnation = 4,   // incarnation != W.inc[node] (or not newer, for RESUME)
  kPrimaryAlive = 5,       // tie-break: W still hears W.primary's current incarnation
  kNotPrimary = 6,         // SOLO / JOIN / RESUME from a node that is not W.primary
  kAlreadyMember = 7,      // JOIN for a node already in W.members
  kNotSoloOfRecord = 8,    // RESUME while W.members != {node}
};

struct Heartbeat {
  NodeId node = 0;
  Role role = Role::kBackup;
  std::uint64_t incarnation = 0;
  std::uint64_t epoch = 0;
  friend bool operator==(const Heartbeat&, const Heartbeat&) = default;
};

struct Promote {
  std::uint64_t from_epoch = 0;
  NodeId candidate = 0;
  std::uint64_t incarnation = 0;
  std::uint64_t last_index = 0;
  friend bool operator==(const Promote&, const Promote&) = default;
};

struct Solo {
  std::uint64_t from_epoch = 0;
  NodeId primary = 0;
  std::uint64_t incarnation = 0;
  friend bool operator==(const Solo&, const Solo&) = default;
};

// JOIN is sent by the solo primary once the joiner has caught up to zero lag
// with release paused (10 §5): it carries both incarnations, and W records the
// joiner's.
struct Join {
  std::uint64_t from_epoch = 0;
  NodeId primary = 0;
  NodeId node = 0;
  std::uint64_t primary_incarnation = 0;
  std::uint64_t node_incarnation = 0;
  std::uint64_t last_index = 0;
  friend bool operator==(const Join&, const Join&) = default;
};

struct Resume {
  std::uint64_t from_epoch = 0;
  NodeId node = 0;
  std::uint64_t incarnation = 0;
  friend bool operator==(const Resume&, const Resume&) = default;
};

// GRANT: the new configuration, addressed to the requester's incarnation. A
// node acts on it only if `incarnation` equals its own (10 §2).
struct Grant {
  std::uint64_t epoch = 0;
  NodeId primary = 0;
  Members members = 0;
  MsgType request = MsgType::kPromote;
  NodeId to_node = 0;
  std::uint64_t incarnation = 0;
  std::uint64_t from_epoch = 0;
  friend bool operator==(const Grant&, const Grant&) = default;
};

// REJECT: the reason plus the witness's current configuration.
struct Reject {
  std::uint64_t epoch = 0;
  NodeId primary = 0;
  Members members = 0;
  MsgType request = MsgType::kPromote;
  RejectReason reason = RejectReason::kStaleEpoch;
  NodeId to_node = 0;
  std::uint64_t incarnation = 0;
  std::uint64_t from_epoch = 0;
  friend bool operator==(const Reject&, const Reject&) = default;
};

using Message = std::variant<Heartbeat, Promote, Solo, Join, Resume, Grant, Reject>;

[[nodiscard]] MsgType type_of(const Message& m) noexcept;
[[nodiscard]] const char* to_string(MsgType t) noexcept;
[[nodiscard]] const char* to_string(RejectReason r) noexcept;

enum class DecodeError : std::uint8_t { kShort, kMagic, kVersion, kType, kLength, kCrc, kPadding, kField };
[[nodiscard]] const char* to_string(DecodeError e) noexcept;

struct Encoded {
  std::array<std::byte, kMaxDatagram> bytes{};
  std::size_t size = 0;
  [[nodiscard]] std::span<const std::byte> span() const noexcept { return {bytes.data(), size}; }
};

[[nodiscard]] Encoded encode(const Message& m) noexcept;
[[nodiscard]] std::expected<Message, DecodeError> decode(std::span<const std::byte> datagram) noexcept;

}  // namespace lle::witness

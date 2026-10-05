#pragma once
// TotalView-ITCH 5.0 codec (03-protocols §3), generated from the X-macro tables
// itch50_layouts.def and itch50_enums.def.
//
// For each of the 23 message types the table expands into:
//   struct <Name>              decoded value (header + body fields), used to encode;
//   class  <Name>View          zero-copy view; every field is a fixed-offset load;
//   encode(span, const Name&)  writes exactly Name::kLen bytes (0 if `out` is short);
//   encode_unchecked(p, m)     same without the size check (hot path);
// plus kMsgLen[256], message_name(), visit() (switch dispatch to the typed view)
// and decode() returning a MessageView.
//
// Wire conventions (spec "Data Types"): big-endian unsigned integers, Alpha
// fields left-justified and space-padded, Price(4) = u32 with 4 implied
// decimals (lle::PxE4), Price(8) = u64 with 8 implied decimals (PxE8), and a
// 48-bit timestamp in ns since midnight. No allocation, no exceptions.
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "common/assert.h"
#include "common/types.h"
#include "proto/itch50/field_codec.h"

namespace lle::itch50 {

inline constexpr std::size_t kHeaderLen = 11;  // type(1) locate(2) tracking(2) timestamp(6)
inline constexpr std::size_t kMinMsgLen = 12;
inline constexpr std::size_t kMaxMsgLen = 50;
inline constexpr std::uint64_t kMaxTimestamp = 86'400ull * 1'000'000'000ull;  // exclusive: one day in ns

// ---------------------------------------------------------------------------
// Enumerations (tolerant: char-backed, every byte representable)
// ---------------------------------------------------------------------------
#define ITCH_ENUM(Name) enum class Name : char {
#define ITCH_VALUE(Name, E, c) E = c,
#define ITCH_ENUM_END(Name) \
  }                         \
  ;
#include "proto/itch50/itch50_enums.def"

// True iff the byte is in the spec's published value set.
#define ITCH_ENUM(Name)                                  \
  [[nodiscard]] constexpr bool is_valid(Name v) noexcept { \
    switch (v) {
#define ITCH_VALUE(Name, E, c) case Name::E:
#define ITCH_ENUM_END(Name) \
  return true;              \
  default:                  \
    return false;           \
    }                       \
    }
#include "proto/itch50/itch50_enums.def"

#define ITCH_ENUM(Name)                                             \
  [[nodiscard]] constexpr std::string_view to_string(Name v) noexcept { \
    switch (v) {
#define ITCH_VALUE(Name, E, c) \
  case Name::E:                \
    return #E;
#define ITCH_ENUM_END(Name) \
  default:                  \
    return "?";             \
    }                       \
    }
#include "proto/itch50/itch50_enums.def"

[[nodiscard]] constexpr bool is_valid(Side s) noexcept { return s == Side::Buy || s == Side::Sell; }
[[nodiscard]] constexpr std::string_view to_string(Side s) noexcept {
  return s == Side::Buy ? "Buy" : (s == Side::Sell ? "Sell" : "?");
}

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
#define ITCH_MSG(T, Name, L) \
  struct Name;               \
  class Name##View;
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"

// ---------------------------------------------------------------------------
// Common header view (offsets 0..10 of every message)
// ---------------------------------------------------------------------------
class MessageHeaderView {
 public:
  explicit constexpr MessageHeaderView(const std::byte* p) noexcept : p_(p) {}

  [[nodiscard]] char message_type() const noexcept { return static_cast<char>(p_[0]); }
#define LLE_ITCH_HDR_GETTER(f, off, len, K, E)                                \
  [[nodiscard]] FieldCodec<Kind::K, len, E>::value_type f() const noexcept { \
    return FieldCodec<Kind::K, len, E>::load(p_ + (off));                    \
  }
  LLE_ITCH50_HEADER_FIELDS(LLE_ITCH_HDR_GETTER)
#undef LLE_ITCH_HDR_GETTER
  [[nodiscard]] const std::byte* data() const noexcept { return p_; }

 protected:
  const std::byte* p_;
};

// ---------------------------------------------------------------------------
// Value structs
// ---------------------------------------------------------------------------
#define LLE_ITCH_HDR_MEMBER(f, off, len, K, E) FieldCodec<Kind::K, len, E>::value_type f{};
#define ITCH_MSG(T, Name, L)                 \
  struct Name {                              \
    using View = Name##View;                 \
    static constexpr char kType = T;         \
    static constexpr std::size_t kLen = L;   \
    LLE_ITCH50_HEADER_FIELDS(LLE_ITCH_HDR_MEMBER)
#define ITCH_FIELD(Name, f, off, len, K, E) FieldCodec<Kind::K, len, E>::value_type f{};
#define ITCH_END(Name)                                                   \
  friend constexpr bool operator==(const Name&, const Name&) = default; \
  }                                                                      \
  ;
#include "proto/itch50/itch50_layouts.def"
#undef LLE_ITCH_HDR_MEMBER

// ---------------------------------------------------------------------------
// Zero-copy views
// ---------------------------------------------------------------------------
#define ITCH_MSG(T, Name, L)                                                      \
  class Name##View : public MessageHeaderView {                                   \
   public:                                                                        \
    using Value = Name;                                                           \
    static constexpr char kType = T;                                              \
    static constexpr std::size_t kLen = L;                                        \
    using MessageHeaderView::MessageHeaderView;                                   \
    [[nodiscard]] std::span<const std::byte, L> bytes() const noexcept {          \
      return std::span<const std::byte, L>(p_, L);                                \
    }                                                                             \
    [[nodiscard]] Name to_struct() const noexcept;
#define ITCH_FIELD(Name, f, off, len, K, E)                                   \
  [[nodiscard]] FieldCodec<Kind::K, len, E>::value_type f() const noexcept { \
    return FieldCodec<Kind::K, len, E>::load(p_ + (off));                    \
  }
#define ITCH_END(Name) \
  }                    \
  ;
#include "proto/itch50/itch50_layouts.def"

#define LLE_ITCH_HDR_COPY(f, off, len, K, E) m.f = f();
#define ITCH_MSG(T, Name, L)                            \
  inline Name Name##View::to_struct() const noexcept { \
    Name m;                                             \
    LLE_ITCH50_HEADER_FIELDS(LLE_ITCH_HDR_COPY)
#define ITCH_FIELD(Name, f, off, len, K, E) m.f = f();
#define ITCH_END(Name) \
  return m;            \
  }
#include "proto/itch50/itch50_layouts.def"
#undef LLE_ITCH_HDR_COPY

// ---------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------
#define LLE_ITCH_HDR_STORE(f, off, len, K, E) FieldCodec<Kind::K, len, E>::store(p + (off), m.f);
#define ITCH_MSG(T, Name, L)                                             \
  inline void encode_unchecked(std::byte* p, const Name& m) noexcept { \
    p[0] = static_cast<std::byte>(T);                                   \
    LLE_ITCH50_HEADER_FIELDS(LLE_ITCH_HDR_STORE)
#define ITCH_FIELD(Name, f, off, len, K, E) FieldCodec<Kind::K, len, E>::store(p + (off), m.f);
#define ITCH_END(Name) }
#include "proto/itch50/itch50_layouts.def"
#undef LLE_ITCH_HDR_STORE

// Writes the message into `out`; returns the bytes written (Name::kLen) or 0 if
// `out` is too small.
#define ITCH_MSG(T, Name, L)                                                             \
  inline std::size_t encode(std::span<std::byte> out, const Name& m) noexcept {         \
    if (out.size() < (L)) [[unlikely]]                                                   \
      return 0;                                                                          \
    encode_unchecked(out.data(), m);                                                     \
    return (L);                                                                          \
  }
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"

// ---------------------------------------------------------------------------
// Layout checks: fields tile every message; totals equal the spec.
// ---------------------------------------------------------------------------
namespace detail {
#define LLE_ITCH_HDR_SPAN(f, off, len, K, E) FieldSpan{off, len},
inline constexpr FieldSpan kHeaderSpans[] = {LLE_ITCH50_HEADER_FIELDS(LLE_ITCH_HDR_SPAN)};
#undef LLE_ITCH_HDR_SPAN
static_assert(tiles(kHeaderSpans, 1, kHeaderLen), "ITCH 5.0 header fields must tile [1, 11)");

#define ITCH_MSG(T, Name, L) inline constexpr FieldSpan k##Name##Spans[] = {
#define ITCH_FIELD(Name, f, off, len, K, E) FieldSpan{off, len},
#define ITCH_END(Name) \
  }                    \
  ;
#include "proto/itch50/itch50_layouts.def"

#define ITCH_MSG(T, Name, L)                                                               \
  static_assert(tiles(k##Name##Spans, kHeaderLen, L), "ITCH 5.0 " #Name                   \
                                                      ": body fields must tile [11, len)"); \
  static_assert((L) >= kMinMsgLen && (L) <= kMaxMsgLen);
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"

constexpr std::array<std::uint8_t, 256> make_msg_len_table() noexcept {
  std::array<std::uint8_t, 256> t{};
#define ITCH_MSG(T, Name, L) t[static_cast<unsigned char>(T)] = (L);
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
  return t;
}
}  // namespace detail

// Message length by type byte; 0 for types ITCH 5.0 does not define.
inline constexpr std::array<std::uint8_t, 256> kMsgLen = detail::make_msg_len_table();

// All defined type bytes, in spec order.
inline constexpr char kMessageTypes[] = {
#define ITCH_MSG(T, Name, L) T,
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
};
inline constexpr std::size_t kNumMessageTypes = sizeof(kMessageTypes);

// Second, independent transcription of the spec totals (R1a Q3 "Len").
static_assert(kNumMessageTypes == 23);
static_assert(SystemEvent::kLen == 12 && StockDirectory::kLen == 39 && StockTradingAction::kLen == 25);
static_assert(RegShoRestriction::kLen == 20 && MarketParticipantPosition::kLen == 26 && MwcbDeclineLevel::kLen == 35);
static_assert(MwcbStatus::kLen == 12 && IpoQuotingPeriodUpdate::kLen == 28 && LuldAuctionCollar::kLen == 35);
static_assert(OperationalHalt::kLen == 21 && AddOrder::kLen == 36 && AddOrderMpid::kLen == 40);
static_assert(OrderExecuted::kLen == 31 && OrderExecutedWithPrice::kLen == 36 && OrderCancel::kLen == 23);
static_assert(OrderDelete::kLen == 19 && OrderReplace::kLen == 35 && Trade::kLen == 44);
static_assert(CrossTrade::kLen == 40 && BrokenTrade::kLen == 19 && Noii::kLen == 50);
static_assert(RetailInterest::kLen == 20 && DlcrPriceDiscovery::kLen == 48);
static_assert(kMsgLen['S'] == 12 && kMsgLen['R'] == 39 && kMsgLen['H'] == 25 && kMsgLen['Y'] == 20);
static_assert(kMsgLen['L'] == 26 && kMsgLen['V'] == 35 && kMsgLen['W'] == 12 && kMsgLen['K'] == 28);
static_assert(kMsgLen['J'] == 35 && kMsgLen['h'] == 21 && kMsgLen['A'] == 36 && kMsgLen['F'] == 40);
static_assert(kMsgLen['E'] == 31 && kMsgLen['C'] == 36 && kMsgLen['X'] == 23 && kMsgLen['D'] == 19);
static_assert(kMsgLen['U'] == 35 && kMsgLen['P'] == 44 && kMsgLen['Q'] == 40 && kMsgLen['B'] == 19);
static_assert(kMsgLen['I'] == 50 && kMsgLen['N'] == 20 && kMsgLen['O'] == 48);
static_assert(kMsgLen['G'] == 0 && kMsgLen['a'] == 0 && kMsgLen[0] == 0);

// Struct name for a type byte ("AddOrder"), or "" if undefined.
[[nodiscard]] constexpr std::string_view message_name(char type) noexcept {
  switch (type) {
#define ITCH_MSG(T, Name, L) \
  case T:                    \
    return #Name;
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
    default:
      return {};
  }
}

// Message locate rule (spec): 0 for messages not tied to a stock (S, V, W) and,
// per the spec text, for K even though K carries a Stock field.
[[nodiscard]] constexpr bool locate_must_be_zero(char type) noexcept {
  return type == 'S' || type == 'V' || type == 'W' || type == 'K';
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
enum class DecodeStatus : std::uint8_t { Ok, Empty, UnknownType, BadLength };

[[nodiscard]] constexpr std::string_view to_string(DecodeStatus s) noexcept {
  switch (s) {
    case DecodeStatus::Ok:
      return "ok";
    case DecodeStatus::Empty:
      return "empty";
    case DecodeStatus::UnknownType:
      return "unknown_type";
    case DecodeStatus::BadLength:
      return "bad_length";
  }
  return "?";
}

// Calls `vis(<Name>View)` for a well-formed message (known type, exact length).
template <class Visitor>
inline DecodeStatus visit(std::span<const std::byte> msg, Visitor&& vis) {
  if (msg.empty()) [[unlikely]]
    return DecodeStatus::Empty;
  switch (static_cast<char>(msg[0])) {
#define ITCH_MSG(T, Name, L)               \
  case T:                                  \
    if (msg.size() != (L)) [[unlikely]]    \
      return DecodeStatus::BadLength;      \
    vis(Name##View{msg.data()});           \
    return DecodeStatus::Ok;
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
    default:
      return DecodeStatus::UnknownType;
  }
}

// As visit(), for bytes whose framing already matched kMsgLen. Returns false
// (and does not call `vis`) for an undefined type.
template <class Visitor>
inline bool visit_unchecked(const std::byte* p, Visitor&& vis) {
  switch (static_cast<char>(p[0])) {
#define ITCH_MSG(T, Name, L)     \
  case T:                        \
    vis(Name##View{p});          \
    return true;
#define ITCH_FIELD(Name, f, off, len, K, E)
#define ITCH_END(Name)
#include "proto/itch50/itch50_layouts.def"
    default:
      return false;
  }
}

// A validated message: known type, exact length.
class MessageView {
 public:
  constexpr MessageView(const std::byte* p, std::size_t n) noexcept : p_(p), n_(n) {}
  [[nodiscard]] char type() const noexcept { return static_cast<char>(p_[0]); }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {p_, n_}; }
  [[nodiscard]] MessageHeaderView header() const noexcept { return MessageHeaderView{p_}; }
  template <class V>
  [[nodiscard]] bool is() const noexcept {
    return type() == V::kType;
  }
  template <class V>
  [[nodiscard]] V as() const noexcept {
    LLE_DASSERT(type() == V::kType && n_ == V::kLen, "MessageView::as: wrong type");
    return V{p_};
  }
  template <class Visitor>
  void visit(Visitor&& vis) const {
    (void)visit_unchecked(p_, vis);
  }

 private:
  const std::byte* p_;
  std::size_t n_;
};

[[nodiscard]] inline std::expected<MessageView, DecodeStatus> decode(std::span<const std::byte> msg) noexcept {
  if (msg.empty()) [[unlikely]]
    return std::unexpected(DecodeStatus::Empty);
  const std::size_t want = kMsgLen[static_cast<unsigned char>(msg[0])];
  if (want == 0) [[unlikely]]
    return std::unexpected(DecodeStatus::UnknownType);
  if (msg.size() != want) [[unlikely]]
    return std::unexpected(DecodeStatus::BadLength);
  return MessageView{msg.data(), msg.size()};
}

}  // namespace lle::itch50

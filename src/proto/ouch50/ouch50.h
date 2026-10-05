#pragma once
// OUCH 5.0 rev 1.05 codec (03-protocols s4). Byte-exact encoders and decoders
// for all 8 inbound and 17 outbound messages and all 26 TagValue tags.
//
// Layers:
//  - InboundDecoder / OutboundDecoder: tolerant framing (type, length,
//    Appendage Length, element structure). Unknown tags are left for the
//    caller to skip. Letters overlap between directions, so decoding is
//    always direction-typed (R1b D3.4).
//  - validate_inbound(): the engine's strict check from the journaled bytes
//    (ADR-027): framing + enums + price/quantity domains + unknown,
//    disallowed and duplicate tags. Pure; no state.
//  - validate_outbound(): the same strictness for what we emit, including the
//    exact Appendage Length rule ("parse tolerantly, emit exactly").
//  - MessageWriter / encode(): emits the fixed part and the appendage exactly
//    as the spec marks Appendage Length (DECISIONS.md).
// Nothing here allocates or throws.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

#include "common/assert.h"
#include "common/endian.h"
#include "common/types.h"
#include "proto/ouch50/message_view.h"
#include "proto/ouch50/ouch50_layout.gen.h"
#include "proto/ouch50/ouch50_messages.gen.h"
#include "proto/ouch50/spec_types.h"
#include "proto/ouch50/tagvalue.h"

namespace lle::ouch50 {

// ---------------------------------------------------------------------------- prices (s1.2)

enum class PriceKind : std::uint8_t { Limit, Market, Invalid };

inline constexpr std::uint64_t kMaxLimitPrice = static_cast<std::uint64_t>(kPxMaxLimit);   // $199,999.9900
inline constexpr std::uint64_t kMarketPrice = static_cast<std::uint64_t>(kPxMarket);       // 0x7FFFFFFF
inline constexpr std::uint64_t kMarketPriceAlt = static_cast<std::uint64_t>(kPxMarketAlt); // $200,000.0000

// Valid limit 1..1,999,999,900; {2,000,000,000; 0x7FFFFFFF} = market; anything
// else (including 0) is invalid -> 0x001D (03-protocols s4, R1b risk 4).
[[nodiscard]] constexpr PriceKind classify_price(std::uint64_t p) noexcept {
  if (p >= 1 && p <= kMaxLimitPrice) return PriceKind::Limit;
  if (p == kMarketPrice || p == kMarketPriceAlt) return PriceKind::Market;
  return PriceKind::Invalid;
}

// ---------------------------------------------------------------------------- errors

// Order of checks (first failure wins; DECISIONS.md "Validation order"):
//  framing: Empty, UnknownType, TooShort, TooLong, AppendageLengthMismatch, MalformedTagValue
//  fixed fields in wire order: BadFieldValue
//  elements in wire order: UnknownTag, DisallowedTag, DuplicateTag, BadTagLength, BadTagValue
//  outbound only: AppendageRule
enum class Error : std::uint8_t {
  Empty = 1,
  UnknownType,
  TooShort,
  TooLong,
  AppendageLengthMismatch,
  MalformedTagValue,
  BadFieldValue,
  UnknownTag,
  DisallowedTag,
  DuplicateTag,
  BadTagLength,
  BadTagValue,
  AppendageRule,
};

[[nodiscard]] constexpr std::string_view to_string(Error e) noexcept {
  switch (e) {
    case Error::Empty: return "Empty";
    case Error::UnknownType: return "UnknownType";
    case Error::TooShort: return "TooShort";
    case Error::TooLong: return "TooLong";
    case Error::AppendageLengthMismatch: return "AppendageLengthMismatch";
    case Error::MalformedTagValue: return "MalformedTagValue";
    case Error::BadFieldValue: return "BadFieldValue";
    case Error::UnknownTag: return "UnknownTag";
    case Error::DisallowedTag: return "DisallowedTag";
    case Error::DuplicateTag: return "DuplicateTag";
    case Error::BadTagLength: return "BadTagLength";
    case Error::BadTagValue: return "BadTagValue";
    case Error::AppendageRule: return "AppendageRule";
  }
  return {};
}

struct Failure {
  Error error = Error::Empty;
  std::uint16_t offset = 0;  // byte offset in the message of the offending field / element / length
  RejectReason reason = RejectReason::Other;  // what the engine reports in 'J' (inbound)
  std::uint8_t tag = 0;      // offending tag for tag errors
  friend constexpr bool operator==(const Failure&, const Failure&) = default;
};

// ---------------------------------------------------------------------------- framed views

template <Direction D>
class FramedView {
 public:
  FramedView() noexcept = default;
  FramedView(const MsgDesc* desc, std::span<const std::byte> bytes, bool has_applen) noexcept
      : desc_(desc), bytes_(bytes), has_applen_(has_applen) {}

  [[nodiscard]] const MsgDesc& desc() const noexcept { return *desc_; }
  [[nodiscard]] char type() const noexcept { return desc_->type; }
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool has_appendage_length() const noexcept { return has_applen_; }
  [[nodiscard]] std::uint16_t appendage_length() const noexcept {
    return has_applen_ ? load_be16(bytes_.data() + desc_->base_len) : std::uint16_t{0};
  }
  [[nodiscard]] std::span<const std::byte> appendage() const noexcept {
    return has_applen_ ? bytes_.subspan(desc_->fixed_len) : std::span<const std::byte>{};
  }
  [[nodiscard]] TagValueRange tags() const noexcept { return TagValueRange(appendage()); }

  // Typed view; the caller must check type() first (asserted in debug builds).
  template <class View>
  [[nodiscard]] View as() const noexcept {
    LLE_DASSERT(View::type() == type());
    return View(bytes_);
  }

  // Invokes f(TypedView) for this message's type.
  template <class F>
  void visit(F&& f) const {
    if constexpr (D == Direction::Inbound) {
      (void)visit_inbound(type(), bytes_, static_cast<F&&>(f));
    } else {
      (void)visit_outbound(type(), bytes_, static_cast<F&&>(f));
    }
  }

 private:
  const MsgDesc* desc_ = nullptr;
  std::span<const std::byte> bytes_;
  bool has_applen_ = false;
};

using InboundView = FramedView<Direction::Inbound>;
using OutboundView = FramedView<Direction::Outbound>;

// ---------------------------------------------------------------------------- decoders

// Tolerant framing for messages from a client (inbound). Required Appendage
// Length on O/U/C/D/E; optional on X/M/Q.
class InboundDecoder {
 public:
  [[nodiscard]] static std::expected<InboundView, Failure> decode(std::span<const std::byte> msg) noexcept;
};

// Tolerant framing for messages from the exchange (outbound), as a client
// would parse them: Appendage Length optional on Opt* types and also on 'E'
// (spec does not mark it optional, but R1b risk 2: parse both forms).
class OutboundDecoder {
 public:
  [[nodiscard]] static std::expected<OutboundView, Failure> decode(std::span<const std::byte> msg) noexcept;
};

// Strict inbound validation, run by the engine on journaled bytes (ADR-027).
[[nodiscard]] std::expected<InboundView, Failure> validate_inbound_detailed(std::span<const std::byte> msg) noexcept;
[[nodiscard]] inline std::expected<InboundView, RejectReason> validate_inbound(std::span<const std::byte> msg) noexcept {
  auto r = validate_inbound_detailed(msg);
  if (!r) return std::unexpected(r.error().reason);
  return *r;
}

namespace detail {
// The table-driven strict inbound validator, without the O/U/X fast path that
// validate_inbound_detailed() tries first. Same results by construction; kept
// callable so tests and fuzzers can compare the two.
[[nodiscard]] std::expected<InboundView, Failure> validate_inbound_generic(std::span<const std::byte> msg) noexcept;
}  // namespace detail

// Strict outbound validation (exact emission rules); used by tests and debug checks.
[[nodiscard]] std::expected<OutboundView, Failure> validate_outbound(std::span<const std::byte> msg) noexcept;

// The new UserRefNum a consuming message carries (Enter O, Replace U's new
// UserRefNum, Mass Cancel C, Disable D, Enable E), if the bytes are long enough
// to hold it. Cancel X and Modify M reference an existing order and Account
// Query Q carries none: nullopt (03-protocols s4 "UserRefNum").
[[nodiscard]] std::optional<UserRefNum> peek_new_user_ref_num(std::span<const std::byte> inbound) noexcept;

// UserRefIdx (tag 28) of an inbound message whose framing decodes; 0 when absent
// or undecodable (0 is the port-global channel; DECISIONS.md).
[[nodiscard]] std::uint8_t peek_user_ref_idx(std::span<const std::byte> inbound) noexcept;

// ---------------------------------------------------------------------------- encoding

// True when the appendage carries UserRefIdx with a non-zero value.
[[nodiscard]] inline bool has_nonzero_user_ref_idx(std::span<const std::byte> app) noexcept {
  const auto tv = TagValueRange(app).find(Tag::UserRefIdx);
  return tv && tv->value.size() == 1 && tv->u8() != 0;
}

// Writes one message: the fixed part on construction, tags through tags(),
// then finish() applies the Appendage Length rule of Msg:
//   Required                  always emitted (0 when no tags)
//   Optional (inbound X/M/Q)  emitted only when there are tags
//   OptionalUnlessUserRefIdx  emitted (with all tags) only when the tags carry
//                             a non-zero UserRefIdx; otherwise the message ends
//                             at the fixed part and the tags are dropped
//   None                      never
// `out` must hold at least Msg::kFixedLen bytes; finish() returns the message
// length, or 0 if the buffer was too small.
template <class Msg>
class MessageWriter {
 public:
  MessageWriter(std::span<std::byte> out, const Msg& m) noexcept : out_(out) {
    if (out.size() < Msg::kFixedLen) {
      overflow_ = true;
      return;
    }
    m.encode_base(out.data());
    if constexpr (Msg::kRule != AppendageRule::None) tags_ = TagValueWriter(out.subspan(Msg::kFixedLen));
  }

  [[nodiscard]] TagValueWriter& tags() noexcept
    requires(Msg::kRule != AppendageRule::None)
  {
    return tags_;
  }

  [[nodiscard]] std::size_t finish() noexcept {
    if (overflow_ || tags_.overflow()) return 0;
    const std::size_t n = tags_.size();
    if constexpr (Msg::kRule == AppendageRule::None) {
      return Msg::kFixedLen;
    } else if constexpr (Msg::kRule == AppendageRule::Required) {
      return emit(n);
    } else if constexpr (Msg::kRule == AppendageRule::Optional) {
      return n == 0 ? Msg::kBaseLen : emit(n);
    } else {
      return has_nonzero_user_ref_idx(tags_.bytes()) ? emit(n) : Msg::kBaseLen;
    }
  }

 private:
  std::size_t emit(std::size_t n) noexcept {
    store_be16(out_.data() + Msg::kBaseLen, static_cast<std::uint16_t>(n));
    return Msg::kFixedLen + n;
  }

  std::span<std::byte> out_;
  TagValueWriter tags_;
  bool overflow_ = false;
};

template <class Msg>
[[nodiscard]] std::size_t encode(std::span<std::byte> out, const Msg& m) noexcept {
  return MessageWriter<Msg>(out, m).finish();
}

template <class Msg>
  requires(Msg::kRule != AppendageRule::None)
[[nodiscard]] std::size_t encode(std::span<std::byte> out, const Msg& m, const TagSet& tags) noexcept {
  MessageWriter<Msg> w(out, m);
  put_tags(w.tags(), tags);
  return w.finish();
}

}  // namespace lle::ouch50

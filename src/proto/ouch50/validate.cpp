// OUCH 5.0 framing and strict validation (03-protocols s4, ADR-027).
// Table-driven over the generated descriptors; the check order is part of the
// contract (DECISIONS.md) because the independent decoder must agree on the
// first failure.
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>

#include "proto/ouch50/ouch50.h"

namespace lle::ouch50 {
namespace {

struct Framed {
  const MsgDesc* desc = nullptr;
  bool has_applen = false;
};

[[nodiscard]] constexpr Failure make_failure(Error e, std::size_t offset, std::uint16_t reason = 0x000F,
                                             std::uint8_t tag = 0) noexcept {
  return Failure{e, static_cast<std::uint16_t>(offset), static_cast<RejectReason>(reason), tag};
}

[[nodiscard]] std::uint8_t byte_at(std::span<const std::byte> b, std::size_t i) noexcept {
  return std::to_integer<std::uint8_t>(b[i]);
}

[[nodiscard]] std::uint64_t read_uint(const std::byte* p, std::size_t len) noexcept {
  switch (len) {
    case 1: return std::to_integer<std::uint8_t>(p[0]);
    case 2: return load_be16(p);
    case 4: return load_be32(p);
    case 8: return load_be64(p);
    default: return 0;
  }
}

// Framing shared by every decoder: type, length, Appendage Length and the
// element structure of the appendage. `lenient_e` lets the outbound Executed
// message omit Appendage Length (tolerant client parsing, R1b risk 2).
[[nodiscard]] std::expected<Framed, Failure> frame(std::span<const std::byte> b, Direction dir,
                                                   bool lenient_e) noexcept {
  if (b.empty()) return std::unexpected(make_failure(Error::Empty, 0));
  const std::uint8_t type = byte_at(b, 0);
  const MsgDesc* d = dir == Direction::Inbound ? find_inbound(type) : find_outbound(type);
  if (d == nullptr) return std::unexpected(make_failure(Error::UnknownType, 0));
  const std::size_t n = b.size();
  if (d->rule == AppendageRule::None) {
    if (n < d->fixed_len) return std::unexpected(make_failure(Error::TooShort, 0));
    if (n > d->fixed_len) return std::unexpected(make_failure(Error::TooLong, 0));
    return Framed{d, false};
  }
  const bool optional = d->rule == AppendageRule::Optional || d->rule == AppendageRule::OptionalUnlessUserRefIdx ||
                        (lenient_e && dir == Direction::Outbound && type == 'E');
  if (optional) {
    if (n < d->base_len) return std::unexpected(make_failure(Error::TooShort, 0));
    if (n == d->base_len) return Framed{d, false};
    if (n == d->base_len + 1u) return std::unexpected(make_failure(Error::AppendageLengthMismatch, d->base_len));
  } else if (n < d->fixed_len) {
    return std::unexpected(make_failure(Error::TooShort, 0));
  }
  const std::size_t app_len = load_be16(b.data() + d->base_len);
  if (d->fixed_len + app_len != n) return std::unexpected(make_failure(Error::AppendageLengthMismatch, d->base_len));
  TagValueIterator it(b.subspan(d->fixed_len));
  while (it != std::default_sentinel) ++it;
  if (it.malformed()) return std::unexpected(make_failure(Error::MalformedTagValue, d->fixed_len + it.position()));
  return Framed{d, true};
}

[[nodiscard]] bool in_codes(const std::uint16_t* codes, std::size_t count, std::uint16_t v) noexcept {
  for (std::size_t i = 0; i < count; ++i)
    if (codes[i] == v) return true;
  return false;
}

[[nodiscard]] bool zero_or_limit(std::uint64_t v) noexcept { return v == 0 || classify_price(v) == PriceKind::Limit; }

// Fixed-field value checks, in wire order.
[[nodiscard]] std::optional<Failure> check_fields(const MsgDesc& d, std::span<const std::byte> b) noexcept {
  for (std::size_t i = 0; i < d.field_count; ++i) {
    const FieldDesc& f = d.fields[i];
    const std::byte* p = b.data() + f.offset;
    bool ok = true;
    switch (f.check) {
      case CheckKind::None: break;
      case CheckKind::Enum:
        ok = f.type == FieldType::Char ? f.chars->contains(std::to_integer<std::uint8_t>(*p))
                                       : in_codes(f.codes, f.code_count, load_be16(p));
        break;
      case CheckKind::LimitOrMarket: ok = classify_price(load_be64(p)) != PriceKind::Invalid; break;
      case CheckKind::ZeroOrLimit: ok = zero_or_limit(load_be64(p)); break;
      case CheckKind::Range: {
        const std::uint64_t v = read_uint(p, f.len);
        ok = v >= f.lo && v <= f.hi;
        break;
      }
    }
    if (!ok) return make_failure(Error::BadFieldValue, f.offset, f.reject);
  }
  return std::nullopt;
}

// Element checks, in wire order. The structure was verified by frame().
[[nodiscard]] std::optional<Failure> check_tags(const MsgDesc& d, std::span<const std::byte> b) noexcept {
  std::uint32_t seen = 0;
  for (const TagValue& tv : TagValueRange(b.subspan(d.fixed_len))) {
    const std::size_t at = d.fixed_len + tv.offset;
    const TagDesc* td = find_tag(tv.tag);
    if (td == nullptr) return make_failure(Error::UnknownTag, at, 0x000F, tv.tag);
    const std::uint32_t bit = 1u << tv.tag;  // tv.tag < 32 once find_tag succeeds
    if ((d.allowed_tags & bit) == 0) return make_failure(Error::DisallowedTag, at, 0x000F, tv.tag);
    if ((seen & bit) != 0) return make_failure(Error::DuplicateTag, at, 0x000F, tv.tag);
    seen |= bit;
    if (tv.value.size() != td->value_len) return make_failure(Error::BadTagLength, at, 0x000F, tv.tag);
    bool ok = true;
    switch (td->check) {
      case CheckKind::None: break;
      case CheckKind::Enum: ok = td->chars->contains(tv.u8()); break;
      case CheckKind::LimitOrMarket: ok = classify_price(tv.u64()) != PriceKind::Invalid; break;
      case CheckKind::ZeroOrLimit: ok = zero_or_limit(tv.u64()); break;
      case CheckKind::Range: {
        const std::uint64_t v = read_uint(tv.value.data(), tv.value.size());
        ok = v >= td->lo && v <= td->hi;
        break;
      }
    }
    if (!ok) return make_failure(Error::BadTagValue, at, td->reject, tv.tag);
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------- fast path
// Enter O, Replace U and Cancel X are the engine's hot messages. The same
// descriptor checks with everything known at compile time: kInboundMessages[M]
// and its fields are constexpr, so each field's check kind, offset, bounds and
// enum set fold into straight-line code. The fast path only ever ACCEPTS: any
// input it does not accept goes through the table-driven path, which therefore
// decides (and reports) every reject. It accepts exactly when the table-driven
// path does, because it applies the same framing conditions, the same field
// checks in full and, when the appendage is not empty, the same element and
// tag checks (fuzz/ouch50/ouch50_decode_fuzz.cpp compares the two on every
// input).

template <std::size_t M>
inline constexpr const MsgDesc& kFastMsg = kInboundMessages[M];
template <std::size_t M, std::size_t I>
inline constexpr const FieldDesc& kFastField = kInboundMessages[M].fields[I];

template <std::size_t M, std::size_t I>
[[nodiscard]] inline bool fast_field_ok(const std::byte* msg) noexcept {
  constexpr const FieldDesc& f = kFastField<M, I>;
  const std::byte* p = msg + f.offset;
  if constexpr (f.check == CheckKind::None) {
    return true;
  } else if constexpr (f.check == CheckKind::Enum) {
    if constexpr (f.type == FieldType::Char) {
      return f.chars->contains(std::to_integer<std::uint8_t>(*p));
    } else {
      return in_codes(f.codes, f.code_count, load_be16(p));
    }
  } else if constexpr (f.check == CheckKind::LimitOrMarket) {
    return classify_price(load_be64(p)) != PriceKind::Invalid;
  } else if constexpr (f.check == CheckKind::ZeroOrLimit) {
    return zero_or_limit(load_be64(p));
  } else {
    static_assert(f.check == CheckKind::Range);
    const std::uint64_t v = read_uint(p, f.len);
    return v >= f.lo && v <= f.hi;
  }
}

template <std::size_t M, std::size_t... I>
[[nodiscard]] inline bool fast_fields_ok(const std::byte* msg, std::index_sequence<I...>) noexcept {
  return (fast_field_ok<M, I>(msg) && ...);
}

template <std::size_t M>
[[nodiscard]] inline bool fast_accept(std::span<const std::byte> b, bool& has_applen) noexcept {
  constexpr const MsgDesc& d = kFastMsg<M>;
  static_assert(d.rule == AppendageRule::Required || d.rule == AppendageRule::Optional);
  const std::size_t n = b.size();
  if constexpr (d.rule == AppendageRule::Required) {
    if (n < d.fixed_len || d.fixed_len + std::size_t{load_be16(b.data() + d.base_len)} != n) return false;
    has_applen = true;
  } else {
    if (n == d.base_len) {
      has_applen = false;
    } else if (n >= d.fixed_len && d.fixed_len + std::size_t{load_be16(b.data() + d.base_len)} == n) {
      has_applen = true;
    } else {
      return false;
    }
  }
  if (!fast_fields_ok<M>(b.data(), std::make_index_sequence<kFastMsg<M>.field_count>{})) return false;
  if (n > d.fixed_len) {  // a non-empty appendage: element structure, then the tag checks
    TagValueIterator it(b.subspan(d.fixed_len));
    while (it != std::default_sentinel) ++it;
    if (it.malformed() || check_tags(d, b)) return false;
  }
  return true;
}

constexpr std::size_t kFastEnter = 0, kFastReplace = 1, kFastCancel = 2;
static_assert(kInboundMessages[kFastEnter].type == 'O' && kInboundMessages[kFastReplace].type == 'U' &&
              kInboundMessages[kFastCancel].type == 'X');

}  // namespace

namespace detail {

std::expected<InboundView, Failure> validate_inbound_generic(std::span<const std::byte> msg) noexcept {
  auto f = frame(msg, Direction::Inbound, false);
  if (!f) return std::unexpected(f.error());
  if (auto e = check_fields(*f->desc, msg)) return std::unexpected(*e);
  if (f->has_applen) {
    if (auto e = check_tags(*f->desc, msg)) return std::unexpected(*e);
  }
  return InboundView(f->desc, msg, f->has_applen);
}

}  // namespace detail

std::expected<InboundView, Failure> InboundDecoder::decode(std::span<const std::byte> msg) noexcept {
  auto f = frame(msg, Direction::Inbound, false);
  if (!f) return std::unexpected(f.error());
  return InboundView(f->desc, msg, f->has_applen);
}

std::expected<OutboundView, Failure> OutboundDecoder::decode(std::span<const std::byte> msg) noexcept {
  auto f = frame(msg, Direction::Outbound, true);
  if (!f) return std::unexpected(f.error());
  return OutboundView(f->desc, msg, f->has_applen);
}

std::expected<InboundView, Failure> validate_inbound_detailed(std::span<const std::byte> msg) noexcept {
  if (!msg.empty()) {
    bool applen = false;
    switch (std::to_integer<char>(msg[0])) {
      case 'O':
        if (fast_accept<kFastEnter>(msg, applen)) return InboundView(&kInboundMessages[kFastEnter], msg, applen);
        break;
      case 'U':
        if (fast_accept<kFastReplace>(msg, applen)) return InboundView(&kInboundMessages[kFastReplace], msg, applen);
        break;
      case 'X':
        if (fast_accept<kFastCancel>(msg, applen)) return InboundView(&kInboundMessages[kFastCancel], msg, applen);
        break;
      default: break;
    }
  }
  return detail::validate_inbound_generic(msg);
}

std::expected<OutboundView, Failure> validate_outbound(std::span<const std::byte> msg) noexcept {
  auto f = frame(msg, Direction::Outbound, false);
  if (!f) return std::unexpected(f.error());
  const MsgDesc& d = *f->desc;
  if (auto e = check_fields(d, msg)) return std::unexpected(*e);
  if (f->has_applen) {
    if (auto e = check_tags(d, msg)) return std::unexpected(*e);
    // Opt*: the appendage exists only to echo a non-zero UserRefIdx (s3.4 and siblings).
    if (d.rule == AppendageRule::OptionalUnlessUserRefIdx && !has_nonzero_user_ref_idx(msg.subspan(d.fixed_len)))
      return std::unexpected(make_failure(Error::AppendageRule, d.base_len));
  }
  return OutboundView(f->desc, msg, f->has_applen);
}

std::optional<UserRefNum> peek_new_user_ref_num(std::span<const std::byte> inbound) noexcept {
  if (inbound.empty()) return std::nullopt;
  switch (std::to_integer<char>(inbound[0])) {
    case 'O':
    case 'C':
    case 'D':
    case 'E':
      if (inbound.size() < 5) return std::nullopt;
      return load_be32(inbound.data() + 1);
    case 'U':
      if (inbound.size() < 9) return std::nullopt;
      return load_be32(inbound.data() + layout::in::ReplaceOrder::kUserRefNumOff);
    default: return std::nullopt;
  }
}

std::uint8_t peek_user_ref_idx(std::span<const std::byte> inbound) noexcept {
  auto v = InboundDecoder::decode(inbound);
  if (!v) return 0;
  const auto tv = v->tags().find(Tag::UserRefIdx);
  return (tv && tv->value.size() == 1) ? tv->u8() : std::uint8_t{0};
}

}  // namespace lle::ouch50

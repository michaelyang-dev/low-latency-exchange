// Fuzz harness: OUCH 5.0 decoders and strict validators (03-protocols s9).
// Input byte 0 selects the direction (bit 0: 0 inbound, 1 outbound); the rest
// is one OUCH message. Properties checked on every input:
//  - no crash / UB (ASan+UBSan in the fuzz preset);
//  - strict success implies tolerant success with the same view;
//  - a framing failure is reported identically by tolerant and strict paths;
//  - anything the strict validator accepts re-encodes byte-identically through
//    the typed views, MessageWriter and TagValueWriter (encoder == decoder);
//  - strict inbound failures carry a valid RejectReason;
//  - the O/U/X fast path of validate_inbound_detailed gives exactly the result
//    of the table-driven validator (same view, or the same Failure).
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "canonical.h"
#include "common/assert.h"
#include "common/hash.h"
#include "msggen.h"
#include "proto/ouch50/ouch50.h"

namespace {

using namespace lle::ouch50;

bool is_framing(Error e) {
  return e == Error::Empty || e == Error::UnknownType || e == Error::TooShort || e == Error::TooLong ||
         e == Error::AppendageLengthMismatch || e == Error::MalformedTagValue;
}

// Re-encodes a strictly valid message from its decoded parts.
template <Direction D>
void check_round_trip(const FramedView<D>& v) {
  std::array<std::byte, 512> out{};
  std::size_t n = 0;
  v.visit([&](const auto& typed) {
    using Msg = typename std::decay_t<decltype(typed)>::Message;
    MessageWriter<Msg> w(out, typed.to_struct());
    if constexpr (Msg::kRule != AppendageRule::None) {
      for (const TagValue& tv : typed.tags()) w.tags().put_raw(tv.tag, tv.value);
    }
    n = w.finish();
  });
  const auto in = v.bytes();
  if constexpr (D == Direction::Inbound) {
    // Opt types: an explicit empty appendage (AppLen 0) is legal input but we emit the short form.
    const bool empty_opt =
        v.desc().rule == AppendageRule::Optional && v.has_appendage_length() && v.appendage().empty();
    if (empty_opt) {
      LLE_ASSERT(n == v.desc().base_len);
      LLE_ASSERT(std::memcmp(out.data(), in.data(), n) == 0);
      return;
    }
  }
  LLE_ASSERT(n == in.size(), "re-encoded length differs");
  LLE_ASSERT(std::memcmp(out.data(), in.data(), n) == 0, "re-encoded bytes differ");
}

void fuzz_inbound(std::span<const std::byte> b) {
  const auto tolerant = InboundDecoder::decode(b);
  const auto strict = validate_inbound_detailed(b);
  const auto generic = detail::validate_inbound_generic(b);
  LLE_ASSERT(strict.has_value() == generic.has_value(), "fast path and table-driven validator disagree");
  if (strict) {
    LLE_ASSERT(&strict->desc() == &generic->desc() && strict->bytes().data() == generic->bytes().data() &&
                   strict->bytes().size() == generic->bytes().size() &&
                   strict->has_appendage_length() == generic->has_appendage_length(),
               "fast path view differs");
  } else {
    LLE_ASSERT(strict.error() == generic.error(), "fast path failure differs");
  }
  if (strict) {
    LLE_ASSERT(tolerant.has_value());
    LLE_ASSERT(tolerant->type() == strict->type());
    LLE_ASSERT(b.size() <= kMaxInboundOuchLen, "valid inbound longer than kMaxInboundOuchLen");
    check_round_trip(*strict);
    TagSet ts;
    LLE_ASSERT(parse_tags(strict->tags(), ts));
  } else {
    LLE_ASSERT(is_valid_outbound(strict.error().reason), "reject reason must be a spec code");
    if (!tolerant) LLE_ASSERT(tolerant.error() == strict.error());
    if (is_framing(strict.error().error)) LLE_ASSERT(!tolerant.has_value());
    const auto simple = validate_inbound(b);
    LLE_ASSERT(!simple.has_value() && simple.error() == strict.error().reason);
  }
  (void)peek_new_user_ref_num(b);
  (void)peek_user_ref_idx(b);
  (void)canon::inbound_verdict(b);
}

void fuzz_outbound(std::span<const std::byte> b) {
  const auto tolerant = OutboundDecoder::decode(b);
  const auto strict = validate_outbound(b);
  if (strict) {
    LLE_ASSERT(tolerant.has_value());
    LLE_ASSERT(b.size() <= kMaxOutboundOuchLen);
    check_round_trip(*strict);
  }
  if (tolerant) {
    // Typed accessors over every tolerantly decoded message must be safe.
    (void)canon::success(*tolerant);
    TagSet ts;
    (void)parse_tags(tolerant->tags(), ts);
  }
  (void)canon::outbound_verdict(b);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const auto b = std::as_bytes(std::span<const std::uint8_t>(data + 1, size - 1));
  if ((data[0] & 1u) == 0) {
    fuzz_inbound(b);
  } else {
    fuzz_outbound(b);
  }
  return 0;
}

// Seed corpus for the shared mutation driver (fuzz/common/fuzz_driver_main.cpp):
// structured valid, mutated and noise messages in both directions.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 2048 || cap < 2) return 0;
  gen::Generator g(lle::mix64(index + 1));
  const bool outbound = g.rng().chance(1, 2);
  const auto msg = g.any(outbound ? Direction::Outbound : Direction::Inbound);
  const std::size_t n = std::min(cap - 1, msg.size());
  buf[0] = outbound ? 1 : 0;
  if (n > 0) std::memcpy(buf + 1, msg.data(), n);
  return n + 1;
}

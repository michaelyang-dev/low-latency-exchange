// Fuzz target: ITCH 5.0 decode (03-protocols §9 "Fuzzing").
// Properties: no crash or UB on any input; a message that decodes re-encodes
// to exactly the same bytes; the validator never crashes and agrees with the
// decoder on framing.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "common/assert.h"
#include "proto/itch50/itch50.h"
#include "proto/itch50/validator.h"

namespace {

using namespace lle::itch50;

template <class M>
std::size_t put(std::uint8_t* buf, std::size_t cap, const M& m) {
  return encode(std::span<std::byte>(reinterpret_cast<std::byte*>(buf), cap), m);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> in(reinterpret_cast<const std::byte*>(data), size);
  std::array<std::byte, kMaxMsgLen> out{};
  const DecodeStatus st = visit(in, [&](auto v) {
    const auto m = v.to_struct();
    const std::size_t n = encode(out, m);
    LLE_ASSERT(n == in.size(), "re-encoded length differs");
    LLE_ASSERT(std::memcmp(out.data(), in.data(), n) == 0, "decode/encode round trip differs");
    LLE_ASSERT(decltype(v)::kType == static_cast<char>(in[0]));
  });
  const auto d = decode(in);
  LLE_ASSERT(d.has_value() == (st == DecodeStatus::Ok));
  if (!d) LLE_ASSERT(d.error() == st);

  Validator strict(true);
  const std::uint32_t violations = strict.check(in);
  if (st != DecodeStatus::Ok) LLE_ASSERT(violations == 1, "framing errors are reported exactly once");

  // Also treat the input as a stream of back-to-back messages using kMsgLen framing.
  std::size_t at = 0;
  while (at < size) {
    const std::size_t len = kMsgLen[data[at]];
    if (len == 0 || size - at < len) break;
    (void)visit_unchecked(reinterpret_cast<const std::byte*>(data + at), [&](auto v) { (void)v.to_struct(); });
    at += len;
  }
  return 0;
}

// Seeds: one valid message of every type (structure-aware starting points).
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= kNumMessageTypes) return 0;
  const char t = kMessageTypes[index];
  std::size_t n = 0;
  std::array<std::byte, kMaxMsgLen> raw{};
  for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<std::byte>(0x20 + (i * 7) % 60);
  raw[0] = static_cast<std::byte>(t);
  (void)visit(std::span<const std::byte>(raw.data(), kMsgLen[static_cast<unsigned char>(t)]),
              [&](auto v) { n = put(buf, cap, v.to_struct()); });
  return n;
}

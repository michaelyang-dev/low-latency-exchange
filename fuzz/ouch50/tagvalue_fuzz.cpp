// Fuzz harness: TagValue appendage reader and writer (OUCH 5.0 s1.2).
// The whole input is treated as an appendage. Properties:
//  - iteration terminates, offsets strictly increase and stay in bounds;
//  - well_formed() agrees with the iterator's malformed() flag;
//  - re-writing the well-formed elements with TagValueWriter reproduces the
//    consumed prefix byte for byte;
//  - parse_tags never reads out of bounds and agrees on malformed input.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "common/assert.h"
#include "common/hash.h"
#include "common/prng.h"
#include "proto/ouch50/ouch50.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lle::ouch50;
  const auto app = std::as_bytes(std::span<const std::uint8_t>(data, size));
  std::array<std::byte, 8192> out{};
  TagValueWriter w(out);
  std::size_t consumed = 0;
  std::size_t count = 0;
  TagValueIterator it(app);
  for (; it != std::default_sentinel; ++it) {
    const TagValue& tv = *it;
    LLE_ASSERT(tv.offset == consumed, "elements must be contiguous");
    LLE_ASSERT(tv.offset + 2 + tv.value.size() <= app.size());
    LLE_ASSERT(tv.value.data() == app.data() + tv.offset + 2, "zero-copy value");
    consumed = tv.offset + 2 + tv.value.size();
    w.put_raw(tv.tag, tv.value);
    ++count;
    LLE_ASSERT(count <= size, "iteration must terminate");
  }
  const TagValueRange range(app);
  LLE_ASSERT(range.well_formed() == !it.malformed());
  LLE_ASSERT(it.malformed() ? consumed < app.size() : consumed == app.size());
  LLE_ASSERT(!w.overflow() && w.size() == consumed);
  LLE_ASSERT(consumed == 0 || std::memcmp(out.data(), app.data(), consumed) == 0);
  TagSet ts;
  const bool parsed = parse_tags(range, ts);
  if (it.malformed()) LLE_ASSERT(!parsed);
  if (size > 0) (void)range.find(data[size - 1]);
  return 0;
}

// Seed corpus for the shared mutation driver: concatenated plausible elements
// (known tags with right or wrong sizes, unknown tags, occasional corruption).
// Returns 0 past the last seed; a seed is never empty so it is not mistaken for the end.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 1024 || cap < 2) return 0;
  lle::Prng r(lle::mix64(index + 1));
  std::size_t n = 0;
  const std::uint64_t elements = r.below(24);
  for (std::uint64_t e = 0; e < elements; ++e) {
    const auto tag = static_cast<std::uint8_t>(r.chance(3, 4) ? r.below(32) : r.below(256));
    const lle::ouch50::TagDesc* td = lle::ouch50::find_tag(tag);
    std::size_t len = td != nullptr && r.chance(3, 4) ? td->value_len : static_cast<std::size_t>(r.below(12));
    if (n + 2 + len > cap) break;
    buf[n] = static_cast<std::uint8_t>(len + 1);
    buf[n + 1] = tag;
    for (std::size_t i = 0; i < len; ++i) buf[n + 2 + i] = static_cast<std::uint8_t>(r.below(256));
    n += 2 + len;
  }
  if (n > 0 && r.chance(1, 4)) buf[r.below(n)] = static_cast<std::uint8_t>(r.below(256));
  if (n > 0 && r.chance(1, 8)) n = static_cast<std::size_t>(r.below(n));
  if (n == 0) {  // an empty appendage is a valid seed too, but 0 ends the corpus
    buf[0] = 0x02;
    buf[1] = 0x1C;
    n = 2;
  }
  return n;
}

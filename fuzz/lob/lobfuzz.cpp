// lobfuzz: coverage-guided differential harness for the ITCH book builder
// (04-order-book §8 "Harnesses"). The input bytes are decoded by
// FuzzedDataProvider into a short operation stream over a few locates, a
// small ref pool (collisions, unknown refs, reuse), page-boundary and
// >= 2^32 refs, and prices around a few anchors including stubs; every
// operation is applied to RefBook and to every registered variant, and any
// difference aborts (a libFuzzer crash). Built with lle_fuzz(): on Linux with
// the `fuzz` preset as a libFuzzer binary; everywhere as lobfuzz_driver, which
// mutates the seed inputs below (conventions: Apple clang has no libFuzzer
// runtime).
#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "book/variants.h"
#include "common/prng.h"
#include "diff.hpp"
#include "gen.hpp"

namespace {

using lle::lobfuzz::Op;

constexpr lle::PxE4 kAnchors[] = {1, 100, 9'900, 10'000, 503'100, 1'999'999'900, 0xFFFF'FFFFll};

Op decode_op(FuzzedDataProvider& fdp) {
  Op op;
  op.kind = static_cast<Op::Kind>(fdp.ConsumeIntegralInRange<int>(0, 4));
  if (op.kind == Op::Kind::kDeclare && fdp.ConsumeBool()) op.kind = Op::Kind::kAdd;  // adds dominate
  auto ref = [&]() -> lle::OrderRef {
    switch (fdp.ConsumeIntegralInRange<int>(0, 5)) {
      case 0:
      case 1:
      case 2: return fdp.ConsumeIntegralInRange<lle::OrderRef>(0, 31);  // small pool: collisions
      case 3: return 8'190 + fdp.ConsumeIntegralInRange<lle::OrderRef>(0, 4);  // page boundary
      case 4: return (1ull << 32) - 2 + fdp.ConsumeIntegralInRange<lle::OrderRef>(0, 4);
      default: return fdp.ConsumeIntegral<lle::OrderRef>();
    }
  };
  op.ref = ref();
  op.new_ref = fdp.ConsumeIntegralInRange<int>(0, 15) == 0 ? op.ref : ref();
  // A few low locates, rarely the top of the u16 range (the book vector then
  // spans every locate).
  const auto loc = fdp.ConsumeIntegralInRange<lle::Locate>(0, 3);
  op.loc = fdp.ConsumeIntegralInRange<int>(0, 255) == 0 ? static_cast<lle::Locate>(65535 - loc) : loc;
  const int side = fdp.ConsumeIntegralInRange<int>(0, 20);
  op.side = side == 0 ? static_cast<lle::Side>('X') : (side % 2 == 0 ? lle::Side::Buy : lle::Side::Sell);
  const lle::PxE4 anchor = kAnchors[fdp.ConsumeIntegralInRange<std::size_t>(0, std::size(kAnchors) - 1)];
  switch (fdp.ConsumeIntegralInRange<int>(0, 7)) {
    case 0: op.px = fdp.ConsumeIntegral<std::int64_t>(); break;  // mostly out of range
    case 1: op.px = anchor + fdp.ConsumeIntegralInRange<int>(-99, 99); break;
    default: op.px = anchor + 100 * fdp.ConsumeIntegralInRange<int>(-20, 20); break;
  }
  switch (fdp.ConsumeIntegralInRange<int>(0, 7)) {
    case 0: op.qty = fdp.ConsumeIntegral<lle::Qty>(); break;
    case 1: op.qty = 0; break;
    default: op.qty = fdp.ConsumeIntegralInRange<lle::Qty>(1, 300); break;
  }
  return op;
}

template <class V>
struct Lane {
  explicit Lane(const lle::book::BookConfig& cfg) : pair(cfg) {}
  lle::lobfuzz::DiffPair<V> pair;
};

[[noreturn]] void fail(const char* variant, std::size_t i, const Op& op, const std::string& why) {
  std::fprintf(stderr, "lobfuzz divergence: variant %s op %zu (%s): %s\n", variant, i,
               lle::lobfuzz::to_string(op).c_str(), why.c_str());
  std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  FuzzedDataProvider fdp(data, size);
  lle::book::BookConfig cfg;
  constexpr std::uint64_t kDirect[] = {1ull << 13, 1ull << 14, 1ull << 16};
  cfg.max_direct_ref = kDirect[fdp.ConsumeIntegralInRange<int>(0, 2)];
  cfg.reserve_orders = 16;
  cfg.reserve_levels = 4;
  // Decode once, then replay the same stream into every variant.
  std::vector<Op> ops;
  while (fdp.remaining_bytes() > 0 && ops.size() < 2048) ops.push_back(decode_op(fdp));
  lle::book::for_each_variant([&]<class V>() {
    auto lane = std::make_unique<Lane<V>>(cfg);
    std::string why;
    for (std::size_t i = 0; i < ops.size(); ++i) {
      if (!lane->pair.step(ops[i], &why)) fail(V::kName.data(), i, ops[i], why);
      if ((i & 255) == 255 && !lane->pair.full_check(&why)) fail(V::kName.data(), i, ops[i], why);
    }
    if (!lane->pair.full_check(&why)) fail(V::kName.data(), ops.size(), Op{}, why);
  });
  return 0;
}

// Seed inputs for the standalone driver: low-entropy byte streams, which the
// decoder turns into dense operation streams over the small ref pool
// (collisions, reuse, unknown refs) and nearby prices.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 6) return 0;
  lle::Prng rng(0x10BF ^ index);
  const std::size_t n = std::min<std::size_t>(cap, std::size_t{256} << (index % 4));
  const std::uint64_t range = index % 2 == 0 ? 4 : 64;
  for (std::size_t i = 0; i < n; ++i) buf[i] = static_cast<std::uint8_t>(rng.below(range));
  return n;
}

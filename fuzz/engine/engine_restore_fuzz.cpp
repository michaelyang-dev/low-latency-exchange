// engine_restore_fuzz: structure-aware fuzzing of Engine::restore().
//
// Snapshot payloads reach restore() through the CRC-checked snapshot container
// (src/snapshot) with the state hash beside them, so damage should be caught
// before; restore() must nevertheless never crash, never run into undefined
// behaviour, and never accept a state that is inconsistent or that breaks the
// engine later (src/engine/README.md).
//
// Input format: [stream u8][cut u8] then mutations of 3 bytes each
// [offset u16 little-endian][value u8], applied to a cached base snapshot
// (one of 8 generated streams x 4 cut points). A trailing single byte
// truncates the payload to byte/256 of its length; a trailing pair inserts
// that many copies of the second byte at its offset. When restore() accepts
// the result, check() must pass, and again after each of the next 200 records
// of the stream. Any failure aborts.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "engine/engine.h"
#include "gen.hpp"

namespace {

using namespace lle::engine;

struct Base {
  std::deque<std::vector<std::byte>> payloads;
  std::vector<InputRecord> recs;
  std::size_t cut = 0;
  std::vector<std::byte> snap;
};

constexpr std::size_t kStreams = 8;
constexpr std::array<std::size_t, 4> kCuts = {300, 1'200, 2'500, 4'000};
constexpr std::size_t kTail = 200;

const Base& base(std::size_t stream, std::size_t cut_idx) {
  static std::array<std::unique_ptr<Base>, kStreams * kCuts.size()> cache;
  std::unique_ptr<Base>& b = cache[stream * kCuts.size() + cut_idx];
  if (!b) {
    b = std::make_unique<Base>();
    b->cut = kCuts[cut_idx];
    gen::Generator g(7'000 + stream);
    for (std::size_t i = 0; i < b->cut + kTail; ++i) {
      InputRecord r = g.next();
      b->payloads.emplace_back(r.payload.begin(), r.payload.end());
      r.payload = std::span<const std::byte>(b->payloads.back());
      b->recs.push_back(r);
    }
    Engine e;
    BufferSink sink;
    for (std::size_t i = 0; i < b->cut; ++i) {
      sink.clear();
      e.apply(b->recs[i], sink);
    }
    e.snapshot(b->snap);
  }
  return *b;
}

[[noreturn]] void fail(const char* what, const std::string& err) {
  std::fprintf(stderr, "engine_restore_fuzz: %s: %s\n", what, err.c_str());
  std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) return 0;
  const Base& b = base(data[0] % kStreams, data[1] % kCuts.size());
  std::vector<std::byte> bad = b.snap;
  std::size_t i = 2;
  for (; i + 3 <= size; i += 3) {
    if (bad.empty()) break;
    const std::size_t at = (std::size_t{data[i]} | (std::size_t{data[i + 1]} << 8)) % bad.size();
    bad[at] = std::byte{data[i + 2]};
  }
  if (size - i == 1 && !bad.empty()) bad.resize(bad.size() * data[i] / 256);
  if (size - i == 2 && !bad.empty()) {
    const std::size_t at = data[i] * bad.size() / 256;
    bad.insert(bad.begin() + static_cast<std::ptrdiff_t>(at), std::size_t{1} + data[i + 1] % 8, std::byte{data[i + 1]});
  }
  Engine r;
  if (!r.restore(bad)) return 0;
  std::string err;
  if (!r.check(&err)) fail("accepted an inconsistent snapshot", err);
  BufferSink sink;
  for (std::size_t k = b.cut; k < b.recs.size(); ++k) {
    sink.clear();
    r.apply(b.recs[k], sink);
    if (!r.check(&err)) fail("a restored engine broke while replaying", err);
  }
  return 0;
}

// Seeds for the standalone driver: every (stream, cut) base with 1-4 random
// byte overwrites.
extern "C" std::size_t lle_fuzz_seed(std::size_t index, std::uint8_t* buf, std::size_t cap) {
  if (index >= 128 || cap < 14) return 0;
  std::uint64_t x = lle::mix64(index + 1);
  buf[0] = static_cast<std::uint8_t>(index % kStreams);
  buf[1] = static_cast<std::uint8_t>(index / kStreams % kCuts.size());
  const std::size_t muts = 1 + index % 4;
  std::size_t n = 2;
  for (std::size_t k = 0; k < muts; ++k) {
    x = lle::mix64(x);
    buf[n++] = static_cast<std::uint8_t>(x);
    buf[n++] = static_cast<std::uint8_t>(x >> 8);
    buf[n++] = static_cast<std::uint8_t>(x >> 16);
  }
  return n;
}

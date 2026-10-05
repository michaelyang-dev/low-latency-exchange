// GenMC harness: SpscByteRing wrap and padding (08-concurrency-runtime §4, §7).
// A 64-byte ring and four records whose sizes force a pad record and a wrap:
//   r0: payload 24 (record 32) at   0..32
//   r1: payload 16 (record 24) at  32..56
//   r2: payload 16 (record 24): 8 bytes left, so pad 56..64 and the record at 64..88
//   r3: payload  8 (record 16) at  88..104 (offset 24)
// r2 can only be reserved after r0 is released and r3 after r1, so every interleaving
// exercises the producer's acquire of r_ and the consumer's pad skip. Payload words
// encode (record, word); the consumer checks length and every word. GenMC reports any
// race between the producer reusing bytes and the consumer still reading them.
//
// Records are 8-32 bytes in total (payload 0-24): SpscByteRing limits a record to half
// the buffer so a drained ring always has room (08 §4 suggested 8-40-byte records).
//
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/spsc_byte_ring_wrap.cpp
#include <cstddef>
#include <cstdint>

#include "concurrent/spsc_byte_ring.h"
#include "harness.h"

namespace {

constexpr int kRecords = 4;
constexpr std::uint32_t kLen[kRecords] = {24, 16, 16, 8};

alignas(8) std::byte storage[64];
lle::conc::SpscByteRing* ring;  // heap object created by main (see harness.h)

std::uint64_t word(int rec, std::uint32_t w) { return static_cast<std::uint64_t>(rec) * 16 + w + 1; }

void* producer(void*) {
  for (int r = 0; r < kRecords; ++r) {
    std::byte* p = ring->try_reserve(kLen[r]);
    __VERIFIER_assume(p != nullptr);
    auto* words = static_cast<std::uint64_t*>(static_cast<void*>(p));
    for (std::uint32_t w = 0; w < kLen[r] / 8; ++w) words[w] = word(r, w);
    ring->commit();
  }
  return nullptr;
}

void* consumer(void*) {
#ifdef USE_DRAIN
  int next = 0;
  for (int round = 0; round < kRecords && next < kRecords; ++round) {
    const std::size_t n = ring->drain(
        [&](const std::byte* p, std::uint32_t len) {
          assert(len == kLen[next]);
          const auto* words = static_cast<const std::uint64_t*>(static_cast<const void*>(p));
          for (std::uint32_t w = 0; w < len / 8; ++w) assert(words[w] == word(next, w));
          ++next;
        },
        2);
    __VERIFIER_assume(n > 0);
  }
  assert(next == kRecords);
#else
  for (int r = 0; r < kRecords; ++r) {
    std::uint32_t len = 0;
    const std::byte* p = ring->peek(len);
    __VERIFIER_assume(p != nullptr);
    assert(len == kLen[r]);
    const auto* words = static_cast<const std::uint64_t*>(static_cast<const void*>(p));
    for (std::uint32_t w = 0; w < len / 8; ++w) assert(words[w] == word(r, w));
    ring->release();
  }
#endif
  return nullptr;
}

}  // namespace

int main() {
  ring = lle_genmc::make_shared_object<lle::conc::SpscByteRing>();
  ring->init(storage, sizeof(storage));
  pthread_t p = lle_genmc::spawn(producer);
  pthread_t c = lle_genmc::spawn(consumer);
  lle_genmc::join(p);
  lle_genmc::join(c);
  std::uint32_t len = 0;
  assert(ring->peek(len) == nullptr);
  lle_genmc::destroy_shared_object(ring);
  return 0;
}

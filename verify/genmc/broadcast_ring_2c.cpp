// GenMC harness: BroadcastRing<2> (08-concurrency-runtime §6, §7). One producer, two
// consumer cursors over a 64-byte ring; the record sizes force the producer to wait
// for BOTH cursors and to wrap with a pad record (same layout as
// spsc_byte_ring_wrap.cpp). Each consumer must see the full sequence; the producer must
// never overwrite bytes a cursor has not passed (value checks plus GenMC's race check).
//
//   genmc -rc11 -- -std=c++20 -I src verify/genmc/broadcast_ring_2c.cpp
#include <cstddef>
#include <cstdint>

#include "concurrent/broadcast_ring.h"
#include "harness.h"

namespace {

#ifndef RECORDS
#define RECORDS 3
#endif
constexpr int kRecords = RECORDS;  // <= 4
constexpr std::uint32_t kLen[4] = {24, 16, 16, 8};

alignas(8) std::byte storage[64];
using Ring = lle::conc::BroadcastRing<2>;
Ring* ring;  // heap object created by main (see harness.h)

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

void* consumer(void* arg) {
  const auto c = static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(arg));
#ifdef USE_DRAIN
  int next = 0;
  for (int round = 0; round < kRecords && next < kRecords; ++round) {
    const std::size_t n = ring->drain(
        c,
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
  return nullptr;
#endif
  for (int r = 0; r < kRecords; ++r) {
    std::uint32_t len = 0;
    const std::byte* p = ring->peek(c, len);
    __VERIFIER_assume(p != nullptr);
    assert(len == kLen[r]);
    const auto* words = static_cast<const std::uint64_t*>(static_cast<const void*>(p));
    for (std::uint32_t w = 0; w < len / 8; ++w) assert(words[w] == word(r, w));
    ring->release(c);
  }
  return nullptr;
}

}  // namespace

int main() {
  ring = lle_genmc::make_shared_object<Ring>();
  ring->init(storage, sizeof(storage));
  pthread_t p = lle_genmc::spawn(producer);
  pthread_t c0 = lle_genmc::spawn(consumer, reinterpret_cast<void*>(std::uintptr_t{0}));
  pthread_t c1 = lle_genmc::spawn(consumer, reinterpret_cast<void*>(std::uintptr_t{1}));
  lle_genmc::join(p);
  lle_genmc::join(c0);
  lle_genmc::join(c1);
  assert(ring->cursor_position(0) == ring->write_position());
  assert(ring->cursor_position(1) == ring->write_position());
  lle_genmc::destroy_shared_object(ring);
  return 0;
}

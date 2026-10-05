// Multi-threaded stress tests (08-concurrency-runtime §8), checksummed, with random
// producer and consumer pauses. Built twice: concurrent_stress_long_test
// (-DLLE_STRESS_LONG, ctest label "stress") moves >= 1e8 items through every production
// queue, always at full count; concurrent_stress_test (label "unit") runs the same
// cases at quick counts (stress_util.h). Every item carries its sequence number and a hash of it, so a
// lost, duplicated, reordered or torn item is caught at the consumer.
#include <gtest/gtest.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "common/hash.h"
#include "concurrent/broadcast_ring.h"
#include "concurrent/mpsc_scq.h"
#include "concurrent/mpsc_vyukov.h"
#include "concurrent/spsc_byte_ring.h"
#include "concurrent/spsc_ring.h"
#include "stress_util.h"

namespace lle::conc {
namespace {

using test::Pauser;
using test::stress_items;

// The queue type and the items moved, as gtest properties: tools/stress/run_shards.py
// reads them from --gtest_output=json and appends one ledger record per passed test
// (T28: >= 1e10 items per production queue, accumulated over shards).
void record_items(const char* queue, std::uint64_t items) {
  ::testing::Test::RecordProperty("queue", queue);
  ::testing::Test::RecordProperty("items", std::to_string(items));
}

template <class Q>
struct QueueName;
template <class T, std::size_t Cap>
struct QueueName<MpscScqRing<T, Cap, false>> {
  static constexpr const char* value = "MpscScqRing";
};
template <class T, std::size_t Cap>
struct QueueName<MpscScqRing<T, Cap, true>> {
  static constexpr const char* value = "MpscScqRing<single-consumer>";
};
template <class T, std::size_t Cap>
struct QueueName<VyukovMpscRing<T, Cap>> {
  static constexpr const char* value = "VyukovMpscRing";
};

struct Item {
  std::uint64_t seq;
  std::uint64_t check;  // mix64(seq): detects torn slots
};

// ---- SpscRing ----------------------------------------------------------------------

template <std::size_t Cap>
void spsc_ring_stress(std::uint64_t n, std::uint64_t seed) {
  record_items("SpscRing", n);
  auto q = std::make_unique<SpscRing<Item, Cap>>();
  std::thread producer([&] {
    Pauser pause(seed);
    Backoff wait;
    for (std::uint64_t i = 0; i < n;) {
      pause.maybe_pause();
      bool ok;
      if ((i & 1) == 0) {
        ok = q->try_push(Item{i, mix64(i)});
      } else {
        Item* slot = q->try_claim();  // zero-copy path on odd items
        ok = slot != nullptr;
        if (ok) {
          slot->seq = i;
          slot->check = mix64(i);
          q->commit();
        }
      }
      if (ok) {
        ++i;
        wait.reset();
      } else {
        wait.wait();
      }
    }
  });
  Pauser pause(seed ^ 0xC0FFEE);
  Backoff wait;
  std::uint64_t expect = 0, sum = 0, bad = 0;
  while (expect < n) {
    pause.maybe_pause();
    std::size_t got = 0;
    if ((expect & 3) == 0) {
      got = q->drain(
          [&](const Item& it) {
            bad += static_cast<std::uint64_t>((it.seq != expect) || (it.check != mix64(it.seq)));
            sum += it.seq;
            ++expect;
          },
          64);
    } else {
      Item it{};
      if (q->try_pop(it)) {
        bad += static_cast<std::uint64_t>((it.seq != expect) || (it.check != mix64(it.seq)));
        sum += it.seq;
        ++expect;
        got = 1;
      }
    }
    if (got != 0) {
      wait.reset();
    } else {
      wait.wait();
    }
  }
  producer.join();
  EXPECT_EQ(bad, 0u);
  EXPECT_EQ(sum, n * (n - 1) / 2);
  Item it{};
  EXPECT_FALSE(q->try_pop(it));
}

TEST(SpscRingStress, HundredMillionItems) { spsc_ring_stress<1024>(stress_items(100'000'000, 2'000'000), 11); }
TEST(SpscRingStress, Capacity1) { spsc_ring_stress<1>(stress_items(2'000'000, 100'000), 12); }
TEST(SpscRingStress, Capacity2) { spsc_ring_stress<2>(stress_items(2'000'000, 100'000), 13); }
TEST(SpscRingStress, Capacity4) { spsc_ring_stress<4>(stress_items(2'000'000, 100'000), 14); }

// ---- SpscByteRing ------------------------------------------------------------------

// Record i has payload length 8 + 8 * (mix64(i) % 5) (8..40 bytes, logger-shaped): the
// first word is i, the rest repeat mix64(i).
std::uint32_t record_len(std::uint64_t i) { return static_cast<std::uint32_t>(8 + 8 * (mix64(i) % 5)); }

void write_record(std::byte* p, std::uint64_t i, std::uint32_t len) {
  std::memcpy(p, &i, 8);
  const std::uint64_t h = mix64(i);
  for (std::uint32_t off = 8; off < len; off += 8) std::memcpy(p + off, &h, 8);
}

bool record_ok(const std::byte* p, std::uint32_t len, std::uint64_t expect) {
  if (len != record_len(expect)) return false;
  std::uint64_t v = 0;
  std::memcpy(&v, p, 8);
  if (v != expect) return false;
  const std::uint64_t h = mix64(expect);
  for (std::uint32_t off = 8; off < len; off += 8) {
    std::memcpy(&v, p + off, 8);
    if (v != h) return false;
  }
  return true;
}

void byte_ring_stress(std::size_t cap, std::uint64_t n, std::uint64_t seed) {
  record_items("SpscByteRing", n);
  std::vector<std::uint64_t> storage(cap / 8);
  SpscByteRing q;
  q.init(reinterpret_cast<std::byte*>(storage.data()), cap);
  std::thread producer([&] {
    Pauser pause(seed);
    Backoff wait;
    for (std::uint64_t i = 0; i < n;) {
      pause.maybe_pause();
      const std::uint32_t len = record_len(i);
      std::byte* p = q.try_reserve(len);
      if (p == nullptr) {
        wait.wait();
        continue;
      }
      write_record(p, i, len);
      q.commit();
      ++i;
      wait.reset();
    }
  });
  Pauser pause(seed ^ 0xBEEF);
  Backoff wait;
  std::uint64_t expect = 0, bad = 0;
  while (expect < n) {
    pause.maybe_pause();
    std::size_t got = 0;
    if ((expect & 1) == 0) {
      got = q.drain(
          [&](const std::byte* p, std::uint32_t len) {
            bad += !record_ok(p, len, expect);
            ++expect;
          },
          32);
    } else {
      std::uint32_t len = 0;
      if (const std::byte* p = q.peek(len)) {
        bad += !record_ok(p, len, expect);
        ++expect;
        q.release();
        got = 1;
      }
    }
    if (got != 0) {
      wait.reset();
    } else {
      wait.wait();
    }
  }
  producer.join();
  EXPECT_EQ(bad, 0u);
  std::uint32_t len = 0;
  EXPECT_EQ(q.peek(len), nullptr);
}

TEST(SpscByteRingStress, HundredMillionRecords) { byte_ring_stress(64 * 1024, stress_items(100'000'000, 2'000'000), 21); }
TEST(SpscByteRingStress, TinyRingForcesWrap) { byte_ring_stress(128, stress_items(5'000'000, 100'000), 22); }

// ---- BroadcastRing -----------------------------------------------------------------

void broadcast_stress(std::size_t cap, std::uint64_t n, std::uint64_t seed) {
  record_items("BroadcastRing", n);
  constexpr std::size_t kConsumers = 3;
  std::vector<std::uint64_t> storage(cap / 8);
  auto q = std::make_unique<BroadcastRing<kConsumers>>();
  q->init(reinterpret_cast<std::byte*>(storage.data()), cap);
  std::uint64_t bad[kConsumers] = {};
  std::vector<std::thread> consumers;
  for (std::size_t c = 0; c < kConsumers; ++c) {
    consumers.emplace_back([&, c] {
      Pauser pause(seed + 100 + c);
      Backoff wait;
      std::uint64_t expect = 0;
      while (expect < n) {
        pause.maybe_pause();
        const std::size_t got = q->drain(
            c,
            [&](const std::byte* p, std::uint32_t len) {
              bad[c] += !record_ok(p, len, expect);
              ++expect;
            },
            1 + c * 16);  // different batch sizes per consumer
        if (got != 0) {
          wait.reset();
        } else {
          wait.wait();
        }
      }
    });
  }
  Pauser pause(seed);
  Backoff wait;
  for (std::uint64_t i = 0; i < n;) {
    pause.maybe_pause();
    const std::uint32_t len = record_len(i);
    std::byte* p = q->try_reserve(len);
    if (p == nullptr) {
      wait.wait();
      continue;
    }
    write_record(p, i, len);
    q->commit();
    ++i;
    wait.reset();
  }
  for (auto& t : consumers) t.join();
  for (std::size_t c = 0; c < kConsumers; ++c) {
    EXPECT_EQ(bad[c], 0u) << "consumer " << c;
    EXPECT_EQ(q->cursor_position(c), q->write_position());
  }
}

TEST(BroadcastRingStress, HundredMillionRecordsThreeCursors) {
  broadcast_stress(64 * 1024, stress_items(100'000'000, 1'000'000), 31);
}
TEST(BroadcastRingStress, TinyRingForcesWrap) { broadcast_stress(128, stress_items(1'000'000, 50'000), 32); }

// ---- MPSC (SCQ and Vyukov baseline) ------------------------------------------------

// Item = producer id in the top 8 bits, per-producer sequence number below.
constexpr unsigned kSeqBits = 56;
constexpr std::uint64_t kSeqMask = (std::uint64_t{1} << kSeqBits) - 1;

template <class Q>
void mpsc_stress(std::size_t producers, std::uint64_t per_producer, std::uint64_t seed) {
  record_items(QueueName<Q>::value, producers * per_producer);
  auto q = std::make_unique<Q>();
  std::vector<std::thread> threads;
  for (std::size_t p = 0; p < producers; ++p) {
    threads.emplace_back([&, p] {
      Pauser pause(seed + p);
      Backoff wait;
      for (std::uint64_t i = 0; i < per_producer;) {
        pause.maybe_pause();
        if (q->try_push((static_cast<std::uint64_t>(p) << kSeqBits) | i)) {
          ++i;
          wait.reset();
        } else {
          wait.wait();
        }
      }
    });
  }
  std::vector<std::uint64_t> next(producers, 0);
  std::uint64_t received = 0, fifo_violations = 0, bad_ids = 0, sum = 0;
  const std::uint64_t total = per_producer * producers;
  Pauser pause(seed ^ 0xFACE);
  Backoff wait;
  while (received < total) {
    pause.maybe_pause();
    std::uint64_t v = 0;
    if (!q->try_pop(v)) {
      wait.wait();
      continue;
    }
    wait.reset();
    const std::uint64_t p = v >> kSeqBits;
    const std::uint64_t s = v & kSeqMask;
    if (p >= producers) {
      ++bad_ids;
    } else {
      // Per-producer FIFO and no loss: producer p's items arrive as 0, 1, 2, ...
      fifo_violations += (s != next[p]);
      next[p] = s + 1;
    }
    sum += s;
    ++received;
  }
  for (auto& t : threads) t.join();
  std::uint64_t v = 0;
  EXPECT_FALSE(q->try_pop(v));  // nothing extra (no duplicates)
  EXPECT_EQ(bad_ids, 0u);
  EXPECT_EQ(fifo_violations, 0u);
  for (std::size_t p = 0; p < producers; ++p) EXPECT_EQ(next[p], per_producer) << "producer " << p;
  EXPECT_EQ(sum, producers * (per_producer * (per_producer - 1) / 2));  // multiset equality
}

// SCQ: 1e8 items in total over 1..4 producers.
TEST(MpscScqStress, OneProducer) { mpsc_stress<MpscScqRing<std::uint64_t, 1024>>(1, stress_items(25'000'000, 500'000), 41); }
TEST(MpscScqStress, TwoProducers) { mpsc_stress<MpscScqRing<std::uint64_t, 1024>>(2, stress_items(12'500'000, 250'000), 42); }
TEST(MpscScqStress, ThreeProducers) {
  mpsc_stress<MpscScqRing<std::uint64_t, 1024>>(3, stress_items(8'333'334, 166'667), 43);
}
TEST(MpscScqStress, FourProducers) { mpsc_stress<MpscScqRing<std::uint64_t, 1024>>(4, stress_items(6'250'000, 125'000), 44); }
// Capacity edges: Cap = number of producers (the paper's k <= n bound at its limit).
TEST(MpscScqStress, Capacity1OneProducer) { mpsc_stress<MpscScqRing<std::uint64_t, 1>>(1, stress_items(1'000'000, 50'000), 45); }
TEST(MpscScqStress, Capacity2TwoProducers) { mpsc_stress<MpscScqRing<std::uint64_t, 2>>(2, stress_items(500'000, 25'000), 46); }
TEST(MpscScqStress, Capacity4FourProducers) { mpsc_stress<MpscScqRing<std::uint64_t, 4>>(4, stress_items(250'000, 12'500), 47); }
// More producers than capacity: try_push may report full spuriously, but nothing is
// lost, duplicated or reordered.
TEST(MpscScqStress, Capacity2FourProducers) { mpsc_stress<MpscScqRing<std::uint64_t, 2>>(4, stress_items(250'000, 12'500), 48); }

// The single-consumer specialization (ADR-031; not on the production path).
TEST(MpscScqScStress, OneProducer) {
  mpsc_stress<MpscScqRing<std::uint64_t, 1024, true>>(1, stress_items(25'000'000, 500'000), 61);
}
TEST(MpscScqScStress, FourProducers) {
  mpsc_stress<MpscScqRing<std::uint64_t, 1024, true>>(4, stress_items(6'250'000, 125'000), 62);
}
TEST(MpscScqScStress, Capacity2TwoProducers) {
  mpsc_stress<MpscScqRing<std::uint64_t, 2, true>>(2, stress_items(500'000, 25'000), 63);
}

TEST(MpscVyukovStress, OneProducer) { mpsc_stress<VyukovMpscRing<std::uint64_t, 1024>>(1, stress_items(10'000'000, 200'000), 51); }
TEST(MpscVyukovStress, FourProducers) { mpsc_stress<VyukovMpscRing<std::uint64_t, 1024>>(4, stress_items(2'500'000, 50'000), 52); }
TEST(MpscVyukovStress, Capacity2TwoProducers) { mpsc_stress<VyukovMpscRing<std::uint64_t, 2>>(2, stress_items(500'000, 25'000), 53); }

}  // namespace
}  // namespace lle::conc

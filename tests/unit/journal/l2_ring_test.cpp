// L2 broadcast ring (06 §5): multi-cursor delivery, back-pressure, restart validation.
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "common/prng.h"
#include "journal/l2_ring.h"
#include "journal/l2_storage.h"
#include "journal/record.h"

namespace lle::journal {
namespace {

constexpr std::size_t kCap = 256 * 1024;
constexpr std::uint64_t kNonce = 0xFEEDBEEF12345677ull;

struct Buf {
  explicit Buf(std::size_t n) : p(new std::uint64_t[n / 8]()) {}
  std::byte* data() { return reinterpret_cast<std::byte*>(p.get()); }
  std::unique_ptr<std::uint64_t[]> p;
};

// Appends `n` OUCH records continuing `b`; returns false on back-pressure.
bool append(L2Ring<3>& ring, RecordBuilder& b, Prng& rng, std::size_t n, std::vector<std::vector<std::byte>>* out) {
  std::vector<std::byte> msg(140);
  for (auto& x : msg) x = static_cast<std::byte>(rng.next_u64());
  for (std::size_t i = 0; i < n; ++i) {
    const OuchInbound o{1, 2, 3, std::span<const std::byte>(msg).first(rng.below(141))};
    std::byte* dst = ring.try_reserve(record_size(o));
    if (dst == nullptr) return false;
    const auto r = b.append(std::span<std::byte>(dst, record_size(o)), b.chain().last_ts + 10, o);
    if (out != nullptr) out->emplace_back(r.begin(), r.end());
    ring.commit();
  }
  return true;
}

TEST(L2Ring, EveryCursorSeesEveryRecordInOrder) {
  Buf buf(kCap);
  L2Ring<3> ring;
  ring.init(buf.data(), kCap, kNonce);
  RecordBuilder b(ring.sealer());
  Prng rng(1);
  std::vector<std::vector<std::byte>> sent;
  for (int round = 0; round < 50; ++round) {
    ASSERT_TRUE(append(ring, b, rng, 40, &sent));
    for (std::size_t c = 0; c < 3; ++c) {
      std::size_t got = 0;
      while (ring.drain(
                 c,
                 [&](const RecordView& v) {
                   EXPECT_TRUE(ring.sealer().verify(v.data()).has_value());
                   ++got;
                 },
                 7) != 0) {
      }
      EXPECT_EQ(got, 40u);
    }
  }
  // Cursor-by-cursor content check with peek/release.
  ASSERT_TRUE(append(ring, b, rng, 5, &sent));
  for (std::size_t c = 0; c < 3; ++c) {
    for (std::size_t k = sent.size() - 5; k < sent.size(); ++k) {
      const RecordView v = ring.peek(c);
      ASSERT_FALSE(v.empty());
      EXPECT_EQ(std::vector<std::byte>(v.bytes().begin(), v.bytes().end()), sent[k]);
      ring.release(c);
    }
    EXPECT_TRUE(ring.peek(c).empty());
  }
}

TEST(L2Ring, SlowestCursorGatesTheWriter) {
  Buf buf(kCap);
  L2Ring<3> ring;
  ring.init(buf.data(), kCap, kNonce);
  RecordBuilder b(ring.sealer());
  Prng rng(2);
  std::size_t appended = 0;
  while (append(ring, b, rng, 1, nullptr)) ++appended;
  EXPECT_GT(appended, 1000u);
  EXPECT_GE(ring.backlog(1), kCap - 2 * (kMaxRecordBytes + 8));
  // Two cursors catch up; the third still gates.
  for (std::size_t c : {std::size_t{0}, std::size_t{2}}) {
    while (ring.drain(c, [](const RecordView&) {}, 64) != 0) {
    }
  }
  EXPECT_FALSE(append(ring, b, rng, 1, nullptr));
  std::size_t freed = ring.drain(1, [](const RecordView&) {}, 100);
  EXPECT_EQ(freed, 100u);
  EXPECT_TRUE(append(ring, b, rng, 1, nullptr));
}

// Restart: a new process maps the same storage and revalidates by CRC and chain.
TEST(L2Ring, RestoreRepublishesTheChainFromAnIndex) {
  for (int variant = 0; variant < 4; ++variant) {
    Buf buf(kCap);
    std::vector<std::vector<std::byte>> sent;
    ChainState at_durable{};
    std::uint64_t durable = 0;
    {
      L2Ring<3> ring;
      ring.init(buf.data(), kCap, kNonce);
      RecordBuilder b(ring.sealer());
      Prng rng(3 + static_cast<std::uint64_t>(variant));
      // Several laps around the ring (cursors keep up), so the live chain wraps.
      for (int lap = 0; lap < 12; ++lap) {
        ASSERT_TRUE(append(ring, b, rng, 300, &sent));
        for (std::size_t c = 0; c < 3; ++c) {
          while (ring.drain(c, [](const RecordView&) {}, 1000) != 0) {
          }
        }
      }
      ASSERT_TRUE(append(ring, b, rng, 500, &sent));  // in L2, not consumed yet
      durable = sent.size() - 700;
      const RecordView last_durable(sent[durable - 1]);
      at_durable = ChainState{durable, last_durable.content(), last_durable.ts_ns(), last_durable.epoch()};
    }  // "crash": the ring object is gone, the storage survives

    std::uint64_t expect_last = sent.size();
    if (variant == 1) {
      // A corrupted record: the restored chain stops just before it.
      const RecordView victim(sent[sent.size() - 100]);
      for (std::size_t off = 0; off + 48 <= kCap; off += 8) {
        if (std::memcmp(buf.data() + off + 8, victim.data(), 40) == 0) {
          buf.data()[off + 8 + 44] ^= std::byte{1};
          break;
        }
      }
      expect_last = sent.size() - 100;
    }
    L2Ring<3> ring;
    ring.init(buf.data(), kCap, kNonce);
    const auto prev = variant == 2 ? std::optional<std::uint32_t>(at_durable.last_crc ^ 1)
                                   : std::optional<std::uint32_t>(at_durable.last_crc);
    const L2RestoreResult r = ring.restore(durable + 1, variant == 3 ? std::nullopt : prev);
    if (variant == 2) {  // the ring holds a different history: nothing restored
      EXPECT_FALSE(r.found);
      EXPECT_TRUE(ring.peek(0).empty());
      continue;
    }
    ASSERT_TRUE(r.found);
    EXPECT_EQ(r.chain.last_index, expect_last);
    EXPECT_EQ(r.records, expect_last - durable);
    EXPECT_EQ(r.chain.last_crc, RecordView(sent[expect_last - 1]).content());
    for (std::size_t c = 0; c < 3; ++c) {
      std::uint64_t next = durable + 1;
      while (ring.drain(
                 c,
                 [&](const RecordView& v) {
                   EXPECT_EQ(v.index(), next);
                   EXPECT_TRUE(same_content(v, RecordView(sent[next - 1])));
                   ++next;
                 },
                 64) != 0) {
      }
      EXPECT_EQ(next, expect_last + 1);
    }
    // The sequencer continues after the restored chain.
    RecordBuilder b(ring.sealer(), r.chain);
    Prng rng(99);
    ASSERT_TRUE(append(ring, b, rng, 10, nullptr));
    EXPECT_EQ(b.chain().last_index, expect_last + 10);
    // A second restore from the same point finds exactly one copy of each record.
    const L2RestoreResult r2 = ring.restore(durable + 1, prev);
    EXPECT_EQ(r2.chain.last_index, expect_last + 10);
  }
}

TEST(L2Ring, RestoreOfMissingIndexIsEmpty) {
  Buf buf(kCap);
  L2Ring<3> ring;
  ring.init(buf.data(), kCap, kNonce);
  RecordBuilder b(ring.sealer());
  Prng rng(5);
  ASSERT_TRUE(append(ring, b, rng, 50, nullptr));
  const L2RestoreResult r = ring.restore(51, std::nullopt);  // everything was durable
  EXPECT_FALSE(r.found);
  EXPECT_EQ(r.records, 0u);
  EXPECT_TRUE(ring.peek(0).empty());
}

TEST(L2Storage, FileBackedRingSurvivesProcessRestart) {
  const auto dir = std::filesystem::temp_directory_path() / ("lle_l2_" + std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  L2StorageOptions o;
  o.path = (dir / "l2-0-20260930-1.ring").string();
  o.capacity = kCap;
  o.day = 20260930;
  o.epoch = 1;
  Prng rng(7);
  std::vector<std::vector<std::byte>> sent;
  std::uint64_t nonce = 0;
  {
    auto s = L2Storage::open(o, rng);
    ASSERT_TRUE(s.has_value()) << s.error();
    EXPECT_FALSE(s->reopened());
    nonce = s->nonce();
    L2Ring<3> ring;
    ring.init(s->data(), s->capacity(), s->nonce());
    RecordBuilder b(ring.sealer());
    ASSERT_TRUE(append(ring, b, rng, 200, &sent));
  }
  {
    auto s = L2Storage::open(o, rng);
    ASSERT_TRUE(s.has_value());
    EXPECT_TRUE(s->reopened());
    EXPECT_EQ(s->nonce(), nonce);
    L2Ring<3> ring;
    ring.init(s->data(), s->capacity(), s->nonce());
    const L2RestoreResult r = ring.restore(101, RecordView(sent[99]).content());
    ASSERT_TRUE(r.found);
    EXPECT_EQ(r.chain.last_index, 200u);
  }
  {
    // Another epoch: a new ring with a fresh nonce; the old records never validate.
    o.epoch = 2;
    auto s = L2Storage::open(o, rng);
    ASSERT_TRUE(s.has_value());
    EXPECT_FALSE(s->reopened());
    EXPECT_NE(s->nonce(), nonce);
    L2Ring<3> ring;
    ring.init(s->data(), s->capacity(), s->nonce());
    EXPECT_FALSE(ring.restore(101, std::nullopt).found);
  }
  {
    auto s = L2Storage::open(L2StorageOptions{"", kCap, 4096, 0, 0, 0, true}, rng);
    ASSERT_TRUE(s.has_value());
    EXPECT_FALSE(s->reopened());
  }
  std::filesystem::remove_all(dir);
}

}  // namespace
}  // namespace lle::journal

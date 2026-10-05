// Loader validation and payload cursor (06 §9): round trips, typed values across
// chunk boundaries, corruption and truncation at every byte, chunk swaps and
// splices, crafted headers with valid CRCs, reads past the end.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>
#include <variant>
#include <vector>

#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"
#include "snapshot_test_util.h"

namespace lle::snap {
namespace {

using test::open_error;

constexpr std::uint32_t kSmallChunk = 4096;

TEST(SnapshotReader, RoundTripSizes) {
  Prng rng(1);
  const auto sessions = test::sample_sessions();
  for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{100}, std::size_t{kSmallChunk - 1},
                              std::size_t{kSmallChunk}, std::size_t{kSmallChunk + 1}, std::size_t{3 * kSmallChunk - 1},
                              std::size_t{3 * kSmallChunk}, std::size_t{3 * kSmallChunk + 1}}) {
    SCOPED_TRACE(n);
    const auto payload = test::random_bytes(rng, n);
    const auto meta = test::sample_meta(n + 1);
    const auto img = test::encode_or_die(meta, sessions, payload, kSmallChunk);
    auto r = Reader::open(img);
    ASSERT_TRUE(r.has_value()) << to_string(r.error());
    EXPECT_EQ(r->meta(), meta);
    EXPECT_EQ(std::vector<SessionSeq>(r->sessions().begin(), r->sessions().end()), sessions);
    EXPECT_EQ(r->layout().payload_bytes, n);
    EXPECT_EQ(r->layout().chunk_count, (n + kSmallChunk - 1) / kSmallChunk);
    EXPECT_EQ(r->layout().file_bytes, img.size());
    EXPECT_EQ(img.size() % 8, 0u);
    EXPECT_EQ(r->remaining(), n);
    EXPECT_EQ(test::read_rest(*r), payload);
    EXPECT_EQ(r->remaining(), 0u);
    EXPECT_TRUE(r->ok());
  }
}

TEST(SnapshotReader, EmptyPayloadNoSessions) {
  const auto img = test::encode_or_die(test::sample_meta(), {}, {}, kDefaultChunkBytes);
  EXPECT_EQ(img.size(), kHeaderBytes + kSessionTableTailBytes + kTrailerBytes);
  auto r = Reader::open(img);
  ASSERT_TRUE(r.has_value());
  EXPECT_TRUE(r->sessions().empty());
  EXPECT_EQ(r->remaining(), 0u);
  EXPECT_EQ(r->get_u8(), 0u);
  EXPECT_FALSE(r->ok());
}

// Typed values written at every alignment relative to chunk boundaries read back
// exactly; this also checks the writer's and reader's fast and slow paths agree.
TEST(SnapshotReader, TypedRoundTripAcrossChunkBoundaries) {
  using Value = std::variant<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, std::int32_t, std::int64_t,
                             std::vector<std::byte>>;
  Prng rng(2);
  std::vector<Value> script;
  WriterOptions opts;
  opts.chunk_bytes = kSmallChunk;
  auto w = Writer::create_in_memory(test::sample_meta(), {}, opts);
  ASSERT_TRUE(w.has_value());
  for (int i = 0; i < 6000; ++i) {
    switch (rng.below(7)) {
      case 0: script.emplace_back(static_cast<std::uint8_t>(rng.next_u64())); break;
      case 1: script.emplace_back(static_cast<std::uint16_t>(rng.next_u64())); break;
      case 2: script.emplace_back(static_cast<std::uint32_t>(rng.next_u64())); break;
      case 3: script.emplace_back(rng.next_u64()); break;
      case 4: script.emplace_back(static_cast<std::int32_t>(rng.next_u64())); break;
      case 5: script.emplace_back(static_cast<std::int64_t>(rng.next_u64())); break;
      default: script.emplace_back(test::random_bytes(rng, rng.below(40))); break;
    }
    std::visit(
        [&](const auto& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, std::uint8_t>) w->put_u8(v);
          if constexpr (std::is_same_v<T, std::uint16_t>) w->put_u16(v);
          if constexpr (std::is_same_v<T, std::uint32_t>) w->put_u32(v);
          if constexpr (std::is_same_v<T, std::uint64_t>) w->put_u64(v);
          if constexpr (std::is_same_v<T, std::int32_t>) w->put_i32(v);
          if constexpr (std::is_same_v<T, std::int64_t>) w->put_i64(v);
          if constexpr (std::is_same_v<T, std::vector<std::byte>>) w->put_bytes(v);
        },
        script.back());
  }
  ASSERT_TRUE(w->ok());
  const std::uint64_t written = w->payload_bytes();
  auto img = w->finish_image();
  ASSERT_TRUE(img.has_value());
  auto r = Reader::open(*img);
  ASSERT_TRUE(r.has_value());
  ASSERT_EQ(r->remaining(), written);
  ASSERT_GT(r->layout().chunk_count, 5u);
  for (const Value& expected : script) {
    std::visit(
        [&](const auto& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, std::uint8_t>) EXPECT_EQ(r->get_u8(), v);
          if constexpr (std::is_same_v<T, std::uint16_t>) EXPECT_EQ(r->get_u16(), v);
          if constexpr (std::is_same_v<T, std::uint32_t>) EXPECT_EQ(r->get_u32(), v);
          if constexpr (std::is_same_v<T, std::uint64_t>) EXPECT_EQ(r->get_u64(), v);
          if constexpr (std::is_same_v<T, std::int32_t>) EXPECT_EQ(r->get_i32(), v);
          if constexpr (std::is_same_v<T, std::int64_t>) EXPECT_EQ(r->get_i64(), v);
          if constexpr (std::is_same_v<T, std::vector<std::byte>>) {
            std::vector<std::byte> got(v.size());
            EXPECT_TRUE(r->get_bytes(got));
            EXPECT_EQ(got, v);
          }
        },
        expected);
  }
  EXPECT_TRUE(r->ok());
  EXPECT_EQ(r->remaining(), 0u);
}

// The typed helpers are exactly little-endian bytes: a u64 straddling the first
// chunk boundary is split across the two chunks in the image.
TEST(SnapshotReader, TypedValueStraddlingABoundaryIsLittleEndianBytes) {
  WriterOptions opts;
  opts.chunk_bytes = kSmallChunk;
  auto w = Writer::create_in_memory(test::sample_meta(), {}, opts);
  ASSERT_TRUE(w.has_value());
  const std::vector<std::byte> filler(kSmallChunk - 3, std::byte{0xEE});
  w->write(filler);
  w->put_u64(0x0807060504030201ull);
  w->put_i64(-2);
  auto img = w->finish_image();
  ASSERT_TRUE(img.has_value());

  std::vector<std::byte> manual = filler;
  for (std::uint8_t b = 1; b <= 8; ++b) manual.push_back(std::byte{b});
  for (int i = 0; i < 8; ++i) manual.push_back(std::byte{i == 0 ? std::uint8_t{0xFE} : std::uint8_t{0xFF}});
  EXPECT_EQ(*img, test::encode_or_die(test::sample_meta(), {}, manual, kSmallChunk));

  auto r = Reader::open(*img);
  ASSERT_TRUE(r.has_value());
  ASSERT_TRUE(r->skip(filler.size()));
  EXPECT_EQ(r->position(), kSmallChunk - 3);
  EXPECT_EQ(r->get_u64(), 0x0807060504030201ull);
  EXPECT_EQ(r->get_i64(), -2);
  EXPECT_EQ(r->remaining(), 0u);
}

TEST(SnapshotReader, ReadingPastTheEndFailsAndIsSticky) {
  std::vector<std::byte> payload(10);
  for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>(i + 1);
  const auto img = test::encode_or_die(test::sample_meta(), {}, payload, kSmallChunk);
  {
    auto r = Reader::open(img);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->get_u64(), 0x0807060504030201ull);
    EXPECT_EQ(r->get_u32(), 0u);  // 2 bytes left
    EXPECT_FALSE(r->ok());
    EXPECT_EQ(r->remaining(), 2u);  // nothing consumed
    EXPECT_EQ(r->get_u8(), 0u);     // sticky even though it would fit
    std::vector<std::byte> out(1, std::byte{0x77});
    EXPECT_FALSE(r->read(out));
    EXPECT_EQ(out[0], std::byte{0});
  }
  {
    auto r = Reader::open(img);
    ASSERT_TRUE(r.has_value());
    std::vector<std::byte> out(11, std::byte{0x77});
    EXPECT_FALSE(r->read(out));
    EXPECT_EQ(out, std::vector<std::byte>(11));  // zero-filled
    EXPECT_FALSE(r->ok());
  }
  {
    auto r = Reader::open(img);
    ASSERT_TRUE(r.has_value());
    EXPECT_FALSE(r->skip(11));
    EXPECT_FALSE(r->ok());
  }
  {
    auto r = Reader::open(img);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->skip(10));
    EXPECT_TRUE(r->read({}));  // an empty read at the end is fine
    EXPECT_TRUE(r->ok());
    EXPECT_FALSE(r->skip(std::numeric_limits<std::uint64_t>::max()));
  }
}

TEST(SnapshotReader, SessionsRoundTripAndOrderIsEnforced) {
  const std::vector<SessionSeq> sessions = {{0, 0}, {1, 1}, {0xFFFFFFFFu, 0xFFFFFFFFFFFFFFFFull}};
  const auto img = test::encode_or_die(test::sample_meta(), sessions, {}, kSmallChunk);
  auto r = Reader::open(img);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(std::vector<SessionSeq>(r->sessions().begin(), r->sessions().end()), sessions);

  const std::vector<SessionSeq> unsorted = {{5, 1}, {3, 1}};
  const std::vector<SessionSeq> duplicate = {{3, 1}, {3, 2}};
  for (const auto* bad : {&unsorted, &duplicate}) {
    auto e = encode_image(test::sample_meta(), *bad, {}, kSmallChunk);
    ASSERT_FALSE(e.has_value());
    EXPECT_EQ(e.error().code, ErrorCode::UnsortedSessions);
  }

  // Swapped entries behind valid CRCs are still rejected by the loader.
  auto swapped = img;
  std::byte tmp[kSessionEntryBytes];
  std::memcpy(tmp, swapped.data() + kHeaderBytes, kSessionEntryBytes);
  std::memcpy(swapped.data() + kHeaderBytes, swapped.data() + kHeaderBytes + kSessionEntryBytes, kSessionEntryBytes);
  std::memcpy(swapped.data() + kHeaderBytes + kSessionEntryBytes, tmp, kSessionEntryBytes);
  test::reseal_all(swapped);
  EXPECT_EQ(open_error(swapped), LoadError::UnsortedSessions);

  auto dup = img;
  std::memcpy(dup.data() + kHeaderBytes + kSessionEntryBytes, dup.data() + kHeaderBytes, kSessionEntryBytes);
  test::reseal_all(dup);
  EXPECT_EQ(open_error(dup), LoadError::UnsortedSessions);
}

// A ~9 KiB image: header, 3 sessions, two full 4 KiB chunks and a short one.
std::vector<std::byte> small_image(std::uint64_t seed = 3) {
  Prng rng(seed);
  return test::encode_or_die(test::sample_meta(), test::sample_sessions(), test::random_bytes(rng, 9000),
                             kSmallChunk);
}

TEST(SnapshotReader, EveryCorruptedByteIsDetected) {
  const auto img = small_image();
  ASSERT_TRUE(Reader::open(img).has_value());
  auto copy = img;
  for (std::size_t i = 0; i < img.size(); ++i) {
    for (const std::uint8_t mask : {std::uint8_t{0x01}, std::uint8_t{0x80}, std::uint8_t{0xFF}}) {
      copy[i] ^= std::byte{mask};
      EXPECT_FALSE(Reader::open(copy).has_value()) << "offset " << i << " mask " << int{mask};
      copy[i] = img[i];
    }
  }
}

TEST(SnapshotReader, EveryTruncationIsDetected) {
  const auto img = small_image();
  for (std::size_t n = 0; n < img.size(); ++n) {
    EXPECT_FALSE(Reader::open(std::span<const std::byte>(img).first(n)).has_value()) << "length " << n;
  }
  auto longer = img;
  longer.push_back(std::byte{0});
  EXPECT_EQ(open_error(longer), LoadError::BadLength);
  longer.resize(img.size() + 8);
  EXPECT_EQ(open_error(longer), LoadError::BadLength);
}

TEST(SnapshotReader, SwappedOrDuplicatedChunksAreDetected) {
  Prng rng(4);
  const auto img =
      test::encode_or_die(test::sample_meta(), {}, test::random_bytes(rng, 3 * kSmallChunk), kSmallChunk);
  auto r = Reader::open(img);
  ASSERT_TRUE(r.has_value());
  const std::size_t frame = kSmallChunk + 8;  // data + crc + pad
  const auto off = static_cast<std::size_t>(r->layout().payload_offset);

  auto swapped = img;
  std::vector<std::byte> tmp(img.begin() + static_cast<std::ptrdiff_t>(off),
                             img.begin() + static_cast<std::ptrdiff_t>(off + frame));
  std::memcpy(swapped.data() + off, img.data() + off + frame, frame);
  std::memcpy(swapped.data() + off + frame, tmp.data(), frame);
  EXPECT_EQ(open_error(swapped), LoadError::BadChunkCrc);

  auto duplicated = img;
  std::memcpy(duplicated.data() + off + frame, img.data() + off, frame);
  EXPECT_EQ(open_error(duplicated), LoadError::BadChunkCrc);
}

// Chunk 1 of another snapshot with the same layout carries a valid CRC for
// index 1; only the trailer's cross-section CRC can catch the splice.
TEST(SnapshotReader, ChunkSplicedFromAnotherSnapshotIsDetected) {
  const auto a = small_image(5);
  const auto b = small_image(6);
  ASSERT_EQ(a.size(), b.size());
  auto r = Reader::open(a);
  ASSERT_TRUE(r.has_value());
  const auto off = static_cast<std::size_t>(r->layout().payload_offset) + (kSmallChunk + 8);
  auto spliced = a;
  std::memcpy(spliced.data() + off, b.data() + off, kSmallChunk + 8);
  EXPECT_EQ(open_error(spliced), LoadError::BadTrailer);
}

TEST(SnapshotReader, CraftedHeadersWithValidCrcs) {
  const auto img = small_image();
  auto edit32 = [&](std::size_t off, std::uint32_t v) {
    auto c = img;
    if (c.data() == nullptr) return c;  // lets GCC prove the pointer non-null
    store_le32(c.data() + off, v);
    test::reseal_header(c);
    return c;
  };
  auto edit64 = [&](std::size_t off, std::uint64_t v) {
    auto c = img;
    if (c.data() == nullptr) return c;  // lets GCC prove the pointer non-null
    store_le64(c.data() + off, v);
    test::reseal_header(c);
    return c;
  };
  EXPECT_EQ(open_error(std::span<const std::byte>(img).first(kHeaderBytes - 1)), LoadError::Truncated);
  {
    auto c = img;
    c[0] = std::byte{'X'};
    EXPECT_EQ(open_error(c), LoadError::BadMagic);
  }
  EXPECT_EQ(open_error(edit32(hdr::kVersion, 2)), LoadError::UnsupportedVersion);
  EXPECT_EQ(open_error(edit32(hdr::kHeaderBytes, 64)), LoadError::BadHeader);
  EXPECT_EQ(open_error(edit32(hdr::kFlags, 1)), LoadError::BadHeader);
  EXPECT_EQ(open_error(edit32(hdr::kReserved + 32, 1)), LoadError::BadHeader);
  {
    auto c = img;
    c[hdr::kDay] ^= std::byte{1};  // CRC not resealed
    EXPECT_EQ(open_error(c), LoadError::BadHeaderCrc);
  }
  for (const std::uint32_t cb : {0u, 1u, 2048u, 4095u, 4097u, 0x80000000u, 0xFFFFFFFFu}) {
    EXPECT_EQ(open_error(edit32(hdr::kChunkBytes, cb)), LoadError::BadChunkSize) << cb;
  }
  EXPECT_EQ(open_error(edit32(hdr::kChunkCount, 2)), LoadError::BadChunkCount);
  EXPECT_EQ(open_error(edit32(hdr::kChunkCount, 4)), LoadError::BadChunkCount);
  // Hostile sizes: no overflow, no huge allocation, just a clean error.
  EXPECT_EQ(open_error(edit64(hdr::kPayloadBytes, std::numeric_limits<std::uint64_t>::max())),
            LoadError::BadChunkCount);
  {
    auto c = edit64(hdr::kPayloadBytes, std::uint64_t{kSmallChunk} * 0xFFFFFFFFull);
    std::byte* const p = c.data();
    ASSERT_NE(p, nullptr);
    store_le32(p + hdr::kChunkCount, 0xFFFFFFFFu);
    test::reseal_header(c);
    EXPECT_EQ(open_error(c), LoadError::Truncated);
  }
  EXPECT_EQ(open_error(edit32(hdr::kSessionCount, 0xFFFFFFFFu)), LoadError::Truncated);
  EXPECT_EQ(open_error(edit32(hdr::kSessionCount, 2)), LoadError::BadLength);  // file now 16 bytes too long
}

TEST(SnapshotReader, NonZeroPaddingAndReservedFieldsBehindValidCrcs) {
  const auto img = small_image();
  auto r = Reader::open(img);
  ASSERT_TRUE(r.has_value());
  const SnapshotLayout l = r->layout();
  {
    auto c = img;  // session entry reserved field
    c[kHeaderBytes + 4] = std::byte{1};
    test::reseal_all(c);
    EXPECT_EQ(open_error(c), LoadError::BadSessionTable);
  }
  {
    auto c = img;  // session table pad
    c[kHeaderBytes + kSessionEntryBytes * l.session_count + 4] = std::byte{1};
    test::reseal_all(c);
    EXPECT_EQ(open_error(c), LoadError::BadSessionTable);
  }
  {
    auto c = img;  // pad after the first chunk's CRC
    c[l.payload_offset + kSmallChunk + 4] = std::byte{1};
    test::reseal_all(c);
    EXPECT_EQ(open_error(c), LoadError::BadPadding);
  }
  {
    auto c = img;  // pad after the last (short) chunk's CRC: 9000 - 8192 = 808 bytes + crc + 4 pad
    c[l.file_bytes - kTrailerBytes - 1] = std::byte{1};
    test::reseal_all(c);
    EXPECT_EQ(open_error(c), LoadError::BadPadding);
  }
  {
    auto c = img;  // trailer pad
    c[l.file_bytes - 1] = std::byte{1};
    test::reseal_all(c);
    EXPECT_EQ(open_error(c), LoadError::BadTrailer);
  }
}

TEST(SnapshotReader, RandomInputsNeverValidate) {
  Prng rng(9);
  for (int i = 0; i < 2000; ++i) {
    auto junk = test::random_bytes(rng, rng.below(600));
    if (junk.size() >= 8 && rng.chance(1, 2)) std::memcpy(junk.data(), kMagic.data(), kMagic.size());
    EXPECT_FALSE(Reader::open(junk).has_value());
  }
}

}  // namespace
}  // namespace lle::snap

// Snapshot format v1 golden tests, layout arithmetic and file naming (06 §9).
// The golden CRC values were computed with an independent bitwise CRC32C
// (reflected polynomial 0x82F63B78), not with lle::crc32c.
#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"
#include "snapshot_test_util.h"

namespace lle::snap {
namespace {

using test::TempDir;

SnapshotMeta golden_meta() {
  SnapshotMeta m;
  m.day = 20260930;
  m.epoch = 3;
  m.index = 0x0102030405060708ull;
  m.snapshot_id = 42;
  m.mold_seq = 0x1122334455667788ull;
  m.state_hash = 0xDEADBEEFCAFEF00Dull;
  m.build_id = 0xABCDEF;
  return m;
}

// Header for golden_meta() with chunk_bytes 4096, 2 sessions, 10000 payload
// bytes (3 chunks), hand-assembled from the offset table in format.h.
constexpr std::uint8_t kGoldenHeader[kHeaderBytes] = {
    'L',  'L',  'E',  'S',  'N',  'A',  'P',  '1',   //   0 magic
    0x01, 0x00, 0x00, 0x00,                          //   8 version 1
    0x80, 0x00, 0x00, 0x00,                          //  12 header_bytes 128
    0x42, 0x28, 0x35, 0x01,                          //  16 day 20260930 = 0x01352842
    0x03, 0x00, 0x00, 0x00,                          //  20 epoch 3
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,  //  24 index
    0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  32 snapshot_id 42
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,  //  40 mold_seq
    0x0D, 0xF0, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,  //  48 state_hash
    0xEF, 0xCD, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00,  //  56 build_id
    0x00, 0x10, 0x00, 0x00,                          //  64 chunk_bytes 4096
    0x02, 0x00, 0x00, 0x00,                          //  68 session_count 2
    0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  72 payload_bytes 10000
    0x03, 0x00, 0x00, 0x00,                          //  80 chunk_count 3
    0x00, 0x00, 0x00, 0x00,                          //  84 flags
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //  88 reserved (36 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,                          //
    0x2A, 0x32, 0x13, 0xF5,                          // 124 header_crc 0xF513322A
};

std::vector<std::byte> as_bytes_vec(const std::uint8_t* p, std::size_t n) {
  std::vector<std::byte> v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::byte>(p[i]);
  return v;
}

TEST(SnapshotFormat, GoldenHeaderBytes) {
  const auto layout = compute_layout(4096, 2, 10000);
  ASSERT_TRUE(layout.has_value());
  EXPECT_EQ(layout->chunk_count, 3u);
  const auto header = encode_header(golden_meta(), *layout);
  EXPECT_EQ(std::vector<std::byte>(header.begin(), header.end()), as_bytes_vec(kGoldenHeader, kHeaderBytes));
}

TEST(SnapshotFormat, WriterFileStartsWithGoldenHeader) {
  TempDir dir;
  WriterOptions opts;
  opts.chunk_bytes = 4096;
  const std::vector<SessionSeq> sessions = {{1, 10}, {2, 20}};
  auto w = Writer::create(dir.path(), golden_meta(), sessions, opts);
  ASSERT_TRUE(w.has_value());
  Prng rng(11);
  w->write(test::random_bytes(rng, 10000));
  auto path = w->commit();
  ASSERT_TRUE(path.has_value()) << to_string(path.error());
  const auto file = test::read_file(*path);
  ASSERT_GE(file.size(), kHeaderBytes);
  EXPECT_EQ(std::vector<std::byte>(file.begin(), file.begin() + kHeaderBytes),
            as_bytes_vec(kGoldenHeader, kHeaderBytes));
}

// A whole 200-byte image: one session, a 5-byte payload.
TEST(SnapshotFormat, GoldenTinyImage) {
  std::vector<std::uint8_t> e;
  auto le32 = [&](std::uint32_t v) {
    for (int i = 0; i < 4; ++i) e.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
  };
  auto le64 = [&](std::uint64_t v) {
    for (int i = 0; i < 8; ++i) e.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
  };
  auto text = [&](const char* s) {
    for (; *s != '\0'; ++s) e.push_back(static_cast<std::uint8_t>(*s));
  };
  // Header.
  text("LLESNAP1");
  le32(1);
  le32(128);
  le32(20260930);
  le32(3);
  le64(0x0102030405060708ull);
  le64(42);
  le64(0x1122334455667788ull);
  le64(0xDEADBEEFCAFEF00Dull);
  le64(0xABCDEF);
  le32(4096);  // chunk_bytes
  le32(1);     // session_count
  le64(5);     // payload_bytes
  le32(1);     // chunk_count
  le32(0);     // flags
  for (int i = 0; i < 36; ++i) e.push_back(0);
  le32(0x5D810402);  // header_crc
  // Session table.
  le32(7);
  le32(0);
  le64(1000);
  le32(0x4EB31FBF);  // table_crc
  le32(0);
  // Chunk 0: "hello", crc32c_extend(crc32c(le64(0)), "hello"), 7 pad bytes.
  text("hello");
  le32(0x6358689D);
  for (int i = 0; i < 7; ++i) e.push_back(0);
  // Trailer.
  text("LLESEND1");
  le64(200);
  le32(0x5D810402);  // header_crc copy
  le32(0x9374F505);  // sections_crc over le32(table_crc) || le32(chunk_crc 0)
  le32(0x0C0056CE);  // trailer_crc
  le32(0);
  ASSERT_EQ(e.size(), 200u);

  const std::vector<SessionSeq> sessions = {{7, 1000}};
  const std::string hello = "hello";
  const auto payload = std::as_bytes(std::span<const char>(hello.data(), hello.size()));
  const auto img = test::encode_or_die(golden_meta(), sessions, payload, 4096);
  EXPECT_EQ(img, as_bytes_vec(e.data(), e.size()));

  auto r = Reader::open(img);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->meta(), golden_meta());
  ASSERT_EQ(r->sessions().size(), 1u);
  EXPECT_EQ(r->sessions()[0], (SessionSeq{7, 1000}));
  EXPECT_EQ(test::read_rest(*r), std::vector<std::byte>(payload.begin(), payload.end()));
}

TEST(SnapshotFormat, ChunkCrcIsSeededWithTheChunkIndex) {
  const std::vector<std::byte> data(100, std::byte{0x5A});
  EXPECT_NE(chunk_crc(0, data), chunk_crc(1, data));
  std::byte seed[8];
  store_le64(seed, 7);
  EXPECT_EQ(chunk_crc(7, data), crc32c_extend(crc32c(seed, 8), data.data(), data.size()));
}

TEST(SnapshotFormat, ComputeLayout) {
  const auto empty = compute_layout(4096, 0, 0);
  ASSERT_TRUE(empty.has_value());
  EXPECT_EQ(empty->chunk_count, 0u);
  EXPECT_EQ(empty->payload_offset, 136u);
  EXPECT_EQ(empty->file_bytes, 168u);

  const auto one = compute_layout(4096, 2, 4096);
  ASSERT_TRUE(one.has_value());
  EXPECT_EQ(one->chunk_count, 1u);
  EXPECT_EQ(one->payload_offset, 128u + 32u + 8u);
  EXPECT_EQ(one->file_bytes, 168u + 4104u + 32u);

  const auto tail = compute_layout(4096, 0, 4097);
  ASSERT_TRUE(tail.has_value());
  EXPECT_EQ(tail->chunk_count, 2u);
  EXPECT_EQ(tail->file_bytes, 136u + 4104u + 8u + 32u);  // 1 byte + crc + 3 pad

  EXPECT_FALSE(compute_layout(4095, 0, 0).has_value());
  EXPECT_FALSE(compute_layout(2048, 0, 0).has_value());
  EXPECT_FALSE(compute_layout(0, 0, 0).has_value());
  EXPECT_FALSE(compute_layout(std::uint64_t{1} << 31, 0, 0).has_value());
  EXPECT_TRUE(compute_layout(kMaxChunkBytes, 0, 0).has_value());

  // Largest representable chunk count, and one past it: no overflow either way.
  const std::uint64_t max_chunks = std::numeric_limits<std::uint32_t>::max();
  const auto big = compute_layout(4096, std::numeric_limits<std::uint32_t>::max(), 4096 * max_chunks);
  ASSERT_TRUE(big.has_value());
  EXPECT_EQ(big->chunk_count, max_chunks);
  EXPECT_GT(big->file_bytes, 4096 * max_chunks);
  EXPECT_FALSE(compute_layout(4096, 0, 4096 * (max_chunks + 1)).has_value());
  EXPECT_FALSE(compute_layout(4096, 0, std::numeric_limits<std::uint64_t>::max()).has_value());
  EXPECT_FALSE(compute_layout(kMaxChunkBytes, 0, std::numeric_limits<std::uint64_t>::max()).has_value());
}

TEST(SnapshotFormat, SameStateComparesIndexHashAndMoldSeq) {
  const SnapshotMeta a = test::sample_meta(500);
  SnapshotMeta b = a;
  EXPECT_TRUE(same_state(a, b));
  b.build_id ^= 1;
  b.epoch += 1;
  b.snapshot_id += 1;
  EXPECT_TRUE(same_state(a, b));  // identity fields outside the state
  b = a;
  b.index += 1;
  EXPECT_FALSE(same_state(a, b));
  b = a;
  b.state_hash ^= 1;
  EXPECT_FALSE(same_state(a, b));
  b = a;
  b.mold_seq += 1;
  EXPECT_FALSE(same_state(a, b));
}

TEST(SnapshotNaming, PathsAndNames) {
  EXPECT_EQ(snapshot_file_name(42), "00000000000000000042.snap");
  EXPECT_EQ(snapshot_file_name(std::numeric_limits<std::uint64_t>::max()), "18446744073709551615.snap");
  EXPECT_EQ(snapshot_path("/x/snap/20260930", 42), "/x/snap/20260930/00000000000000000042.snap");
  EXPECT_EQ(snapshot_path("/x/snap/20260930/", 42), "/x/snap/20260930/00000000000000000042.snap");
  EXPECT_EQ(snapshot_temp_path("d", 7), "d/00000000000000000007.snap.tmp");
  EXPECT_EQ(snapshot_day_dir("/data", 20260930), "/data/snap/20260930");
  EXPECT_EQ(snapshot_day_dir("/data/", 20260101), "/data/snap/20260101");
}

TEST(SnapshotNaming, ParseRoundTripsAndRejectsEverythingElse) {
  for (const std::uint64_t v : {std::uint64_t{0}, std::uint64_t{42}, std::uint64_t{10'000'000},
                                std::numeric_limits<std::uint64_t>::max()}) {
    EXPECT_EQ(parse_snapshot_file_name(snapshot_file_name(v)), v);
  }
  for (const char* bad : {"", ".snap", "42.snap", "0000000000000000042.snap", "000000000000000000042.snap",
                          "00000000000000000042.snap.tmp", "00000000000000000042.SNAP", "0000000000000000004a.snap",
                          "+0000000000000000042.snap", "-0000000000000000042.snap", " 0000000000000000042.snap",
                          "00000000000000000042.snaq", "00000000000000000042.snap ", "18446744073709551616.snap",
                          "99999999999999999999.snap"}) {
    EXPECT_FALSE(parse_snapshot_file_name(bad).has_value()) << bad;
  }
}

TEST(SnapshotFormat, ErrorStrings) {
  for (int i = 0; i <= static_cast<int>(LoadError::Io); ++i) {
    EXPECT_NE(to_string(static_cast<LoadError>(i)), "unknown");
  }
  const std::string s = to_string(Error{ErrorCode::Io, 2, "open(temp)"});
  EXPECT_NE(s.find("open(temp)"), std::string::npos);
}

}  // namespace
}  // namespace lle::snap

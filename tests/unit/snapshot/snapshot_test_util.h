#pragma once
// Helpers shared by the snapshot tests (06 §9).
#include <gtest/gtest.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "common/prng.h"
#include "snapshot/format.h"
#include "snapshot/reader.h"
#include "snapshot/writer.h"

namespace lle::snap::test {

inline std::vector<std::byte> random_bytes(Prng& rng, std::size_t n) {
  std::vector<std::byte> v(n);
  for (auto& b : v) b = static_cast<std::byte>(rng.next_u64());
  return v;
}

inline SnapshotMeta sample_meta(std::uint64_t index = 1000) {
  SnapshotMeta m;
  m.day = 20260930;
  m.epoch = 2;
  m.index = index;
  m.snapshot_id = index / 10;
  m.mold_seq = index * 3 + 1;
  m.state_hash = 0x9E3779B97F4A7C15ull ^ index;
  m.build_id = 0xB111D;
  return m;
}

inline std::vector<SessionSeq> sample_sessions() { return {{3, 17}, {9, 1}, {40000, 123456789012ull}}; }

inline std::vector<std::byte> encode_or_die(const SnapshotMeta& meta, std::span<const SessionSeq> sessions,
                                            std::span<const std::byte> payload, std::uint32_t chunk_bytes) {
  auto img = encode_image(meta, sessions, payload, chunk_bytes);
  EXPECT_TRUE(img.has_value());
  return img ? std::move(*img) : std::vector<std::byte>{};
}

// Reads the rest of the payload.
inline std::vector<std::byte> read_rest(Reader& r) {
  std::vector<std::byte> out(static_cast<std::size_t>(r.remaining()));
  EXPECT_TRUE(r.read(out));
  return out;
}

inline std::vector<std::byte> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  std::vector<char> c((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::vector<std::byte> out(c.size());
  for (std::size_t i = 0; i < c.size(); ++i) out[i] = static_cast<std::byte>(c[i]);
  return out;
}

inline void write_file(const std::string& path, std::span<const std::byte> bytes) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  for (const std::byte b : bytes) f.put(static_cast<char>(b));
}

inline bool exists(const std::string& path) {
  std::error_code ec;
  return std::filesystem::exists(path, ec);
}

inline std::vector<std::string> list_dir(const std::string& dir) {
  std::vector<std::string> names;
  std::error_code ec;
  for (const auto& e : std::filesystem::directory_iterator(dir, ec)) names.push_back(e.path().filename().string());
  std::sort(names.begin(), names.end());
  return names;
}

// Unique per process and per test; removed on destruction.
class TempDir {
 public:
  TempDir() {
    static int counter = 0;
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string name = std::string("lle_snapshot_") + (info != nullptr ? info->name() : "x") + "_" +
                             std::to_string(::getpid()) + "_" + std::to_string(counter++);
    path_ = (std::filesystem::temp_directory_path() / name).string();
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

 private:
  std::string path_;
};

// Recomputes the header CRC (and nothing else) after a test edits header fields.
inline void reseal_header(std::vector<std::byte>& img) {
  std::byte* const p = img.data();
  if (p == nullptr) return;  // an empty image has no header (lets GCC prove p non-null)
  store_le32(p + hdr::kHeaderCrc, crc32c(p, hdr::kHeaderCrc));
}

// Recomputes every CRC of an image whose layout fields are still valid, so a test
// can plant a semantic defect (padding, ordering, reserved bits) behind valid CRCs.
inline void reseal_all(std::vector<std::byte>& img) {
  reseal_header(img);
  const std::byte* p = img.data();
  const auto layout = compute_layout(load_le32(p + hdr::kChunkBytes), load_le32(p + hdr::kSessionCount),
                                     load_le64(p + hdr::kPayloadBytes));
  ASSERT_TRUE(layout.has_value());
  ASSERT_EQ(layout->file_bytes, img.size());
  std::byte* table = img.data() + kHeaderBytes;
  const std::size_t entries = std::size_t{kSessionEntryBytes} * layout->session_count;
  const std::uint32_t table_crc = crc32c(table, entries);
  store_le32(table + entries, table_crc);
  std::byte le[4];
  store_le32(le, table_crc);
  std::uint32_t sections = crc32c(le, 4);
  std::uint64_t off = layout->payload_offset;
  for (std::uint64_t k = 0; k < layout->chunk_count; ++k) {
    const std::uint64_t len =
        k + 1 < layout->chunk_count ? layout->chunk_bytes : layout->payload_bytes - k * layout->chunk_bytes;
    const std::uint32_t crc = chunk_crc(k, std::span<const std::byte>(img.data() + off, len));
    store_le32(img.data() + off + len, crc);
    sections = crc32c_extend(sections, img.data() + off + len, 4);
    off += chunk_frame_bytes(len);
  }
  std::byte* t = img.data() + img.size() - kTrailerBytes;
  store_le32(t + trl::kHeaderCrc, load_le32(p + hdr::kHeaderCrc));
  store_le32(t + trl::kSectionsCrc, sections);
  store_le32(t + trl::kTrailerCrc, crc32c(t, trl::kTrailerCrc));
}

inline LoadError open_error(std::span<const std::byte> img) {
  auto r = Reader::open(img);
  EXPECT_FALSE(r.has_value());
  return r ? LoadError::Io : r.error();
}

}  // namespace lle::snap::test

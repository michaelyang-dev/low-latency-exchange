#pragma once
// Shared helpers for the output-log tests (06 §8).
#include <gtest/gtest.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "common/endian.h"
#include "common/prng.h"
#include "common/types.h"
#include "outlog/format.h"

namespace lle::outlog::test {

// A fresh directory per test under the system temp directory; removed with
// everything in it when the test ends.
class TempDir {
 public:
  TempDir() {
    const ::testing::TestInfo* info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string name = "lle-outlog-" + std::to_string(::getpid()) + "-" + std::to_string(next_id());
    if (info != nullptr) name += std::string("-") + info->test_suite_name() + "." + info->name();
    path_ = std::filesystem::temp_directory_path() / name;
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] std::string file(const std::string& name) const { return (path_ / name).string(); }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  static int next_id() {
    static int id = 0;
    return id++;
  }
  std::filesystem::path path_;
};

// Deterministic message bytes for (seed, seq).
inline void fill_message(std::uint64_t seed, SeqNo seq, std::span<std::byte> out) {
  Prng rng(seed * 0x9E3779B97F4A7C15ull + seq);
  for (std::byte& b : out) b = static_cast<std::byte>(rng.next_u64() & 0xFF);
}

inline std::vector<std::byte> make_message(std::uint64_t seed, SeqNo seq, std::size_t len) {
  std::vector<std::byte> m(len);
  fill_message(seed, seq, m);
  return m;
}

// Mostly small (ITCH-sized) lengths with occasional large ones, so tests
// cover the full range without writing hundreds of megabytes.
inline std::size_t random_length(Prng& rng) {
  if (rng.chance(1, 64)) return static_cast<std::size_t>(rng.range(1, static_cast<std::int64_t>(kMaxMessageBytes)));
  return static_cast<std::size_t>(rng.range(1, 64));
}

inline std::vector<std::byte> read_file(const std::string& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return {};
  std::vector<std::byte> out(static_cast<std::size_t>(size));
  std::ifstream in(path, std::ios::binary);
  in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  out.resize(static_cast<std::size_t>(in.gcount()));
  return out;
}

inline void write_file(const std::string& path, std::span<const std::byte> bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

// Parses an index file by hand (independently of the library loader).
struct ParsedIndex {
  bool header_ok = false;
  std::vector<std::uint64_t> entries;
  std::size_t trailing_bytes = 0;
};

inline ParsedIndex parse_index(const std::string& path) {
  ParsedIndex p;
  const std::vector<std::byte> raw = read_file(path);
  if (raw.size() < kIndexHeaderBytes) return p;
  p.header_ok = index_header_valid(std::span<const std::byte>(raw).first(kIndexHeaderBytes));
  const std::size_t body = raw.size() - kIndexHeaderBytes;
  for (std::size_t k = 0; k < body / kIndexEntryBytes; ++k) {
    p.entries.push_back(load_le64(raw.data() + kIndexHeaderBytes + k * kIndexEntryBytes));
  }
  p.trailing_bytes = body % kIndexEntryBytes;
  return p;
}

// Index entries expected for messages of the given lengths.
inline std::vector<std::uint64_t> expected_entries(const std::vector<std::size_t>& lengths) {
  std::vector<std::uint64_t> e;
  std::uint64_t off = 0;
  for (std::size_t i = 0; i < lengths.size(); ++i) {
    if (i % kIndexInterval == 0) e.push_back(off);
    off += kLengthPrefixBytes + lengths[i];
  }
  return e;
}

inline std::span<const std::byte> as_bytes(const std::vector<std::byte>& v) { return {v.data(), v.size()}; }

}  // namespace lle::outlog::test

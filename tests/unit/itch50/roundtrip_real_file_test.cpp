// RoundTripRealFile (03-protocols §9), bounded for CI: decode -> encode -> memcmp
// over the first kMaxRecords records of every NASDAQ file in data/itch/*.gz.
// Skipped when the (git-ignored) data directory is absent. The full-day runs
// over every record are done by apps/itch_roundtrip.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "proto/itch50/binary_file.h"
#include "proto/itch50/itch50.h"

namespace lle::itch50 {
namespace {

constexpr std::uint64_t kMaxRecords = 5'000'000;

std::vector<std::filesystem::path> data_files() {
  std::vector<std::filesystem::path> out;
  const std::filesystem::path dir = std::filesystem::path(LLE_SOURCE_DIR) / "data" / "itch";
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) return out;
  for (const auto& e : std::filesystem::directory_iterator(dir, ec))
    if (e.path().extension() == ".gz") out.push_back(e.path());
  std::sort(out.begin(), out.end());
  return out;
}

TEST(RoundTripRealFile, FirstRecordsOfEveryDataFile) {
  const auto files = data_files();
  if (files.empty()) GTEST_SKIP() << "no data/itch/*.gz present";
  for (const auto& path : files) {
    SCOPED_TRACE(path.filename().string());
    BinaryFileReader r;
    ASSERT_TRUE(r.open(path.string()).has_value());
    std::uint64_t records = 0, diffs = 0, bad_len = 0, unknown = 0, framing = 0;
    std::array<std::uint64_t, 256> per_type{};
    std::array<std::byte, kMaxMsgLen> out{};
    while (records < kMaxRecords) {
      const Record rec = r.next();
      if (rec.status == RecordStatus::EndOfFile) break;
      if (rec.status == RecordStatus::EndOfSession) {
        ++records;
        continue;
      }
      if (rec.status != RecordStatus::Message) {
        ++framing;
        break;
      }
      ++records;
      ++per_type[static_cast<unsigned char>(rec.data[0])];
      const DecodeStatus st = visit(rec.data, [&](auto v) {
        const std::size_t n = encode(out, v.to_struct());
        if (n != rec.data.size() || std::memcmp(out.data(), rec.data.data(), n) != 0) ++diffs;
      });
      if (st == DecodeStatus::UnknownType) ++unknown;
      if (st == DecodeStatus::BadLength) ++bad_len;
    }
    EXPECT_GT(records, 0u);
    EXPECT_EQ(framing, 0u);
    EXPECT_EQ(unknown, 0u);
    EXPECT_EQ(bad_len, 0u);
    EXPECT_EQ(diffs, 0u);
    // Every NASDAQ day starts with System Event 'O'.
    EXPECT_GE(per_type['S'] + per_type['I'], 1u);
  }
}

}  // namespace
}  // namespace lle::itch50

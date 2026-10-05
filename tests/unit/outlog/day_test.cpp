// OutlogDay: per-day layout and per-session writers (06 §8, §10).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "outlog/day.h"
#include "outlog/format.h"
#include "outlog/reader.h"
#include "outlog_test_util.h"

namespace lle::outlog {
namespace {

using test::as_bytes;
using test::make_message;
using test::TempDir;

constexpr std::uint32_t kDay = 20260930;

TEST(OutlogDay, Paths) {
  EXPECT_EQ(OutlogDay::day_dir("/data/outlog", kDay), "/data/outlog/20260930");
  EXPECT_EQ(OutlogDay::itch_path("/data/outlog", kDay), "/data/outlog/20260930/itch.bin");
  EXPECT_EQ(OutlogDay::soup_path("/data/outlog", kDay, 42), "/data/outlog/20260930/soup-000042.bin");
  EXPECT_EQ(OutlogDay::soup_path("/data/outlog", kDay, 0), "/data/outlog/20260930/soup-000000.bin");
  EXPECT_EQ(OutlogDay::soup_path("/data/outlog", kDay, 999'999), "/data/outlog/20260930/soup-999999.bin");
  EXPECT_EQ(OutlogDay::itch_path("r", 10'101), "r/00010101/itch.bin");
  EXPECT_EQ(index_path(OutlogDay::itch_path("/data/outlog", kDay)), "/data/outlog/20260930/itch.bin.idx");
}

TEST(OutlogDay, OpensItchAndOneWriterPerSession) {
  TempDir dir;
  const std::string root = dir.file("outlog");
  const std::vector<std::uint32_t> sessions = {42, 7, 123'456};
  {
    OutlogDay day;
    ASSERT_TRUE(day.open(root, kDay, sessions).has_value());
    EXPECT_TRUE(day.is_open());
    EXPECT_EQ(day.day(), kDay);
    EXPECT_EQ(std::vector<std::uint32_t>(day.sessions().begin(), day.sessions().end()),
              (std::vector<std::uint32_t>{7, 42, 123'456}));

    // Every file exists from the start: nothing is opened on the append path.
    for (const char* name : {"itch.bin", "soup-000007.bin", "soup-000042.bin", "soup-123456.bin"}) {
      const std::string p = OutlogDay::day_dir(root, kDay) + "/" + name;
      EXPECT_TRUE(std::filesystem::exists(p)) << p;
      EXPECT_TRUE(std::filesystem::exists(index_path(p))) << p;
    }

    ASSERT_NE(day.soup(7), nullptr);
    ASSERT_NE(day.soup(42), nullptr);
    ASSERT_NE(day.soup(123'456), nullptr);
    EXPECT_NE(day.soup(7), day.soup(42));
    EXPECT_EQ(day.soup(8), nullptr);
    EXPECT_EQ(day.soup(0), nullptr);
    EXPECT_EQ(day.soup(999'999), nullptr);
    EXPECT_EQ(day.soup(42)->path(), OutlogDay::soup_path(root, kDay, 42));

    for (SeqNo s = 1; s <= 10; ++s) EXPECT_EQ(day.itch().append(as_bytes(make_message(1, s, 20))).value(), s);
    for (SeqNo s = 1; s <= 3; ++s) EXPECT_EQ(day.soup(42)->append(as_bytes(make_message(42, s, 9))).value(), s);
    EXPECT_EQ(day.soup(123'456)->append(as_bytes(make_message(9, 1, 1))).value(), 1u);
    ASSERT_TRUE(day.flush_all().has_value());

    // Visible to readers after flush_all(), each file with its own sequence.
    OutlogReader r;
    ASSERT_TRUE(r.open(OutlogDay::soup_path(root, kDay, 42)).has_value());
    EXPECT_EQ(r.count(), 3u);
    std::vector<std::byte> scratch(64);
    const auto m = r.read(2, scratch);
    ASSERT_TRUE(m.has_value());
    const std::vector<std::byte> want = make_message(42, 2, 9);
    EXPECT_TRUE(m->size() == want.size() && std::memcmp(m->data(), want.data(), want.size()) == 0);
    EXPECT_EQ(std::filesystem::file_size(OutlogDay::itch_path(root, kDay)), 10u * 22u);
    EXPECT_EQ(std::filesystem::file_size(OutlogDay::soup_path(root, kDay, 7)), 0u);
    ASSERT_TRUE(day.close().has_value());
    EXPECT_FALSE(day.is_open());
    EXPECT_EQ(day.soup(42), nullptr);
  }

  // Reopening the same day (restart) continues every sequence.
  OutlogDay day;
  ASSERT_TRUE(day.open(root, kDay, sessions).has_value());
  EXPECT_EQ(day.itch().count(), 10u);
  EXPECT_EQ(day.soup(42)->count(), 3u);
  EXPECT_EQ(day.soup(7)->count(), 0u);
  EXPECT_EQ(day.soup(123'456)->count(), 1u);
  EXPECT_EQ(day.soup(42)->append(as_bytes(make_message(42, 4, 9))).value(), 4u);

  // Rollover: the next day gets its own directory and fresh sequences.
  ASSERT_TRUE(day.open(root, kDay + 1, sessions).has_value());
  EXPECT_EQ(day.itch().count(), 0u);
  EXPECT_EQ(day.soup(42)->count(), 0u);
  EXPECT_TRUE(std::filesystem::exists(OutlogDay::itch_path(root, kDay + 1)));
  OutlogReader r;
  ASSERT_TRUE(r.open(OutlogDay::soup_path(root, kDay, 42)).has_value());
  EXPECT_EQ(r.count(), 4u);
}

TEST(OutlogDay, NoSessions) {
  TempDir dir;
  OutlogDay day;
  ASSERT_TRUE(day.open(dir.file("o"), kDay, {}).has_value());
  EXPECT_TRUE(day.sessions().empty());
  EXPECT_EQ(day.soup(1), nullptr);
  const std::byte m[] = {std::byte{'S'}};
  EXPECT_EQ(day.itch().append(m).value(), 1u);
  EXPECT_TRUE(day.close().has_value());
}

TEST(OutlogDay, RejectsInvalidConfiguration) {
  TempDir dir;
  const std::string root = dir.file("o");
  OutlogDay day;
  const std::vector<std::uint32_t> dup = {3, 1, 3};
  EXPECT_FALSE(day.open(root, kDay, dup).has_value());
  const std::vector<std::uint32_t> too_big = {1, 1'000'000};
  EXPECT_FALSE(day.open(root, kDay, too_big).has_value());
  for (const std::uint32_t bad_day : {0u, 20261301u, 20260900u, 20260932u, 100'000'000u}) {
    EXPECT_FALSE(day.open(root, bad_day, {}).has_value()) << bad_day;
  }
  EXPECT_FALSE(day.is_open());
  EXPECT_EQ(day.flush_all().error(), Error::NotOpen);
  EXPECT_FALSE(std::filesystem::exists(root));  // nothing created for a rejected configuration
}

}  // namespace
}  // namespace lle::outlog

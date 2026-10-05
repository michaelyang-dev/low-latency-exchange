// Decoder on synthetic files built with the file encoders (no runtime, fully
// deterministic): exact text, merge order, wall-time interpolation, filters,
// JSON escaping, format robustness and header/chunk validation.
#include "log/decoder.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "log/file_format.h"
#include "log/format_text.h"
#include "log/level.h"
#include "log/record.h"
#include "log/varint.h"

namespace lle::nlog {
namespace {

using decode::LogFile;
using decode::RenderOptions;
using decode::Status;
using decode::TimeMode;

constexpr std::int64_t kT0 = 1'000'000'000'000'000'000;  // 2001-09-09T01:46:40Z

std::vector<std::byte> base_file(std::uint64_t hz = 1'000'000'000) {
  std::vector<std::byte> b;
  file::append_file_header(b, file::FileHeader{kT0, hz, "synthetic", 0});
  ArgKinds k1{};
  k1[0] = ArgKind::kU64;
  k1[1] = ArgKind::kStr;
  ArgKinds k2{};
  k2[0] = ArgKind::kI32;
  const std::vector<file::DictEntry> dict = {
      {3, static_cast<std::uint8_t>(Level::kInfo), 2, k1, 10, "src/a/alpha.cpp", "alpha {} name {}"},
      {7, static_cast<std::uint8_t>(Level::kError), 1, k2, 20, "beta.cpp", "beta {:+d}"},
      {9, static_cast<std::uint8_t>(Level::kDebug), 0, {}, 30, "gamma.cpp", "gamma"},
  };
  file::append_dict_chunk(b, dict);
  return b;
}

void add_extent(std::vector<std::byte>& b, std::uint32_t tid,
                const std::vector<std::tuple<std::uint32_t, std::uint64_t, std::vector<ArgValue>>>& recs) {
  file::ExtentBuilder eb;
  eb.reset(tid);
  for (const auto& [site, tsc, args] : recs) eb.add_values(site, 0, tsc, args);
  eb.finish_into(b);
}

std::string tsc_text(const LogFile& f, decode::Filter filter = {}) {
  RenderOptions ro;
  ro.time = TimeMode::kTsc;
  ro.filter = std::move(filter);
  return decode::render_to_string(f, ro);
}

TEST(NlogDecoder, MergesThreadsByTscAndFormatsExactly) {
  auto b = base_file();
  file::append_thread_chunk(b, 1, 4096, "one");
  file::append_thread_chunk(b, 2, 4096, "two");
  using V = std::vector<ArgValue>;
  add_extent(b, 1, {{3, 10, V{ArgValue::of_unsigned(ArgKind::kU64, 1), ArgValue::of_string("x")}},
                    {7, 30, V{ArgValue::of_signed(ArgKind::kI32, 5)}}});
  add_extent(b, 2, {{9, 20, V{}}, {7, 40, V{ArgValue::of_signed(ArgKind::kI32, -6)}}});
  add_extent(b, 1, {{3, 50, V{ArgValue::of_unsigned(ArgKind::kU64, 2), ArgValue::of_string("y", true)}}});
  file::append_end_chunk(b, 60, 5, 0, 0);
  const LogFile f = LogFile::parse(b);
  ASSERT_EQ(f.info().status, Status::kOk);
  EXPECT_TRUE(f.info().clean_end);
  EXPECT_EQ(f.info().node, "synthetic");
  EXPECT_EQ(f.info().extents, 3u);
  EXPECT_EQ(f.threads().at(2).name, "two");
  EXPECT_EQ(tsc_text(f),
            "10 INFO  t1 alpha.cpp:10 alpha 1 name x\n"
            "20 DEBUG t2 gamma.cpp:30 gamma\n"
            "30 ERROR t1 beta.cpp:20 beta +5\n"
            "40 ERROR t2 beta.cpp:20 beta -6\n"
            "50 INFO  t1 alpha.cpp:10 alpha 2 name y...\n");
}

TEST(NlogDecoder, NonMonotonicTimestampsWithinAThreadRoundTrip) {
  auto b = base_file();
  using V = std::vector<ArgValue>;
  const std::uint64_t big = std::numeric_limits<std::uint64_t>::max();
  add_extent(b, 4, {{9, 100, V{}}, {9, 5, V{}}, {9, big, V{}}, {9, 0, V{}}});
  const LogFile f = LogFile::parse(b);
  std::vector<std::uint64_t> seen;
  f.for_each([&](const decode::Record& r) {
    seen.push_back(r.tsc);
    return true;
  });
  // One thread: its own (program) order is kept even when not sorted.
  EXPECT_EQ(seen, (std::vector<std::uint64_t>{100, 5, big, 0}));
}

TEST(NlogDecoder, WallTimeInterpolatesBetweenCalibrations) {
  auto b = base_file();
  // The counter's nominal rate says 1 ns/tick, but between the two calibrations
  // wall time advanced 2 ns per tick: interpolation must follow the calibrations.
  file::append_calib_chunk(b, file::Calibration{1000, kT0, 1'000'000'000, 0});
  file::append_calib_chunk(b, file::Calibration{2000, kT0 + 2000, 1'000'000'000, 0});
  const LogFile f = LogFile::parse(b);
  EXPECT_EQ(f.to_wall_ns(1000), kT0);
  EXPECT_EQ(f.to_wall_ns(1500), kT0 + 1000);
  EXPECT_EQ(f.to_wall_ns(2000), kT0 + 2000);
  EXPECT_EQ(f.to_wall_ns(500), kT0 - 500);    // before the first: nominal rate
  EXPECT_EQ(f.to_wall_ns(3000), kT0 + 3000);  // after the last: nominal rate
  std::string s;
  append_utc_time(s, *f.to_wall_ns(1500));
  EXPECT_EQ(s, "2001-09-09T01:46:40.000001000Z");
}

TEST(NlogDecoder, WallTimeWithoutCalibrationFallsBackToTsc) {
  auto b = base_file();
  add_extent(b, 1, {{9, 77, {}}});
  const LogFile f = LogFile::parse(b);
  EXPECT_FALSE(f.to_wall_ns(77).has_value());
  RenderOptions ro;  // wall mode
  EXPECT_EQ(decode::render_to_string(f, ro), "tsc:77 DEBUG t1 gamma.cpp:30 gamma\n");
}

TEST(NlogDecoder, UtcFormatting) {
  std::string s;
  append_utc_time(s, 0);
  EXPECT_EQ(s, "1970-01-01T00:00:00.000000000Z");
  s.clear();
  append_utc_time(s, -1);
  EXPECT_EQ(s, "1969-12-31T23:59:59.999999999Z");
  s.clear();
  append_utc_time(s, 1'709'208'000'123'456'789);  // 2024-02-29T12:00:00.123456789Z (leap day)
  EXPECT_EQ(s, "2024-02-29T12:00:00.123456789Z");
  s.clear();
  append_utc_time(s, std::numeric_limits<std::int64_t>::max());  // extremes reach here from corrupt files
  EXPECT_EQ(s, "2262-04-11T23:47:16.854775807Z");
  s.clear();
  append_utc_time(s, std::numeric_limits<std::int64_t>::min());
  EXPECT_EQ(s, "1677-09-21T00:12:43.145224192Z");
}

TEST(NlogDecoder, Filters) {
  auto b = base_file();
  file::append_calib_chunk(b, file::Calibration{0, kT0, 1'000'000'000, 0});
  using V = std::vector<ArgValue>;
  add_extent(b, 1, {{9, 10, V{}}, {7, 20, V{ArgValue::of_signed(ArgKind::kI32, 1)}}});
  add_extent(b, 2, {{9, 15, V{}}, {7, 25, V{ArgValue::of_signed(ArgKind::kI32, 2)}}});
  const LogFile f = LogFile::parse(b);
  decode::Filter level;
  level.min_level = static_cast<std::uint8_t>(Level::kError);
  EXPECT_EQ(tsc_text(f, level), "20 ERROR t1 beta.cpp:20 beta +1\n25 ERROR t2 beta.cpp:20 beta +2\n");
  decode::Filter thread;
  thread.threads = {2};
  EXPECT_EQ(tsc_text(f, thread), "15 DEBUG t2 gamma.cpp:30 gamma\n25 ERROR t2 beta.cpp:20 beta +2\n");
  decode::Filter site;
  site.sites = {9};
  EXPECT_EQ(tsc_text(f, site), "10 DEBUG t1 gamma.cpp:30 gamma\n15 DEBUG t2 gamma.cpp:30 gamma\n");
  decode::Filter tsc;
  tsc.from_tsc = 15;
  tsc.to_tsc = 25;
  EXPECT_EQ(tsc_text(f, tsc), "15 DEBUG t2 gamma.cpp:30 gamma\n20 ERROR t1 beta.cpp:20 beta +1\n");
  decode::Filter wall;
  wall.from_ns = kT0 + 11;
  wall.to_ns = kT0 + 20;
  EXPECT_EQ(tsc_text(f, wall), "15 DEBUG t2 gamma.cpp:30 gamma\n");
}

TEST(NlogDecoder, JsonlEscapesStrings) {
  auto b = base_file();
  const std::string tricky = std::string("q\"b\\n\nt\t\x01 ") + "\xC3\xA9" + "\xFF";
  add_extent(b, 1, {{3, 1, {ArgValue::of_unsigned(ArgKind::kU64, 9), ArgValue::of_string(tricky)}}});
  const LogFile f = LogFile::parse(b);
  RenderOptions ro;
  ro.format = decode::OutputFormat::kJsonl;
  ro.full_paths = true;
  EXPECT_EQ(decode::render_to_string(f, ro),
            "{\"tsc\":1,\"level\":\"INFO\",\"thread\":1,\"site\":3,\"file\":\"src/a/alpha.cpp\",\"line\":10,"
            "\"msg\":\"alpha 9 name q\\\"b\\\\n\\nt\\t\\u0001 \xC3\xA9\\ufffd\",\"args\":[9,\"q\\\"b\\\\n\\nt\\t\\u0001 "
            "\xC3\xA9\\ufffd\"]}\n");
  // Text mode keeps one record per line by escaping control characters.
  EXPECT_EQ(tsc_text(f), "1 INFO  t1 alpha.cpp:10 alpha 9 name q\"b\\n\\nt\\t\\x01 \xC3\xA9\xFF\n");
}

TEST(NlogDecoder, MalformedRecordStopsOnlyItsExtent) {
  auto b = base_file();
  using V = std::vector<ArgValue>;
  add_extent(b, 1, {{9, 1, V{}}, {55, 2, V{}}, {9, 3, V{}}});  // site 55 is not in the dictionary
  add_extent(b, 1, {{9, 4, V{}}});
  const LogFile f = LogFile::parse(b);
  ASSERT_EQ(f.info().status, Status::kOk);
  std::vector<std::uint64_t> seen;
  const auto ms = f.for_each([&](const decode::Record& r) {
    seen.push_back(r.tsc);
    return true;
  });
  EXPECT_EQ(seen, (std::vector<std::uint64_t>{1, 4}));
  EXPECT_EQ(ms.bad_extents, 1u);
}

TEST(NlogDecoder, UnknownChunkTypesAreSkipped) {
  auto b = base_file();
  const std::size_t at = file::begin_chunk(b);
  b.push_back(std::byte{0xAB});
  file::end_chunk(b, at, static_cast<file::ChunkType>(99));
  add_extent(b, 1, {{9, 5, {}}});
  const LogFile f = LogFile::parse(b);
  EXPECT_EQ(f.info().status, Status::kOk);
  EXPECT_EQ(f.info().unknown_chunks, 1u);
  EXPECT_EQ(tsc_text(f), "5 DEBUG t1 gamma.cpp:30 gamma\n");
}

TEST(NlogDecoder, HeaderValidation) {
  auto good = base_file();
  EXPECT_EQ(LogFile::parse(good).info().status, Status::kOk);
  EXPECT_EQ(LogFile::parse({good.data(), 10}).info().status, Status::kBadHeader);

  auto bad_magic = good;
  bad_magic[0] = std::byte{'X'};
  EXPECT_EQ(LogFile::parse(bad_magic).info().status, Status::kBadHeader);

  auto bad_crc = good;
  bad_crc[40] ^= std::byte{1};  // node name byte
  EXPECT_EQ(LogFile::parse(bad_crc).info().status, Status::kBadHeader);
  EXPECT_EQ(LogFile::parse(bad_crc, {.verify_crc = false}).info().status, Status::kOk);

  auto v2 = good;
  store_le16(v2.data() + 8, 2);
  store_le32(v2.data() + 60, crc32c(v2.data(), 60));
  EXPECT_EQ(LogFile::parse(v2).info().status, Status::kUnsupportedVersion);

  auto minor = good;  // newer minor version: still readable
  store_le16(minor.data() + 10, 7);
  store_le32(minor.data() + 60, crc32c(minor.data(), 60));
  const LogFile fm = LogFile::parse(minor);
  EXPECT_EQ(fm.info().status, Status::kOk);
  EXPECT_EQ(fm.info().version_minor, 7);
}

TEST(NlogDecoder, ChunkCrcAndLengthValidation) {
  auto b = base_file();
  const std::size_t dict_end = b.size();
  add_extent(b, 1, {{9, 5, {}}});
  auto bad_crc = b;
  bad_crc[dict_end + file::kChunkHeaderBytes + 2] ^= std::byte{0x10};
  const LogFile f1 = LogFile::parse(bad_crc);
  EXPECT_EQ(f1.info().status, Status::kCorrupt);
  EXPECT_EQ(f1.info().valid_bytes, dict_end);
  auto huge = b;
  store_le32(huge.data() + dict_end + 8, 0xFFFF'FFF0u);
  EXPECT_EQ(LogFile::parse(huge).info().status, Status::kCorrupt);
  auto bad_magic = b;
  bad_magic[dict_end] = std::byte{0};
  EXPECT_EQ(LogFile::parse(bad_magic).info().status, Status::kCorrupt);
}

TEST(NlogDecoder, DictionaryText) {
  const auto b = base_file();
  const LogFile f = LogFile::parse(b);
  EXPECT_EQ(decode::dictionary_text(f),
            "3 INFO  src/a/alpha.cpp:10 [u64,str] alpha {} name {}\n"
            "7 ERROR beta.cpp:20 [i32] beta {:+d}\n"
            "9 DEBUG gamma.cpp:30 [] gamma\n");
}

TEST(NlogFormatText, RobustAgainstBadFormatStrings) {
  const ArgValue one = ArgValue::of_unsigned(ArgKind::kU32, 1);
  const ArgValue str = ArgValue::of_string("s");
  auto fmt = [](std::string_view f, std::vector<ArgValue> a) {
    std::string out;
    format_message(out, f, a);
    return out;
  };
  EXPECT_EQ(fmt("a {} b {}", {one}), "a 1 b {?}");               // missing argument
  EXPECT_EQ(fmt("a {}", {one, one}), "a 1");                     // extra argument ignored
  EXPECT_EQ(fmt("{:f}", {str}), "{?}");                          // spec rejected by std::format
  EXPECT_EQ(fmt("{:99999999}", {one}), "{?}");                   // absurd width refused
  EXPECT_EQ(fmt("{0}", {one}), "{?}");                           // positional
  EXPECT_EQ(fmt("x {", {one}), "x {");                           // unterminated
  EXPECT_EQ(fmt("{{}} }} {:>3}", {one}), "{} }   1");            // escapes
  EXPECT_EQ(fmt("{:{}}", {one, one}), "{?}}");                   // nested field
  EXPECT_EQ(fmt("{}", {ArgValue{}}), "{?}");                     // kind none
}

TEST(NlogVarint, RoundTripAndRejectsBadEncodings) {
  const std::uint64_t vals[] = {0, 1, 127, 128, 300, 1ull << 35, std::numeric_limits<std::uint64_t>::max()};
  for (const std::uint64_t v : vals) {
    std::byte buf[kMaxVarintBytes];
    const std::size_t n = put_varint(buf, v);
    const std::byte* p = buf;
    std::uint64_t out = 0;
    ASSERT_TRUE(get_varint(p, buf + n, out));
    EXPECT_EQ(out, v);
    EXPECT_EQ(p, buf + n);
    const std::byte* q = buf;
    if (n > 1) EXPECT_FALSE(get_varint(q, buf + n - 1, out)) << "truncated";
  }
  const std::int64_t svals[] = {0, -1, 1, -64, 64, std::numeric_limits<std::int64_t>::min(),
                                std::numeric_limits<std::int64_t>::max()};
  for (const std::int64_t v : svals) EXPECT_EQ(zigzag_decode(zigzag_encode(v)), v);
  std::byte over[11];
  for (auto& x : over) x = std::byte{0x80};
  over[10] = std::byte{0};
  const std::byte* p = over;
  std::uint64_t out = 0;
  EXPECT_FALSE(get_varint(p, over + 11, out)) << "11-byte encoding";
  std::byte high[10];
  for (auto& x : high) x = std::byte{0xFF};
  high[9] = std::byte{0x02};  // bit 64 set
  p = high;
  EXPECT_FALSE(get_varint(p, high + 10, out));
}

}  // namespace
}  // namespace lle::nlog

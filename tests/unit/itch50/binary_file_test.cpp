#include <gtest/gtest.h>
#include <unistd.h>
#include <zlib.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "common/endian.h"
#include "common/prng.h"
#include "proto/itch50/binary_file.h"

namespace lle::itch50 {
namespace {

void append_record(std::vector<std::byte>& out, std::span<const std::byte> msg) {
  const std::size_t at = out.size();
  out.resize(at + 2 + msg.size());
  store_be16(out.data() + at, static_cast<std::uint16_t>(msg.size()));
  if (!msg.empty()) std::memcpy(out.data() + at + 2, msg.data(), msg.size());
}

// Random records (lengths 0..max_len, payload byte i = (seed+i)) and the expected list.
std::vector<std::byte> make_stream(std::uint64_t seed, std::size_t n, std::size_t max_len,
                                   std::vector<std::vector<std::byte>>& expected) {
  Prng rng(seed);
  std::vector<std::byte> out;
  for (std::size_t i = 0; i < n; ++i) {
    std::vector<std::byte> msg(rng.below(max_len + 1));
    for (auto& b : msg) b = static_cast<std::byte>(rng.next_u64());
    append_record(out, msg);
    expected.push_back(std::move(msg));
  }
  return out;
}

std::string temp_path(const std::string& name) {
  return ::testing::TempDir() + "lle_itch50_" + std::to_string(::getpid()) + "_" + name;
}

void write_file(const std::string& path, std::span<const std::byte> data) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  ASSERT_NE(f, nullptr);
  ASSERT_EQ(std::fwrite(data.data(), 1, data.size(), f), data.size());
  std::fclose(f);
}

void write_gz(const std::string& path, std::span<const std::byte> data, const char* mode = "wb") {
  gzFile g = gzopen(path.c_str(), mode);
  ASSERT_NE(g, nullptr);
  ASSERT_EQ(gzwrite(g, data.data(), static_cast<unsigned>(data.size())), static_cast<int>(data.size()));
  gzclose(g);
}

template <class Reader>
void expect_records(Reader& r, const std::vector<std::vector<std::byte>>& expected) {
  for (std::size_t i = 0; i < expected.size(); ++i) {
    const Record rec = r.next();
    ASSERT_EQ(rec.status, expected[i].empty() ? RecordStatus::EndOfSession : RecordStatus::Message) << i;
    ASSERT_EQ(rec.data.size(), expected[i].size()) << i;
    ASSERT_EQ(std::memcmp(rec.data.data(), expected[i].data(), expected[i].size()), 0) << i;
  }
  EXPECT_EQ(r.next().status, RecordStatus::EndOfFile);
  EXPECT_EQ(r.next().status, RecordStatus::EndOfFile);
}

TEST(BinaryFileView, ParsesRecordsAndEndOfSession) {
  std::vector<std::vector<std::byte>> expected;
  const auto stream = make_stream(1, 5000, 80, expected);
  BinaryFileView v(stream);
  expect_records(v, expected);
  EXPECT_EQ(v.offset(), stream.size());
}

TEST(BinaryFileView, Truncation) {
  std::vector<std::byte> s;
  const std::byte msg[3] = {std::byte{'S'}, std::byte{1}, std::byte{2}};
  append_record(s, msg);
  s.push_back(std::byte{0});  // half a length prefix
  {
    BinaryFileView v(s);
    EXPECT_EQ(v.next().status, RecordStatus::Message);
    const Record r = v.next();
    EXPECT_EQ(r.status, RecordStatus::Truncated);
    EXPECT_EQ(r.data.size(), 1u);
    EXPECT_EQ(v.next().status, RecordStatus::EndOfFile);
  }
  s.back() = std::byte{0};
  s.push_back(std::byte{10});  // length 10, no body
  s.push_back(std::byte{'A'});
  BinaryFileView v(s);
  EXPECT_EQ(v.next().status, RecordStatus::Message);
  const Record r = v.next();
  EXPECT_EQ(r.status, RecordStatus::Truncated);
  EXPECT_EQ(r.data.size(), 3u);
}

TEST(BinaryFileReader, PlainFileAcrossBufferBoundaries) {
  std::vector<std::vector<std::byte>> expected;
  auto stream = make_stream(2, 20000, 300, expected);
  // A maximum-length record that cannot fit in the remainder of any buffer.
  std::vector<std::byte> big(65535);
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::byte>(i * 7);
  append_record(stream, big);
  expected.push_back(big);
  const std::string path = temp_path("plain.bin");
  write_file(path, stream);
  BinaryFileReader r;
  ASSERT_TRUE(r.open(path, BinaryFileReader::kMinBufferBytes).has_value());
  EXPECT_FALSE(r.compressed());
  expect_records(r, expected);
  EXPECT_EQ(r.bytes_consumed(), stream.size());
  std::remove(path.c_str());
}

TEST(BinaryFileReader, GzipFile) {
  std::vector<std::vector<std::byte>> expected;
  const auto stream = make_stream(3, 50000, 60, expected);
  const std::string path = temp_path("one.gz");
  write_gz(path, stream);
  BinaryFileReader r;
  ASSERT_TRUE(r.open(path, BinaryFileReader::kMinBufferBytes).has_value());
  EXPECT_TRUE(r.compressed());
  expect_records(r, expected);
  EXPECT_EQ(r.bytes_consumed(), stream.size());
  std::remove(path.c_str());
}

TEST(BinaryFileReader, MultiMemberGzip) {
  std::vector<std::vector<std::byte>> e1, e2;
  const auto s1 = make_stream(4, 3000, 50, e1);
  const auto s2 = make_stream(5, 3000, 50, e2);
  const std::string path = temp_path("multi.gz");
  write_gz(path, s1, "wb");
  write_gz(path, s2, "ab");  // appends a second gzip member
  e1.insert(e1.end(), e2.begin(), e2.end());
  BinaryFileReader r;
  ASSERT_TRUE(r.open(path).has_value());
  expect_records(r, e1);
  std::remove(path.c_str());
}

TEST(BinaryFileReader, TruncatedGzipIsAnError) {
  std::vector<std::vector<std::byte>> expected;
  const auto stream = make_stream(6, 20000, 60, expected);
  const std::string path = temp_path("trunc.gz");
  write_gz(path, stream);
  // Cut the compressed file in half.
  std::FILE* f = std::fopen(path.c_str(), "rb");
  ASSERT_NE(f, nullptr);
  std::vector<char> gz(1 << 22);
  const std::size_t n = std::fread(gz.data(), 1, gz.size(), f);
  std::fclose(f);
  write_file(path, std::as_bytes(std::span(gz.data(), n / 2)));
  BinaryFileReader r;
  ASSERT_TRUE(r.open(path).has_value());
  Record rec;
  std::size_t messages = 0;
  while ((rec = r.next()).status == RecordStatus::Message || rec.status == RecordStatus::EndOfSession) ++messages;
  EXPECT_EQ(rec.status, RecordStatus::IoError);
  EXPECT_GT(messages, 0u);
  EXPECT_LT(messages, expected.size());
  EXPECT_FALSE(r.error().empty());
  std::remove(path.c_str());
}

TEST(BinaryFileReader, TruncatedPlainRecordAndEmptyFile) {
  std::vector<std::byte> s;
  const std::byte msg[2] = {std::byte{'D'}, std::byte{1}};
  append_record(s, msg);
  s.push_back(std::byte{0});
  s.push_back(std::byte{19});
  s.push_back(std::byte{'D'});
  const std::string path = temp_path("trunc.bin");
  write_file(path, s);
  BinaryFileReader r;
  ASSERT_TRUE(r.open(path).has_value());
  EXPECT_EQ(r.next().status, RecordStatus::Message);
  EXPECT_EQ(r.next().status, RecordStatus::Truncated);
  EXPECT_EQ(r.next().status, RecordStatus::EndOfFile);

  write_file(path, {});
  ASSERT_TRUE(r.open(path).has_value());
  EXPECT_EQ(r.next().status, RecordStatus::EndOfFile);
  std::remove(path.c_str());

  EXPECT_FALSE(r.open(temp_path("does_not_exist")).has_value());
  EXPECT_EQ(r.next().status, RecordStatus::IoError);
}

TEST(MappedFile, MapsPlainFile) {
  std::vector<std::vector<std::byte>> expected;
  const auto stream = make_stream(7, 1000, 40, expected);
  const std::string path = temp_path("mapped.bin");
  write_file(path, stream);
  MappedFile mf;
  ASSERT_TRUE(mf.open(path).has_value());
  ASSERT_EQ(mf.bytes().size(), stream.size());
  BinaryFileView v(mf.bytes());
  expect_records(v, expected);
  std::remove(path.c_str());
}

}  // namespace
}  // namespace lle::itch50

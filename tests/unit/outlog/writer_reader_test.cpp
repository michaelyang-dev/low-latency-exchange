// OutlogWriter / OutlogReader: format, index, random access, streaming (06 §8).
#include <gtest/gtest.h>
#include <sys/resource.h>

#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "common/crc32c.h"
#include "common/endian.h"
#include "common/prng.h"
#include "outlog/format.h"
#include "outlog/reader.h"
#include "outlog/repair.h"
#include "outlog/writer.h"
#include "outlog_test_util.h"

namespace lle::outlog {
namespace {

using test::as_bytes;
using test::make_message;
using test::TempDir;

constexpr std::uint64_t kSeed = 0x0071;

// Writes one message per entry of `lengths` (content from make_message).
void write_log(const std::string& path, const std::vector<std::size_t>& lengths,
               std::size_t buffer_bytes = OutlogWriter::kDefaultBufferBytes) {
  OutlogWriter w;
  ASSERT_TRUE(w.open(path, buffer_bytes).has_value());
  for (std::size_t i = 0; i < lengths.size(); ++i) {
    const auto r = w.append(as_bytes(make_message(kSeed, i + 1, lengths[i])));
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(*r, i + 1);
  }
  ASSERT_TRUE(w.close().has_value());
}

// Appends messages [first, last) (0-based) of the log described by `lengths`.
bool append_range(OutlogWriter& w, const std::vector<std::size_t>& lengths, std::size_t first, std::size_t last) {
  bool ok = true;
  for (std::size_t i = first; i < last; ++i) {
    ok = ok && w.append(as_bytes(make_message(kSeed, i + 1, lengths[i]))) == SeqNo{i + 1};
  }
  return ok;
}

std::vector<std::size_t> small_lengths(std::size_t n, std::uint64_t seed) {
  Prng rng(seed);
  std::vector<std::size_t> lens(n);
  for (auto& l : lens) l = static_cast<std::size_t>(rng.range(1, 40));
  return lens;
}

std::uint64_t total_bytes(const std::vector<std::size_t>& lengths, std::size_t n) {
  std::uint64_t b = 0;
  for (std::size_t i = 0; i < n; ++i) b += kLengthPrefixBytes + lengths[i];
  return b;
}

void expect_message(OutlogReader& r, SeqNo seq, std::size_t len) {
  static std::vector<std::byte> scratch(kMaxMessageBytes);  // reused: 64 KiB per call dominates Debug runs
  const auto m = r.read(seq, scratch);
  ASSERT_TRUE(m.has_value()) << "seq " << seq << ": " << to_string(m.error());
  const std::vector<std::byte> want = make_message(kSeed, seq, len);
  ASSERT_EQ(m->size(), want.size()) << "seq " << seq;
  EXPECT_EQ(std::memcmp(m->data(), want.data(), want.size()), 0) << "seq " << seq;
}

TEST(OutlogWriter, RoundTripRandomLengths) {
  TempDir dir;
  Prng rng(1);
  std::vector<std::size_t> lens = {1, 2, kMaxMessageBytes, kMaxMessageBytes - 1, 3};
  while (lens.size() < 3000) lens.push_back(test::random_length(rng));
  lens.push_back(kMaxMessageBytes);
  lens.push_back(1);
  lens.push_back(2);

  // The minimum buffer forces a write(2) on almost every large message.
  for (const std::size_t buffer : {OutlogWriter::kMinBufferBytes, OutlogWriter::kDefaultBufferBytes}) {
    const std::string path = dir.file("rt-" + std::to_string(buffer) + ".bin");
    {
      OutlogWriter w;
      ASSERT_TRUE(w.open(path, buffer).has_value());
      for (std::size_t i = 0; i < lens.size(); ++i) {
        const auto r = w.append(as_bytes(make_message(kSeed, i + 1, lens[i])));
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(*r, i + 1);
      }
      EXPECT_EQ(w.count(), lens.size());
      EXPECT_EQ(w.bytes(), total_bytes(lens, lens.size()));
      ASSERT_TRUE(w.close().has_value());
    }
    EXPECT_EQ(std::filesystem::file_size(path), total_bytes(lens, lens.size()));

    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    EXPECT_EQ(r.count(), lens.size());
    EXPECT_EQ(r.bytes(), total_bytes(lens, lens.size()));
    EXPECT_FALSE(r.index_rebuilt());
    for (SeqNo s = 1; s <= lens.size(); ++s) expect_message(r, s, lens[s - 1]);

    SeqNo next = 1;
    const std::size_t n = r.for_each(1, lens.size() + 10, [&](SeqNo seq, std::span<const std::byte> msg) {
      EXPECT_EQ(seq, next);
      const std::vector<std::byte> want = make_message(kSeed, seq, lens[seq - 1]);
      EXPECT_TRUE(msg.size() == want.size() && std::memcmp(msg.data(), want.data(), want.size()) == 0);
      ++next;
    });
    EXPECT_EQ(n, lens.size());
  }
}

TEST(OutlogWriter, IndexHasAnEntryEvery4096Messages) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(20'000, 2);
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(path, OutlogWriter::kMinBufferBytes).has_value());
    // An entry appears only once the message it points to is in the data file.
    const std::vector<std::size_t> checkpoints = {1, 4095, 4096, 4097, 8192, 8193, 12'289, 20'000};
    std::size_t next_check = 0;
    for (std::size_t i = 0; i < lens.size(); ++i) {
      ASSERT_TRUE(w.append(as_bytes(make_message(kSeed, i + 1, lens[i]))).has_value());
      if (next_check < checkpoints.size() && i + 1 == checkpoints[next_check]) {
        ASSERT_TRUE(w.flush().has_value());
        const test::ParsedIndex idx = test::parse_index(index_path(path));
        EXPECT_EQ(idx.entries.size(), index_entries_for(i + 1)) << "after " << i + 1;
        EXPECT_EQ(std::filesystem::file_size(path), total_bytes(lens, i + 1));
        ++next_check;
      }
    }
    ASSERT_TRUE(w.close().has_value());
  }

  // Header, field by field.
  const std::vector<std::byte> raw = test::read_file(index_path(path));
  ASSERT_GE(raw.size(), kIndexHeaderBytes);
  EXPECT_EQ(std::memcmp(raw.data(), "LLEOIDX1", 8), 0);
  EXPECT_EQ(load_le32(raw.data() + 8), 1u);
  EXPECT_EQ(load_le32(raw.data() + 12), 4096u);
  EXPECT_EQ(load_le64(raw.data() + 16), 0u);
  EXPECT_EQ(load_le32(raw.data() + 24), 0u);
  EXPECT_EQ(load_le32(raw.data() + 28), crc32c(raw.data(), 28));

  // Entries: ceil(20000 / 4096) = 5, each pointing at the length prefix of
  // message k*4096 + 1, checked against an independent parse of the data.
  const test::ParsedIndex idx = test::parse_index(index_path(path));
  EXPECT_TRUE(idx.header_ok);
  EXPECT_EQ(idx.trailing_bytes, 0u);
  ASSERT_EQ(idx.entries.size(), 5u);
  EXPECT_EQ(raw.size(), kIndexHeaderBytes + 5 * kIndexEntryBytes);
  EXPECT_EQ(idx.entries, test::expected_entries(lens));
  const std::vector<std::byte> data = test::read_file(path);
  std::uint64_t off = 0;
  for (std::size_t i = 0; i < lens.size(); ++i) {
    if (i % kIndexInterval == 0) EXPECT_EQ(idx.entries[i / kIndexInterval], off) << "entry " << i / kIndexInterval;
    ASSERT_EQ(load_be16(data.data() + off), lens[i]);
    off += kLengthPrefixBytes + lens[i];
  }
  EXPECT_EQ(off, data.size());
}

TEST(OutlogReader, RandomAccessBySequenceNumber) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 3);
  write_log(path, lens);

  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  ASSERT_EQ(r.count(), 10'000u);
  const SeqNo last = r.count();
  for (const SeqNo s : {SeqNo{1}, SeqNo{4095}, SeqNo{4096}, SeqNo{4097}, SeqNo{8192}, SeqNo{8193}, last}) {
    expect_message(r, s, lens[s - 1]);
  }
  // Backwards and in a seeded random order (the read hint must not leak).
  for (SeqNo back = 0; back < last; back += 97) expect_message(r, last - back, lens[last - back - 1]);
  Prng rng(33);
  for (int i = 0; i < 500; ++i) {
    const SeqNo s = 1 + rng.below(last);
    expect_message(r, s, lens[s - 1]);
  }

  std::vector<std::byte> scratch(kMaxMessageBytes);
  EXPECT_EQ(r.read(0, scratch).error(), Error::OutOfRange);
  EXPECT_EQ(r.read(last + 1, scratch).error(), Error::OutOfRange);
  EXPECT_EQ(r.read(1'000'000, scratch).error(), Error::OutOfRange);

  // Scratch exactly the message length works; one byte less does not.
  std::vector<std::byte> exact(lens[4096 - 1]);
  EXPECT_TRUE(r.read(4096, exact).has_value());
  std::vector<std::byte> small(lens[4096 - 1] - 1);
  EXPECT_EQ(r.read(4096, small).error(), Error::ScratchTooSmall);

  // Offsets agree with the format.
  const std::vector<std::uint64_t> entries = test::expected_entries(lens);
  EXPECT_EQ(r.offset_of(1).value(), 0u);
  EXPECT_EQ(r.offset_of(4097).value(), entries[1]);
  EXPECT_EQ(r.offset_of(8193).value(), entries[2]);
  EXPECT_EQ(r.offset_of(4098).value(), entries[1] + kLengthPrefixBytes + lens[4096]);
  EXPECT_EQ(r.offset_of(last + 1).value(), r.bytes());
  EXPECT_EQ(r.offset_of(last + 2).error(), Error::OutOfRange);
  EXPECT_EQ(r.offset_of(0).error(), Error::OutOfRange);
}

TEST(OutlogReader, ForEachAcrossIndexBoundaries) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(3 * 4096 + 10, 4);
  write_log(path, lens);
  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  const SeqNo count = r.count();

  auto run = [&](SeqNo from, std::size_t max) {
    std::vector<SeqNo> seen;
    const std::size_t n = r.for_each(from, max, [&](SeqNo seq, std::span<const std::byte> msg) {
      const std::vector<std::byte> want = make_message(kSeed, seq, lens[seq - 1]);
      EXPECT_TRUE(msg.size() == want.size() && std::memcmp(msg.data(), want.data(), want.size()) == 0)
          << "seq " << seq;
      seen.push_back(seq);
    });
    EXPECT_EQ(n, seen.size());
    return seen;
  };
  auto range = [](SeqNo first, SeqNo last) {
    std::vector<SeqNo> v;
    for (SeqNo s = first; s <= last; ++s) v.push_back(s);
    return v;
  };

  EXPECT_EQ(run(4090, 20), range(4090, 4109));
  EXPECT_EQ(run(8190, 10), range(8190, 8199));
  EXPECT_EQ(run(4096, 4098), range(4096, 8193));
  EXPECT_EQ(run(1, 1'000'000), range(1, count));
  EXPECT_EQ(run(count - 2, 100), range(count - 2, count));
  EXPECT_EQ(run(count, 1), range(count, count));
  EXPECT_TRUE(run(0, 5).empty());
  EXPECT_TRUE(run(count + 1, 5).empty());
  EXPECT_TRUE(run(5, 0).empty());

  // A callback returning bool stops the scan after the message it rejects.
  std::vector<SeqNo> seen;
  const std::size_t n = r.for_each(4095, 100, [&](SeqNo seq, std::span<const std::byte>) {
    seen.push_back(seq);
    return seen.size() < 3;
  });
  EXPECT_EQ(n, 3u);
  EXPECT_EQ(seen, range(4095, 4097));
}

TEST(OutlogReader, RefreshSeesOnlyCompleteRecords) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(9000, 5);
  OutlogWriter w;
  ASSERT_TRUE(w.open(path).has_value());
  ASSERT_TRUE(append_range(w, lens, 0, 5000));
  ASSERT_TRUE(w.flush().has_value());

  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  EXPECT_EQ(r.count(), 5000u);
  ASSERT_TRUE(append_range(w, lens, 5000, 8000));
  ASSERT_TRUE(r.refresh().has_value());
  EXPECT_EQ(r.count(), 5000u);  // still in the writer's buffer
  ASSERT_TRUE(w.flush().has_value());
  ASSERT_TRUE(r.refresh().has_value());
  EXPECT_EQ(r.count(), 8000u);
  EXPECT_EQ(r.index_entries().size(), 2u);
  expect_message(r, 8000, lens[7999]);
  expect_message(r, 4097, lens[4096]);
  ASSERT_TRUE(w.close().has_value());

  // A record still being written (or torn by a crash) does not count.
  std::vector<std::byte> data = test::read_file(path);
  const std::vector<std::byte> extra = make_message(kSeed, 8001, lens[8000]);
  std::vector<std::byte> record(kLengthPrefixBytes + extra.size());
  store_be16(record.data(), static_cast<std::uint16_t>(extra.size()));
  std::memcpy(record.data() + kLengthPrefixBytes, extra.data(), extra.size());
  for (const std::size_t part : {std::size_t{1}, std::size_t{2}, record.size() - 1}) {
    std::vector<std::byte> partial = data;
    partial.insert(partial.end(), record.begin(), record.begin() + static_cast<std::ptrdiff_t>(part));
    test::write_file(path, partial);
    ASSERT_TRUE(r.refresh().has_value());
    EXPECT_EQ(r.count(), 8000u) << "partial " << part;
  }
  data.insert(data.end(), record.begin(), record.end());
  test::write_file(path, data);
  ASSERT_TRUE(r.refresh().has_value());
  EXPECT_EQ(r.count(), 8001u);
  expect_message(r, 8001, lens[8000]);

  // Shrinking underneath the reader (truncate_to) makes it start over.
  ASSERT_TRUE(truncate_to(path, 100).has_value());
  ASSERT_TRUE(r.refresh().has_value());
  EXPECT_EQ(r.count(), 100u);
  expect_message(r, 100, lens[99]);
}

TEST(OutlogWriter, ReopenAndAppendContinuesSequence) {
  TempDir dir;
  const std::string path = dir.file("soup-000001.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 6);
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(path).has_value());
    ASSERT_TRUE(append_range(w, lens, 0, 5000));
  }  // destructor flushes and closes
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(path).has_value());
    EXPECT_EQ(w.count(), 5000u);
    EXPECT_EQ(w.bytes(), total_bytes(lens, 5000));
    for (std::size_t i = 5000; i < lens.size(); ++i) {
      const auto r = w.append(as_bytes(make_message(kSeed, i + 1, lens[i])));
      ASSERT_TRUE(r.has_value());
      EXPECT_EQ(*r, i + 1);
    }
    ASSERT_TRUE(w.close().has_value());
  }
  EXPECT_EQ(test::parse_index(index_path(path)).entries, test::expected_entries(lens));
  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  EXPECT_EQ(r.count(), lens.size());
  for (SeqNo s = 1; s <= lens.size(); s += 37) expect_message(r, s, lens[s - 1]);
  expect_message(r, lens.size(), lens.back());
}

TEST(OutlogWriter, AppendRejectsEmptyAndOversizeMessages) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  OutlogWriter w;
  const std::vector<std::byte> big(kMaxMessageBytes + 1, std::byte{0x5A});
  EXPECT_EQ(w.append(as_bytes(big)).error(), Error::NotOpen);
  EXPECT_EQ(w.flush().error(), Error::NotOpen);

  ASSERT_TRUE(w.open(path).has_value());
  EXPECT_EQ(w.append({}).error(), Error::EmptyMessage);
  EXPECT_EQ(w.append(as_bytes(big)).error(), Error::MessageTooLarge);
  EXPECT_EQ(w.count(), 0u);
  EXPECT_EQ(w.bytes(), 0u);
  EXPECT_FALSE(w.failed());  // rejected input is not an I/O failure
  EXPECT_EQ(w.append(std::span<const std::byte>(big).first(kMaxMessageBytes)).value(), 1u);
  EXPECT_EQ(w.append(std::span<const std::byte>(big).first(1)).value(), 2u);
  ASSERT_TRUE(w.sync().has_value());
  ASSERT_TRUE(w.close().has_value());
  EXPECT_EQ(std::filesystem::file_size(path), kMaxRecordBytes + 3);
}

TEST(OutlogWriter, BinaryFileFraming) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  std::vector<std::byte> m300(300);
  for (std::size_t i = 0; i < m300.size(); ++i) m300[i] = static_cast<std::byte>(i);
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(path).has_value());
    const std::byte a[] = {std::byte{'A'}};
    const std::byte b[] = {std::byte{0x01}, std::byte{0x02}};
    ASSERT_TRUE(w.append(a).has_value());
    ASSERT_TRUE(w.append(b).has_value());
    ASSERT_TRUE(w.append(as_bytes(m300)).has_value());
    ASSERT_TRUE(w.close().has_value());
  }
  // [u16 big-endian length][payload], back to back, no file header.
  const std::vector<std::byte> raw = test::read_file(path);
  ASSERT_EQ(raw.size(), 3u + 4u + 302u);
  const unsigned char head[] = {0x00, 0x01, 'A', 0x00, 0x02, 0x01, 0x02, 0x01, 0x2C, 0x00, 0x01, 0x02};
  for (std::size_t i = 0; i < sizeof head; ++i) EXPECT_EQ(raw[i], std::byte{head[i]}) << "byte " << i;
  EXPECT_EQ(raw.back(), std::byte{299 & 0xFF});
}

TEST(OutlogWriter, OneWriterPerFile) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  OutlogWriter w;
  ASSERT_TRUE(w.open(path).has_value());
  const std::byte m[] = {std::byte{1}};
  ASSERT_TRUE(w.append(m).has_value());
  OutlogWriter second;
  EXPECT_FALSE(second.open(path).has_value());
  EXPECT_FALSE(repair(path).ok());
  EXPECT_EQ(truncate_to(path, 0).error(), Error::Locked);
  ASSERT_TRUE(w.close().has_value());
  ASSERT_TRUE(second.open(path).has_value());
  EXPECT_EQ(second.count(), 1u);
}

TEST(OutlogWriter, WriteErrorIsSticky) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  OutlogWriter w;
  ASSERT_TRUE(w.open(path, OutlogWriter::kMinBufferBytes).has_value());

  // Make the data file unable to grow past 4 KiB: write(2) fails with EFBIG
  // (SIGXFSZ ignored). ctest runs each test in its own process; the limit is
  // restored before any assertion anyway.
  rlimit old{};
  ASSERT_EQ(::getrlimit(RLIMIT_FSIZE, &old), 0);
  const auto old_handler = std::signal(SIGXFSZ, SIG_IGN);
  rlimit lim = old;
  lim.rlim_cur = 4096;
  ASSERT_EQ(::setrlimit(RLIMIT_FSIZE, &lim), 0);
  const std::vector<std::byte> m(1000, std::byte{7});
  bool appends_ok = true;
  for (int i = 0; i < 10; ++i) appends_ok = appends_ok && w.append(as_bytes(m)).has_value();
  const auto flushed = w.flush();
  const auto after = w.append(as_bytes(m));
  const auto flushed_again = w.flush();
  ::setrlimit(RLIMIT_FSIZE, &old);
  std::signal(SIGXFSZ, old_handler);

  EXPECT_TRUE(appends_ok);  // buffered: nothing written yet
  ASSERT_FALSE(flushed.has_value());
  EXPECT_EQ(flushed.error(), Error::Io);
  EXPECT_TRUE(w.failed());
  EXPECT_EQ(after.error(), Error::Io);
  EXPECT_EQ(flushed_again.error(), Error::Io);
  EXPECT_NE(w.error_message().find("cannot write"), std::string::npos) << w.error_message();
  EXPECT_FALSE(w.close().has_value());

  // The torn tail left by the failed write is repaired on the next open.
  OutlogWriter again;
  ASSERT_TRUE(again.open(path).has_value());
  EXPECT_EQ(again.count(), 4u);  // 4 x 1002 bytes fit below 4096
  EXPECT_EQ(again.bytes(), 4u * 1002u);
}

}  // namespace
}  // namespace lle::outlog

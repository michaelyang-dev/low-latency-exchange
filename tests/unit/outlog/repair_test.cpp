// Output-log repair, index rebuilding, truncation and regeneration (06 §8).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

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

constexpr std::uint64_t kSeed = 0x0072;

std::vector<std::size_t> small_lengths(std::size_t n, std::uint64_t seed) {
  Prng rng(seed);
  std::vector<std::size_t> lens(n);
  for (auto& l : lens) l = static_cast<std::size_t>(rng.range(1, 40));
  return lens;
}

void write_log(const std::string& path, const std::vector<std::size_t>& lengths) {
  OutlogWriter w;
  ASSERT_TRUE(w.open(path).has_value());
  for (std::size_t i = 0; i < lengths.size(); ++i) {
    ASSERT_TRUE(w.append(as_bytes(make_message(kSeed, i + 1, lengths[i]))).has_value());
  }
  ASSERT_TRUE(w.close().has_value());
}

std::uint64_t total_bytes(const std::vector<std::size_t>& lengths, std::size_t n) {
  std::uint64_t b = 0;
  for (std::size_t i = 0; i < n; ++i) b += kLengthPrefixBytes + lengths[i];
  return b;
}

std::vector<std::size_t> prefix(const std::vector<std::size_t>& v, std::size_t n) {
  return {v.begin(), v.begin() + static_cast<std::ptrdiff_t>(n)};
}

bool message_equals(OutlogReader& r, SeqNo seq, std::span<const std::byte> want) {
  static std::vector<std::byte> scratch(kMaxMessageBytes);  // reused: 64 KiB per call dominates Debug runs
  const auto m = r.read(seq, scratch);
  return m.has_value() && m->size() == want.size() && std::memcmp(m->data(), want.data(), want.size()) == 0;
}

// Every message of the log, read sequentially and at random.
void expect_log(OutlogReader& r, const std::vector<std::size_t>& lens) {
  ASSERT_EQ(r.count(), lens.size());
  SeqNo next = 1;
  bool all_equal = true;
  r.for_each(1, lens.size(), [&](SeqNo seq, std::span<const std::byte> msg) {
    const std::vector<std::byte> want = make_message(kSeed, seq, lens[seq - 1]);
    all_equal = all_equal && seq == next++ && msg.size() == want.size() &&
                std::memcmp(msg.data(), want.data(), want.size()) == 0;
  });
  EXPECT_TRUE(all_equal);
  EXPECT_EQ(next, lens.size() + 1);
  Prng rng(lens.size());
  for (int i = 0; i < 200 && !lens.empty(); ++i) {
    const SeqNo s = 1 + rng.below(lens.size());
    EXPECT_TRUE(message_equals(r, s, as_bytes(make_message(kSeed, s, lens[s - 1])))) << "seq " << s;
  }
}

TEST(OutlogRepair, TornTailAtEveryOffsetOfTheLastThreeRecords) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  // 4097 messages: the last one opens index block 1, so cutting into it must
  // also drop index entry 1.
  std::vector<std::size_t> lens = small_lengths(4097, 7);
  lens[4094] = 300;
  lens[4095] = 1;
  lens[4096] = 2;
  write_log(path, lens);
  const std::vector<std::byte> data = test::read_file(path);
  const std::vector<std::byte> idx = test::read_file(index_path(path));
  ASSERT_EQ(test::parse_index(index_path(path)).entries.size(), 2u);

  std::vector<std::uint64_t> ends(lens.size() + 1, 0);  // ends[n] = bytes of the first n records
  for (std::size_t i = 0; i < lens.size(); ++i) ends[i + 1] = ends[i] + kLengthPrefixBytes + lens[i];
  ASSERT_EQ(ends.back(), data.size());

  const std::uint64_t first_cut = ends[lens.size() - 3];
  for (std::uint64_t cut = first_cut; cut < data.size(); ++cut) {
    std::size_t complete = lens.size() - 3;
    while (complete < lens.size() && ends[complete + 1] <= cut) ++complete;
    const std::uint64_t valid = ends[complete];
    const std::span<const std::byte> torn(data.data(), static_cast<std::size_t>(cut));

    // repair()
    test::write_file(path, torn);
    test::write_file(index_path(path), idx);
    const RepairResult rr = repair(path);
    ASSERT_TRUE(rr.ok()) << rr.error;
    ASSERT_EQ(rr.messages, complete) << "cut " << cut;
    EXPECT_EQ(rr.bytes, valid);
    EXPECT_EQ(rr.truncated_bytes, cut - valid);
    EXPECT_EQ(std::filesystem::file_size(path), valid);
    EXPECT_EQ(test::parse_index(index_path(path)).entries, test::expected_entries(prefix(lens, complete)));

    // OutlogWriter::open() repairs too, then appending continues.
    test::write_file(path, torn);
    test::write_file(index_path(path), idx);
    const std::vector<std::byte> extra = make_message(kSeed + 1, cut, 5);
    {
      OutlogWriter w;
      ASSERT_TRUE(w.open(path).has_value());
      ASSERT_EQ(w.count(), complete) << "cut " << cut;
      EXPECT_EQ(w.bytes(), valid);
      EXPECT_EQ(w.append(as_bytes(extra)).value(), complete + 1);
      ASSERT_TRUE(w.close().has_value());
    }
    EXPECT_EQ(std::filesystem::file_size(path), valid + kLengthPrefixBytes + extra.size());
    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    ASSERT_EQ(r.count(), complete + 1);
    EXPECT_TRUE(message_equals(r, complete + 1, as_bytes(extra)));
    EXPECT_TRUE(message_equals(r, complete, as_bytes(make_message(kSeed, complete, lens[complete - 1]))));
    std::vector<std::size_t> want_lens = prefix(lens, complete);
    want_lens.push_back(extra.size());
    EXPECT_EQ(test::parse_index(index_path(path)).entries, test::expected_entries(want_lens));
  }
}

TEST(OutlogRepair, ZeroFilledTailIsTruncated) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(5000, 8);
  write_log(path, lens);
  // A crash can leave the file extended with zeros past the last write.
  std::vector<std::byte> data = test::read_file(path);
  data.resize(data.size() + 4096, std::byte{0});
  test::write_file(path, data);

  OutlogReader r;
  ASSERT_TRUE(r.open(path).has_value());
  EXPECT_EQ(r.count(), 5000u);
  const RepairResult rr = repair(path);
  ASSERT_TRUE(rr.ok()) << rr.error;
  EXPECT_EQ(rr.messages, 5000u);
  EXPECT_EQ(rr.truncated_bytes, 4096u);
  EXPECT_FALSE(rr.index_rebuilt);
  EXPECT_EQ(std::filesystem::file_size(path), total_bytes(lens, lens.size()));
}

TEST(OutlogRepair, MissingIndexIsRebuilt) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 9);
  write_log(path, lens);
  const std::vector<std::uint64_t> want = test::expected_entries(lens);
  ASSERT_TRUE(std::filesystem::remove(index_path(path)));

  {
    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    EXPECT_TRUE(r.index_rebuilt());
    EXPECT_EQ(std::vector<std::uint64_t>(r.index_entries().begin(), r.index_entries().end()), want);
    expect_log(r, lens);
  }
  EXPECT_FALSE(std::filesystem::exists(index_path(path)));  // readers never write the index

  const RepairResult rr = repair(path);
  ASSERT_TRUE(rr.ok()) << rr.error;
  EXPECT_TRUE(rr.index_rebuilt);
  EXPECT_EQ(rr.messages, lens.size());
  EXPECT_EQ(rr.truncated_bytes, 0u);
  const test::ParsedIndex parsed = test::parse_index(index_path(path));
  EXPECT_TRUE(parsed.header_ok);
  EXPECT_EQ(parsed.entries, want);
  EXPECT_FALSE(repair(path).index_rebuilt);  // idempotent

  // The writer recreates a missing index as well.
  ASSERT_TRUE(std::filesystem::remove(index_path(path)));
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(path).has_value());
    EXPECT_EQ(w.count(), lens.size());
  }
  EXPECT_EQ(test::parse_index(index_path(path)).entries, want);
}

TEST(OutlogRepair, GarbageIndexIsRebuilt) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 10);
  write_log(path, lens);
  const std::vector<std::uint64_t> want = test::expected_entries(lens);

  Prng rng(11);
  std::vector<std::byte> garbage(1000);
  for (auto& b : garbage) b = static_cast<std::byte>(rng.next_u64() & 0xFF);
  // Random bytes, and a valid header followed by random entries.
  std::vector<std::byte> bad_entries(kIndexHeaderBytes + 6 * kIndexEntryBytes);
  const auto header = encode_index_header();
  std::memcpy(bad_entries.data(), header.data(), header.size());
  for (std::size_t i = kIndexHeaderBytes; i < bad_entries.size(); ++i) {
    bad_entries[i] = static_cast<std::byte>(rng.next_u64() & 0xFF);
  }

  for (const auto& bad : {garbage, bad_entries}) {
    test::write_file(index_path(path), bad);
    {
      OutlogReader r;
      ASSERT_TRUE(r.open(path).has_value());
      EXPECT_TRUE(r.index_rebuilt());
      EXPECT_EQ(std::vector<std::uint64_t>(r.index_entries().begin(), r.index_entries().end()), want);
      expect_log(r, lens);
    }
    const RepairResult rr = repair(path);
    ASSERT_TRUE(rr.ok()) << rr.error;
    EXPECT_TRUE(rr.index_rebuilt);
    EXPECT_EQ(rr.messages, lens.size());
    EXPECT_EQ(test::parse_index(index_path(path)).entries, want);
  }
}

// Valid header, plausible but wrong entries: caught when the block is used.
TEST(OutlogRepair, InconsistentIndexIsDetectedAndRebuilt) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(5 * 4096 + 100, 12);
  write_log(path, lens);
  const std::vector<std::uint64_t> want = test::expected_entries(lens);
  ASSERT_EQ(want.size(), 6u);

  struct Case {
    const char* name;
    std::size_t entry;
    std::uint64_t value;
  };
  const Case cases[] = {
      {"mid-record", 2, want[2] + 3},
      {"one record late", 1, want[1] + kLengthPrefixBytes + lens[4096]},
      {"last entry", 5, want[5] + 1},
      {"block before last", 4, want[4] - 1},
  };
  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    std::vector<std::uint64_t> bad = want;
    bad[c.entry] = c.value;
    ASSERT_TRUE(detail::write_index(index_path(path), bad).has_value());

    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    ASSERT_EQ(r.count(), lens.size());
    const SeqNo probe = SeqNo{c.entry} * kIndexInterval + 10;
    EXPECT_TRUE(message_equals(r, probe, as_bytes(make_message(kSeed, probe, lens[probe - 1]))));
    EXPECT_TRUE(r.index_rebuilt());
    expect_log(r, lens);
    EXPECT_EQ(std::vector<std::uint64_t>(r.index_entries().begin(), r.index_entries().end()), want);

    const RepairResult rr = repair(path);
    ASSERT_TRUE(rr.ok()) << rr.error;
    EXPECT_TRUE(rr.index_rebuilt);
    EXPECT_EQ(test::parse_index(index_path(path)).entries, want);
  }
}

TEST(OutlogRepair, ShortOrOverlongIndex) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 13);
  write_log(path, lens);
  const std::vector<std::byte> data = test::read_file(path);
  const std::vector<std::byte> idx = test::read_file(index_path(path));

  // Header + one entry + a torn half entry: the index merely lags.
  test::write_file(index_path(path), std::span<const std::byte>(idx).first(kIndexHeaderBytes + 12));
  {
    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    expect_log(r, lens);
  }
  RepairResult rr = repair(path);
  ASSERT_TRUE(rr.ok()) << rr.error;
  EXPECT_TRUE(rr.index_rebuilt);
  EXPECT_EQ(test::parse_index(index_path(path)).entries, test::expected_entries(lens));

  // Data cut back at a record boundary behind the index's back: entries
  // past the data are ignored.
  test::write_file(path, std::span<const std::byte>(data).first(static_cast<std::size_t>(total_bytes(lens, 5000))));
  test::write_file(index_path(path), idx);
  {
    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    expect_log(r, prefix(lens, 5000));
    EXPECT_EQ(r.index_entries().size(), 2u);
  }
  rr = repair(path);
  ASSERT_TRUE(rr.ok()) << rr.error;
  EXPECT_TRUE(rr.index_rebuilt);
  EXPECT_EQ(rr.messages, 5000u);
  EXPECT_EQ(test::parse_index(index_path(path)).entries, test::expected_entries(prefix(lens, 5000)));
}

TEST(OutlogRepair, TruncateTo) {
  TempDir dir;
  const std::string path = dir.file("itch.bin");
  const std::vector<std::size_t> lens = small_lengths(10'000, 14);
  write_log(path, lens);

  EXPECT_EQ(truncate_to(path, 10'001).error(), Error::OutOfRange);
  EXPECT_EQ(truncate_to(dir.file("missing.bin"), 0).error(), Error::Io);
  for (const SeqNo keep : {SeqNo{10'000}, SeqNo{8193}, SeqNo{8192}, SeqNo{5000}, SeqNo{4097}, SeqNo{4096}, SeqNo{1},
                           SeqNo{0}}) {
    SCOPED_TRACE(keep);
    ASSERT_TRUE(truncate_to(path, keep).has_value());
    EXPECT_EQ(std::filesystem::file_size(path), total_bytes(lens, keep));
    const test::ParsedIndex parsed = test::parse_index(index_path(path));
    EXPECT_TRUE(parsed.header_ok);
    EXPECT_EQ(parsed.entries, test::expected_entries(prefix(lens, keep)));
    OutlogReader r;
    ASSERT_TRUE(r.open(path).has_value());
    EXPECT_FALSE(r.index_rebuilt());
    expect_log(r, prefix(lens, keep));
  }

  // A torn tail goes too.
  write_log(path, lens);
  std::vector<std::byte> data = test::read_file(path);
  data.push_back(std::byte{0x00});
  test::write_file(path, data);
  ASSERT_TRUE(truncate_to(path, lens.size()).has_value());
  EXPECT_EQ(std::filesystem::file_size(path), total_bytes(lens, lens.size()));
}

// Deterministic stand-in for the journal replay: message `seq` of the day.
std::size_t regen_length(SeqNo seq) {
  if (seq % 5000 == 1234) return kMaxMessageBytes;
  return 1 + static_cast<std::size_t>((seq * 2654435761u) % 48);
}

struct DaySource {
  SeqNo last;
  std::span<const std::byte> operator()(SeqNo seq, std::span<std::byte> scratch) const {
    if (seq > last) return {};
    const std::span<std::byte> out = scratch.first(regen_length(seq));
    test::fill_message(kSeed, seq, out);
    return out;
  }
};

TEST(OutlogRepair, RegenerateExtendsTruncatedLogByteForByte) {
  TempDir dir;
  const std::string orig = dir.file("orig.bin");
  const std::string copy = dir.file("copy.bin");
  constexpr SeqNo kTotal = 3 * 4096 + 77;
  {
    OutlogWriter w;
    ASSERT_TRUE(w.open(orig).has_value());
    const auto n = regenerate(w, DaySource{kTotal});
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(*n, kTotal);
    EXPECT_EQ(w.count(), kTotal);
    EXPECT_EQ(regenerate(w, DaySource{kTotal}).value(), 0u);  // nothing more to add
  }
  const std::vector<std::byte> data = test::read_file(orig);
  const std::vector<std::byte> idx = test::read_file(index_path(orig));

  for (const SeqNo cut : {SeqNo{0}, SeqNo{1}, SeqNo{1234}, SeqNo{4096}, SeqNo{4097}, SeqNo{9000}, kTotal}) {
    SCOPED_TRACE(cut);
    test::write_file(copy, data);
    test::write_file(index_path(copy), idx);
    ASSERT_TRUE(truncate_to(copy, cut).has_value());
    if (cut < kTotal) EXPECT_EQ(first_difference(orig, copy), cut + 1);
    OutlogWriter w;
    ASSERT_TRUE(w.open(copy).has_value());
    ASSERT_EQ(w.count(), cut);
    const auto n = regenerate(w, DaySource{kTotal});
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(*n, kTotal - cut);
    ASSERT_TRUE(w.close().has_value());
    EXPECT_EQ(first_difference(orig, copy), std::nullopt);
    EXPECT_TRUE(test::read_file(copy) == data);
    EXPECT_TRUE(test::read_file(index_path(copy)) == idx);
  }
}

TEST(OutlogRepair, RegenerateReportsErrors) {
  TempDir dir;
  OutlogWriter w;
  EXPECT_EQ(regenerate(w, DaySource{10}).error(), Error::NotOpen);
  ASSERT_TRUE(w.open(dir.file("x.bin")).has_value());
  const std::vector<std::byte> too_big(kMaxMessageBytes + 1);
  const auto oversize = [&](SeqNo, std::span<std::byte>) { return std::span<const std::byte>(too_big); };
  EXPECT_EQ(regenerate(w, oversize).error(), Error::MessageTooLarge);
  EXPECT_EQ(w.count(), 0u);
}

TEST(OutlogRepair, FirstDifference) {
  TempDir dir;
  const std::string a = dir.file("a.bin");
  const std::string b = dir.file("b.bin");
  const std::vector<std::size_t> lens = small_lengths(6000, 15);
  write_log(a, lens);

  // Writes `lens` to b, letting `edit` change the message for each seq.
  auto write_b = [&](auto edit) {
    std::filesystem::remove(b);
    std::filesystem::remove(index_path(b));
    OutlogWriter w;
    ASSERT_TRUE(w.open(b).has_value());
    for (std::size_t i = 0; i < lens.size(); ++i) {
      std::vector<std::byte> m = make_message(kSeed, i + 1, lens[i]);
      edit(i + 1, m);
      ASSERT_TRUE(w.append(as_bytes(m)).has_value());
    }
    ASSERT_TRUE(w.close().has_value());
  };

  write_b([](SeqNo, std::vector<std::byte>&) {});
  EXPECT_EQ(first_difference(a, b), std::nullopt);
  EXPECT_EQ(first_difference(a, a), std::nullopt);

  write_b([](SeqNo s, std::vector<std::byte>& m) {
    if (s == 777) m[0] ^= std::byte{1};
  });
  EXPECT_EQ(first_difference(a, b), 777u);
  EXPECT_EQ(first_difference(b, a), 777u);

  write_b([](SeqNo s, std::vector<std::byte>& m) {
    if (s == 4097) m.push_back(std::byte{0});
  });
  EXPECT_EQ(first_difference(a, b), 4097u);

  write_b([](SeqNo, std::vector<std::byte>&) {});
  ASSERT_TRUE(truncate_to(b, 500).has_value());
  EXPECT_EQ(first_difference(a, b), 501u);
  EXPECT_EQ(first_difference(b, a), 501u);

  // A torn tail is not a message.
  write_b([](SeqNo, std::vector<std::byte>&) {});
  std::vector<std::byte> torn = test::read_file(b);
  torn.push_back(std::byte{0x00});
  torn.push_back(std::byte{0x09});
  torn.push_back(std::byte{0x41});
  test::write_file(b, torn);
  EXPECT_EQ(first_difference(a, b), std::nullopt);

  // A missing file reads as an empty log.
  EXPECT_EQ(first_difference(dir.file("none1.bin"), dir.file("none2.bin")), std::nullopt);
  EXPECT_EQ(first_difference(dir.file("none1.bin"), a), 1u);
}

}  // namespace
}  // namespace lle::outlog

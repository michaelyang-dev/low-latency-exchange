// File writer, atomic publication, MappedSnapshot, validate_file and find_latest
// (06 §7 step 4, §9).
#include <gtest/gtest.h>

#include <cerrno>
#include <cstdint>
#include <filesystem>
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

constexpr std::uint32_t kSmallChunk = 4096;

WriterOptions small_chunks() {
  WriterOptions o;
  o.chunk_bytes = kSmallChunk;
  return o;
}

// Writes `payload` in uneven pieces so writes straddle chunk boundaries.
void write_in_pieces(Writer& w, std::span<const std::byte> payload, Prng& rng) {
  std::size_t at = 0;
  while (at < payload.size()) {
    const std::size_t n = std::min<std::size_t>(payload.size() - at, 1 + rng.below(3 * kSmallChunk));
    w.write(payload.subspan(at, n));
    at += n;
  }
}

std::string write_snapshot(const std::string& dir, std::uint64_t index, std::span<const std::byte> payload) {
  auto w = Writer::create(dir, test::sample_meta(index), test::sample_sessions(), small_chunks());
  EXPECT_TRUE(w.has_value());
  if (!w) return {};
  w->write(payload);
  auto path = w->commit();
  EXPECT_TRUE(path.has_value());
  return path ? *path : std::string{};
}

TEST(SnapshotWriter, CommitIsAtomicAndMatchesEncodeImage) {
  TempDir dir;
  Prng rng(1);
  const auto payload = test::random_bytes(rng, 5 * kSmallChunk + 123);
  const auto meta = test::sample_meta(777);
  const auto sessions = test::sample_sessions();
  auto w = Writer::create(dir.path(), meta, sessions, small_chunks());
  ASSERT_TRUE(w.has_value()) << to_string(w.error());
  EXPECT_EQ(w->temp_path(), snapshot_temp_path(dir.path(), 777));
  EXPECT_EQ(w->final_path(), snapshot_path(dir.path(), 777));
  write_in_pieces(*w, payload, rng);
  EXPECT_TRUE(w->ok());
  EXPECT_EQ(w->payload_bytes(), payload.size());
  // Before commit only the temporary file exists.
  EXPECT_TRUE(test::exists(snapshot_temp_path(dir.path(), 777)));
  EXPECT_FALSE(test::exists(snapshot_path(dir.path(), 777)));

  auto path = w->commit();
  ASSERT_TRUE(path.has_value()) << to_string(path.error());
  EXPECT_EQ(*path, snapshot_path(dir.path(), 777));
  EXPECT_EQ(test::list_dir(dir.path()), std::vector<std::string>{snapshot_file_name(777)});
  EXPECT_EQ(test::read_file(*path), test::encode_or_die(meta, sessions, payload, kSmallChunk));

  auto m = MappedSnapshot::open(*path);
  ASSERT_TRUE(m.has_value()) << to_string(m.error());
  EXPECT_EQ(m->meta(), meta);
  EXPECT_EQ(std::vector<SessionSeq>(m->reader().sessions().begin(), m->reader().sessions().end()), sessions);
  EXPECT_EQ(test::read_rest(m->reader()), payload);

  auto v = validate_file(*path);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, meta);
}

TEST(SnapshotWriter, DefaultChunkSizeWithMultiMiBPayload) {
  TempDir dir;
  Prng rng(2);
  const auto payload = test::random_bytes(rng, (std::size_t{3} << 20) + 12345);
  auto w = Writer::create(dir.path(), test::sample_meta(10'000'000), test::sample_sessions());
  ASSERT_TRUE(w.has_value());
  write_in_pieces(*w, payload, rng);
  auto path = w->commit();
  ASSERT_TRUE(path.has_value()) << to_string(path.error());
  auto m = MappedSnapshot::open(*path);
  ASSERT_TRUE(m.has_value()) << to_string(m.error());
  EXPECT_EQ(m->reader().layout().chunk_bytes, kDefaultChunkBytes);
  EXPECT_EQ(m->reader().layout().chunk_count, 4u);
  EXPECT_EQ(test::read_rest(m->reader()), payload);
}

TEST(SnapshotWriter, FullFsyncOption) {
  TempDir dir;
  WriterOptions o = small_chunks();
  o.full_fsync = true;
  auto w = Writer::create(dir.path(), test::sample_meta(5), {}, o);
  ASSERT_TRUE(w.has_value());
  w->put_u64(1);
  auto path = w->commit();
  ASSERT_TRUE(path.has_value()) << to_string(path.error());
  EXPECT_TRUE(validate_file(*path).has_value());
}

TEST(SnapshotWriter, AbortAndDestructorLeaveNoFiles) {
  TempDir dir;
  {
    auto w = Writer::create(dir.path(), test::sample_meta(1), {}, small_chunks());
    ASSERT_TRUE(w.has_value());
    w->write(std::vector<std::byte>(3 * kSmallChunk));
    w->abort();
    EXPECT_FALSE(w->ok());
    EXPECT_TRUE(test::list_dir(dir.path()).empty());
    w->abort();  // idempotent
    auto c = w->commit();
    ASSERT_FALSE(c.has_value());
    EXPECT_EQ(c.error().code, ErrorCode::Closed);
  }
  {
    auto w = Writer::create(dir.path(), test::sample_meta(2), {}, small_chunks());
    ASSERT_TRUE(w.has_value());
    w->put_u32(7);
    EXPECT_FALSE(test::list_dir(dir.path()).empty());
  }
  EXPECT_TRUE(test::list_dir(dir.path()).empty());
}

TEST(SnapshotWriter, UseAfterCommitIsRejected) {
  TempDir dir;
  auto w = Writer::create(dir.path(), test::sample_meta(3), {}, small_chunks());
  ASSERT_TRUE(w.has_value());
  w->put_u8(1);
  ASSERT_TRUE(w->commit().has_value());
  EXPECT_TRUE(w->ok());
  w->put_u64(2);
  EXPECT_FALSE(w->ok());
  auto again = w->commit();
  ASSERT_FALSE(again.has_value());
  EXPECT_EQ(again.error().code, ErrorCode::Closed);
  // The committed file is untouched by the rejected calls and the destructor.
  EXPECT_TRUE(validate_file(snapshot_path(dir.path(), 3)).has_value());
}

TEST(SnapshotWriter, MovedWriterKeepsOwnershipOfTheTempFile) {
  TempDir dir;
  auto w = Writer::create(dir.path(), test::sample_meta(4), {}, small_chunks());
  ASSERT_TRUE(w.has_value());
  w->put_u32(1);
  Writer moved(std::move(*w));
  w->put_u32(2);  // ignored: the moved-from writer is closed
  EXPECT_FALSE(w->ok());
  moved.put_u32(3);
  auto path = moved.commit();
  ASSERT_TRUE(path.has_value()) << to_string(path.error());
  auto m = MappedSnapshot::open(*path);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->reader().get_u32(), 1u);
  EXPECT_EQ(m->reader().get_u32(), 3u);
  EXPECT_EQ(m->reader().remaining(), 0u);
}

TEST(SnapshotWriter, InvalidArguments) {
  TempDir dir;
  for (const std::uint32_t cb : {0u, 2048u, 4095u, 5000u, 0x80000000u}) {
    WriterOptions o;
    o.chunk_bytes = cb;
    auto w = Writer::create(dir.path(), test::sample_meta(), {}, o);
    ASSERT_FALSE(w.has_value());
    EXPECT_EQ(w.error().code, ErrorCode::InvalidArgument);
  }
  const std::vector<SessionSeq> unsorted = {{2, 0}, {1, 0}};
  const std::vector<SessionSeq> duplicate = {{1, 0}, {1, 5}};
  for (const auto* bad : {&unsorted, &duplicate}) {
    auto w = Writer::create(dir.path(), test::sample_meta(), *bad, small_chunks());
    ASSERT_FALSE(w.has_value());
    EXPECT_EQ(w.error().code, ErrorCode::UnsortedSessions);
    auto m = Writer::create_in_memory(test::sample_meta(), *bad, small_chunks());
    ASSERT_FALSE(m.has_value());
    EXPECT_EQ(m.error().code, ErrorCode::UnsortedSessions);
  }
  EXPECT_TRUE(test::list_dir(dir.path()).empty());

  auto missing = Writer::create(dir.path() + "/no/such/dir", test::sample_meta(), {}, small_chunks());
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.error().code, ErrorCode::Io);
  EXPECT_EQ(missing.error().sys_errno, ENOENT);

  // Each finisher belongs to one mode.
  auto mem = Writer::create_in_memory(test::sample_meta(), {}, small_chunks());
  ASSERT_TRUE(mem.has_value());
  EXPECT_EQ(mem->commit().error().code, ErrorCode::InvalidArgument);
  auto file = Writer::create(dir.path(), test::sample_meta(), {}, small_chunks());
  ASSERT_TRUE(file.has_value());
  EXPECT_EQ(file->finish_image().error().code, ErrorCode::InvalidArgument);
}

TEST(SnapshotWriter, StaleTempFileIsReplacedAndExistingSnapshotOverwritten) {
  TempDir dir;
  const std::vector<std::byte> junk(100, std::byte{0xAB});
  test::write_file(snapshot_temp_path(dir.path(), 9), junk);
  Prng rng(3);
  const auto first = test::random_bytes(rng, 5000);
  const auto path = write_snapshot(dir.path(), 9, first);
  EXPECT_EQ(test::list_dir(dir.path()), std::vector<std::string>{snapshot_file_name(9)});

  // Rewriting the same mark (snapshotd restarted) replaces the file atomically.
  const auto second = test::random_bytes(rng, 7000);
  EXPECT_EQ(write_snapshot(dir.path(), 9, second), path);
  auto m = MappedSnapshot::open(path);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(test::read_rest(m->reader()), second);
}

TEST(SnapshotFiles, ValidateFileErrors) {
  TempDir dir;
  EXPECT_EQ(validate_file(dir.path() + "/missing.snap").error(), LoadError::Io);
  EXPECT_EQ(validate_file(dir.path()).error(), LoadError::Io);  // a directory
  const std::string empty = dir.path() + "/empty.snap";
  test::write_file(empty, {});
  EXPECT_EQ(validate_file(empty).error(), LoadError::Truncated);

  Prng rng(4);
  const std::string path = write_snapshot(dir.path(), 50, test::random_bytes(rng, 9000));
  auto bytes = test::read_file(path);
  bytes[bytes.size() / 2] ^= std::byte{0x10};
  test::write_file(path, bytes);
  EXPECT_EQ(validate_file(path).error(), LoadError::BadChunkCrc);
}

TEST(SnapshotFiles, FindLatestPicksNewestValidAtOrBelowMax) {
  TempDir dir;
  Prng rng(5);
  for (const std::uint64_t index : {100u, 200u, 300u, 400u}) {
    write_snapshot(dir.path(), index, test::random_bytes(rng, 1000 + index * 20));
  }
  // 400 is corrupt.
  {
    auto bytes = test::read_file(snapshot_path(dir.path(), 400));
    bytes[kHeaderBytes + 100] ^= std::byte{1};
    test::write_file(snapshot_path(dir.path(), 400), bytes);
  }
  // A valid image of index 500 left as a temporary file: never a candidate.
  test::write_file(snapshot_temp_path(dir.path(), 500),
                   test::encode_or_die(test::sample_meta(500), {}, {}, kSmallChunk));
  // A valid snapshot under the wrong name (header says 100): skipped.
  test::write_file(snapshot_path(dir.path(), 350), test::read_file(snapshot_path(dir.path(), 100)));
  // Unrelated entries.
  test::write_file(dir.path() + "/notes.txt", {});
  test::write_file(dir.path() + "/garbage.snap", std::vector<std::byte>(500, std::byte{1}));
  std::error_code ec;
  std::filesystem::create_directory(snapshot_path(dir.path(), 600), ec);

  auto latest = find_latest(dir.path(), std::numeric_limits<std::uint64_t>::max());
  ASSERT_TRUE(latest.has_value());
  EXPECT_EQ(latest->path, snapshot_path(dir.path(), 300));
  EXPECT_EQ(latest->meta, test::sample_meta(300));
  EXPECT_EQ(latest->layout.session_count, test::sample_sessions().size());

  EXPECT_EQ(find_latest(dir.path(), 299)->meta.index, 200u);
  EXPECT_EQ(find_latest(dir.path(), 300)->meta.index, 300u);
  EXPECT_EQ(find_latest(dir.path(), 100)->meta.index, 100u);
  EXPECT_FALSE(find_latest(dir.path(), 99).has_value());
}

TEST(SnapshotFiles, FindLatestOnEmptyOrMissingDirectory) {
  TempDir dir;
  EXPECT_FALSE(find_latest(dir.path(), 1000).has_value());
  EXPECT_FALSE(find_latest(dir.path() + "/missing", 1000).has_value());
}

}  // namespace
}  // namespace lle::snap

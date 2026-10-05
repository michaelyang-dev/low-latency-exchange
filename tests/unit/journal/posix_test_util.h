#pragma once
// Helpers for journal tests on a real file system.
#include <gtest/gtest.h>

#include <unistd.h>

#include <filesystem>
#include <string>

#include "journal/journal_writer.h"
#include "journal/posix_segment_dir.h"
#include "journal/segment_preparer.h"
#include "journal_test_util.h"

namespace lle::journal::testing {

namespace fs = std::filesystem;
using PosixWriter = JournalWriter<PosixJournalDevice>;

struct TempDir {
  TempDir() {
    path = fs::temp_directory_path() / ("lle_journal_" + std::to_string(::getpid()) + "_" + std::to_string(counter++));
    fs::remove_all(path);
    fs::create_directories(path);
  }
  ~TempDir() { fs::remove_all(path); }
  fs::path path;
  static inline int counter = 0;
};

// Writes `n` records into a fresh journal directory; returns the stream.
inline RecordStream write_journal(const fs::path& dir, std::size_t n, std::uint64_t seed, std::size_t segments = 3) {
  RecordStream s(seed);
  auto d = PosixSegmentDir::open(dir.string());
  EXPECT_TRUE(d.has_value());
  Prng nonces(seed);
  SegmentPreparer prep(*d, nonces, kDay, kSegmentHeaderBytes + 256 * 1024);
  JournalWriterOptions o;
  o.day = kDay;
  PosixWriter w(o);
  w.start(ChainState{});
  for (std::size_t i = 0; i < segments; ++i) {
    auto p = prep.create();
    EXPECT_TRUE(p.has_value());
    if (p) EXPECT_TRUE(w.add_prepared(d->device(p->handle), p->handle, p->header));
  }
  for (std::size_t i = 0; i < n; ++i) {
    const auto rec = s.next();
    for (;;) {
      const auto st = w.append(rec, s.sealer());
      if (st == PosixWriter::Status::Ok) break;
      EXPECT_EQ(st, PosixWriter::Status::Busy);
      if (st != PosixWriter::Status::Busy) return s;
      (void)w.flush();
      (void)w.poll();
    }
  }
  while (w.batch_used() != 0 || w.in_flight() != 0) {
    (void)w.flush();
    (void)w.poll();
  }
  EXPECT_EQ(w.durable_index(), n);
  // Rename assigned segments to their canonical names (off the hot path).
  PosixWriter::AssignedSegment a;
  while (w.take_assigned(a)) EXPECT_TRUE(d->rename(a.handle, segment_file_name(a.header.epoch, a.header.first_index)));
  EXPECT_TRUE(d->sync_dir());
  return s;
}

}  // namespace lle::journal::testing

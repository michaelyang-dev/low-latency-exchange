// Rejoin truncation of the L3 journal (10 §5 step 2): after truncate_journal(t) and
// recovery the journal ends exactly at t with records 1..t unchanged, the writer
// resumes after t, and a different continuation becomes the durable history.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "common/prng.h"
#include "journal/journal_writer.h"
#include "journal/reader.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "repl/journal_truncate.h"

namespace lle::repl {
namespace {

using namespace lle::journal;
using Bytes = std::vector<std::byte>;
using Writer = JournalWriter<MemJournalDevice>;
constexpr std::uint32_t kDay = 20260930;
constexpr std::uint64_t kSegBytes = kSegmentHeaderBytes + 128 * 1024;

struct Journal {
  MemSegmentDir dir;
  Prng nonces{11};
  std::unique_ptr<SegmentPreparer<MemSegmentDir, Prng>> prep;
  Journal() { prep = std::make_unique<SegmentPreparer<MemSegmentDir, Prng>>(dir, nonces, kDay, kSegBytes); }
};

JournalWriterOptions opts() {
  JournalWriterOptions o;
  o.day = kDay;
  return o;
}

// Appends `recs` (canonical) and waits until all are durable.
void write_all(Writer& w, const std::vector<Bytes>& recs, std::size_t from) {
  static const Sealer canonical;
  for (std::size_t i = from; i < recs.size(); ++i) {
    for (int spins = 0;; ++spins) {
      const auto st = w.append(recs[i], canonical);
      if (st == Writer::Status::Ok) break;
      ASSERT_EQ(st, Writer::Status::Busy);
      ASSERT_LT(spins, 100000);
      (void)w.flush();
      (void)w.poll();
    }
  }
  for (int spins = 0; w.durable_index() < recs.size(); ++spins) {
    ASSERT_LT(spins, 100000);
    (void)w.flush();
    (void)w.poll();
  }
}

std::vector<Bytes> make_records(std::uint64_t seed, std::size_t n, ChainState start, std::uint32_t epoch) {
  static const Sealer canonical;
  Prng rng(seed);
  RecordBuilder b(canonical, start);
  b.set_epoch(epoch);
  std::vector<Bytes> out;
  Bytes buf(kMaxRecordBytes);
  const Bytes blob(4000, std::byte{0x6b});
  for (std::size_t i = 0; i < n; ++i) {
    const auto len = static_cast<std::size_t>(rng.below(3000));
    const auto r = b.append(std::span<std::byte>(buf), 1'790'000'000'000'000'000 + static_cast<Nanos>(i + 1) * 1000,
                            OuchInbound{static_cast<std::uint32_t>(i), 1, 1, std::span<const std::byte>(blob).first(len)});
    out.emplace_back(r.begin(), r.end());
  }
  return out;
}

std::vector<Bytes> read_back(MemSegmentDir& dir) {
  std::vector<Bytes> out;
  ReadOptions o;
  o.day = kDay;
  (void)read_journal(dir, o, [&](const RecordView& v, const RecordLocation& loc) {
    Bytes b(v.bytes().begin(), v.bytes().end());
    store_le32(b.data() + hdr::kCrc, loc.sealer->content_of(v.data()));  // canonical form
    out.push_back(std::move(b));
    return true;
  });
  return out;
}

TEST(ReplJournalTruncate, EveryCutPointRecoversExactlyThePrefix) {
  Journal base;
  Writer w(opts());
  for (int i = 0; i < 8; ++i) {
    auto p = base.prep->create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(base.dir.device(p->handle), p->handle, p->header));
  }
  const std::vector<Bytes> recs = make_records(5, 300, ChainState{}, 1);
  write_all(w, recs, 0);
  const RecoveryResult full = recover(base.dir, RecoveryOptions{kDay, kInflightWindow, false});
  ASSERT_EQ(full.status, RecoveryStatus::Ok);
  ASSERT_EQ(full.chain.last_index, 300u);
  ASSERT_GE(full.segments.size(), 3u) << "the test must cross segment boundaries";

  // Cut points: empty, inside the first segment, at and next to segment boundaries, the tail.
  std::vector<std::uint64_t> cuts = {0, 1, 2, 57, 299, 300};
  for (const auto& s : full.segments) {
    const std::uint64_t first = s.header.first_index;
    cuts.push_back(first - 1);
    cuts.push_back(first);
    cuts.push_back(first + 1);
  }
  for (const std::uint64_t t : cuts) {
    if (t > 300) continue;
    SCOPED_TRACE("t = " + std::to_string(t));
    MemSegmentDir dir = base.dir.clone(true);
    Prng nonces(99 + t);
    SegmentPreparer<MemSegmentDir, Prng> prep(dir, nonces, kDay, kSegBytes);
    const TruncateResult tr = truncate_journal(dir, prep, kDay, t);
    ASSERT_TRUE(tr.ok) << tr.detail;
    EXPECT_EQ(tr.chain.last_index, t);
    RecoveryResult r = recover(dir, RecoveryOptions{kDay, kInflightWindow, true});
    ASSERT_TRUE(r.usable()) << r.detail;
    EXPECT_EQ(r.chain.last_index, t);
    std::vector<Bytes> got = read_back(dir);
    ASSERT_EQ(got.size(), t);
    for (std::uint64_t i = 0; i < t; ++i) ASSERT_EQ(got[i], recs[i]) << "record " << i + 1;
    // A divergent continuation (epoch 2) after t becomes the history.
    Writer w2(opts());
    ASSERT_TRUE(resume_writer(w2, dir, r));
    for (int i = 0; i < 3; ++i) {
      auto p = prep.create();
      ASSERT_TRUE(p.has_value());
      (void)w2.add_prepared(dir.device(p->handle), p->handle, p->header);
    }
    std::vector<Bytes> next(recs.begin(), recs.begin() + static_cast<std::ptrdiff_t>(t));
    const std::vector<Bytes> more = make_records(1000 + t, 40, r.chain, 2);
    next.insert(next.end(), more.begin(), more.end());
    write_all(w2, next, t);
    const RecoveryResult r2 = recover(dir, RecoveryOptions{kDay, kInflightWindow, false});
    ASSERT_EQ(r2.status, RecoveryStatus::Ok) << r2.detail;
    EXPECT_EQ(r2.chain.last_index, t + 40);
    got = read_back(dir);
    ASSERT_EQ(got.size(), next.size());
    for (std::size_t i = 0; i < next.size(); ++i) ASSERT_EQ(got[i], next[i]) << "record " << i + 1;
  }
}

TEST(ReplJournalTruncate, BeyondTheTailIsANoOp) {
  Journal j;
  Writer w(opts());
  for (int i = 0; i < 3; ++i) {
    auto p = j.prep->create();
    ASSERT_TRUE(p.has_value());
    ASSERT_TRUE(w.add_prepared(j.dir.device(p->handle), p->handle, p->header));
  }
  const std::vector<Bytes> recs = make_records(8, 20, ChainState{}, 1);
  write_all(w, recs, 0);
  const TruncateResult tr = truncate_journal(j.dir, *j.prep, kDay, 25);
  EXPECT_TRUE(tr.ok);
  EXPECT_EQ(tr.chain.last_index, 20u);
  EXPECT_EQ(tr.recycled, 0u);
  EXPECT_EQ(read_back(j.dir).size(), 20u);
}

}  // namespace
}  // namespace lle::repl

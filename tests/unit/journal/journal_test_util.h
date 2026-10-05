#pragma once
// Helpers for journal tests: a deterministic random record stream (sealed for an L2
// ring nonce, as the sequencer would produce it), writer drivers and read-back checks.
#include <gtest/gtest.h>

#include <cstddef>
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

namespace lle::journal::testing {

inline constexpr std::uint32_t kDay = 20260930;
inline constexpr std::uint64_t kL2Nonce = 0x5EA1ED0F00D5EA1Dull;

struct StreamMix {
  std::uint32_t max_ouch = 140;
  std::uint32_t big_every = 0;  // every Nth record is a large Config chunk (0: never)
  std::uint32_t big_max = ConfigChunk::kMaxChunkBytes;
};

// Random but deterministic records; keeps a copy of every record so tests can compare
// what recovery returns with what was appended.
class RecordStream {
 public:
  using Mix = StreamMix;

  explicit RecordStream(std::uint64_t seed, Mix mix = {}) : rng_(seed), mix_(mix), sealer_(kL2Nonce), builder_(sealer_) {
    builder_.set_epoch(1);
    for (std::size_t i = 0; i < ConfigChunk::kMaxChunkBytes; i += 8) store_le64(blob_.get() + i, rng_.next_u64());
  }

  [[nodiscard]] const Sealer& sealer() const noexcept { return sealer_; }
  [[nodiscard]] const ChainState& chain() const noexcept { return builder_.chain(); }
  [[nodiscard]] std::size_t size() const noexcept { return recs_.size(); }
  // Record with journal index i (1-based) as generated (sealed for the L2 nonce).
  [[nodiscard]] std::span<const std::byte> at(std::uint64_t i) const { return recs_[i - 1]; }

  std::span<const std::byte> next() {
    std::span<std::byte> out(scratch_.get(), kMaxRecordBytes);
    ts_ += 1 + static_cast<Nanos>(rng_.below(5000));
    const std::uint64_t n = recs_.size() + 1;
    std::span<std::byte> r;
    if (mix_.big_every != 0 && n % mix_.big_every == 0) {
      const auto len = static_cast<std::size_t>(1 + rng_.below(mix_.big_max));
      r = builder_.append(out, ts_, ConfigChunk{ConfigTable::Symbols, 0, 1, static_cast<std::uint32_t>(len),
                                                std::span<const std::byte>(blob_.get(), ConfigChunk::kMaxChunkBytes).first(len)});
    } else {
      switch (rng_.below(20)) {
        case 0:
          r = builder_.append(out, ts_, SessionEvent{static_cast<std::uint32_t>(rng_.below(100)), 1,
                                                     SessionEventKind::Login, rng_.below(1000)});
          break;
        case 1:
          r = builder_.append(out, ts_, Timer{static_cast<std::uint32_t>(n), TimerKind::Noii, ts_});
          break;
        case 2:
          r = builder_.append(out, ts_,
                              Admin{7, 1, 3, std::span<const std::byte>(blob_.get(), ConfigChunk::kMaxChunkBytes).first(rng_.below(300))});
          break;
        case 3:
          if (rng_.chance(1, 4)) builder_.set_epoch(builder_.chain().epoch + 1);
          r = builder_.append(out, ts_, EpochStart{builder_.chain().epoch, 1, rng_.next_u64()});
          break;
        default: {
          const auto len = static_cast<std::size_t>(rng_.below(mix_.max_ouch + 1));
          r = builder_.append(out, ts_,
                              OuchInbound{static_cast<std::uint32_t>(rng_.below(64)), 7, 0,
                                          std::span<const std::byte>(blob_.get(), ConfigChunk::kMaxChunkBytes).first(len)});
          break;
        }
      }
    }
    recs_.emplace_back(r.begin(), r.end());
    return recs_.back();
  }

  // After recovery: forget records past `c.last_index` and continue the chain from `c`
  // (the records after it were never durable and will be regenerated differently).
  void rewind(const ChainState& c) {
    recs_.resize(c.last_index);
    builder_.reset(c);
    if (c.last_ts > ts_) ts_ = c.last_ts;
  }

 private:
  Prng rng_;
  Mix mix_;
  Sealer sealer_;
  RecordBuilder builder_;
  Nanos ts_ = 1'790'000'000'000'000'000;
  std::unique_ptr<std::byte[]> blob_{new std::byte[ConfigChunk::kMaxChunkBytes + 8]};
  std::unique_ptr<std::byte[]> scratch_{new std::byte[kMaxRecordBytes]};
  std::vector<std::vector<std::byte>> recs_;
};

// Prepares `n` fresh segments in `dir` with a seeded nonce stream.
inline std::vector<PreparedSegment> prepare_segments(MemSegmentDir& dir, std::size_t n, std::uint64_t segment_bytes,
                                                     std::uint64_t seed = 7) {
  Prng nonce_rng(seed);
  SegmentPreparer prep(dir, nonce_rng, kDay, segment_bytes);
  std::vector<PreparedSegment> out;
  for (std::size_t i = 0; i < n; ++i) {
    auto p = prep.create();
    EXPECT_TRUE(p.has_value());
    if (p) out.push_back(*p);
  }
  return out;
}

using MemWriter = JournalWriter<MemJournalDevice>;

inline JournalWriterOptions writer_options() {
  JournalWriterOptions o;
  o.day = kDay;
  return o;
}

// Appends one record, flushing and polling while the writer is busy.
inline void append_one(MemWriter& w, std::span<const std::byte> rec, const Sealer& s) {
  for (int spins = 0;; ++spins) {
    const auto st = w.append(rec, s);
    if (st == MemWriter::Status::Ok) return;
    ASSERT_EQ(st, MemWriter::Status::Busy) << "append failed";
    ASSERT_LT(spins, 1000000);
    (void)w.flush();
    (void)w.poll();
  }
}

// Flushes and polls until every appended record is durable.
inline void drain(MemWriter& w) {
  for (int spins = 0; w.batch_used() != 0 || w.in_flight() != 0; ++spins) {
    ASSERT_LT(spins, 1000000);
    ASSERT_FALSE(w.failed());
    (void)w.flush();
    (void)w.poll();
  }
  ASSERT_EQ(w.durable_index(), w.appended_index());
}

// Reads the journal back and checks it equals records 1..last of `s` (content-wise).
inline void expect_journal_matches(MemSegmentDir& dir, const RecordStream& s, std::uint64_t last) {
  std::uint64_t next = 1;
  const auto sum = read_journal(dir, ReadOptions{}, [&](const RecordView& r, const RecordLocation&) {
    EXPECT_EQ(r.index(), next);
    if (next <= s.size()) {
      const RecordView orig(s.at(next));
      EXPECT_TRUE(same_content(r, orig)) << "index " << next;
    }
    ++next;
    return true;
  });
  EXPECT_EQ(sum.chain.last_index, last);
  EXPECT_EQ(next, last + 1);
}

}  // namespace lle::journal::testing

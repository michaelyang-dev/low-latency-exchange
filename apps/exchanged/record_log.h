#pragma once
// RecordLog: the node's journal readable by index, for the replication core
// (repl::Host::log_read, log_tail, log_epoch_end, 10 §2-§5). Records are kept in
// canonical form (seal == content crc, journal/record.h), the form they cross the
// replication interface in.
//
// The newest records live in a fixed arena (mold::MessageRing keyed by journal
// index: the oldest are evicted first, nothing is allocated after construction);
// older ones are read back from the L3 segments (catch-up of a lagging node; cold).
// Appends come from the seq/repl thread only: the sequencer's ring adapter tees every
// record it commits to L2, and the replica's log_append writes replicated records.
// A restarted paired node loads its recovered journal (load(); cold) and, after a
// rejoin truncation, loads it again up to the truncation point.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "journal/posix_segment_dir.h"
#include "journal/reader.h"
#include "journal/record.h"
#include "proto/moldudp64/message_store.h"

namespace lle::exch {

// Opens the day's L3 journal read-only: open(dir) -> expected<SegmentDirLike, string>.
// RecordLog reads POSIX segment files; the simulator opens its disk's.
struct PosixL3Opener {
  [[nodiscard]] auto operator()(const std::string& dir) const {
    return journal::PosixSegmentDir::open(dir, false, journal::PosixDeviceOptions{.read_only = true});
  }
};

template <class Opener>
class BasicRecordLog {
 public:
  BasicRecordLog(std::size_t arena_bytes, std::size_t max_records, std::string l3_dir, std::uint32_t day,
                 Opener open = {})
      : arena_bytes_(arena_bytes),
        max_records_(max_records),
        ring_(std::make_unique<mold::MessageRing>(max_records, arena_bytes, 1)),
        l3_dir_(std::move(l3_dir)),
        day_(day),
        canonical_(std::make_unique<journal::Sealer>()),
        open_(std::move(open)) {}
  BasicRecordLog(const BasicRecordLog&) = delete;
  BasicRecordLog& operator=(const BasicRecordLog&) = delete;

  // Restarts the arena after `base` (records <= base.last_index are in L3). Cold.
  void reset(const journal::ChainState& base) {
    ring_ = std::make_unique<mold::MessageRing>(max_records_, arena_bytes_, base.last_index + 1);
    tail_ = base;
    window_.clear();
    window_bytes_.clear();
    window_first_ = 0;
    resume_offset_ = 0;
    l3_seen_ = 0;
  }

  // Reloads records 1..upto from the L3 journal (a restart; cold). The newest that fit
  // stay in the arena; older ones are read back from L3. False if the journal does not
  // hold a contiguous run 1..upto.
  bool load(std::uint64_t upto) {
    reset(journal::ChainState{});
    if (upto == 0) return true;
    auto dir = open_(l3_dir_);
    if (!dir) return false;
    journal::ReadOptions o;
    o.day = day_;
    o.from_index = 1;
    o.to_index = upto;
    std::vector<std::byte> buf(journal::kMaxRecordBytes);
    bool ok = true;
    (void)journal::read_journal(*dir, o, [&](const journal::RecordView& r, const journal::RecordLocation& loc) {
      std::memcpy(buf.data(), r.data(), r.len());
      store_le32(buf.data() + journal::hdr::kCrc, loc.sealer->content_of(r.data()));
      const std::span<const std::byte> rec(buf.data(), r.len());
      const journal::RecordView v{rec};
      if (v.index() != tail_.last_index + 1) {
        ok = false;
        return false;
      }
      if (!ring_->append(rec)) {  // the oldest are evicted (read back from L3)
        ok = false;
        return false;
      }
      tail_ = journal::ChainState{v.index(), v.crc(), v.ts_ns(), v.epoch()};
      return true;
    });
    return ok && tail_.last_index == upto;
  }

  // Appends the next record, sealed by `src`; it is stored re-sealed canonically.
  bool append_from(const std::byte* rec, std::uint32_t len, const journal::Sealer& src) noexcept {
    std::byte buf[journal::kMaxRecordBytes];
    std::memcpy(buf, rec, len);
    (void)canonical_->reseal(buf, src);
    return append_canonical(std::span<const std::byte>(buf, len));
  }

  bool append_canonical(std::span<const std::byte> rec) noexcept {
    const journal::RecordView v{rec};
    if (v.index() != tail_.last_index + 1) return false;
    if (!ring_->append(rec)) return false;
    tail_ = journal::ChainState{v.index(), v.crc(), v.ts_ns(), v.epoch()};
    return true;
  }

  // The node's L3 durable index (the replication stage's poll): a read past the last
  // record found in L3, of a record the arena no longer holds, then fails at once until
  // durability passes that record, instead of walking the journal on every attempt (the
  // arena can evict records the io stage has not made durable yet). Not set: every read
  // looks in L3.
  void note_durable(std::uint64_t d) noexcept { durable_hint_ = d; }

  [[nodiscard]] const journal::ChainState& tail() const noexcept { return tail_; }
  [[nodiscard]] std::uint64_t lowest() const noexcept { return ring_->lowest(); }

  // Copies record `idx` (canonical) into `out`; its length, or 0 if not held.
  std::uint32_t read(std::uint64_t idx, std::span<std::byte> out) const {
    if (idx == 0 || idx > tail_.last_index) return 0;
    if (const auto r = ring_->get(idx)) {
      if (r->size() > out.size()) return 0;
      std::memcpy(out.data(), r->data(), r->size());
      return static_cast<std::uint32_t>(r->size());
    }
    return read_l3(idx, out);
  }

  // Visits records [from, tail] in order (arena or L3): f(const journal::RecordView&),
  // returning false to stop. Cold (epoch queries during rejoin).
  template <class F>
  void scan(std::uint64_t from, F&& f) const {
    std::unique_ptr<std::byte[]> buf(new std::byte[journal::kMaxRecordBytes]);
    for (std::uint64_t i = from; i <= tail_.last_index; ++i) {
      const std::uint32_t n = read(i, std::span<std::byte>(buf.get(), journal::kMaxRecordBytes));
      if (n == 0) return;
      if (!f(journal::RecordView(std::span<const std::byte>(buf.get(), n)))) return;
    }
  }

 private:
  // Records older than the arena come from L3 a window at a time. A catch-up reads them
  // in order and rewinds (go-back-N) to its oldest unacknowledged record, at most
  // kRewindRecords back. Reading on past the window slides it: it keeps its newest
  // kRewindRecords records and continues the journal walk where the window ended, so
  // neither the reads nor the rewinds walk a segment again. Any other read fills a new
  // window starting kRewindRecords before the record, skipping the segments before it.
  std::uint32_t read_l3(std::uint64_t idx, std::span<std::byte> out) const {
    if (!in_window(idx)) {
      if (idx > l3_seen_ && durable_hint_ <= l3_seen_) return 0;  // not in L3 yet
      const bool slid = idx == window_first_ + window_.size() && window_first_ != 0 && slide_window();
      if (!slid || !in_window(idx)) {
        const std::uint64_t back = std::min<std::uint64_t>(idx - 1, kRewindRecords);
        if (!fill_window(idx - back) || !in_window(idx)) {
          if (!fill_window(idx)) return 0;  // large records cut the window short of idx
        }
      }
    }
    const auto& [off, len] = window_[idx - window_first_];
    if (len > out.size()) return 0;
    std::memcpy(out.data(), window_bytes_.data() + off, len);
    return len;
  }
  bool fill_window(std::uint64_t from) const {
    window_.clear();
    window_bytes_.clear();
    window_first_ = 0;
    resume_offset_ = 0;
    journal::ReadOptions o;
    o.from_index = from;
    o.skip_before_from = true;  // a window near the tail costs the window, not the day
    if (!walk_into_window(o, from)) return false;
    window_first_ = from;
    return true;
  }
  // Drops all but the newest kRewindRecords records and reads on from where the window
  // ended. False if it could not continue (the window is then unchanged or empty).
  bool slide_window() const {
    if (resume_offset_ == 0) return false;
    const std::size_t drop = window_.size() > kRewindRecords ? window_.size() - kRewindRecords : 0;
    if (drop != 0) {
      const std::size_t cut = window_[drop].first;
      window_bytes_.erase(window_bytes_.begin(), window_bytes_.begin() + static_cast<std::ptrdiff_t>(cut));
      window_.erase(window_.begin(), window_.begin() + static_cast<std::ptrdiff_t>(drop));
      for (auto& [off, len] : window_) off -= cut;
      window_first_ += drop;
    }
    const std::size_t had = window_.size();
    journal::ReadOptions o;
    o.from_index = window_first_ + had;
    o.resume_segment = resume_segment_;
    o.resume_offset = resume_offset_;
    o.resume_chain = resume_chain_;
    (void)walk_into_window(o, window_first_);
    return window_.size() > had;
  }
  // Appends records o.from_index.. to the window (whose first index is `first`) up to
  // kWindowRecords or kWindowBytes, and remembers where the walk can resume.
  bool walk_into_window(journal::ReadOptions o, std::uint64_t first) const {
    auto dir = open_(l3_dir_);
    if (!dir) return false;
    o.day = day_;
    o.to_index = std::min(tail_.last_index, first + kWindowRecords - 1);
    const std::size_t had = window_.size();
    (void)journal::read_journal(*dir, o, [&](const journal::RecordView& r, const journal::RecordLocation& loc) {
      if (r.index() != first + window_.size()) return false;
      const std::size_t at = window_bytes_.size();
      window_bytes_.insert(window_bytes_.end(), r.data(), r.data() + r.len());
      const std::uint32_t content = loc.sealer->content_of(r.data());
      store_le32(window_bytes_.data() + at + journal::hdr::kCrc, content);
      window_.emplace_back(at, r.len());
      l3_seen_ = std::max(l3_seen_, r.index());
      resume_segment_ = loc.header->first_index;
      resume_offset_ = loc.offset + r.len();
      resume_chain_ = journal::ChainState{r.index(), content, r.ts_ns(), r.epoch()};
      return window_bytes_.size() < kWindowBytes;
    });
    return window_.size() > had;
  }

  [[nodiscard]] bool in_window(std::uint64_t idx) const noexcept {
    return window_first_ != 0 && idx >= window_first_ && idx < window_first_ + window_.size();
  }

  static constexpr std::uint64_t kWindowRecords = 16'384;
  static constexpr std::uint64_t kRewindRecords = 8'192;  // repl::Config::window_records
  static constexpr std::size_t kWindowBytes = std::size_t{4} << 20;

  std::size_t arena_bytes_;
  std::size_t max_records_;
  std::unique_ptr<mold::MessageRing> ring_;
  std::string l3_dir_;
  std::uint32_t day_;
  std::unique_ptr<journal::Sealer> canonical_;
  journal::ChainState tail_{};
  mutable std::vector<std::pair<std::size_t, std::uint32_t>> window_;  // L3 window: offset, length
  mutable std::vector<std::byte> window_bytes_;
  mutable std::uint64_t window_first_ = 0;
  // Where the walk that filled the window can resume (after its last record).
  mutable std::uint64_t resume_segment_ = 0;  // that segment's first index
  mutable std::uint64_t resume_offset_ = 0;   // 0: nowhere
  mutable journal::ChainState resume_chain_{};
  mutable std::uint64_t l3_seen_ = 0;                            // the highest index found in L3
  std::uint64_t durable_hint_ = ~std::uint64_t{0};              // note_durable(); unknown: max
  Opener open_;
};

using RecordLog = BasicRecordLog<PosixL3Opener>;

}  // namespace lle::exch

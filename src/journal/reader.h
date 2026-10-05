#pragma once
// Read-only journal iteration (tools, replay, snapshotd following L3 segments):
// walks the valid prefix of a journal directory with exactly the validity rules of
// recovery (06 §7) and hands each record to a callback. Never writes.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>

#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment_dir.h"
#include "journal/segment_scan.h"

namespace lle::journal {

struct ReadOptions {
  std::uint32_t day = 0;  // 0: the day of the earliest assigned segment
  std::uint64_t from_index = 0;
  std::uint64_t to_index = std::numeric_limits<std::uint64_t>::max();
  bool include_pads = false;
};

// Where a record lives. `sealer` is the segment's: sealer->content_of(rec) gives the
// content crc without a CRC pass.
struct RecordLocation {
  std::size_t handle = 0;
  std::uint64_t offset = 0;
  const SegmentHeader* header = nullptr;
  const Sealer* sealer = nullptr;
};

enum class ReadStop : std::uint8_t {
  End,          // the valid prefix ended (first invalid position, or no more segments)
  Callback,     // the callback returned false
  ToIndex,      // reached options.to_index
  ChainBreak,   // a segment does not continue its predecessor
  Duplicate,    // two segments claim the same first index
  IoError,
  Empty,        // no assigned segment
};
[[nodiscard]] std::string_view to_string(ReadStop s) noexcept;

struct ReadSummary {
  ReadStop stop = ReadStop::Empty;
  ChainState chain;               // last valid record walked
  std::uint64_t first_index = 0;  // first valid index seen
  std::uint64_t records = 0;      // valid non-Pad records walked (delivered or not)
  std::uint64_t delivered = 0;    // records passed to the callback
  std::size_t segments = 0;       // assigned segments visited
  std::size_t end_handle = 0;     // where the walk ended
  std::uint64_t end_offset = 0;
};

// F: bool(const RecordView&, const RecordLocation&); return false to stop.
template <SegmentDirLike Dir, class F>
ReadSummary read_journal(Dir& dir, const ReadOptions& opts, F&& f) {
  ReadSummary s;
  const detail::HeaderScan hs = detail::scan_headers(dir, opts.day);
  if (hs.assigned.empty()) return s;
  for (std::size_t k = 1; k < hs.assigned.size(); ++k) {
    if (hs.assigned[k].header.first_index == hs.assigned[k - 1].header.first_index) {
      s.stop = ReadStop::Duplicate;
      return s;
    }
  }
  const SegmentHeader& first = hs.assigned.front().header;
  ChainState chain{first.first_index - 1, first.prev_last_crc, 0, 0};
  ChainState accepted = chain;  // last record not rejected by to_index
  auto sealer = std::make_unique<Sealer>();
  s.stop = ReadStop::End;
  for (std::size_t k = 0; k < hs.assigned.size(); ++k) {
    const auto& e = hs.assigned[k];
    if (k > 0 && (e.header.first_index != chain.last_index + 1 || e.header.prev_last_crc != chain.last_crc)) {
      s.stop = ReadStop::ChainBreak;
      break;
    }
    auto& dev = dir.device(e.handle);
    const std::uint64_t limit = std::min(dev.size(), e.header.segment_bytes);
    ChunkedReader<typename Dir::Device> rd(dev, limit);
    *sealer = Sealer(e.header.nonce);
    const RecordLocation base{e.handle, 0, &e.header, sealer.get()};
    bool stopped = false;
    const WalkResult w = walk_segment(rd, *sealer, chain, kSegmentHeaderBytes,
                                      [&](const RecordView& rec, std::uint64_t off, bool pad) {
                                        if (!pad && rec.index() > opts.to_index) {
                                          s.stop = ReadStop::ToIndex;
                                          stopped = true;
                                          return false;
                                        }
                                        if (!pad) {
                                          if (s.first_index == 0) s.first_index = rec.index();
                                          ++s.records;
                                          accepted = ChainState{rec.index(), sealer->content_of(rec.data()),
                                                                rec.ts_ns(), rec.epoch()};
                                        }
                                        if ((pad && !opts.include_pads) || (!pad && rec.index() < opts.from_index)) {
                                          return true;
                                        }
                                        RecordLocation loc = base;
                                        loc.offset = off;
                                        if (!pad) ++s.delivered;
                                        if (!f(rec, loc)) {
                                          s.stop = ReadStop::Callback;
                                          stopped = true;
                                          return false;
                                        }
                                        return true;
                                      });
    ++s.segments;
    s.end_handle = e.handle;
    s.end_offset = w.end;
    if (rd.io_error()) {
      s.stop = ReadStop::IoError;
      break;
    }
    if (stopped) break;
  }
  // walk_segment advances its chain before the callback sees a record, so a record
  // rejected by to_index is not part of the summary.
  s.chain = accepted;
  return s;
}

// Pull-style reader over the same valid prefix (lockstep comparison of two journals,
// journal_diff). The view returned by next() stays valid until the next call.
template <SegmentDirLike Dir>
class JournalCursor {
 public:
  explicit JournalCursor(Dir& dir, std::uint32_t day = 0)
      : dir_(&dir), hs_(detail::scan_headers(dir, day)), sealer_(std::make_unique<Sealer>()) {
    for (std::size_t k = 1; k < hs_.assigned.size(); ++k) {
      if (hs_.assigned[k].header.first_index == hs_.assigned[k - 1].header.first_index) {
        stop_ = ReadStop::Duplicate;
        return;
      }
    }
    if (hs_.assigned.empty()) {
      stop_ = ReadStop::Empty;
      return;
    }
    const SegmentHeader& h = hs_.assigned.front().header;
    chain_ = ChainState{h.first_index - 1, h.prev_last_crc, 0, 0};
    stop_ = ReadStop::End;
    done_ = !open(0);
  }

  // The next valid non-Pad record, or an empty view at the end of the valid prefix.
  RecordView next() {
    while (!done_) {
      const std::uint64_t limit = rd_->limit();
      const std::byte* h = off_ + kHeaderBytes <= limit ? rd_->get(off_, kHeaderBytes) : nullptr;
      const std::uint32_t len = h == nullptr ? 0 : load_le32(h + hdr::kLen);
      const std::byte* p = (len >= kHeaderBytes && len <= kMaxRecordBytes && len % kRecordAlign == 0 && off_ + len <= limit)
                               ? rd_->get(off_, len)
                               : nullptr;
      std::uint32_t content = 0;
      const RecordCheck c = p == nullptr ? RecordCheck::Invalid : check_record(p, len, *sealer_, chain_, content);
      if (c == RecordCheck::Invalid) {
        if (rd_->io_error()) {
          stop_ = ReadStop::IoError;
          done_ = true;
        } else {
          done_ = !open(seg_ + 1);
        }
        continue;
      }
      off_ += len;
      if (c == RecordCheck::ValidPad) continue;
      const RecordView v(std::span<const std::byte>(p, len));
      chain_ = ChainState{v.index(), content, v.ts_ns(), v.epoch()};
      return v;
    }
    return {};
  }

  [[nodiscard]] ReadStop stop() const noexcept { return stop_; }
  [[nodiscard]] const ChainState& chain() const noexcept { return chain_; }
  [[nodiscard]] const Sealer& sealer() const noexcept { return *sealer_; }

 private:
  bool open(std::size_t k) {
    if (k >= hs_.assigned.size()) return false;
    const auto& e = hs_.assigned[k];
    if (k > 0 && (e.header.first_index != chain_.last_index + 1 || e.header.prev_last_crc != chain_.last_crc)) {
      stop_ = ReadStop::ChainBreak;
      return false;
    }
    auto& dev = dir_->device(e.handle);
    rd_ = std::make_unique<ChunkedReader<typename Dir::Device>>(dev, std::min(dev.size(), e.header.segment_bytes));
    *sealer_ = Sealer(e.header.nonce);
    seg_ = k;
    off_ = kSegmentHeaderBytes;
    return true;
  }

  Dir* dir_;
  detail::HeaderScan hs_;
  std::unique_ptr<Sealer> sealer_;
  std::unique_ptr<ChunkedReader<typename Dir::Device>> rd_;
  std::size_t seg_ = 0;
  std::uint64_t off_ = 0;
  ChainState chain_{};
  ReadStop stop_ = ReadStop::Empty;
  bool done_ = true;
};

}  // namespace lle::journal

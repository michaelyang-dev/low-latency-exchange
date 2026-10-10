#pragma once
// Journal recovery, `journal::recover(dir) -> RecoveryResult` (06 §7).
//
//  1. Read every segment header; ignore segments whose header CRC or nonce is invalid
//     (or that belong to another day). Prepared (unassigned) segments are spares; a
//     spare whose data area is not all zero was written to by an assignment whose
//     header never became durable and must be recycled before use.
//  2. Walk records in journal order. A record is valid only if its length is in
//     bounds, its CRC verifies with the segment nonce, its index is the predecessor's
//     + 1, its prev_crc equals the predecessor's content crc, and its epoch is
//     monotonic (segment_scan.h). Consecutive segments must continue each other
//     (first_index, prev_last_crc).
//  3. At the first invalid position x, inspect only the in-flight window
//     [x, x + QD x 64 KiB):
//       - torn tail: no validly sealed record exists beyond the window (sealed records
//         inside it come from writes that persisted out of order; they were never
//         counted in durable_index). Zero the window, close a partial block with a Pad
//         so the writer resumes on a 4 KiB boundary, and sync.
//       - corruption: a validly sealed record exists beyond the window. Refuse: nothing
//         is modified (a backup resynchronizes; solo mode is an operator incident).
//     Only the last segment can have a torn tail: the writer drains every write of a
//     segment before assigning the next one, so a non-last segment that has a sealed
//     record after its end of data is corruption too.
//     Repair also zeroes a window that already reads as zeros, and rewrites the window
//     before x and every segment header: what reads return may be in the page cache
//     only (a killed process, or a failed write whose pages the kernel marked clean),
//     and the verdict must hold after a power cut (DST-002, DST-022).
//  Steps 4-5 (newest snapshot <= the last valid index, replay with output suppressed,
//  rejoin truncation) belong to the node startup sequence (snap::find_latest, 10 §5).
//
// Seals bind records to one incarnation of one segment, so validly sealed records can
// only have been written by this journal into this segment after its last preparation.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "journal/journal_device.h"
#include "journal/journal_writer.h"
#include "journal/record.h"
#include "journal/segment.h"
#include "journal/segment_dir.h"
#include "journal/segment_preparer.h"
#include "journal/segment_scan.h"

namespace lle::journal {

enum class RecoveryStatus : std::uint8_t {
  Ok,          // a valid (possibly empty) prefix was found; the tail is clean or repaired
  Empty,       // no assigned segment: a fresh journal
  Corruption,  // refused: see CorruptionKind; nothing was modified
  IoError,     // a read or a repair write failed
};
enum class CorruptionKind : std::uint8_t {
  None,
  DuplicateSegment,        // two assigned segments claim the same first index
  SegmentChainBreak,       // a segment does not continue its predecessor (index, prev crc)
  DataAfterSealedSegment,  // a non-last segment has a sealed record after its end of data
  ValidRecordBeyondWindow, // the last segment has a sealed record beyond the in-flight window
};
[[nodiscard]] std::string_view to_string(RecoveryStatus s) noexcept;
[[nodiscard]] std::string_view to_string(CorruptionKind k) noexcept;

struct RecoveryOptions {
  std::uint32_t day = 0;                            // 0: the day of the earliest assigned segment
  std::uint64_t inflight_window = kInflightWindow;  // QD x batch bytes of the writer
  bool repair = true;                               // false: report only, never write
};

struct RecoveredSegment {
  std::size_t handle = 0;
  SegmentHeader header;
  std::uint64_t data_end = 0;  // end of the valid records (incl. pads)
  std::uint64_t records = 0;   // valid non-Pad records
};

struct RecoveryResult {
  RecoveryStatus status = RecoveryStatus::Empty;
  CorruptionKind corruption = CorruptionKind::None;
  std::uint32_t day = 0;
  ChainState chain;               // the last valid record (last_index 0: none)
  std::uint64_t first_index = 0;  // first valid index (0: none)
  std::uint64_t records = 0;
  std::vector<RecoveredSegment> segments;  // assigned segments walked, in journal order

  // Tail of the last segment (status Ok).
  std::uint64_t tail_offset = 0;        // x: the first invalid position
  std::uint64_t window_end = 0;         // end of the in-flight window (clipped to the segment)
  bool torn_tail = false;               // partial block at x, or non-zero bytes in the window
  std::uint64_t discarded_records = 0;  // sealed records inside the window (never durable)
  bool repaired = false;                // the window was zeroed / the block closed with a Pad
  std::uint64_t resume_offset = 0;      // 4 KiB-aligned offset where the writer continues

  // Corruption details.
  std::size_t bad_handle = 0;
  std::uint64_t bad_offset = 0;

  std::vector<PreparedSegment> spares;    // clean prepared segments, ready for the writer
  std::vector<std::size_t> dirty_spares;  // prepared but written to: recycle before use
  std::vector<std::size_t> ignored;       // unreadable/invalid header, or another day
  std::string detail;                     // one-line summary for logs and tools

  [[nodiscard]] bool usable() const noexcept { return status == RecoveryStatus::Ok || status == RecoveryStatus::Empty; }
};

namespace detail {

struct HeaderScan {
  struct Entry {
    std::size_t handle = 0;
    SegmentHeader header;
  };
  std::uint32_t day = 0;
  std::vector<Entry> assigned;  // sorted by (first_index, epoch, handle)
  std::vector<Entry> prepared;
  std::vector<std::size_t> ignored;
};

template <SegmentDirLike Dir>
HeaderScan scan_headers(Dir& dir, std::uint32_t day) {
  HeaderScan s;
  const std::unique_ptr<std::byte[]> buf(new std::byte[kSegmentHeaderBytes]);
  const std::span<std::byte> block(buf.get(), kSegmentHeaderBytes);
  std::vector<HeaderScan::Entry> all;
  for (std::size_t i = 0; i < dir.count(); ++i) {
    auto& dev = dir.device(i);
    if (!read_exact(dev, 0, block)) {
      s.ignored.push_back(i);
      continue;
    }
    const auto h = decode_segment_header(block);
    if (!h) {
      s.ignored.push_back(i);
      continue;
    }
    all.push_back({i, *h});
  }
  if (day == 0) {
    const HeaderScan::Entry* first = nullptr;
    for (const auto& e : all) {
      if (e.header.assigned() && (first == nullptr || e.header.first_index < first->header.first_index)) first = &e;
    }
    if (first == nullptr && !all.empty()) first = &all.front();
    if (first != nullptr) day = first->header.day;
  }
  s.day = day;
  for (const auto& e : all) {
    if (e.header.day != day) {
      s.ignored.push_back(e.handle);
    } else {
      (e.header.assigned() ? s.assigned : s.prepared).push_back(e);
    }
  }
  std::sort(s.assigned.begin(), s.assigned.end(), [](const HeaderScan::Entry& a, const HeaderScan::Entry& b) {
    if (a.header.first_index != b.header.first_index) return a.header.first_index < b.header.first_index;
    if (a.header.epoch != b.header.epoch) return a.header.epoch < b.header.epoch;
    return a.handle < b.handle;
  });
  std::sort(s.ignored.begin(), s.ignored.end());
  return s;
}

struct FreeDeleter {
  void operator()(std::byte* p) const noexcept { std::free(p); }
};
using AlignedBuf = std::unique_ptr<std::byte, FreeDeleter>;

inline AlignedBuf aligned_zeroed(std::size_t n) {
  auto* p = static_cast<std::byte*>(std::aligned_alloc(kBlockBytes, n));
  if (p != nullptr) std::memset(p, 0, n);
  return AlignedBuf(p);
}

// Zeroes [from, to) with block-aligned dsync writes (read-modify-write of the first
// block so the valid bytes before `from` survive). `to` is rounded up to a block
// boundary, capped at `limit`.
template <JournalDeviceLike Device>
bool zero_range(Device& dev, std::uint64_t from, std::uint64_t to, std::uint64_t limit) {
  constexpr std::size_t kChunk = std::size_t{1} << 20;
  to = std::min(align_up_block(to), limit);
  if (from >= to) return true;
  AlignedBuf buf = aligned_zeroed(kChunk);
  if (buf == nullptr) return false;
  const std::uint64_t blk = align_down_block(from);
  if (from > blk) {
    // The block may be the last, partial one of a short (damaged) file.
    const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(kBlockBytes, limit - blk));
    const std::span<std::byte> b(buf.get(), n);
    if (!read_exact(dev, blk, b)) return false;
    std::memset(b.data() + (from - blk), 0, n - (from - blk));
    if (write_sync(dev, blk, std::span<const std::byte>(b), true) != static_cast<std::int32_t>(n)) return false;
    std::memset(b.data(), 0, n);
    from = blk + n;
  }
  while (from < to) {
    const std::uint64_t n = std::min<std::uint64_t>(kChunk, to - from);
    if (write_sync(dev, from, std::span<const std::byte>(buf.get(), static_cast<std::size_t>(n)), true) !=
        static_cast<std::int32_t>(n)) {
      return false;
    }
    from += n;
  }
  return true;
}

// Rewrites [from, to) with what reads return now, with dsync (DST-002). After a
// process is killed between pwrite and fdatasync, or after an fdatasync failed and
// the kernel marked the pages clean (R6 D4.1, "fsyncgate"), reads keep returning
// bytes that may never reach the disk; an fsync does not write such pages, a
// rewrite does. Recovery rewrites everything it bases its result on.
// The range is widened to whole blocks (O_DIRECT devices) within the file.
template <JournalDeviceLike Device>
bool repersist(Device& dev, std::uint64_t from, std::uint64_t to) {
  constexpr std::size_t kChunk = std::size_t{1} << 20;
  from = align_down_block(from);
  to = std::min(align_up_block(to), dev.size());
  if (from >= to) return true;
  AlignedBuf buf = aligned_zeroed(kChunk);
  if (buf == nullptr) return false;
  while (from < to) {
    const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, to - from));
    const std::span<std::byte> b(buf.get(), n);
    if (!read_exact(dev, from, b)) return false;
    if (write_sync(dev, from, std::span<const std::byte>(b), true) != static_cast<std::int32_t>(n)) return false;
    from += n;
  }
  return true;
}

// Re-persists the header block of every segment file: the scan's verdicts (assigned,
// spare, ignored after an invalidated header) must hold after a power loss, or a
// segment whose recycling had failed could come back with stale records.
template <SegmentDirLike Dir>
bool repersist_headers(Dir& dir) {
  for (std::size_t i = 0; i < dir.count(); ++i) {
    auto& dev = dir.device(i);
    if (!repersist(dev, 0, std::min<std::uint64_t>(dev.size(), kSegmentHeaderBytes))) return false;
  }
  return true;
}

// Writes a Pad of `len` bytes at `at` (read-modify-write of the blocks it touches).
template <JournalDeviceLike Device>
bool write_pad(Device& dev, std::uint64_t at, std::uint32_t len, const ChainState& chain, const Sealer& sealer) {
  const std::uint64_t blk = align_down_block(at);
  const std::uint64_t end = align_up_block(at + len);
  const auto n = static_cast<std::size_t>(end - blk);
  AlignedBuf buf = aligned_zeroed(n);
  if (buf == nullptr) return false;
  const std::span<std::byte> b(buf.get(), n);
  if (!read_exact(dev, blk, b)) return false;
  build_pad(b.data() + (at - blk), len, chain, sealer);
  return write_sync(dev, blk, std::span<const std::byte>(b), true) == static_cast<std::int32_t>(n);
}

}  // namespace detail

template <SegmentDirLike Dir>
RecoveryResult recover(Dir& dir, const RecoveryOptions& opts = {}) {
  RecoveryResult r;
  detail::HeaderScan hs = detail::scan_headers(dir, opts.day);
  r.day = hs.day;
  r.ignored = hs.ignored;

  const auto corrupt = [&](CorruptionKind k, std::size_t handle, std::uint64_t off, std::string what) {
    r.status = RecoveryStatus::Corruption;
    r.corruption = k;
    r.bad_handle = handle;
    r.bad_offset = off;
    r.detail = std::string(to_string(k)) + ": " + what;
    return r;
  };
  const auto io_error = [&](std::string what) {
    r.status = RecoveryStatus::IoError;
    r.detail = "I/O error: " + what;
    return r;
  };

  // Spares: clean only if nothing was written after the header (an assignment whose
  // header write never became durable can leave data within the first window).
  for (const auto& e : hs.prepared) {
    auto& dev = dir.device(e.handle);
    const std::uint64_t limit = std::min(dev.size(), e.header.segment_bytes);
    ChunkedReader<typename Dir::Device> rd(dev, limit);
    const std::uint64_t to = std::min(limit, std::uint64_t{kSegmentHeaderBytes} + opts.inflight_window);
    const RangeProbe p = probe_range(rd, Sealer(), kSegmentHeaderBytes, to, 0);
    if (rd.io_error()) return io_error("reading spare segment");
    if (p.nonzero) {
      r.dirty_spares.push_back(e.handle);
    } else {
      r.spares.push_back(PreparedSegment{e.handle, e.header});
    }
  }

  if (hs.assigned.empty()) {
    if (opts.repair && !detail::repersist_headers(dir)) return io_error("re-persisting segment headers");
    r.status = RecoveryStatus::Empty;
    r.detail = "no assigned segment";
    return r;
  }
  for (std::size_t k = 1; k < hs.assigned.size(); ++k) {
    if (hs.assigned[k].header.first_index == hs.assigned[k - 1].header.first_index) {
      return corrupt(CorruptionKind::DuplicateSegment, hs.assigned[k].handle, 0,
                     "first index " + std::to_string(hs.assigned[k].header.first_index));
    }
  }

  const auto& first = hs.assigned.front().header;
  ChainState chain{first.first_index - 1, first.prev_last_crc, 0, 0};
  auto sealer = std::make_unique<Sealer>();

  for (std::size_t k = 0; k < hs.assigned.size(); ++k) {
    const auto& e = hs.assigned[k];
    const SegmentHeader& h = e.header;
    // Record epochs are checked by the walk (the chain carries them across segments);
    // a header's epoch is informational: it names the epoch of the record that was
    // first assigned to the segment, which may never have become durable.
    if (k > 0 && (h.first_index != chain.last_index + 1 || h.prev_last_crc != chain.last_crc)) {
      return corrupt(CorruptionKind::SegmentChainBreak, e.handle, 0,
                     "segment first index " + std::to_string(h.first_index) + " after index " +
                         std::to_string(chain.last_index));
    }
    auto& dev = dir.device(e.handle);
    const std::uint64_t limit = std::min(dev.size(), h.segment_bytes);
    ChunkedReader<typename Dir::Device> rd(dev, limit);
    *sealer = Sealer(h.nonce);
    const WalkResult w = walk_segment(rd, *sealer, chain, kSegmentHeaderBytes,
                                      [](const RecordView&, std::uint64_t, bool) { return true; });
    if (rd.io_error()) return io_error("reading segment");
    if (w.records != 0 && r.first_index == 0) r.first_index = w.first_index;
    r.records += w.records;
    r.segments.push_back(RecoveredSegment{e.handle, h, w.end, w.records});

    if (k + 1 < hs.assigned.size()) {
      const RangeProbe after = probe_range(rd, *sealer, w.end, limit, 0);
      if (rd.io_error()) return io_error("reading segment");
      if (after.first_sealed) {
        return corrupt(CorruptionKind::DataAfterSealedSegment, e.handle, *after.first_sealed,
                       "sealed record at offset " + std::to_string(*after.first_sealed) + " after end of data " +
                           std::to_string(w.end));
      }
      continue;
    }

    // The last segment: torn tail or corruption, decided by the in-flight window.
    const std::uint64_t x = w.end;
    const std::uint64_t window_end = std::min(limit, x + opts.inflight_window);
    const RangeProbe beyond = probe_range(rd, *sealer, window_end, limit, 0);
    if (rd.io_error()) return io_error("reading segment");
    if (beyond.first_sealed) {
      return corrupt(CorruptionKind::ValidRecordBeyondWindow, e.handle, *beyond.first_sealed,
                     "sealed record at offset " + std::to_string(*beyond.first_sealed) + ", last valid index " +
                         std::to_string(chain.last_index) + " ends at " + std::to_string(x));
    }
    const RangeProbe inside = probe_range(rd, *sealer, x, window_end, ~std::uint64_t{0});
    if (rd.io_error()) return io_error("reading segment");
    r.tail_offset = x;
    r.window_end = window_end;
    r.discarded_records = inside.sealed_records;
    const bool partial_block = x % kBlockBytes != 0;
    r.torn_tail = inside.nonzero || partial_block;

    std::uint64_t resume = x;
    std::uint32_t pad_len = 0;
    if (partial_block) {
      const auto gap = static_cast<std::uint32_t>(align_up_block(x) - x);
      pad_len = gap >= kHeaderBytes ? gap : gap + kBlockBytes;
      if (x + pad_len <= limit) {
        resume = x + pad_len;
      } else {
        pad_len = 0;
        resume = h.segment_bytes;  // nothing more fits: the writer moves to the next segment
      }
    }
    // A file shorter than its header says is damaged: never append to it again.
    if (limit < h.segment_bytes) resume = h.segment_bytes;
    r.resume_offset = resume;
    if (opts.repair) {
      // Zero first, then close the block: a crash in between leaves zeros after x,
      // which the next recovery handles the same way. The window is zeroed even when
      // it reads as zeros (DST-022): they can be in the page cache only, from a zeroing
      // whose write failed (fsyncgate, as for repersist below) over records that a power
      // cut brings back. A rejoin truncation's failed chunk always lies inside it
      // (repl/journal_truncate.h); after a later truncation it would lie beyond.
      if (!detail::zero_range(dev, x, window_end, limit)) return io_error("zeroing the window after the tail");
    }
    if (opts.repair && r.torn_tail) {
      if (pad_len != 0 && !detail::write_pad(dev, x, pad_len, chain, *sealer)) return io_error("writing pad");
      if (sync_device(dev) != 0) return io_error("sync after repair");
      r.repaired = true;
    }
    if (opts.repair) {
      // Everything the chain now relies on that may still be in the page cache only:
      // at most the writer's in-flight window before x (earlier segments were fully
      // synced before the writer moved on), plus every header block.
      const std::uint64_t lo = x > kSegmentHeaderBytes + opts.inflight_window
                                   ? align_down_block(x - opts.inflight_window)
                                   : std::uint64_t{kSegmentHeaderBytes};
      if (!detail::repersist(dev, lo, std::min(x, limit))) return io_error("re-persisting the tail");
      if (!detail::repersist_headers(dir)) return io_error("re-persisting segment headers");
    }
  }

  r.chain = chain;
  r.status = RecoveryStatus::Ok;
  r.detail = "last index " + std::to_string(chain.last_index) + (r.torn_tail ? ", torn tail at offset " +
                                                                                   std::to_string(r.tail_offset) +
                                                                                   (r.repaired ? " (repaired)" : "")
                                                                             : ", clean tail");
  return r;
}

// Opens `dir_path` as a PosixSegmentDir and recovers it (recovery.cpp).
RecoveryResult recover(const std::string& dir_path, const RecoveryOptions& opts = {});

// Positions `w` after a successful recovery: resume in the last segment (or start()
// when the journal is empty) and queue the clean spares. Returns false if the result
// is unusable or a torn tail was reported but not repaired.
template <SegmentDirLike Dir>
bool resume_writer(JournalWriter<typename Dir::Device>& w, Dir& dir, const RecoveryResult& r) {
  if (!r.usable() || (r.torn_tail && !r.repaired)) return false;
  if (r.status == RecoveryStatus::Ok) {
    const RecoveredSegment& t = r.segments.back();
    w.resume(dir.device(t.handle), t.handle, t.header, r.resume_offset, r.chain);
  } else {
    w.start(r.chain);
  }
  for (const auto& s : r.spares) (void)w.add_prepared(dir.device(s.handle), s.handle, s.header);
  return true;
}

}  // namespace lle::journal

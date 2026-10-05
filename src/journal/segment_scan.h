#pragma once
// Scanning primitives shared by recovery (recovery.h) and the read-only journal reader
// (reader.h): chunked reads of a segment, the record validity rule of 06 §7, and the
// "is there any validly sealed record in this range" probe used to tell a torn tail
// from corruption.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "common/endian.h"
#include "journal/journal_device.h"
#include "journal/record.h"
#include "journal/segment.h"

namespace lle::journal {

// Reads a segment through a fixed buffer; get(off, n) returns a pointer to [off, off+n)
// or nullptr when that range is beyond `limit` or the device fails.
template <JournalDeviceLike Device>
class ChunkedReader {
 public:
  ChunkedReader(Device& d, std::uint64_t limit, std::size_t chunk = std::size_t{1} << 20)
      : d_(&d), limit_(limit), cap_(chunk_size(chunk, limit)), buf_(new std::byte[cap_]) {}

  const std::byte* get(std::uint64_t off, std::size_t n) {
    if (off + n > limit_ || off + n < off) return nullptr;
    if (off >= base_ && off + n <= base_ + len_) return buf_.get() + (off - base_);
    if (!fill(off)) return nullptr;
    if (len_ < n) return nullptr;  // file shorter than the header says
    return buf_.get();
  }

  // The cached bytes from `off` on (refilled from `off` when fewer than one maximal
  // record remain cached before the limit); empty at the limit or on error.
  std::span<const std::byte> window(std::uint64_t off) {
    if (off >= limit_) return {};
    const bool cached = off >= base_ && off < base_ + len_;
    const std::uint64_t tail = cached ? base_ + len_ - off : 0;
    if (!cached || (tail < kMaxRecordBytes && base_ + len_ < limit_)) {
      if (!fill(off)) return {};
    }
    return {buf_.get() + (off - base_), static_cast<std::size_t>(base_ + len_ - off)};
  }

  // Drops the cached chunk (after the device was written).
  void invalidate() noexcept { len_ = 0; }
  [[nodiscard]] bool io_error() const noexcept { return io_error_; }
  [[nodiscard]] std::uint64_t limit() const noexcept { return limit_; }
  [[nodiscard]] std::uint64_t bytes_read() const noexcept { return bytes_read_; }  // device bytes, all fills

 private:
  static std::size_t chunk_size(std::size_t chunk, std::uint64_t limit) noexcept {
    std::size_t c = chunk < 2 * kMaxRecordBytes ? 2 * kMaxRecordBytes : chunk;
    if (limit < c) c = limit < 2 * kMaxRecordBytes ? 2 * kMaxRecordBytes : static_cast<std::size_t>(limit);
    return c;
  }

  bool fill(std::uint64_t off) {
    const std::uint64_t want64 = limit_ - off < cap_ ? limit_ - off : cap_;
    const std::int64_t r = d_->read(off, std::span<std::byte>(buf_.get(), static_cast<std::size_t>(want64)));
    if (r < 0) {
      io_error_ = true;
      len_ = 0;
      return false;
    }
    base_ = off;
    len_ = static_cast<std::size_t>(r);
    bytes_read_ += static_cast<std::uint64_t>(r);
    return true;
  }

  Device* d_;
  std::uint64_t limit_;
  std::size_t cap_;
  std::unique_ptr<std::byte[]> buf_;  // not zero-initialized: only read-filled bytes are used
  std::uint64_t base_ = 0;
  std::size_t len_ = 0;
  std::uint64_t bytes_read_ = 0;
  bool io_error_ = false;
};

enum class RecordCheck : std::uint8_t { Valid, ValidPad, Invalid };

// Structural + seal check of the record at `p` (`avail` bytes readable there).
// Returns the record length when the record is sealed by `sealer`.
inline std::optional<std::uint32_t> sealed_record_at(const std::byte* p, std::uint64_t avail, const Sealer& sealer,
                                                     std::uint32_t* content = nullptr) noexcept {
  if (avail < kHeaderBytes) return std::nullopt;
  const std::uint32_t len = load_le32(p + hdr::kLen);
  if (len < kHeaderBytes || len % kRecordAlign != 0 || len > kMaxRecordBytes || len > avail) return std::nullopt;
  if (!valid_record_type(load_le16(p + hdr::kType))) return std::nullopt;
  const auto c = sealer.verify(p);
  if (!c) return std::nullopt;
  if (content != nullptr) *content = *c;
  return len;
}

// 06 §7 step 2: a record is valid only if its length is in bounds, its CRC verifies
// with the segment nonce, its index is the predecessor's + 1, its prev_crc equals the
// predecessor's content crc, and its epoch is monotonic. A Pad is valid filler when it
// is sealed and repeats the chain position (index and prev_crc of the last record).
inline RecordCheck check_record(const std::byte* p, std::uint64_t avail, const Sealer& sealer, const ChainState& chain,
                                std::uint32_t& content) noexcept {
  const auto len = sealed_record_at(p, avail, sealer, &content);
  if (!len) return RecordCheck::Invalid;
  const std::uint64_t index = load_le64(p + hdr::kIndex);
  const std::uint32_t prev = load_le32(p + hdr::kPrevCrc);
  if (load_le16(p + hdr::kType) == static_cast<std::uint16_t>(RecordType::Pad)) {
    return index == chain.last_index && prev == chain.last_crc ? RecordCheck::ValidPad : RecordCheck::Invalid;
  }
  if (index != chain.last_index + 1 || prev != chain.last_crc || load_le32(p + hdr::kEpoch) < chain.epoch) {
    return RecordCheck::Invalid;
  }
  return RecordCheck::Valid;
}

struct WalkResult {
  std::uint64_t end = 0;      // first invalid position (or the segment end)
  std::uint64_t records = 0;  // valid non-Pad records walked
  std::uint64_t first_index = 0;
};

// Walks valid records of one segment from `off`, advancing `chain`. on_record is called
// as on_record(const RecordView&, std::uint64_t offset, bool is_pad) and returns false
// to stop early (the walk then ends after that record).
template <JournalDeviceLike Device, class F>
WalkResult walk_segment(ChunkedReader<Device>& rd, const Sealer& sealer, ChainState& chain, std::uint64_t off,
                        F&& on_record) {
  WalkResult w;
  const std::uint64_t limit = rd.limit();
  for (;;) {
    w.end = off;
    if (off + kHeaderBytes > limit) break;
    const std::byte* h = rd.get(off, kHeaderBytes);
    if (h == nullptr) break;
    const std::uint32_t len = load_le32(h + hdr::kLen);
    if (len < kHeaderBytes || len % kRecordAlign != 0 || len > kMaxRecordBytes || off + len > limit) break;
    const std::byte* p = rd.get(off, len);
    if (p == nullptr) break;
    std::uint32_t content = 0;
    const RecordCheck c = check_record(p, len, sealer, chain, content);
    if (c == RecordCheck::Invalid) break;
    const RecordView view(std::span<const std::byte>(p, len));
    bool go = true;
    if (c == RecordCheck::Valid) {
      chain = ChainState{view.index(), content, view.ts_ns(), view.epoch()};
      if (w.records == 0) w.first_index = view.index();
      ++w.records;
      go = on_record(view, off, false);
    } else {
      go = on_record(view, off, true);
    }
    off += len;
    w.end = off;
    if (!go) break;
  }
  return w;
}

struct RangeProbe {
  std::optional<std::uint64_t> first_sealed;  // offset of the first validly sealed record
  std::uint64_t sealed_records = 0;           // sealed records found (counting stops at max)
  bool nonzero = false;                       // any non-zero byte seen
};

// Looks for validly sealed records starting at any 8-byte-aligned offset in [from, to).
// Records may extend past `to` (up to the reader's limit). Stops counting after
// `max_records` (0: stop at the first one).
template <JournalDeviceLike Device>
RangeProbe probe_range(ChunkedReader<Device>& rd, const Sealer& sealer, std::uint64_t from, std::uint64_t to,
                       std::uint64_t max_records = 0) {
  RangeProbe r;
  const std::uint64_t limit = rd.limit();
  if (to > limit) to = limit;
  std::uint64_t off = from;
  while (off + kRecordAlign <= to) {
    const std::span<const std::byte> win = rd.window(off);
    if (win.size() < kRecordAlign) break;
    const std::uint64_t scan = std::min<std::uint64_t>(win.size(), to - off);
    std::uint64_t j = 0;
    bool refill = false;
    while (j + kRecordAlign <= scan) {
      const std::byte* w = win.data() + j;
      if (load_le64(w) == 0) {
        j += kRecordAlign;
        continue;
      }
      r.nonzero = true;
      const std::uint32_t len = load_le32(w);
      const std::uint64_t avail = limit - (off + j);
      if (len < kHeaderBytes || len % kRecordAlign != 0 || len > kMaxRecordBytes || len > avail) {
        j += kRecordAlign;
        continue;
      }
      if (j + len > win.size()) {  // the candidate extends past the cached window
        if (j == 0) break;         // cannot happen: a refill caches at least one record
        refill = true;
        break;
      }
      if (sealed_record_at(w, len, sealer)) {
        if (!r.first_sealed) r.first_sealed = off + j;
        ++r.sealed_records;
        if (r.sealed_records > max_records) return r;
        j += len;  // continue after the record
        continue;
      }
      j += kRecordAlign;
    }
    if (!refill && j == 0) break;
    off += j;
  }
  return r;
}

}  // namespace lle::journal

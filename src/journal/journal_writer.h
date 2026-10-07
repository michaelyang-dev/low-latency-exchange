#pragma once
// JournalWriter: the L3 durable segment writer of the `io` stage (06 §6).
//
// Records arrive already sealed (by the sequencer, for the L2 ring) and are copied
// into the open 64 KiB batch, re-sealed for the current segment's nonce with one XOR
// (record.h). Natural group commit: the caller appends whatever is available, then
// flush() submits the batch, padded to a 4 KiB boundary with a Pad record, as one
// dsync write (RWF_DSYNC on io_uring); no delay is ever added. At most `queue_depth`
// writes are outstanding.
//
// durable_index advances only over the contiguous prefix of completed writes, in
// submission order, whatever order the device completes them in. Records that are in a
// later completed write while an earlier one is still pending are not durable yet.
//
// Segment switch: a segment is sealed by draining every outstanding write (all of them
// durable) before the next segment's header is written. Recovery relies on this: only
// the LAST segment can have a torn tail. The header carries first_index, epoch and the
// previous segment's last content crc; batches of the new segment may be submitted
// right after its header write, and count as durable only after it (in-order rule).
//
// Error policy (06 §6): a negative or short completion, or a refused submission, is
// fatal: the writer stops (failed()), durable_index freezes at the last contiguous
// durable write, and nothing is retried (never retry fsync, R6 D4.1). The owner halts
// intake and triggers failover.
//
// Allocation: batch buffers (4 KiB aligned, registrable with io_uring) and the segment
// sealers are allocated by the constructor; append/flush/poll never allocate.
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <span>

#include "common/assert.h"
#include "common/endian.h"
#include "env/buggify.h"
#include "journal/journal_device.h"
#include "journal/record.h"
#include "journal/segment.h"

namespace lle::journal {

struct JournalWriterOptions {
  std::uint32_t day = 0;                    // YYYYMMDD stamped into segment headers
  std::uint32_t queue_depth = kQueueDepth;  // outstanding writes, 1..kMaxQueueDepth
  std::uint32_t batch_bytes = kBatchBytes;  // multiple of 4 KiB, >= 2 x kMaxRecordBytes
  std::uint32_t buffers = 8;                // batch buffers, >= queue_depth + 1
  // Paired assertion (09 §5, TigerStyle): re-verify each record's seal before writing.
  // One CRC pass per record on the io core (~4% of a core at 400 MB/s).
  bool verify_records = true;
};

template <JournalDeviceLike Device>
class JournalWriter {
 public:
  static constexpr std::uint32_t kMaxQueueDepth = 8;
  static constexpr std::uint32_t kMaxBuffers = 16;
  static constexpr std::size_t kMaxPrepared = 8;

  enum class Status : std::uint8_t {
    Ok,           // record copied into the open batch; the caller may release it
    Busy,         // no room until outstanding writes complete: poll() and retry
    NeedSegment,  // the current segment is full and no prepared segment is queued
    Failed,       // fatal I/O error earlier; the writer is stopped
    BadRecord,    // not the next record of the chain, bad length/seal, or a Pad
  };

  struct FatalError {
    std::uint64_t tag = 0;
    std::uint64_t offset = 0;
    std::uint32_t expected = 0;
    std::int32_t result = 0;  // -errno, short byte count, or -EAGAIN for a refused submission
  };

  // A segment whose header the writer has written; the owner renames it to its
  // canonical file name (segment_file_name) off the hot path.
  struct AssignedSegment {
    std::size_t handle = 0;
    SegmentHeader header;
  };

  struct Stats {
    std::uint64_t records = 0;
    std::uint64_t record_bytes = 0;
    std::uint64_t writes = 0;
    std::uint64_t write_bytes = 0;
    std::uint64_t pad_bytes = 0;
    std::uint64_t segments = 0;
    std::uint64_t busy = 0;
  };

  explicit JournalWriter(const JournalWriterOptions& opts) : opts_(opts) {
    LLE_ASSERT(opts_.queue_depth >= 1 && opts_.queue_depth <= kMaxQueueDepth, "queue depth");
    LLE_ASSERT(opts_.batch_bytes % kBlockBytes == 0 && opts_.batch_bytes >= 2 * kMaxRecordBytes, "batch size");
    LLE_ASSERT(opts_.buffers >= opts_.queue_depth + 1 && opts_.buffers <= kMaxBuffers, "buffer count");
    const std::size_t bytes = std::size_t{opts_.buffers} * opts_.batch_bytes + kSegmentHeaderBytes;
    mem_.reset(static_cast<std::byte*>(std::aligned_alloc(kBlockBytes, bytes)));
    LLE_ASSERT(mem_ != nullptr, "batch buffer allocation");
    std::memset(mem_.get(), 0, bytes);
    for (std::uint32_t b = 0; b < opts_.buffers; ++b) {
      bufs_[b] = std::span<std::byte>(mem_.get() + std::size_t{b} * opts_.batch_bytes, opts_.batch_bytes);
    }
    header_buf_ = mem_.get() + std::size_t{opts_.buffers} * opts_.batch_bytes;
    sealer_ = std::make_unique<Sealer>();
  }

  JournalWriter(const JournalWriter&) = delete;
  JournalWriter& operator=(const JournalWriter&) = delete;

  // Batch buffers, e.g. for IORING_REGISTER_BUFFERS (WRITE_FIXED).
  [[nodiscard]] std::span<const std::span<std::byte>> batch_buffers() const noexcept {
    return {bufs_.data(), opts_.buffers};
  }

  // ---- positioning (cold) ----------------------------------------------------------

  // Start of a day, or after a recovery that left no segment to continue in: the first
  // append assigns a prepared segment. Everything up to chain.last_index is durable.
  void start(const ChainState& chain) noexcept {
    reset_position(chain);
    seg_ = nullptr;
  }

  // Continue in the last segment found by recovery, at its 4 KiB-aligned resume offset.
  void resume(Device& dev, std::size_t handle, const SegmentHeader& h, std::uint64_t offset, const ChainState& chain) {
    LLE_ASSERT(h.assigned() && offset % kBlockBytes == 0 && offset >= kSegmentHeaderBytes && offset <= h.segment_bytes,
               "bad resume point");
    reset_position(chain);
    seg_ = &dev;
    seg_handle_ = handle;
    seg_header_ = h;
    *sealer_ = Sealer(h.nonce);
    woff_ = offset;
  }

  // Queues a prepared (unassigned) segment for the next switch. Returns false if the
  // queue is full or the header does not describe a usable prepared segment.
  bool add_prepared(Device& dev, std::size_t handle, const SegmentHeader& h) noexcept {
    if (prepared_n_ == kMaxPrepared || h.assigned() || h.day != opts_.day || !usable_nonce(h.nonce) ||
        h.segment_bytes < kSegmentHeaderBytes + opts_.batch_bytes || h.segment_bytes % kBlockBytes != 0) {
      return false;
    }
    prepared_[(prepared_head_ + prepared_n_) % kMaxPrepared] = Prepared{&dev, handle, h};
    ++prepared_n_;
    return true;
  }
  [[nodiscard]] std::size_t prepared_count() const noexcept { return prepared_n_; }

  // ---- hot path ------------------------------------------------------------------------

  // Copies one sealed record (sealed by `src`) into the open batch.
  Status append(std::span<const std::byte> rec, const Sealer& src) noexcept {
    if (failed_) return Status::Failed;
    if (SIM_BUGGIFY("journal.writer_spurious_busy")) return busy_or_failed();  // 09 §4: spurious EAGAIN
    if (rec.size() < kHeaderBytes || rec.size() > kMaxRecordBytes) return Status::BadRecord;
    const std::uint32_t len = load_le32(rec.data() + hdr::kLen);
    if (len != rec.size() || len % kRecordAlign != 0) return Status::BadRecord;
    const std::uint16_t type = load_le16(rec.data() + hdr::kType);
    if (!valid_record_type(type) || type == static_cast<std::uint16_t>(RecordType::Pad)) return Status::BadRecord;
    const std::uint64_t index = load_le64(rec.data() + hdr::kIndex);
    const std::uint32_t epoch = load_le32(rec.data() + hdr::kEpoch);
    if (index != chain_.last_index + 1 || load_le32(rec.data() + hdr::kPrevCrc) != chain_.last_crc ||
        epoch < chain_.epoch) {
      return Status::BadRecord;
    }
    std::uint32_t content;
    if (opts_.verify_records) {
      const auto v = src.verify(rec.data());
      if (!v) return Status::BadRecord;
      content = *v;
    } else {
      content = src.content_of(rec.data());
    }

    for (;;) {
      if (seg_ == nullptr || need_switch_) {
        if (batch_used_ != 0) {
          if (!submit_batch()) return busy_or_failed();
          continue;
        }
        if (in_flight() != 0) return busy_or_failed();  // seal the segment: drain first
        if (prepared_n_ == 0) return Status::NeedSegment;
        if (!switch_segment(index, epoch)) return Status::Failed;
        continue;
      }
      const std::uint64_t room = seg_header_.segment_bytes - woff_;
      const std::uint64_t cap = room < opts_.batch_bytes ? room : opts_.batch_bytes;
      if (padded_batch_bytes(batch_used_ + len) <= cap) break;
      if (batch_used_ != 0) {
        if (!submit_batch()) return busy_or_failed();
        continue;
      }
      need_switch_ = true;  // an empty batch does not fit: the segment is full
    }

    std::byte* dst = bufs_[cur_buf_].data() + batch_used_;
    std::memcpy(dst, rec.data(), len);
    store_le32(dst + hdr::kCrc, content ^ sealer_->mask(len));
    batch_used_ += len;
    batch_last_index_ = index;
    chain_ = ChainState{index, content, static_cast<Nanos>(load_le64(rec.data() + hdr::kTs)), epoch};
    ++stats_.records;
    stats_.record_bytes += len;
    return Status::Ok;
  }

  // Submits the open batch if there is one and the queue has room (group commit).
  bool flush() noexcept { return !failed_ && batch_used_ != 0 && submit_batch(); }

  // Reaps completions and advances durable_index. Returns completions processed.
  std::size_t poll() noexcept {
    if (seg_ == nullptr) return 0;
    const std::size_t n = seg_->poll([this](const env::DiskCompletion& c) { on_completion(c); });
    retire();
    return n;
  }

  // ---- state ----------------------------------------------------------------------------
  [[nodiscard]] std::uint64_t durable_index() const noexcept { return durable_index_; }
  // The last record of the newest submitted batch (0: none yet): the owner times a
  // batch's commit from its submission until durable_index() reaches this.
  [[nodiscard]] std::uint64_t submitted_index() const noexcept { return submitted_index_; }
  [[nodiscard]] std::uint64_t appended_index() const noexcept { return chain_.last_index; }
  [[nodiscard]] const ChainState& chain() const noexcept { return chain_; }
  [[nodiscard]] bool failed() const noexcept { return failed_; }
  [[nodiscard]] const FatalError& error() const noexcept { return error_; }
  [[nodiscard]] std::size_t in_flight() const noexcept { return static_cast<std::size_t>(next_tag_ - oldest_tag_); }
  [[nodiscard]] std::uint32_t batch_used() const noexcept { return batch_used_; }
  [[nodiscard]] std::uint64_t write_offset() const noexcept { return woff_; }
  [[nodiscard]] bool has_segment() const noexcept { return seg_ != nullptr; }
  [[nodiscard]] const SegmentHeader& segment_header() const noexcept { return seg_header_; }
  [[nodiscard]] std::size_t segment_handle() const noexcept { return seg_handle_; }
  [[nodiscard]] const Stats& stats() const noexcept { return stats_; }

  // Drains the queue of segments assigned since the last call (oldest first).
  bool take_assigned(AssignedSegment& out) noexcept {
    if (assigned_n_ == 0) return false;
    out = assigned_[assigned_head_];
    assigned_head_ = (assigned_head_ + 1) % kMaxPrepared;
    --assigned_n_;
    return true;
  }

 private:
  static constexpr std::uint32_t kMaxSlots = 16;  // > kMaxQueueDepth; tag % kMaxSlots is unique
  static constexpr std::uint32_t kHeaderBuffer = ~std::uint32_t{0};
  static_assert(kMaxSlots > kMaxQueueDepth);

  struct Slot {
    std::uint64_t tag = 0;
    std::uint64_t offset = 0;
    std::uint64_t last_index = 0;  // highest record index in the write; 0 for a header
    std::uint32_t len = 0;
    std::uint32_t buffer = 0;
    bool completed = false;
    bool ok = false;
  };
  struct Prepared {
    Device* dev = nullptr;
    std::size_t handle = 0;
    SegmentHeader header;
  };
  struct FreeDeleter {
    void operator()(std::byte* p) const noexcept { std::free(p); }
  };

  void reset_position(const ChainState& chain) noexcept {
    LLE_ASSERT(in_flight() == 0, "repositioning with writes in flight");
    chain_ = chain;
    durable_index_ = chain.last_index;
    submitted_index_ = chain.last_index;
    batch_used_ = 0;
    batch_last_index_ = 0;
    need_switch_ = false;
  }

  Status busy_or_failed() noexcept {
    if (failed_) return Status::Failed;
    ++stats_.busy;
    return Status::Busy;
  }

  void fail(std::uint64_t tag, std::uint64_t offset, std::uint32_t expected, std::int32_t result) noexcept {
    if (!failed_) error_ = FatalError{tag, offset, expected, result};
    failed_ = true;
  }

  std::uint32_t pick_free_buffer() const noexcept {
    for (std::uint32_t b = 0; b < opts_.buffers; ++b) {
      if (!owned_[b]) return b;
    }
    LLE_UNREACHABLE("no free batch buffer");
  }

  bool submit_slot(std::uint64_t offset, std::span<const std::byte> bytes, std::uint32_t buffer,
                   std::uint64_t last_index) noexcept {
    const std::uint64_t tag = next_tag_++;
    Slot& s = slots_[tag % kMaxSlots];
    s = Slot{tag, offset, last_index, static_cast<std::uint32_t>(bytes.size()), buffer, false, false};
    if (buffer != kHeaderBuffer) owned_[buffer] = true;
    if (!seg_->submit_write(offset, bytes, true, tag)) {
      fail(tag, offset, s.len, -EAGAIN);
      return false;
    }
    ++stats_.writes;
    stats_.write_bytes += bytes.size();
    return true;
  }

  bool submit_batch() noexcept {
    if (failed_ || batch_used_ == 0 || in_flight() >= opts_.queue_depth) return false;
    const auto padded = static_cast<std::uint32_t>(padded_batch_bytes(batch_used_));
    const std::uint32_t gap = padded - batch_used_;
    std::byte* buf = bufs_[cur_buf_].data();
    if (gap != 0) {
      build_pad(buf + batch_used_, gap, chain_, *sealer_);
      stats_.pad_bytes += gap;
    }
    const std::uint32_t b = cur_buf_;
    if (!submit_slot(woff_, std::span<const std::byte>(buf, padded), b, batch_last_index_)) return false;
    woff_ += padded;
    if (batch_last_index_ != 0) submitted_index_ = batch_last_index_;
    batch_used_ = 0;
    batch_last_index_ = 0;
    cur_buf_ = pick_free_buffer();
    return true;
  }

  bool switch_segment(std::uint64_t first_index, std::uint32_t epoch) noexcept {
    const Prepared p = prepared_[prepared_head_];
    prepared_head_ = (prepared_head_ + 1) % kMaxPrepared;
    --prepared_n_;
    SegmentHeader h = p.header;
    h.day = opts_.day;
    h.epoch = epoch;
    h.first_index = first_index;
    h.prev_last_crc = chain_.last_crc;
    seg_ = p.dev;
    seg_handle_ = p.handle;
    seg_header_ = h;
    *sealer_ = Sealer(h.nonce);  // ~4K CRC steps, once per segment
    woff_ = kSegmentHeaderBytes;
    need_switch_ = false;
    ++stats_.segments;
    if (assigned_n_ < kMaxPrepared) {
      assigned_[(assigned_head_ + assigned_n_) % kMaxPrepared] = AssignedSegment{p.handle, h};
      ++assigned_n_;
    }
    encode_segment_header(std::span<std::byte, kSegmentHeaderBytes>(header_buf_, kSegmentHeaderBytes), h);
    return submit_slot(0, std::span<const std::byte>(header_buf_, kSegmentHeaderBytes), kHeaderBuffer, 0);
  }

  void on_completion(const env::DiskCompletion& c) noexcept {
    Slot& s = slots_[c.tag % kMaxSlots];
    if (s.tag != c.tag || s.completed || c.tag < oldest_tag_ || c.tag >= next_tag_) {
      fail(c.tag, 0, 0, c.result);  // a completion we never asked for
      return;
    }
    s.completed = true;
    s.ok = c.result >= 0 && static_cast<std::uint32_t>(c.result) == s.len;
    if (!s.ok) fail(c.tag, s.offset, s.len, c.result);
  }

  void retire() noexcept {
    while (oldest_tag_ < next_tag_) {
      Slot& s = slots_[oldest_tag_ % kMaxSlots];
      if (!s.completed || !s.ok) break;
      if (s.last_index != 0) durable_index_ = s.last_index;
      if (s.buffer != kHeaderBuffer) owned_[s.buffer] = false;
      ++oldest_tag_;
    }
  }

  JournalWriterOptions opts_;
  std::unique_ptr<std::byte, FreeDeleter> mem_;
  std::array<std::span<std::byte>, kMaxBuffers> bufs_{};
  std::array<bool, kMaxBuffers> owned_{};
  std::byte* header_buf_ = nullptr;
  std::unique_ptr<Sealer> sealer_;  // current segment's sealer (16 KiB)

  // Current segment.
  Device* seg_ = nullptr;
  std::size_t seg_handle_ = 0;
  SegmentHeader seg_header_{};
  std::uint64_t woff_ = 0;  // file offset of the open batch
  bool need_switch_ = false;

  // Open batch.
  std::uint32_t cur_buf_ = 0;
  std::uint32_t batch_used_ = 0;
  std::uint64_t batch_last_index_ = 0;

  // Outstanding writes, in submission order: tags [oldest_tag_, next_tag_).
  std::array<Slot, kMaxSlots> slots_{};
  std::uint64_t next_tag_ = 1;
  std::uint64_t oldest_tag_ = 1;

  ChainState chain_{};
  std::uint64_t durable_index_ = 0;
  std::uint64_t submitted_index_ = 0;  // the last record of the newest submitted batch
  bool failed_ = false;
  FatalError error_{};

  std::array<Prepared, kMaxPrepared> prepared_{};
  std::size_t prepared_head_ = 0;
  std::size_t prepared_n_ = 0;
  std::array<AssignedSegment, kMaxPrepared> assigned_{};
  std::size_t assigned_head_ = 0;
  std::size_t assigned_n_ = 0;
  Stats stats_{};
};

}  // namespace lle::journal

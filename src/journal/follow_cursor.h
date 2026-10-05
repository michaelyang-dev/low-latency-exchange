#pragma once
// FollowCursor: reads a journal directory while its writer appends to it (snapshotd,
// 06 §9), with exactly the validity rules of recovery (06 §7: seal, index + 1, prev_crc
// chain, monotonic epoch, Pad filler) and without reading anything twice.
//
// It keeps its place (segment, offset, chain state) across polls. A poll reads on from
// that offset: a run of new records costs their bytes plus at most one chunk of read-ahead
// (2 x kMaxRecordBytes), whatever the size of the segment so far; a poll with nothing new
// costs one header-sized read at the tail. The directory is listed again only when the
// cursor has been idle at its tail for a while (rescans back off from rescan_min_idle to
// rescan_max_idle idle polls), to find the next segment after the writer switched (or
// restarted) and to check that the history it walked is still the journal's.
//
// Divergence (FollowStatus::Diverged): the record walked last is no longer in the
// journal as walked (a rejoin truncated it, 10 §5, or a crash lost records the cursor had
// read before they were durable), its segment was recycled, or the record before the
// position given to seek() is not in the journal (or has another content crc). Seen
// once, the cursor lists the directory afresh and positions again before reporting it,
// so a listing taken while the writer renamed a segment cannot fake one. After
// Diverged the cursor stays put until seek().
//
// Opener: a callable returning a fresh read-only listing of the directory, as
// std::optional<Dir> or std::expected<Dir, E> (Dir: SegmentDirLike, movable). Its
// devices must read what the writer wrote (a POSIX file, a shared in-memory device).
// Cold path (housekeeping process); allocates when it lists the directory.
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>

#include "common/endian.h"
#include "journal/record.h"
#include "journal/recovery.h"
#include "journal/segment.h"
#include "journal/segment_dir.h"
#include "journal/segment_scan.h"

namespace lle::journal {

struct FollowOptions {
  std::uint32_t day = 0;               // 0: the day of the earliest assigned segment
  std::uint32_t rescan_min_idle = 2;   // idle polls at the tail before listing the directory again
  std::uint32_t rescan_max_idle = 64;  // the back-off cap while nothing arrives
};

enum class FollowStatus : std::uint8_t {
  Records,    // walked at least one record (delivered, or below the position)
  Idle,       // nothing new (detail() says why when the journal has no segment yet)
  Stopped,    // the callback returned false; the record it returned false for is consumed
  Diverged,   // see above; seek() to go on
  NoJournal,  // the directory cannot be opened
  IoError,    // a device read failed; the next poll positions again
};

struct FollowStats {
  std::uint64_t polls = 0;
  std::uint64_t records = 0;     // valid records walked
  std::uint64_t delivered = 0;   // records passed to the callback
  std::uint64_t listings = 0;    // directory listings (opener calls)
  std::uint64_t positions = 0;   // positionings (seek, and after a suspected divergence)
  std::uint64_t suspicions = 0;  // divergences seen once (confirmed or not by a fresh listing)
  std::uint64_t segments = 0;    // segments entered
  std::uint64_t bytes_read = 0;  // device bytes read
};

template <class Opener>
class FollowCursor {
 public:
  using Listing = std::invoke_result_t<Opener&>;
  using Dir = typename Listing::value_type;
  using Device = typename Dir::Device;
  static_assert(SegmentDirLike<Dir>, "the opener lists a journal directory");

  explicit FollowCursor(Opener open, FollowOptions o = {})
      : open_(std::move(open)), o_(o), sealer_(std::make_unique<Sealer>()) {
    if (o_.rescan_min_idle == 0) o_.rescan_min_idle = 1;
    if (o_.rescan_max_idle < o_.rescan_min_idle) o_.rescan_max_idle = o_.rescan_min_idle;
  }

  // Records from index `next` on (1: the start of the day). Record next-1 must be in
  // the journal; `prev_crc` is its content crc when known (checked when it is walked).
  void seek(std::uint64_t next, std::optional<std::uint32_t> prev_crc = std::nullopt) {
    next_ = next == 0 ? 1 : next;
    want_crc_ = prev_crc;
    suspect_ = false;
    diverged_ = false;
    drop();
  }

  // Walks what the journal holds beyond the position, calling f(const RecordView&) ->
  // bool for each record from next_index() on (up to `max_records` records walked).
  template <class F>
  FollowStatus poll(F&& f, std::uint64_t max_records = ~std::uint64_t{0}) {
    settled_ = false;
    ++st_.polls;
    if (diverged_) return FollowStatus::Diverged;
    if (!positioned_) {
      const Step s = position();
      if (s != Step::Ok) return status_of(s);
    }
    std::uint64_t walked = 0;
    for (;;) {
      if (walked >= max_records) return FollowStatus::Records;
      std::uint32_t content = 0;
      const std::byte* p = nullptr;
      std::uint32_t len = 0;
      const RecordCheck c = read_at(off_, p, len, content);
      if (c == RecordCheck::Invalid) {
        if (io_error_ || rd_->io_error()) return io_failure();
        rd_->invalidate();  // what is read next comes from the device again
        tail_ = true;
        if (walked != 0) return FollowStatus::Records;
        const Step s = at_tail();
        if (s == Step::Ok) continue;  // the next segment
        return status_of(s);
      }
      tail_ = false;
      const RecordView v(std::span<const std::byte>(p, len));
      const std::uint64_t at = off_;
      off_ += len;
      if (c == RecordCheck::ValidPad) continue;
      chain_ = ChainState{v.index(), content, v.ts_ns(), v.epoch()};
      last_off_ = at;
      last_len_ = len;
      have_last_ = true;
      ++st_.records;
      ++walked;
      idle_ = 0;
      backoff_ = o_.rescan_min_idle;
      if (v.index() < next_) {  // walking up to the position
        if (v.index() + 1 == next_ && want_crc_ && content != *want_crc_) return suspect("the record before the position differs");
        if (v.index() + 1 == next_) verified();
        continue;
      }
      verified();
      ++next_;
      ++st_.delivered;
      if (!f(v)) return FollowStatus::Stopped;
    }
  }

  [[nodiscard]] std::uint64_t next_index() const noexcept { return next_; }
  // The last record walked (content crc), or the chain the current segment starts from.
  [[nodiscard]] const ChainState& chain() const noexcept { return chain_; }
  [[nodiscard]] const FollowStats& stats() const noexcept {
    st_.bytes_read = bytes_done_ + (rd_ ? rd_->bytes_read() : 0);
    return st_;
  }
  // Why the last poll found no journal, no segment, or a divergence.
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  // The last poll was Idle with a fresh look at the directory: as of now the cursor has
  // read everything the journal holds (or there is no segment yet). A one-shot reader
  // polls until this holds.
  [[nodiscard]] bool settled() const noexcept { return settled_; }
  // Why the cursor last suspected a divergence (empty: never).
  [[nodiscard]] const std::string& last_suspicion() const noexcept { return last_suspicion_; }

 private:
  enum class Step : std::uint8_t { Ok, Idle, NoJournal, Suspect, Diverged, IoError };

  static FollowStatus status_of(Step s) noexcept {
    switch (s) {
      case Step::Ok: return FollowStatus::Records;
      case Step::Idle: return FollowStatus::Idle;
      case Step::Suspect: return FollowStatus::Idle;
      case Step::NoJournal: return FollowStatus::NoJournal;
      case Step::Diverged: return FollowStatus::Diverged;
      case Step::IoError: return FollowStatus::IoError;
    }
    return FollowStatus::Idle;
  }

  // Forgets the listing and the place; the next poll positions again at next_.
  void drop() {
    if (rd_) bytes_done_ += rd_->bytes_read();
    rd_.reset();
    dir_.reset();
    positioned_ = false;
    have_last_ = false;
    tail_ = false;
    io_error_ = false;
    verified_ = false;
    idle_ = 0;
    backoff_ = o_.rescan_min_idle;
  }

  // A divergence seen for the first time: list afresh and position again before
  // reporting it (Step::Suspect polls as Idle).
  FollowStatus suspect(const char* why) { return status_of(suspect_step(why)); }
  Step suspect_step(const char* why) {
    detail_ = why;
    last_suspicion_ = why;
    ++st_.suspicions;
    // Position again expecting the record walked last once the position was verified
    // (otherwise the one seek() named).
    if (verified_ && have_last_ && chain_.last_index + 1 == next_) want_crc_ = chain_.last_crc;
    drop();
    if (suspect_) {
      diverged_ = true;
      return Step::Diverged;
    }
    suspect_ = true;
    return Step::Suspect;
  }
  void verified() noexcept {
    suspect_ = false;
    verified_ = true;
  }

  FollowStatus io_failure() {
    detail_ = "device read failed";
    if (verified_ && have_last_ && chain_.last_index + 1 == next_) want_crc_ = chain_.last_crc;
    drop();
    return FollowStatus::IoError;
  }

  std::optional<Dir> list() {
    ++st_.listings;
    Listing l = open_();
    if (!l) {
      if constexpr (requires { l.error(); }) {
        if constexpr (std::convertible_to<decltype(l.error()), std::string>) detail_ = l.error();
        else detail_ = "the journal directory cannot be opened";
      } else {
        detail_ = "the journal directory cannot be opened";
      }
      return std::nullopt;
    }
    return std::optional<Dir>(std::move(*l));
  }

  void open_reader(std::size_t handle, const SegmentHeader& h) {
    if (rd_) bytes_done_ += rd_->bytes_read();
    auto& dev = dir_->device(handle);
    rd_ = std::make_unique<ChunkedReader<Device>>(dev, std::min(dev.size(), h.segment_bytes),
                                                  2 * std::size_t{kMaxRecordBytes});
    handle_ = handle;
    hdr_ = h;
    *sealer_ = Sealer(h.nonce);
  }

  // The segment that holds record next_ - 1 (or starts at next_), walked from its start.
  Step position() {
    ++st_.positions;
    auto l = list();
    if (!l) return Step::NoJournal;
    const detail::HeaderScan hs = detail::scan_headers(*l, o_.day);
    const detail::HeaderScan::Entry* pick = nullptr;
    for (const auto& e : hs.assigned) {
      if (e.header.first_index <= next_) pick = &e;
    }
    if (pick == nullptr) {
      // No segment holds record next_ - 1: there is no journal yet (position 1), or the
      // history before the position is gone.
      if (next_ > 1) return suspect_step("the journal does not hold the record before the position");
      detail_ = hs.assigned.empty() ? "no journal segment yet" : "the journal starts after the position";
      settled_ = true;
      return Step::Idle;
    }
    std::size_t same = 0;
    for (const auto& e : hs.assigned) same += e.header.first_index == pick->header.first_index ? 1 : 0;
    if (same != 1) {
      detail_ = "two segments claim the same first index";
      return Step::Idle;
    }
    const std::size_t handle = pick->handle;
    const SegmentHeader h = pick->header;
    dir_ = std::move(l);
    open_reader(handle, h);
    ++st_.segments;
    chain_ = ChainState{h.first_index - 1, h.prev_last_crc, 0, 0};
    have_last_ = false;
    off_ = kSegmentHeaderBytes;
    positioned_ = true;
    if (h.first_index == next_) {
      if (want_crc_ && *want_crc_ != h.prev_last_crc && next_ > 1) {
        positioned_ = false;
        return suspect_step("the segment at the position does not chain to the record before it");
      }
      verified();
    }
    return Step::Ok;
  }

  // The record at `off` (`p`, `len`). At the tail a header-sized read comes first, so
  // a poll with nothing new does not refill a whole chunk.
  RecordCheck read_at(std::uint64_t off, const std::byte*& p, std::uint32_t& len, std::uint32_t& content) {
    const std::uint64_t limit = rd_->limit();
    if (off + kHeaderBytes > limit) return RecordCheck::Invalid;
    if (tail_) {
      const std::int64_t r = dir_->device(handle_).read(off, std::span<std::byte>(probe_, kHeaderBytes));
      if (r < 0) {
        io_error_ = true;
        return RecordCheck::Invalid;
      }
      bytes_done_ += static_cast<std::uint64_t>(r);
      if (r < static_cast<std::int64_t>(kHeaderBytes) || load_le32(probe_ + hdr::kLen) == 0) return RecordCheck::Invalid;
    }
    const std::byte* h = rd_->get(off, kHeaderBytes);
    if (h == nullptr) return RecordCheck::Invalid;
    len = load_le32(h + hdr::kLen);
    if (len < kHeaderBytes || len % kRecordAlign != 0 || len > kMaxRecordBytes || off + len > limit)
      return RecordCheck::Invalid;
    p = rd_->get(off, len);
    if (p == nullptr) return RecordCheck::Invalid;
    return check_record(p, len, *sealer_, chain_, content);
  }

  // Nothing valid at the tail. Still in the positioning walk: the journal does not hold
  // the record before the position. Otherwise wait, and every so often list the
  // directory: check the history walked so far, and look for the next segment.
  Step at_tail() {
    if (chain_.last_index + 1 < next_) return suspect_step("the journal ends before the position");
    ++idle_;
    if (idle_ < backoff_) return Step::Idle;
    idle_ = 0;
    backoff_ = std::min(backoff_ * 2, o_.rescan_max_idle);
    return rescan();
  }

  Step rescan() {
    // 1. The record walked last (or this segment's header) is still what was walked.
    if (have_last_) {
      const std::byte* p = rd_->get(last_off_, last_len_);
      std::uint32_t content = 0;
      const auto len = p == nullptr ? std::nullopt : sealed_record_at(p, last_len_, *sealer_, &content);
      rd_->invalidate();
      if (!len || *len != last_len_ || load_le64(p + hdr::kIndex) != chain_.last_index || content != chain_.last_crc)
        return suspect_step("the record walked last is no longer in the journal");
    }
    // 2. A fresh listing: this segment must still be there, assigned as it was.
    auto l = list();
    if (!l) return Step::Idle;  // cannot list now: try again later
    const detail::HeaderScan hs = detail::scan_headers(*l, hdr_.day);
    const detail::HeaderScan::Entry* self = nullptr;
    const detail::HeaderScan::Entry* next = nullptr;
    std::size_t nexts = 0;
    for (const auto& e : hs.assigned) {
      if (e.header == hdr_) self = &e;
      if (e.header.first_index == chain_.last_index + 1 && e.header.prev_last_crc == chain_.last_crc &&
          e.header.epoch >= chain_.epoch && !(e.header == hdr_)) {
        next = &e;
        ++nexts;
      }
    }
    if (self == nullptr) return suspect_step("the segment being read was recycled or removed");
    const std::size_t self_handle = self->handle;
    const std::optional<std::pair<std::size_t, SegmentHeader>> succ =
        nexts == 1 ? std::optional<std::pair<std::size_t, SegmentHeader>>({next->handle, next->header}) : std::nullopt;
    dir_ = std::move(l);
    if (succ) {
      // 3. The writer moved on (the segment filled up, or it restarted): only the last
      // segment can have a torn tail (journal_writer.h), so this one is complete.
      open_reader(succ->first, succ->second);
      ++st_.segments;
      off_ = kSegmentHeaderBytes;
      have_last_ = false;
      tail_ = false;
      return Step::Ok;
    }
    // Same segment, read through the new listing (a fresh handle, its current size).
    open_reader(self_handle, hdr_);
    settled_ = true;
    return Step::Idle;
  }

  Opener open_;
  FollowOptions o_;
  std::optional<Dir> dir_;
  std::unique_ptr<ChunkedReader<Device>> rd_;
  std::unique_ptr<Sealer> sealer_;
  std::size_t handle_ = 0;
  SegmentHeader hdr_{};
  std::uint64_t off_ = 0;
  ChainState chain_{};
  std::uint64_t last_off_ = 0;
  std::uint32_t last_len_ = 0;
  bool have_last_ = false;
  bool tail_ = false;      // the last read found nothing valid: probe before refilling
  bool io_error_ = false;  // a probe read failed
  std::byte probe_[kHeaderBytes] = {};
  bool positioned_ = false;
  bool suspect_ = false;
  bool verified_ = false;  // the walk reached the position with the expected chain
  bool diverged_ = false;
  bool settled_ = false;
  std::uint64_t next_ = 1;
  std::optional<std::uint32_t> want_crc_;
  std::uint32_t idle_ = 0;
  std::uint32_t backoff_ = 2;
  std::uint64_t bytes_done_ = 0;
  mutable FollowStats st_{};
  std::string detail_;
  std::string last_suspicion_;
};

}  // namespace lle::journal

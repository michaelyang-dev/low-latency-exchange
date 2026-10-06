#pragma once
// L2Ring<N>: the L2 broadcast ring of journal records (06 §4, §5).
//
// A thin wrapper over conc::BroadcastRing<N> (single writer: the sequencer; N cursors:
// journal writer, replicator, engine). The writer is gated by the slowest cursor: a
// reservation fails once that cursor lags by the ring capacity, which is the
// sequencer's back-pressure signal. Every ring element is one journal record sealed
// with the ring instance's nonce (record.h), so the ring can be revalidated after a
// process crash; records never straddle the end (BroadcastRing pads to the end).
//
// Restart (06 §5): the BroadcastRing positions live in process memory, but the bytes
// live in L2Storage (a hugetlbfs file in production). A restarted process calls
// restore(from_index, prev_crc): it finds the record with that index by scanning the
// storage, follows the hash chain while records validate, then re-publishes exactly
// that chain from position 0 so every cursor sees it again, and zeroes the rest so no
// stale copy can ever be mistaken for a live record. from_index is normally
// durable_index + 1 from L3 recovery.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "common/assert.h"
#include "common/endian.h"
#include "concurrent/broadcast_ring.h"
#include "concurrent/byte_record.h"
#include "journal/record.h"

namespace lle::journal {

struct L2RestoreResult {
  bool found = false;          // the record `from_index` was in the ring and chained
  std::uint64_t records = 0;   // records re-published (from_index .. chain.last_index)
  ChainState chain;            // the last restored record (valid when found)
};

template <std::size_t N>
class L2Ring {
 public:
  static constexpr std::size_t kConsumers = N;

  L2Ring() = default;
  L2Ring(const L2Ring&) = delete;
  L2Ring& operator=(const L2Ring&) = delete;

  // `storage`: `capacity` bytes (power of two, 8-byte aligned), e.g. L2Storage::data().
  // `nonce`: the ring instance's nonce (L2Storage::nonce()). Allocates the 16 KiB
  // sealer; call at startup.
  void init(std::byte* storage, std::size_t capacity, std::uint64_t nonce) {
    LLE_ASSERT(usable_nonce(nonce), "L2 ring nonce");
    LLE_ASSERT(capacity >= 4 * (std::size_t{kMaxRecordBytes} + conc::detail::kHeaderBytes), "L2 ring too small");
    storage_ = storage;
    capacity_ = capacity;
    sealer_ = std::make_unique<Sealer>(nonce);
    ring_.init(storage, capacity);
  }

  [[nodiscard]] const Sealer& sealer() const noexcept { return *sealer_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

  // ---- producer (the sequencer) --------------------------------------------------
  // Space for one journal record of `record_len` bytes (multiple of 8, <= kMaxRecordBytes);
  // nullptr when the slowest cursor lags by the capacity (back-pressure).
  [[nodiscard]] std::byte* try_reserve(std::uint32_t record_len) noexcept { return ring_.try_reserve(record_len); }
  // Publishes the reserved record to every cursor; the record must be complete and sealed.
  void commit() noexcept { ring_.commit(); }

  // ---- consumer c ------------------------------------------------------------------
  // The next record for cursor `c`, or an empty view.
  [[nodiscard]] RecordView peek(std::size_t c) noexcept {
    std::uint32_t n = 0;
    const std::byte* p = ring_.peek(c, n);
    return p == nullptr ? RecordView{} : RecordView(std::span<const std::byte>(p, n));
  }
  void release(std::size_t c) noexcept { ring_.release(c); }

  // Calls f(const RecordView&) for up to `max` records; publishes the cursor once.
  template <class F>
  std::size_t drain(std::size_t c, F&& f, std::size_t max) {
    return ring_.drain(
        c, [&](const std::byte* p, std::uint32_t n) { f(RecordView(std::span<const std::byte>(p, n))); }, max);
  }

  // Bytes published but not yet consumed by cursor `c` (approximate across threads).
  [[nodiscard]] std::uint64_t backlog(std::size_t c) const noexcept {
    return ring_.write_position() - ring_.cursor_position(c);
  }

  // ---- restart (cold path; no consumer may run) --------------------------------------
  // `prev_crc`: the content crc the record `from_index` must chain to (from L3
  // recovery), or nullopt to accept any.
  L2RestoreResult restore(std::uint64_t from_index, std::optional<std::uint32_t> prev_crc) {
    L2RestoreResult res;
    std::vector<std::byte> chain_bytes;
    const std::optional<std::uint64_t> start = find(from_index, prev_crc);
    if (start) {
      std::uint64_t off = *start;
      std::uint64_t walked = 0;
      ChainState c{from_index - 1, prev_crc.value_or(0), 0, 0};
      bool first = true;
      while (walked < capacity_) {
        if (off + conc::detail::kHeaderBytes > capacity_) break;
        const std::uint32_t elen = load_raw<std::uint32_t>(storage_ + off);
        const std::uint32_t eflags = load_raw<std::uint32_t>(storage_ + off + 4);
        if ((eflags & conc::detail::kPadFlag) != 0) {
          // A pad covers the tail; the next element starts at offset 0.
          if (off + conc::detail::kHeaderBytes + elen != capacity_ || off == 0) break;
          walked += capacity_ - off;
          off = 0;
          continue;
        }
        const auto len = record_at(off, elen);
        if (!len) break;
        const std::byte* rec = storage_ + off + conc::detail::kHeaderBytes;
        std::uint32_t content = 0;
        if (!chains(rec, c, first, content)) break;
        first = false;
        const RecordView v(std::span<const std::byte>(rec, *len));
        c = ChainState{v.index(), content, v.ts_ns(), v.epoch()};
        chain_bytes.insert(chain_bytes.end(), rec, rec + *len);
        ++res.records;
        const std::uint64_t step = conc::detail::record_bytes(*len);
        walked += step;
        off += step;
        if (off == capacity_) off = 0;
      }
      res.found = res.records != 0;
      res.chain = c;
    }
    // Re-publish the chain from position 0, then zero everything else.
    ring_.init(storage_, capacity_);
    std::uint64_t used = 0;
    for (std::size_t pos = 0; pos < chain_bytes.size();) {
      const std::uint32_t len = load_le32(chain_bytes.data() + pos);
      std::byte* dst = ring_.try_reserve(len);
      LLE_ASSERT(dst != nullptr, "restored chain must fit an empty ring");
      std::memcpy(dst, chain_bytes.data() + pos, len);
      ring_.commit();
      pos += len;
      used += conc::detail::record_bytes(len);
    }
    std::memset(storage_ + used, 0, capacity_ - used);
    return res;
  }

 private:
  // A validly sealed journal record framed by a ring element header at `off`.
  std::optional<std::uint32_t> record_at(std::uint64_t off, std::uint32_t elen) const noexcept {
    const std::uint64_t room = capacity_ - off - conc::detail::kHeaderBytes;
    if (elen < kHeaderBytes || elen > kMaxRecordBytes || elen % kRecordAlign != 0 || elen > room) return std::nullopt;
    const std::byte* rec = storage_ + off + conc::detail::kHeaderBytes;
    if (load_le32(rec + hdr::kLen) != elen || !valid_record_type(load_le16(rec + hdr::kType))) return std::nullopt;
    if (!sealer_->verify(rec)) return std::nullopt;
    return elen;
  }

  // `rec` passed record_at() (seal verified), so its content crc comes from the seal.
  bool chains(const std::byte* rec, const ChainState& c, bool first, std::uint32_t& content) const noexcept {
    content = sealer_->content_of(rec);
    const std::uint64_t index = load_le64(rec + hdr::kIndex);
    if (index != c.last_index + 1) return false;
    if (first) return true;  // find() checked prev_crc
    return load_le32(rec + hdr::kPrevCrc) == c.last_crc && load_le32(rec + hdr::kEpoch) >= c.epoch;
  }

  std::optional<std::uint64_t> find(std::uint64_t index, std::optional<std::uint32_t> prev_crc) const noexcept {
    for (std::uint64_t off = 0; off + conc::detail::kHeaderBytes + kHeaderBytes <= capacity_; off += kRecordAlign) {
      const std::uint32_t elen = load_raw<std::uint32_t>(storage_ + off);
      if (elen < kHeaderBytes || load_raw<std::uint32_t>(storage_ + off + 4) != 0) continue;
      const std::byte* rec = storage_ + off + conc::detail::kHeaderBytes;
      if (load_le64(rec + hdr::kIndex) != index) continue;
      if (prev_crc && load_le32(rec + hdr::kPrevCrc) != *prev_crc) continue;
      if (record_at(off, elen)) return off;
    }
    return std::nullopt;
  }

  std::byte* storage_ = nullptr;
  std::size_t capacity_ = 0;
  std::unique_ptr<Sealer> sealer_;
  conc::BroadcastRing<N> ring_;
};

}  // namespace lle::journal

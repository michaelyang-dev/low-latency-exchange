#pragma once
// BroadcastRing<N>: one producer, N independent consumer cursors over caller-provided
// storage (08-concurrency-runtime §6; journal L2 in 06 §5). Every consumer sees every
// record, in order, at its own pace. The producer may overwrite bytes only after all
// N cursors have passed them; it caches min(cursors) and recomputes it (N acquire
// loads) only when the cached minimum says the ring is full.
//
// Records are variable-length, 8-byte aligned, with the pad-to-end wrap of
// concurrent/byte_record.h (journal records). Each cursor lives on its own line, and
// each consumer's private state on another, so consumers never write a shared line.
//
// Progress: wait-free for the producer and every consumer (bounded steps; calls fail
// fast). A stalled consumer gates the producer by design (journal back-pressure).
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "common/cache.h"
#include "concurrent/byte_record.h"

namespace lle::conc {

template <std::size_t N>
class BroadcastRing {
  static_assert(N >= 1 && N <= 64, "consumer count");

 public:
  BroadcastRing() = default;
  BroadcastRing(const BroadcastRing&) = delete;
  BroadcastRing& operator=(const BroadcastRing&) = delete;

  static constexpr std::size_t consumers() noexcept { return N; }

  // Same contract as SpscByteRing::init: 8-byte-aligned storage, power-of-two
  // capacity in [32, 2^32]; called before any side runs. Traps on a bad argument.
  void init(std::byte* storage, std::size_t capacity_pow2) noexcept {
    if (storage == nullptr || !detail::valid_byte_ring_capacity(capacity_pow2) ||
        (reinterpret_cast<std::uintptr_t>(storage) & (detail::kRecordAlign - 1)) != 0) {
      __builtin_trap();
    }
    buf_ = storage;
    cap_ = capacity_pow2;
    limit_ = cap_ / 2 - detail::kHeaderBytes + 1;
    w_.store(0, std::memory_order_relaxed);
    p_.min_cache = 0;
    p_.pending_end = 0;
    for (std::size_t i = 0; i < N; ++i) {
      cursors_[i].pos.store(0, std::memory_order_relaxed);
      local_[i].wcache = 0;
      local_[i].next = 0;
    }
  }

  std::size_t capacity() const noexcept { return static_cast<std::size_t>(cap_); }
  std::uint32_t max_payload() const noexcept { return limit_ == 0 ? 0 : static_cast<std::uint32_t>(limit_ - 1); }

  // ---- producer ----------------------------------------------------------------

  // Reserves a record; nullptr if the slowest cursor has not freed enough bytes (or
  // the payload exceeds max_payload()). One reservation may be outstanding.
  std::byte* try_reserve(std::uint32_t payload_bytes) noexcept {
    if (payload_bytes >= limit_) return nullptr;
    const std::uint64_t w = w_.load(std::memory_order_relaxed);  // single writer
    const detail::Placement pl = detail::place_record(w, detail::record_bytes(payload_bytes), cap_);
    if (pl.end - p_.min_cache > cap_) {
      p_.min_cache = min_cursor();
      if (pl.end - p_.min_cache > cap_) return nullptr;
    }
    if (pl.pad != 0) {
      detail::write_header(buf_, w & (cap_ - 1), static_cast<std::uint32_t>(pl.pad - detail::kHeaderBytes),
                           detail::kPadFlag);
    }
    const std::uint64_t off = pl.start & (cap_ - 1);
    detail::write_header(buf_, off, payload_bytes, 0);
    p_.pending_end = pl.end;
    return buf_ + off + detail::kHeaderBytes;
  }

  void commit() noexcept {
    // Release publishes the record to every consumer's acquire load of w_.
    w_.store(p_.pending_end, std::memory_order_release);
  }

  // Producer's published position (bytes written so far).
  std::uint64_t write_position() const noexcept { return w_.load(std::memory_order_acquire); }

  // ---- consumer `c` (each index used by exactly one thread) ---------------------

  const std::byte* peek(std::size_t c, std::uint32_t& payload_bytes) noexcept {
    Consumer& me = local_[c];
    std::uint64_t r = cursors_[c].pos.load(std::memory_order_relaxed);  // single writer
    if (r == me.wcache) {
      // Acquire pairs with the producer's release of w_.
      me.wcache = w_.load(std::memory_order_acquire);
      if (r == me.wcache) return nullptr;
    }
    const detail::RecordHeader* h = detail::header_at(buf_, r & (cap_ - 1));
    if ((h->flags & detail::kPadFlag) != 0) {
      r += detail::kHeaderBytes + h->len;  // pad and record were committed together
      h = detail::header_at(buf_, r & (cap_ - 1));
    }
    payload_bytes = h->len;
    me.next = r + detail::record_bytes(h->len);
    return buf_ + (r & (cap_ - 1)) + detail::kHeaderBytes;
  }

  // Advances cursor `c` past the record returned by the last peek(c).
  void release(std::size_t c) noexcept {
    // Release pairs with the producer's acquire in min_cursor(): our reads of the
    // record happen-before the producer reuses its bytes.
    cursors_[c].pos.store(local_[c].next, std::memory_order_release);
  }

  // Calls f(const std::byte*, std::uint32_t) for up to `max_records` records on cursor
  // `c`; publishes the cursor once per batch.
  template <class F>
  std::size_t drain(std::size_t c, F&& f, std::size_t max_records) {
    Consumer& me = local_[c];
    const std::uint64_t r0 = cursors_[c].pos.load(std::memory_order_relaxed);
    std::uint64_t r = r0;
    std::size_t n = 0;
    while (n < max_records) {
      if (r == me.wcache) {
        if (n != 0) break;
        me.wcache = w_.load(std::memory_order_acquire);
        if (r == me.wcache) break;
      }
      const detail::RecordHeader* h = detail::header_at(buf_, r & (cap_ - 1));
      if ((h->flags & detail::kPadFlag) != 0) {
        r += detail::kHeaderBytes + h->len;
        h = detail::header_at(buf_, r & (cap_ - 1));
      }
      const std::uint32_t len = h->len;
      f(static_cast<const std::byte*>(buf_ + (r & (cap_ - 1)) + detail::kHeaderBytes), len);
      r += detail::record_bytes(len);
      ++n;
    }
    if (r != r0) cursors_[c].pos.store(r, std::memory_order_release);
    return n;
  }

  // Cursor position of consumer `c` (bytes consumed; approximate from other threads).
  std::uint64_t cursor_position(std::size_t c) const noexcept {
    return cursors_[c].pos.load(std::memory_order_acquire);
  }

 private:
  std::uint64_t min_cursor() const noexcept {
    // Acquire on each cursor: that consumer's reads of the bytes it passed
    // happen-before our overwrite of them.
    std::uint64_t m = cursors_[0].pos.load(std::memory_order_acquire);
    for (std::size_t i = 1; i < N; ++i) {
      const std::uint64_t v = cursors_[i].pos.load(std::memory_order_acquire);
      if (v < m) m = v;
    }
    return m;
  }

  struct Producer {
    std::uint64_t min_cache = 0;  // cached min(cursors); never ahead of the true min
    std::uint64_t pending_end = 0;
  };
  struct alignas(kFalseSharingBytes) Cursor {
    std::atomic<std::uint64_t> pos{0};
  };
  struct alignas(kFalseSharingBytes) Consumer {
    std::uint64_t wcache = 0;
    std::uint64_t next = 0;
  };

  alignas(kFalseSharingBytes) std::byte* buf_ = nullptr;  // read-only after init()
  std::uint64_t cap_ = 0;
  std::uint64_t limit_ = 0;  // max_payload() + 1; 0 before init()
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> w_{0};
  alignas(kFalseSharingBytes) Producer p_{};
  Cursor cursors_[N];  // members carry their own initializers (no array memset)
  Consumer local_[N];
};

}  // namespace lle::conc

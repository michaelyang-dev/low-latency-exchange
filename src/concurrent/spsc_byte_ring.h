#pragma once
// SpscByteRing: single-producer/single-consumer ring of variable-length records over
// caller-provided storage (08-concurrency-runtime §4). It backs nlog's per-thread
// rings (11-logging-observability). Record format: concurrent/byte_record.h.
//
// Index protocol is SpscRing's (cached opposite positions, acquire/release only, no
// fences), with byte positions instead of slot positions: w_ and r_ are monotonic
// 64-bit byte offsets. The producer publishes one record (plus an optional pad) per
// commit(); the consumer frees one record per release() or a batch per drain().
//
// Include allowlist (08 §7): <atomic>, <cstddef>, <cstdint>, <type_traits> only.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "common/cache.h"
#include "concurrent/byte_record.h"

namespace lle::conc {

class SpscByteRing {
 public:
  SpscByteRing() = default;
  SpscByteRing(const SpscByteRing&) = delete;
  SpscByteRing& operator=(const SpscByteRing&) = delete;

  // `storage` must be 8-byte aligned, `capacity_pow2` a power of two in [32, 2^32], and the
  // memory must outlive the ring. Call before either side runs (startup; the thread
  // start that follows provides the happens-before edge). Traps on a bad argument.
  void init(std::byte* storage, std::size_t capacity_pow2) noexcept {
    if (storage == nullptr || !detail::valid_byte_ring_capacity(capacity_pow2) ||
        (reinterpret_cast<std::uintptr_t>(storage) & (detail::kRecordAlign - 1)) != 0) {
      __builtin_trap();
    }
    buf_ = storage;
    cap_ = capacity_pow2;
    limit_ = cap_ / 2 - detail::kHeaderBytes + 1;
    w_.store(0, std::memory_order_relaxed);
    r_.store(0, std::memory_order_relaxed);
    p_.rcache = 0;
    p_.pending_end = 0;
    c_.wcache = 0;
    c_.next = 0;
  }

  std::size_t capacity() const noexcept { return static_cast<std::size_t>(cap_); }

  // Largest payload try_reserve() accepts: a record may use at most half the buffer,
  // which guarantees that a drained ring always has room for it whatever the wrap
  // position (a pad plus the record then fit in cap bytes).
  std::uint32_t max_payload() const noexcept { return limit_ == 0 ? 0 : static_cast<std::uint32_t>(limit_ - 1); }

  // ---- producer ----------------------------------------------------------------

  // Reserves a record with `payload_bytes` of payload and returns the 8-byte-aligned
  // payload pointer, or nullptr if there is no space now (or the payload exceeds
  // max_payload()). Nothing is visible to the consumer until commit(). Only one
  // reservation may be outstanding; reserving again replaces it.
  std::byte* try_reserve(std::uint32_t payload_bytes) noexcept {
    if (payload_bytes >= limit_) return nullptr;  // also rejects everything before init()
    const std::uint64_t w = w_.load(std::memory_order_relaxed);  // single writer
    const detail::Placement pl = detail::place_record(w, detail::record_bytes(payload_bytes), cap_);
    if (pl.end - p_.rcache > cap_) {
      // Acquire pairs with the consumer's release of r_ (its reads of the bytes we
      // are about to overwrite happen-before our writes).
      p_.rcache = r_.load(std::memory_order_acquire);
      if (pl.end - p_.rcache > cap_) return nullptr;
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

  // Publishes the last reservation (and its pad, if any).
  void commit() noexcept {
    // Release publishes the header(s) and payload to the consumer's acquire of w_.
    w_.store(p_.pending_end, std::memory_order_release);
  }

  // ---- consumer ----------------------------------------------------------------

  // Returns the oldest unread record's payload (8-byte aligned) and its length, or
  // nullptr if the ring is empty. The bytes stay valid until release()/drain().
  // Calling peek() again without release() returns the same record.
  const std::byte* peek(std::uint32_t& payload_bytes) noexcept {
    std::uint64_t r = r_.load(std::memory_order_relaxed);  // single writer
    if (r == c_.wcache) {
      // Acquire pairs with the producer's release of w_: records are visible.
      c_.wcache = w_.load(std::memory_order_acquire);
      if (r == c_.wcache) return nullptr;
    }
    const detail::RecordHeader* h = detail::header_at(buf_, r & (cap_ - 1));
    if ((h->flags & detail::kPadFlag) != 0) {
      // Skip the pad locally; r_ is published past it together with the record. The
      // pad was committed together with the record after it, so that record exists.
      r += detail::kHeaderBytes + h->len;
      h = detail::header_at(buf_, r & (cap_ - 1));
    }
    payload_bytes = h->len;
    c_.next = r + detail::record_bytes(h->len);
    return buf_ + (r & (cap_ - 1)) + detail::kHeaderBytes;
  }

  // Consumes the record returned by the last peek(). Precondition: peek() returned
  // non-null since the previous release().
  void release() noexcept { r_.store(c_.next, std::memory_order_release); }

  // Calls f(const std::byte* payload, std::uint32_t len) for up to `max_records`
  // records and publishes r_ once for the batch. Returns the number consumed.
  template <class F>
  std::size_t drain(F&& f, std::size_t max_records) {
    const std::uint64_t r0 = r_.load(std::memory_order_relaxed);
    std::uint64_t r = r0;
    std::size_t n = 0;
    while (n < max_records) {
      if (r == c_.wcache) {
        if (n != 0) break;  // finish this batch before refreshing the producer line
        c_.wcache = w_.load(std::memory_order_acquire);
        if (r == c_.wcache) break;
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
    if (r != r0) r_.store(r, std::memory_order_release);
    return n;
  }

  // Bytes committed and not yet released (approximate under concurrency).
  std::size_t used_bytes_approx() const noexcept {
    const std::uint64_t r = r_.load(std::memory_order_acquire);
    const std::uint64_t w = w_.load(std::memory_order_acquire);
    const std::uint64_t d = w - r;
    return static_cast<std::size_t>(d > cap_ ? cap_ : d);
  }

 private:
  struct Producer {
    std::uint64_t rcache = 0;       // producer's cached copy of r_
    std::uint64_t pending_end = 0;  // end of the outstanding reservation
  };
  struct Consumer {
    std::uint64_t wcache = 0;  // consumer's cached copy of w_
    std::uint64_t next = 0;    // end of the record returned by the last peek()
  };

  // Read-only after init(); kept off the written lines so it stays shared-clean.
  alignas(kFalseSharingBytes) std::byte* buf_ = nullptr;
  std::uint64_t cap_ = 0;
  std::uint64_t limit_ = 0;  // max_payload() + 1; 0 before init()
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> w_{0};
  alignas(kFalseSharingBytes) Producer p_{};
  alignas(kFalseSharingBytes) std::atomic<std::uint64_t> r_{0};
  alignas(kFalseSharingBytes) Consumer c_{};
};

}  // namespace lle::conc

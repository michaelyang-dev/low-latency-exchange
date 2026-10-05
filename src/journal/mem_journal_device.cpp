#include "journal/mem_journal_device.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "common/assert.h"

namespace lle::journal {

void MemJournalDevice::Bytes::resize(std::uint64_t n) {
  if (n == n_) return;
  std::unique_ptr<std::byte[]> p(new std::byte[n]);
  const std::uint64_t keep = std::min(n, n_);
  if (keep != 0) std::memcpy(p.get(), p_.get(), keep);
  if (n > keep) std::memset(p.get() + keep, 0, n - keep);
  p_ = std::move(p);
  n_ = n;
}

void MemJournalDevice::Bytes::copy_from(const Bytes& o) noexcept {
  const std::uint64_t n = std::min(n_, o.n_);
  if (n != 0) std::memcpy(p_.get(), o.p_.get(), n);
}

MemJournalDevice::MemJournalDevice(std::uint64_t size) : cur_(size), dur_(size) {}

bool MemJournalDevice::overlaps_live(std::uint64_t off, std::uint64_t len) const noexcept {
  const auto hit = [&](std::uint64_t o, std::uint64_t l) { return off < o + l && o < off + len; };
  for (std::size_t i = 0; i < n_pending_; ++i) {
    if (pending_[i].kind == Kind::Write && hit(pending_[i].off, pending_[i].len)) return true;
  }
  for (const Range& r : volatile_) {
    if (hit(r.off, r.len)) return true;
  }
  return false;
}

bool MemJournalDevice::submit_write(std::uint64_t off, std::span<const std::byte> b, bool dsync, std::uint64_t tag) noexcept {
  if (n_pending_ == kMaxInFlight) return false;
  LLE_ASSERT(!overlaps_live(off, b.size()), "MemJournalDevice: overlapping writes in flight");
  Op op;
  op.kind = Kind::Write;
  op.dsync = dsync;
  op.off = off;
  op.len = b.size();
  op.tag = tag;
  if (inject_armed_) {
    if (inject_at_ == 0) {
      op.forced = true;
      op.forced_result = inject_result_;
      inject_armed_ = false;
    } else {
      --inject_at_;
    }
  }
  // The data reaches the "page cache" view now; durability is decided at completion
  // (or by crash()).
  const std::uint64_t end = off + b.size();
  if (end > cur_.size()) {
    cur_.resize(end);
    dur_.resize(end);
  }
  if (!b.empty()) std::memcpy(cur_.data() + off, b.data(), b.size());
  pending_[n_pending_++] = op;
  ++writes_;
  return true;
}

bool MemJournalDevice::submit_sync(std::uint64_t tag) noexcept {
  if (n_pending_ == kMaxInFlight) return false;
  Op op;
  op.kind = Kind::Sync;
  op.tag = tag;
  pending_[n_pending_++] = op;
  ++syncs_;
  return true;
}

void MemJournalDevice::inject_write_result(std::uint64_t nth, std::int32_t result) noexcept {
  inject_armed_ = true;
  inject_at_ = nth;
  inject_result_ = result;
}

void MemJournalDevice::persist(std::uint64_t off, std::uint64_t len) noexcept {
  if (len != 0) std::memcpy(dur_.data() + off, cur_.data() + off, len);
}

env::DiskCompletion MemJournalDevice::complete(std::size_t i) noexcept {
  const Op op = pending_[i];
  // Keep submission order among the rest (FIFO mode completes index 0).
  for (std::size_t k = i + 1; k < n_pending_; ++k) pending_[k - 1] = pending_[k];
  --n_pending_;
  if (op.kind == Kind::Sync) {
    for (const Range& r : volatile_) persist(r.off, r.len);
    volatile_.clear();
    return {op.tag, 0};
  }
  if (op.forced) return {op.tag, op.forced_result};
  if (op.dsync) {
    persist(op.off, op.len);
  } else {
    volatile_.push_back(Range{op.off, op.len});
  }
  return {op.tag, static_cast<std::int32_t>(op.len)};
}

std::int64_t MemJournalDevice::read(std::uint64_t off, std::span<std::byte> out) noexcept {
  if (off >= cur_.size()) return 0;
  const std::uint64_t n = std::min<std::uint64_t>(out.size(), cur_.size() - off);
  if (n != 0) std::memcpy(out.data(), cur_.data() + off, n);
  return static_cast<std::int64_t>(n);
}

bool MemJournalDevice::resize(std::uint64_t n) {
  cur_.resize(n);
  dur_.resize(n);
  return true;
}

std::span<std::byte> MemJournalDevice::tamper() noexcept { return {cur_.data(), cur_.size()}; }

void MemJournalDevice::crash(Prng& rng, const MemCrashOptions& opts) {
  const std::uint64_t total = std::uint64_t{opts.w_drop} + opts.w_full + opts.w_torn;
  const auto fate_of = [&]() -> int {
    if (total == 0) return 0;
    const std::uint64_t x = rng.below(total);
    if (x < opts.w_drop) return 0;
    if (x < std::uint64_t{opts.w_drop} + opts.w_full) return 1;
    return 2;
  };
  const auto apply = [&](std::uint64_t off, std::uint64_t len) {
    switch (fate_of()) {
      case 0:
        break;
      case 1:
        persist(off, len);
        break;
      default: {
        const std::uint64_t sec = opts.sector_bytes == 0 ? 512 : opts.sector_bytes;
        for (std::uint64_t s = 0; s < len; s += sec) {
          const std::uint64_t n = std::min(sec, len - s);
          if (!rng.chance(1, 2)) continue;
          if (opts.garbage_den != 0 && rng.chance(1, opts.garbage_den)) {
            for (std::uint64_t k = 0; k < n; ++k) dur_[off + s + k] = static_cast<std::byte>(rng.next_u64());
          } else {
            persist(off + s, n);
          }
        }
        break;
      }
    }
  };
  for (std::size_t i = 0; i < n_pending_; ++i) {
    if (pending_[i].kind == Kind::Write) apply(pending_[i].off, pending_[i].len);
  }
  for (const Range& r : volatile_) apply(r.off, r.len);
  n_pending_ = 0;
  volatile_.clear();
  // The restarted process sees a fresh device: test controls do not survive a crash.
  inject_armed_ = false;
  hold_ = false;
  only_armed_ = false;
  cur_.copy_from(dur_);
}

}  // namespace lle::journal

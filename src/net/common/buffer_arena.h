#pragma once
// Fixed-capacity buffer arena for RX (and TX staging) buffers.
//
// One aligned allocation at startup holds `count` equally sized buffers; the arena never
// allocates again (08 §1: no allocation after startup). Buffers are addressed by index,
// which is exactly what io_uring provided-buffer rings return (the buffer id) and what
// recvmmsg batches use. A LIFO free list serves slot-style users (TX slots); LIFO keeps
// recently used, cache-warm buffers in circulation.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "common/assert.h"
#include "net/common/error.h"

namespace lle::net {

class BufferArena {
 public:
  BufferArena() = default;
  BufferArena(const BufferArena&) = delete;
  BufferArena& operator=(const BufferArena&) = delete;
  BufferArena(BufferArena&&) noexcept = default;
  BufferArena& operator=(BufferArena&&) noexcept = default;
  ~BufferArena() = default;

  // Allocates `count` buffers of `buf_size` bytes (stride rounded up to 64 bytes), base
  // aligned to `align` (page alignment suits provided-buffer rings). Memory is zeroed,
  // which also faults every page in. May be called once.
  Result<void> init(std::uint32_t count, std::uint32_t buf_size, std::size_t align = 4096);

  [[nodiscard]] bool initialized() const noexcept { return base_ != nullptr; }
  [[nodiscard]] std::uint32_t count() const noexcept { return count_; }
  [[nodiscard]] std::uint32_t buf_size() const noexcept { return buf_size_; }
  [[nodiscard]] std::size_t stride() const noexcept { return stride_; }
  [[nodiscard]] std::byte* base() const noexcept { return base_; }
  [[nodiscard]] std::size_t bytes() const noexcept { return stride_ * count_; }

  [[nodiscard]] std::byte* data(std::uint32_t i) const noexcept {
    LLE_DASSERT(i < count_);
    return base_ + static_cast<std::size_t>(i) * stride_;
  }
  [[nodiscard]] std::span<std::byte> buffer(std::uint32_t i) const noexcept { return {data(i), buf_size_}; }

  // Index of the buffer containing `p` (which must point into the arena).
  [[nodiscard]] std::uint32_t index_of(const std::byte* p) const noexcept {
    LLE_DASSERT(p >= base_ && p < base_ + bytes());
    return static_cast<std::uint32_t>(static_cast<std::size_t>(p - base_) / stride_);
  }

  // Free list over all buffers (initially every buffer is free).
  [[nodiscard]] bool acquire(std::uint32_t& idx) noexcept {
    if (nfree_ == 0) return false;
    idx = free_[--nfree_];
    return true;
  }
  void release(std::uint32_t idx) noexcept {
    LLE_DASSERT(idx < count_ && nfree_ < count_);
    free_[nfree_++] = idx;
  }
  [[nodiscard]] std::uint32_t free_count() const noexcept { return nfree_; }

 private:
  struct FreeDeleter {
    void operator()(std::byte* p) const noexcept;
  };
  std::unique_ptr<std::byte[], FreeDeleter> mem_;
  std::unique_ptr<std::uint32_t[]> free_;
  std::byte* base_ = nullptr;
  std::size_t stride_ = 0;
  std::uint32_t count_ = 0;
  std::uint32_t buf_size_ = 0;
  std::uint32_t nfree_ = 0;
};

}  // namespace lle::net

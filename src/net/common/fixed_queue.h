#pragma once
// Single-threaded fixed-capacity FIFO (power-of-two ring), allocated once at init().
// Used for deferred stream events, ready lists and per-port completion queues.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/assert.h"

namespace lle::net {

template <class T>
class FixedQueue {
 public:
  FixedQueue() = default;

  // Capacity is rounded up to a power of two.
  void init(std::size_t capacity) {
    cap_ = std::bit_ceil(capacity < 2 ? std::size_t{2} : capacity);
    buf_ = std::make_unique<T[]>(cap_);
    head_ = tail_ = 0;
  }

  [[nodiscard]] bool empty() const noexcept { return head_ == tail_; }
  [[nodiscard]] bool full() const noexcept { return tail_ - head_ == cap_; }
  [[nodiscard]] std::size_t size() const noexcept { return static_cast<std::size_t>(tail_ - head_); }
  [[nodiscard]] std::size_t capacity() const noexcept { return cap_; }

  [[nodiscard]] bool push(const T& v) noexcept {
    if (full()) return false;
    buf_[tail_++ & (cap_ - 1)] = v;
    return true;
  }
  [[nodiscard]] T& front() noexcept {
    LLE_DASSERT(!empty());
    return buf_[head_ & (cap_ - 1)];
  }
  void pop() noexcept {
    LLE_DASSERT(!empty());
    ++head_;
  }
  [[nodiscard]] T& operator[](std::size_t i) noexcept { return buf_[(head_ + i) & (cap_ - 1)]; }
  void clear() noexcept { head_ = tail_ = 0; }

 private:
  std::unique_ptr<T[]> buf_;
  std::size_t cap_ = 0;
  std::uint64_t head_ = 0;
  std::uint64_t tail_ = 0;
};

}  // namespace lle::net

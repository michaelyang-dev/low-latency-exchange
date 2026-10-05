#pragma once
// Growable power-of-two FIFO. Grows by doubling only past its high-water mark,
// so steady-state simulation loops do not allocate.
#include <bit>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/assert.h"

namespace lle::sim {

template <class T>
class RingQueue {
 public:
  explicit RingQueue(std::size_t initial = 16) : buf_(std::bit_ceil(initial < 2 ? std::size_t{2} : initial)) {}

  [[nodiscard]] bool empty() const noexcept { return head_ == tail_; }
  [[nodiscard]] std::size_t size() const noexcept { return static_cast<std::size_t>(tail_ - head_); }
  [[nodiscard]] std::size_t capacity() const noexcept { return buf_.size(); }

  void push(const T& v) {
    if (size() == buf_.size()) grow();
    buf_[static_cast<std::size_t>(tail_++) & mask()] = v;
  }
  [[nodiscard]] T& front() noexcept {
    LLE_DASSERT(!empty());
    return buf_[static_cast<std::size_t>(head_) & mask()];
  }
  [[nodiscard]] const T& operator[](std::size_t i) const noexcept {
    return buf_[static_cast<std::size_t>(head_ + i) & mask()];
  }
  void pop() noexcept {
    LLE_DASSERT(!empty());
    ++head_;
  }
  void clear() noexcept { head_ = tail_ = 0; }

 private:
  [[nodiscard]] std::size_t mask() const noexcept { return buf_.size() - 1; }
  void grow() {
    std::vector<T> n(buf_.size() * 2);
    const std::size_t sz = size();
    for (std::size_t i = 0; i < sz; ++i) n[i] = buf_[static_cast<std::size_t>(head_ + i) & mask()];
    buf_.swap(n);
    head_ = 0;
    tail_ = sz;
  }

  std::vector<T> buf_;
  std::uint64_t head_ = 0;
  std::uint64_t tail_ = 0;
};

}  // namespace lle::sim

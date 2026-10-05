#pragma once
// Fixed-capacity byte FIFO used for the TCP send and receive buffers. Storage is
// allocated once, at construction (startup); nothing allocates afterwards.
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>

namespace lle::net::utcp {

class ByteRing {
 public:
  // Up to two contiguous pieces (the ring may wrap).
  struct Spans {
    std::span<const std::byte> first;
    std::span<const std::byte> second;
    [[nodiscard]] std::size_t size() const noexcept { return first.size() + second.size(); }
  };

  ByteRing() = default;
  explicit ByteRing(std::size_t capacity)
      : buf_(capacity != 0 ? std::make_unique<std::byte[]>(capacity) : nullptr), cap_(capacity) {}

  [[nodiscard]] std::size_t capacity() const noexcept { return cap_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t free() const noexcept { return cap_ - size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

  void clear() noexcept {
    head_ = 0;
    size_ = 0;
  }

  // Appends up to free() bytes; returns the number copied.
  std::size_t write(std::span<const std::byte> src) noexcept {
    const std::size_t n = std::min(src.size(), free());
    if (n == 0) return 0;
    std::size_t tail = head_ + size_;
    if (tail >= cap_) tail -= cap_;
    const std::size_t first = std::min(n, cap_ - tail);
    std::memcpy(buf_.get() + tail, src.data(), first);
    if (n > first) std::memcpy(buf_.get(), src.data() + first, n - first);
    size_ += n;
    return n;
  }

  // View of [offset, offset + len) relative to the head, clamped to size().
  [[nodiscard]] Spans peek(std::size_t offset, std::size_t len) const noexcept {
    if (offset >= size_) return {};
    len = std::min(len, size_ - offset);
    std::size_t start = head_ + offset;
    if (start >= cap_) start -= cap_;
    const std::size_t first = std::min(len, cap_ - start);
    Spans s;
    s.first = std::span<const std::byte>(buf_.get() + start, first);
    if (len > first) s.second = std::span<const std::byte>(buf_.get(), len - first);
    return s;
  }

  // Drops up to n bytes from the head.
  void consume(std::size_t n) noexcept {
    n = std::min(n, size_);
    head_ += n;
    if (head_ >= cap_) head_ -= cap_;
    size_ -= n;
    if (size_ == 0) head_ = 0;  // keeps the next write contiguous
  }

 private:
  std::unique_ptr<std::byte[]> buf_;
  std::size_t cap_ = 0;
  std::size_t head_ = 0;
  std::size_t size_ = 0;
};

}  // namespace lle::net::utcp

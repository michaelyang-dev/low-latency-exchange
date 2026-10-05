#pragma once
// Two-region circular byte buffer ("bip buffer") over caller-provided memory.
//
// Every reservation is contiguous, so each staged message can be handed to one SEND
// SQE as is, and bytes already handed to the kernel (the front of region A) never move.
// Region A grows at its end; when the tail has no room the buffer starts region B at
// offset 0 (if the bytes before A's start are free) and switches to it once A drains.
#include <cstddef>
#include <cstdint>
#include <span>

namespace lle::net::uring {

class BipBuffer {
 public:
  void reset(std::byte* mem, std::uint32_t cap) noexcept {
    mem_ = mem;
    cap_ = cap;
    clear();
  }
  void clear() noexcept { a_start_ = a_end_ = b_end_ = 0; }

  // Contiguous space for `n` bytes, or nullptr. Must be followed by commit(n).
  [[nodiscard]] std::byte* reserve(std::uint32_t n) noexcept {
    if (n == 0 || n > cap_) return nullptr;
    if (b_end_ == 0 && a_start_ == a_end_) {
      a_start_ = a_end_ = 0;  // empty: restart at the beginning
    }
    if (b_end_ == 0 && cap_ - a_end_ >= n) {
      reserving_b_ = false;
      return mem_ + a_end_;
    }
    // Region B lives in [0, a_start_).
    if (a_start_ - b_end_ >= n) {
      reserving_b_ = true;
      return mem_ + b_end_;
    }
    return nullptr;
  }
  void commit(std::uint32_t n) noexcept {
    if (reserving_b_) {
      b_end_ += n;
    } else {
      a_end_ += n;
    }
  }

  // Largest single reservation possible right now.
  [[nodiscard]] std::uint32_t max_reserve() const noexcept {
    if (b_end_ == 0 && a_start_ == a_end_) return cap_;
    const std::uint32_t tail = b_end_ == 0 ? cap_ - a_end_ : 0;
    const std::uint32_t head = a_start_ - b_end_;
    return tail > head ? tail : head;
  }

  // Oldest unsent bytes (contiguous: the rest of region A).
  [[nodiscard]] std::span<std::byte> front() const noexcept { return {mem_ + a_start_, a_end_ - a_start_}; }

  void consume(std::uint32_t n) noexcept {
    a_start_ += n;
    if (a_start_ == a_end_) {
      a_start_ = 0;
      a_end_ = b_end_;
      b_end_ = 0;
    }
  }

  [[nodiscard]] std::uint32_t size() const noexcept { return (a_end_ - a_start_) + b_end_; }
  [[nodiscard]] bool empty() const noexcept { return size() == 0; }
  [[nodiscard]] std::uint32_t capacity() const noexcept { return cap_; }

 private:
  std::byte* mem_ = nullptr;
  std::uint32_t cap_ = 0;
  std::uint32_t a_start_ = 0;
  std::uint32_t a_end_ = 0;
  std::uint32_t b_end_ = 0;
  bool reserving_b_ = false;
};

}  // namespace lle::net::uring
